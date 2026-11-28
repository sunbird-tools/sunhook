#include "sh_fixup.h"

#include <stdbool.h>
#include <windows.h>

#include "sh_log.h"
#include "sh_safe.h"

#define SH_FIXUP_THREADS_MAX 4096

typedef LONG(NTAPI *sh_fixup_next_thread_t)(HANDLE process, HANDLE thread, ACCESS_MASK access, ULONG attributes,
                                            ULONG flags, HANDLE *next);

static pthread_mutex_t sh_fixup_lock = PTHREAD_MUTEX_INITIALIZER;
static DWORD sh_fixup_owner;
static size_t sh_fixup_depth;
static HANDLE sh_fixup_threads[SH_FIXUP_THREADS_MAX];
static DWORD sh_fixup_ids[SH_FIXUP_THREADS_MAX];
static size_t sh_fixup_threads_cnt;

static bool sh_fixup_is_parked(DWORD id) {
  for (size_t i = 0; i < sh_fixup_threads_cnt; i++)
    if (sh_fixup_ids[i] == id) return true;
  return false;
}

// NtGetNextThread walks the process's threads without the heap, which a suspended thread may hold
// locked, and the walk repeats because a thread started meanwhile runs unparked. GetThreadContext
// waits until a suspension has taken effect.
void sh_fixup_stop(void) {
  static sh_fixup_next_thread_t next_thread;
  DWORD self = GetCurrentThreadId();
  if (__atomic_load_n(&sh_fixup_owner, __ATOMIC_RELAXED) == self) {
    sh_fixup_depth++;
    return;
  }

  sh_safe_pthread_mutex_lock(&sh_fixup_lock);
  DWORD saved_error = GetLastError();
  __atomic_store_n(&sh_fixup_owner, self, __ATOMIC_RELAXED);
  sh_fixup_depth = 1;
  sh_fixup_threads_cnt = 0;
  if (NULL == next_thread)
    next_thread = (sh_fixup_next_thread_t)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetNextThread");
  if (NULL == next_thread) {
    SH_LOG_WARN("fixup: no NtGetNextThread, threads run unparked");
    goto end;
  }

  const ACCESS_MASK access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                             THREAD_QUERY_LIMITED_INFORMATION;
  bool found = true;
  while (found && sh_fixup_threads_cnt < SH_FIXUP_THREADS_MAX) {
    found = false;
    HANDLE prev = NULL, next;
    bool kept = false;
    while (sh_fixup_threads_cnt < SH_FIXUP_THREADS_MAX &&
           0 == next_thread(GetCurrentProcess(), prev, access, 0, 0, &next)) {
      if (NULL != prev && !kept) CloseHandle(prev);
      prev = next;
      kept = false;
      DWORD id = GetThreadId(next);
      if (id == self || sh_fixup_is_parked(id) || (DWORD)-1 == SuspendThread(next)) continue;
      CONTEXT ctx;
      ctx.ContextFlags = CONTEXT_CONTROL;
      GetThreadContext(next, &ctx);
      sh_fixup_threads[sh_fixup_threads_cnt] = next;
      sh_fixup_ids[sh_fixup_threads_cnt] = id;
      sh_fixup_threads_cnt++;
      kept = true;
      found = true;
    }
    if (NULL != prev && !kept) CloseHandle(prev);
  }

end:
  SetLastError(saved_error);
}

void sh_fixup_resume(const uintptr_t *from, const uintptr_t *to, size_t cnt) {
  if (--sh_fixup_depth > 0) return;

  DWORD saved_error = GetLastError();
  for (size_t i = 0; i < sh_fixup_threads_cnt; i++) {
    HANDLE thread = sh_fixup_threads[i];
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (cnt > 0 && GetThreadContext(thread, &ctx)) {
      for (size_t j = 0; j < cnt; j++) {
        if (ctx.Rip != from[j]) continue;
        ctx.Rip = to[j];
        SetThreadContext(thread, &ctx);
        break;
      }
    }
    ResumeThread(thread);
    CloseHandle(thread);
  }
  sh_fixup_threads_cnt = 0;

  __atomic_store_n(&sh_fixup_owner, 0, __ATOMIC_RELAXED);
  SetLastError(saved_error);
  sh_safe_pthread_mutex_unlock(&sh_fixup_lock);
}
