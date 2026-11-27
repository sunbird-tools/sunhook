#include "sh_fixup.h"

#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdbool.h>

#include "sh_safe.h"

#define SH_FIXUP_THREADS_MAX 4096

static pthread_mutex_t sh_fixup_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t sh_fixup_owner;
static size_t sh_fixup_depth;
static thread_act_t sh_fixup_threads[SH_FIXUP_THREADS_MAX];
static size_t sh_fixup_threads_cnt;

static bool sh_fixup_is_parked(thread_act_t thread) {
  for (size_t i = 0; i < sh_fixup_threads_cnt; i++)
    if (sh_fixup_threads[i] == thread) return true;
  return false;
}

// Nests for sh_util_write_inst(), and re-snapshots because a thread started meanwhile runs unparked.
void sh_fixup_stop(void) {
  pthread_t self = pthread_self();
  if (__atomic_load_n(&sh_fixup_owner, __ATOMIC_RELAXED) == self) {
    sh_fixup_depth++;
    return;
  }

  sh_safe_pthread_mutex_lock(&sh_fixup_lock);
  int saved_errno = errno;
  __atomic_store_n(&sh_fixup_owner, self, __ATOMIC_RELAXED);
  sh_fixup_depth = 1;
  sh_fixup_threads_cnt = 0;

  mach_port_t task = mach_task_self();
  mach_port_t me = mach_thread_self();
  bool found = true;
  while (found && sh_fixup_threads_cnt < SH_FIXUP_THREADS_MAX) {
    thread_act_array_t threads;
    mach_msg_type_number_t cnt;
    if (KERN_SUCCESS != task_threads(task, &threads, &cnt)) break;
    found = false;
    for (mach_msg_type_number_t i = 0; i < cnt; i++) {
      if (threads[i] != me && !sh_fixup_is_parked(threads[i]) &&
          sh_fixup_threads_cnt < SH_FIXUP_THREADS_MAX && KERN_SUCCESS == thread_suspend(threads[i])) {
        sh_fixup_threads[sh_fixup_threads_cnt++] = threads[i];
        found = true;
        continue;
      }
      mach_port_deallocate(task, threads[i]);
    }
    vm_deallocate(task, (vm_address_t)threads, cnt * sizeof(thread_act_t));
  }
  mach_port_deallocate(task, me);
  errno = saved_errno;
}

void sh_fixup_resume(const uintptr_t *from, const uintptr_t *to, size_t cnt) {
  if (--sh_fixup_depth > 0) return;

  int saved_errno = errno;
  mach_port_t task = mach_task_self();
  for (size_t i = 0; i < sh_fixup_threads_cnt; i++) {
    thread_act_t thread = sh_fixup_threads[i];
    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    if (cnt > 0 &&
        KERN_SUCCESS == thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count)) {
      uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(state);
      for (size_t j = 0; j < cnt; j++) {
        if (pc != from[j]) continue;
        arm_thread_state64_set_pc_fptr(state, (void *)to[j]);
        thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, count);
        break;
      }
    }
    thread_resume(thread);
    mach_port_deallocate(task, thread);
  }
  sh_fixup_threads_cnt = 0;

  __atomic_store_n(&sh_fixup_owner, (pthread_t)NULL, __ATOMIC_RELAXED);
  errno = saved_errno;
  sh_safe_pthread_mutex_unlock(&sh_fixup_lock);
}
