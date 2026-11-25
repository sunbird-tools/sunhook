#include "sh_fixup.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <ucontext.h>

#include "sh_log.h"
#include "sh_safe.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#include "linux_syscall_support_android_ext.h"
#pragma clang diagnostic pop

#if defined(__x86_64__)
#define SH_FIXUP_PC(mc) ((mc)->gregs[REG_RIP])
#elif defined(__i386__)
#define SH_FIXUP_PC(mc) ((mc)->gregs[REG_EIP])
#elif defined(__aarch64__)
#define SH_FIXUP_PC(mc) ((mc)->pc)
#elif defined(__arm__)
#define SH_FIXUP_PC(mc) ((mc)->arm_pc)
#endif

// LSS wraps rt_sigaction as sigaction only on arches that need a restorer.
#if defined(__aarch64__)
#define sh_fixup_sigaction(signum, act, old) sys_rt_sigaction((signum), (act), (old), (KERNEL_NSIG + 7) / 8)
#else
#define sh_fixup_sigaction(signum, act, old) sys_sigaction((signum), (act), (old))
#endif

#define SH_FIXUP_WAIT_NS 50000000

static pthread_mutex_t sh_fixup_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t sh_fixup_seq;  // odd while threads are parked
static uintptr_t sh_fixup_from[SH_FIXUP_MAX];
static uintptr_t sh_fixup_to[SH_FIXUP_MAX];
static size_t sh_fixup_cnt;
static size_t sh_fixup_parked;
static size_t sh_fixup_left;
static size_t sh_fixup_sent;
static struct kernel_sigaction sh_fixup_old;
static bool sh_fixup_installed;

static void sh_fixup_handler(int signum, siginfo_t *info, void *uc) {
  uint32_t seq = __atomic_load_n(&sh_fixup_seq, __ATOMIC_ACQUIRE);

  // A late signal after a timeout, or one the app sent.
  if (0 == (seq & 1)) {
    if (sh_fixup_old.sa_flags & SA_SIGINFO) {
      if (NULL != sh_fixup_old.sa_sigaction_) sh_fixup_old.sa_sigaction_(signum, info, uc);
    } else if (SIG_DFL != sh_fixup_old.sa_handler_ && SIG_IGN != sh_fixup_old.sa_handler_) {
      sh_fixup_old.sa_handler_(signum);
    }
    return;
  }

  __atomic_add_fetch(&sh_fixup_parked, 1, __ATOMIC_RELEASE);
  while (seq == __atomic_load_n(&sh_fixup_seq, __ATOMIC_ACQUIRE))
    sys_sched_yield();

  mcontext_t *mc = &((ucontext_t *)uc)->uc_mcontext;
  for (size_t i = 0; i < sh_fixup_cnt; i++) {
    if ((uintptr_t)SH_FIXUP_PC(mc) != sh_fixup_from[i]) continue;
    SH_FIXUP_PC(mc) = (__typeof__(SH_FIXUP_PC(mc)))sh_fixup_to[i];
    break;
  }
  __atomic_add_fetch(&sh_fixup_left, 1, __ATOMIC_RELEASE);
}

static int64_t sh_fixup_now(void) {
  struct kernel_timespec ts;
  sys_clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void sh_fixup_wait(size_t *counter, size_t target) {
  int64_t deadline = sh_fixup_now() + SH_FIXUP_WAIT_NS;
  while (__atomic_load_n(counter, __ATOMIC_ACQUIRE) < target && sh_fixup_now() < deadline)
    sys_sched_yield();
}

// Raw syscalls avoid libc functions that may have just been hooked, and nothing here allocates while
// other threads are parked. A thread that misses the deadline still has the signal pending, so the
// handler then stays installed.
void sh_fixup_stop(void) {
  sh_safe_pthread_mutex_lock(&sh_fixup_lock);
  int saved_errno = errno;

  sh_fixup_cnt = 0;
  sh_fixup_sent = 0;
  __atomic_store_n(&sh_fixup_parked, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&sh_fixup_left, 0, __ATOMIC_RELAXED);
  __atomic_add_fetch(&sh_fixup_seq, 1, __ATOMIC_RELEASE);

  int signum = SIGRTMAX;
  if (!sh_fixup_installed) {
    struct kernel_sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction_ = sh_fixup_handler;
    act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    if (0 != sh_fixup_sigaction(signum, &act, &sh_fixup_old)) goto end;
    sh_fixup_installed = true;
  }

  pid_t pid = sys_getpid();
  pid_t self_tid = sys__gettid();
  int fd = sys_open("/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
  if (fd >= 0) {
    char buf[4096];
    int n;
    while ((n = sys_getdents64(fd, (struct kernel_dirent64 *)(void *)buf, sizeof(buf))) > 0) {
      for (int pos = 0; pos < n;) {
        struct kernel_dirent64 *dirent = (struct kernel_dirent64 *)(void *)(buf + pos);
        pos += dirent->d_reclen;
        pid_t tid = 0;
        for (const char *c = dirent->d_name; '0' <= *c && *c <= '9'; c++)
          tid = tid * 10 + (*c - '0');
        if (tid <= 0 || tid == self_tid) continue;
        if (0 == sys_tgkill(pid, tid, signum)) sh_fixup_sent++;
      }
    }
    sys_close(fd);
  }
  sh_fixup_wait(&sh_fixup_parked, sh_fixup_sent);

end:
  errno = saved_errno;
}

void sh_fixup_resume(const uintptr_t *from, const uintptr_t *to, size_t cnt) {
  int saved_errno = errno;

  memcpy(sh_fixup_from, from, cnt * sizeof(uintptr_t));
  memcpy(sh_fixup_to, to, cnt * sizeof(uintptr_t));
  sh_fixup_cnt = cnt;
  size_t parked = __atomic_load_n(&sh_fixup_parked, __ATOMIC_ACQUIRE);
  __atomic_add_fetch(&sh_fixup_seq, 1, __ATOMIC_RELEASE);
  sh_fixup_wait(&sh_fixup_left, parked);

  if (parked >= sh_fixup_sent && __atomic_load_n(&sh_fixup_left, __ATOMIC_ACQUIRE) >= parked &&
      sh_fixup_installed && 0 == sh_fixup_sigaction(SIGRTMAX, &sh_fixup_old, NULL))
    sh_fixup_installed = false;
  if (parked < sh_fixup_sent)
    SH_LOG_WARN("fixup: %zu of %zu threads parked", parked, sh_fixup_sent);

  errno = saved_errno;
  sh_safe_pthread_mutex_unlock(&sh_fixup_lock);
}
