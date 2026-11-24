#include "sh_inst.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>

#include "sh_config.h"
#include "sh_enter.h"
#include "sh_island.h"
#include "sh_linker.h"
#include "sh_log.h"
#include "sh_recorder.h"
#include "sh_safe.h"
#include "sh_sig.h"
#include "sh_util.h"
#include "sh_x64.h"
#include "shadowhook.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#include "linux_syscall_support_android_ext.h"
#pragma clang diagnostic pop

#define SH_INST_ISLAND_SIZE     16
#define SH_INST_ISLAND_ADDR_OFF 8
#define SH_INST_INSTS_MAX       32

// Keeps every byte of a 16-byte island, or of the enter, within rel32 reach.
#define SH_INST_REL32_RANGE 0x7FFF0000

static uintptr_t sh_inst_range_low(uintptr_t pc) {
  return pc > SH_INST_REL32_RANGE ? pc - SH_INST_REL32_RANGE : 1;
}

static uintptr_t sh_inst_range_high(uintptr_t pc) {
  return UINTPTR_MAX - pc > SH_INST_REL32_RANGE ? pc + SH_INST_REL32_RANGE : UINTPTR_MAX;
}

static void sh_inst_record_bytes(sh_recorder_trace_t *trace, uintptr_t addr, size_t len) {
  for (size_t i = 0; i < len; i++)
    sh_recorder_trace_append(trace, "%02" PRIx8, ((uint8_t *)addr)[i]);
}

static void sh_inst_record(sh_inst_t *self, uintptr_t target_addr, uintptr_t new_addr, bool is_rehook,
                           sh_recorder_trace_t *trace) {
  if (!sh_recorder_get_recordable()) return;

  sh_recorder_trace_append(trace, "B|x86_64|%shook;", is_rehook ? "re" : "");

  sh_recorder_trace_append(trace, "T|%" PRIxPTR "|", target_addr);
  sh_inst_record_bytes(trace, (uintptr_t)self->backup, self->backup_len);
  sh_recorder_trace_append(trace, "|");
  sh_inst_record_bytes(trace, (uintptr_t)self->exit, self->backup_len);
  sh_recorder_trace_append(trace, ";");

  if (self->island_exit.size > 0) {
    sh_recorder_trace_append(trace, "X|%" PRIxPTR "|%zu|", self->island_exit.addr, self->island_exit.type);
    sh_inst_record_bytes(trace, self->island_exit.addr, self->island_exit.size);
    sh_recorder_trace_append(trace, ";");
  }

  sh_recorder_trace_append(trace, "N|%" PRIxPTR ";", new_addr);

  sh_recorder_trace_append(trace, "E|%" PRIxPTR "|", self->enter);
  sh_inst_record_bytes(trace, self->enter, self->enter_len);
  sh_recorder_trace_append(trace, ";");

  sh_recorder_trace_append(trace, "R|%" PRIxPTR ";", target_addr + self->backup_len);
}

// Bytes after a ret or jmp may belong to the next function, so they are only relocated when
// they are padding or an earlier branch targets them.
static int sh_inst_rewrite(sh_inst_t *self, uintptr_t target_addr, size_t needed,
                           sh_inst_set_orig_addr_t set_orig_addr, void *set_orig_addr_arg) {
  const uint8_t *code = (const uint8_t *)target_addr;
  sh_x64_inst_t insts[SH_INST_INSTS_MAX];
  size_t offs[SH_INST_INSTS_MAX], new_offs[SH_INST_INSTS_MAX];
  size_t cnt = 0, len = 0, enter_len = 0;
  bool is_term = false;

  while (len < needed) {
    if (cnt == SH_INST_INSTS_MAX) return SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED;
    sh_x64_inst_t *inst = &insts[cnt];
    if (!sh_x64_decode(code + len, inst)) return SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED;
    if (is_term && !sh_x64_is_padding(code + len, inst)) {
      size_t j = 0;
      while (j < cnt && !(SH_X64_KIND_PLAIN != insts[j].kind &&
                          (intptr_t)(offs[j] + insts[j].len) + insts[j].rel == (intptr_t)len))
        j++;
      if (j == cnt) return SHADOWHOOK_ERRNO_HOOK_SYMSZ;
      is_term = false;
    }

    offs[cnt] = len;
    new_offs[cnt] = enter_len;
    enter_len += sh_x64_rewrite_len(inst);
    len += inst->len;
    is_term = is_term || inst->is_term;
    cnt++;
  }
  if (!is_term) enter_len += SH_X64_ABS_JMP_LEN;
  if (len > sizeof(self->backup) || enter_len > SH_ENTER_SZ) return SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED;

  for (size_t i = 0; i < cnt; i++) {
    sh_x64_inst_t *inst = &insts[i];
    uintptr_t next_pc = target_addr + offs[i] + inst->len;
    uintptr_t dest = 0;

    if (SH_X64_KIND_PLAIN != inst->kind) {
      dest = (uintptr_t)((intptr_t)next_pc + inst->rel);
      if (target_addr <= dest && dest < target_addr + len) {
        size_t j = 0;
        while (j < cnt && offs[j] != dest - target_addr)
          j++;
        if (j == cnt) return SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED;
        dest = self->enter + new_offs[j];
      }
    } else if (0 != inst->disp_off) {
      int32_t disp;
      memcpy(&disp, code + offs[i] + inst->disp_off, sizeof(disp));
      dest = (uintptr_t)((intptr_t)next_pc + disp);
    }

    bool ok;
    sh_x64_rewrite((uint8_t *)(self->enter + new_offs[i]), code + offs[i], inst, dest,
                   self->enter + new_offs[i], &ok);
    if (!ok) return SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED;
  }
  if (!is_term) sh_x64_abs_jmp((uint8_t *)(self->enter + enter_len - SH_X64_ABS_JMP_LEN), target_addr + len);

  memcpy(self->backup, code, len);
  self->backup_len = len;
  self->enter_len = enter_len;

  self->fixup_cnt = 0;
  for (size_t i = 1; i < cnt && offs[i] < needed; i++) {
    self->fixup_offs[self->fixup_cnt] = (uint16_t)offs[i];
    self->fixup_new_offs[self->fixup_cnt] = (uint16_t)new_offs[i];
    self->fixup_cnt++;
  }

  if (NULL != set_orig_addr) set_orig_addr(self->enter, set_orig_addr_arg);
  return 0;
}

static int sh_inst_safe_rewrite(sh_inst_t *self, uintptr_t target_addr, size_t needed,
                                sh_inst_set_orig_addr_t set_orig_addr, void *set_orig_addr_arg) {
  if (0 != sh_util_mprotect(target_addr, needed + SH_X64_INST_MAX_LEN, PROT_READ | PROT_WRITE | PROT_EXEC))
    return SHADOWHOOK_ERRNO_MPROT;

  int r;
  SH_SIG_TRY(SIGSEGV, SIGBUS) {
    r = sh_inst_rewrite(self, target_addr, needed, set_orig_addr, set_orig_addr_arg);
  }
  SH_SIG_CATCH() {
    return SHADOWHOOK_ERRNO_HOOK_REWRITE_CRASH;
  }
  SH_SIG_EXIT
  return r;
}

// Loops such as strcspn's branch back into the patched bytes. A linear sweep is sound because
// clang keeps x86_64 jump tables in .rodata.
static int sh_inst_check_branches(sh_inst_t *self, uintptr_t target_addr, size_t patch_len, uintptr_t func,
                                  size_t func_len) {
  int r = 0;
  SH_SIG_TRY(SIGSEGV, SIGBUS) {
    for (uintptr_t pc = func; pc < func + func_len;) {
      sh_x64_inst_t inst;
      if (!sh_x64_decode((const uint8_t *)pc, &inst)) {
        SH_LOG_WARN("x64: undecodable instruction at %" PRIxPTR ", target %" PRIxPTR, pc, target_addr);
        r = SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED;
        break;
      }
      bool in_backup = target_addr <= pc && pc < target_addr + self->backup_len;
      if (SH_X64_KIND_PLAIN != inst.kind && !in_backup) {
        uintptr_t dest = (uintptr_t)((intptr_t)(pc + inst.len) + inst.rel);
        if (target_addr < dest && dest < target_addr + patch_len) {
          SH_LOG_WARN("x64: branch at %" PRIxPTR " lands inside the patch at %" PRIxPTR, pc, target_addr);
          r = SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED;
          break;
        }
      }
      pc += inst.len;
    }
  }
  SH_SIG_CATCH() {
    r = SHADOWHOOK_ERRNO_HOOK_REWRITE_CRASH;
  }
  SH_SIG_EXIT
  return r;
}

static void sh_inst_get_func(uintptr_t target_addr, sh_addr_info_t *addr_info, uintptr_t *func,
                             size_t *func_len) {
  *func = 0;
  *func_len = 0;

  sh_addr_info_t sym_info;
  memset(&sym_info, 0, sizeof(sym_info));
  sh_addr_info_t *info = addr_info;
  if (NULL == info->dli_saddr) {
    if (0 != sh_linker_get_addr_info_by_addr(&sym_info, (void *)target_addr, addr_info->is_sym_addr,
                                             addr_info->is_proc_start, false))
      goto end;
    info = &sym_info;
  }

  uintptr_t start = (uintptr_t)info->dli_saddr;
  if (start <= target_addr && target_addr < start + info->dli_ssize) {
    *func = start;
    *func_len = info->dli_ssize;
  }

end:
  sh_linker_free_addr_info(&sym_info);
}

static int sh_inst_write_exit(sh_inst_t *self, uintptr_t target_addr, const uint8_t *jmp, size_t jmp_len) {
  uint8_t exit[sizeof(self->exit)];
  memcpy(exit, self->backup, self->backup_len);
  memcpy(exit, jmp, jmp_len);

  int r = sh_util_write_inst(target_addr, exit, jmp_len);
  if (0 != r) return r;
  memcpy(self->exit, exit, self->backup_len);
  return 0;
}

#ifdef SH_CONFIG_TRY_HOOK_WITH_ISLAND
static int sh_inst_reloc_with_island(sh_inst_t *self, uintptr_t target_addr, sh_addr_info_t *addr_info,
                                     uintptr_t new_addr, bool is_rehook, sh_recorder_trace_t *trace) {
  int r;

  // The island ends in an aligned absolute address, so a rehook swaps it with one atomic store.
  if (is_rehook) {
    r = sh_util_write_inst(self->island_exit.addr + SH_INST_ISLAND_ADDR_OFF, &new_addr, sizeof(new_addr));
    if (0 != r) return r;
  } else {
    uintptr_t pc = target_addr + SH_X64_REL_JMP_LEN;
    sh_island_alloc(&self->island_exit, SH_INST_ISLAND_SIZE, sh_inst_range_low(pc), sh_inst_range_high(pc),
                    target_addr, addr_info, trace);
    if (0 == self->island_exit.addr) return SHADOWHOOK_ERRNO_HOOK_ISLAND_EXIT;

    static const uint8_t jmp_rip2[] = {0xFF, 0x25, 0x02, 0x00, 0x00, 0x00, 0xCC, 0xCC};
    uint8_t *island = (uint8_t *)self->island_exit.addr;
    memcpy(island, jmp_rip2, sizeof(jmp_rip2));
    memcpy(island + SH_INST_ISLAND_ADDR_OFF, &new_addr, sizeof(new_addr));

    uint8_t jmp[SH_X64_REL_JMP_LEN];
    sh_x64_rel_jmp(jmp, self->island_exit.addr, target_addr);
    if (0 != (r = sh_inst_write_exit(self, target_addr, jmp, sizeof(jmp)))) {
      sh_island_free(&self->island_exit, (uintptr_t)addr_info->dli_fbase);
      return r;
    }
  }

  sh_inst_record(self, target_addr, new_addr, is_rehook, trace);
  SH_LOG_INFO("x64: %shook (with island) OK. target %" PRIxPTR, is_rehook ? "re" : "", target_addr);
  return 0;
}
#endif

#ifdef SH_CONFIG_TRY_HOOK_WITHOUT_ISLAND
static int sh_inst_reloc_without_island(sh_inst_t *self, uintptr_t target_addr, uintptr_t new_addr,
                                        bool is_rehook, sh_recorder_trace_t *trace) {
  uint8_t jmp[SH_X64_ABS_JMP_LEN];
  sh_x64_abs_jmp(jmp, new_addr);

  int r = sh_inst_write_exit(self, target_addr, jmp, sizeof(jmp));
  if (0 != r) return r;

  sh_inst_record(self, target_addr, new_addr, is_rehook, trace);
  SH_LOG_INFO("x64: %shook (without island) OK. target %" PRIxPTR, is_rehook ? "re" : "", target_addr);
  return 0;
}
#endif

#define SH_INST_FIXUP_WAIT_NS 50000000

static pthread_mutex_t sh_inst_fixup_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t sh_inst_fixup_seq;  // odd while a fixup is running
static uintptr_t sh_inst_fixup_from[16];
static uintptr_t sh_inst_fixup_to[16];
static size_t sh_inst_fixup_cnt;
static size_t sh_inst_fixup_acks;
static struct kernel_sigaction sh_inst_fixup_old;
static bool sh_inst_fixup_installed;

static void sh_inst_fixup_handler(int signum, siginfo_t *info, void *uc) {
  uint32_t seq = __atomic_load_n(&sh_inst_fixup_seq, __ATOMIC_ACQUIRE);

  // A late signal after a timeout, or one the app sent.
  if (0 == (seq & 1)) {
    if (sh_inst_fixup_old.sa_flags & SA_SIGINFO) {
      if (NULL != sh_inst_fixup_old.sa_sigaction_) sh_inst_fixup_old.sa_sigaction_(signum, info, uc);
    } else if (SIG_DFL != sh_inst_fixup_old.sa_handler_ && SIG_IGN != sh_inst_fixup_old.sa_handler_) {
      sh_inst_fixup_old.sa_handler_(signum);
    }
    return;
  }

  greg_t *rip = &((ucontext_t *)uc)->uc_mcontext.gregs[REG_RIP];
  for (size_t i = 0; i < sh_inst_fixup_cnt; i++) {
    if ((uintptr_t)*rip != sh_inst_fixup_from[i]) continue;
    if (seq == __atomic_load_n(&sh_inst_fixup_seq, __ATOMIC_ACQUIRE)) *rip = (greg_t)sh_inst_fixup_to[i];
    break;
  }
  __atomic_add_fetch(&sh_inst_fixup_acks, 1, __ATOMIC_RELEASE);
}

static int64_t sh_inst_fixup_now(void) {
  struct kernel_timespec ts;
  sys_clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

// Moves threads stopped inside the patched bytes to the same instruction in the enter. Raw
// syscalls avoid libc functions that may have just been hooked. A thread that misses the
// deadline still has the signal pending, so the handler then stays installed.
static void sh_inst_fixup_threads(sh_inst_t *self, uintptr_t target_addr) {
  if (0 == self->fixup_cnt) return;

  int saved_errno = errno;
  sh_safe_pthread_mutex_lock(&sh_inst_fixup_lock);

  for (size_t i = 0; i < self->fixup_cnt; i++) {
    sh_inst_fixup_from[i] = target_addr + self->fixup_offs[i];
    sh_inst_fixup_to[i] = self->enter + self->fixup_new_offs[i];
  }
  sh_inst_fixup_cnt = self->fixup_cnt;
  __atomic_store_n(&sh_inst_fixup_acks, 0, __ATOMIC_RELAXED);
  __atomic_add_fetch(&sh_inst_fixup_seq, 1, __ATOMIC_RELEASE);

  int signum = SIGRTMAX;
  if (!sh_inst_fixup_installed) {
    struct kernel_sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction_ = sh_inst_fixup_handler;
    act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    if (0 != sys_sigaction(signum, &act, &sh_inst_fixup_old)) goto end;
    sh_inst_fixup_installed = true;
  }

  pid_t pid = sys_getpid();
  pid_t self_tid = sys__gettid();
  size_t sent = 0;
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
        if (0 == sys_tgkill(pid, tid, signum)) sent++;
      }
    }
    sys_close(fd);
  }

  int64_t deadline = sh_inst_fixup_now() + SH_INST_FIXUP_WAIT_NS;
  while (__atomic_load_n(&sh_inst_fixup_acks, __ATOMIC_ACQUIRE) < sent && sh_inst_fixup_now() < deadline)
    sys_sched_yield();
  size_t acks = __atomic_load_n(&sh_inst_fixup_acks, __ATOMIC_ACQUIRE);

  if (acks >= sent && 0 == sys_sigaction(signum, &sh_inst_fixup_old, NULL)) sh_inst_fixup_installed = false;
  if (acks < sent)
    SH_LOG_WARN("x64: %zu of %zu threads answered the fixup for %" PRIxPTR, acks, sent, target_addr);

end:
  __atomic_add_fetch(&sh_inst_fixup_seq, 1, __ATOMIC_RELEASE);
  sh_safe_pthread_mutex_unlock(&sh_inst_fixup_lock);
  errno = saved_errno;
}

// Relocated rip-relative operands keep their disp32, so the enter has to reach each destination.
static void sh_inst_enter_range(uintptr_t target_addr, uintptr_t *low, uintptr_t *high) {
  volatile uintptr_t lo = target_addr, hi = target_addr;
  SH_SIG_TRY(SIGSEGV, SIGBUS) {
    for (size_t len = 0; len < SH_X64_ABS_JMP_LEN;) {
      const uint8_t *code = (const uint8_t *)(target_addr + len);
      sh_x64_inst_t inst;
      if (!sh_x64_decode(code, &inst)) break;
      len += inst.len;
      if (0 == inst.disp_off) continue;

      int32_t disp;
      memcpy(&disp, code + inst.disp_off, sizeof(disp));
      uintptr_t dest = (uintptr_t)((intptr_t)(target_addr + len) + disp);
      if (dest < lo) lo = dest;
      if (dest > hi) hi = dest;
    }
  }
  SH_SIG_CATCH() {}
  SH_SIG_EXIT
  *low = sh_inst_range_low(hi);
  *high = sh_inst_range_high(lo);
}

int sh_inst_hook(sh_inst_t *self, uintptr_t target_addr, sh_addr_info_t *addr_info, uintptr_t new_addr,
                 bool is_to_interceptor, sh_inst_set_orig_addr_t set_orig_addr, void *set_orig_addr_arg,
                 sh_recorder_trace_t *trace) {
  (void)is_to_interceptor;

  uintptr_t enter_low, enter_high;
  sh_inst_enter_range(target_addr, &enter_low, &enter_high);
  self->enter = sh_enter_alloc_between(enter_low, enter_high);
  if (0 == self->enter) self->enter = sh_enter_alloc();
  if (0 == self->enter) return SHADOWHOOK_ERRNO_HOOK_ENTER;

  uintptr_t func;
  size_t func_len;
  sh_inst_get_func(target_addr, addr_info, &func, &func_len);
  if (0 == func_len) SH_LOG_WARN("x64: no symbol bounds for %" PRIxPTR ", branches unchecked", target_addr);

  int r = -1;
#ifdef SH_CONFIG_TRY_HOOK_WITH_ISLAND
  if (0 == (r = sh_inst_safe_rewrite(self, target_addr, SH_X64_REL_JMP_LEN, set_orig_addr,
                                     set_orig_addr_arg)) &&
      0 == (r = sh_inst_check_branches(self, target_addr, SH_X64_REL_JMP_LEN, func, func_len)) &&
      0 == (r = sh_inst_reloc_with_island(self, target_addr, addr_info, new_addr, false, trace))) {
    sh_inst_fixup_threads(self, target_addr);
    return 0;
  }
#endif

#ifdef SH_CONFIG_TRY_HOOK_WITHOUT_ISLAND
  if (SHADOWHOOK_ERRNO_HOOK_ISLAND_EXIT == r || -1 == r) {
    if (0 == (r = sh_inst_safe_rewrite(self, target_addr, SH_X64_ABS_JMP_LEN, set_orig_addr,
                                       set_orig_addr_arg)) &&
        0 == (r = sh_inst_check_branches(self, target_addr, SH_X64_ABS_JMP_LEN, func, func_len)) &&
        0 == (r = sh_inst_reloc_without_island(self, target_addr, new_addr, false, trace))) {
      sh_inst_fixup_threads(self, target_addr);
      return 0;
    }
  }
#endif

  if (NULL != set_orig_addr) set_orig_addr(0, set_orig_addr_arg);
  sh_enter_free(self->enter);
  return r;
}

int sh_inst_rehook(sh_inst_t *self, uintptr_t target_addr, sh_addr_info_t *addr_info, uintptr_t new_addr,
                   bool is_to_interceptor, sh_recorder_trace_t *trace) {
  (void)is_to_interceptor;

  if (0 != self->island_exit.addr) {
#ifdef SH_CONFIG_TRY_HOOK_WITH_ISLAND
    return sh_inst_reloc_with_island(self, target_addr, addr_info, new_addr, true, trace);
#else
    abort();
#endif
  } else {
#ifdef SH_CONFIG_TRY_HOOK_WITHOUT_ISLAND
    (void)addr_info;
    return sh_inst_reloc_without_island(self, target_addr, new_addr, true, trace);
#else
    abort();
#endif
  }
}

int sh_inst_unhook(sh_inst_t *self, uintptr_t target_addr, uintptr_t load_bias) {
  int r;

  SH_SIG_TRY(SIGSEGV, SIGBUS) {
    r = memcmp((void *)target_addr, self->exit, self->backup_len);
  }
  SH_SIG_CATCH() {
    return SHADOWHOOK_ERRNO_UNHOOK_CMP_CRASH;
  }
  SH_SIG_EXIT
  if (0 != r) return SHADOWHOOK_ERRNO_UNHOOK_TRAMPO_MISMATCH;
  if (0 != (r = sh_util_write_inst(target_addr, self->backup, self->backup_len))) return r;

  if (0 != self->island_exit.addr) sh_island_free(&self->island_exit, load_bias);
  sh_enter_free(self->enter);

  SH_LOG_INFO("x64: unhook OK. target %" PRIxPTR, target_addr);
  return 0;
}

void sh_inst_free_after_dlclose(sh_inst_t *self, uintptr_t target_addr) {
  if (0 != self->island_exit.addr) sh_island_free_after_dlclose(&self->island_exit);
  sh_enter_free(self->enter);

  SH_LOG_INFO("x64: free_after_dlclose OK. target %" PRIxPTR, target_addr);
}

extern void shadowhook_interceptor_glue(void);

// The red zone is skipped because an intercepted instruction may sit in a leaf function
// that keeps live data below rsp.
void sh_inst_build_glue_launcher(void *buf, void *ctx) {
  static const uint8_t code[] = {
      0x48, 0x8D, 0x64, 0x24, 0x80,        // lea  rsp, [rsp - 0x80]
      0xFF, 0x35, 0x0D, 0x00, 0x00, 0x00,  // push qword ptr [rip + 13] (ctx)
      0xFF, 0x25, 0x0F, 0x00, 0x00, 0x00,  // jmp  qword ptr [rip + 15] (glue)
      0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  };
  uintptr_t glue = (uintptr_t)shadowhook_interceptor_glue;
  uint8_t *b = (uint8_t *)buf;
  memcpy(b, code, sizeof(code));
  memcpy(b + 24, &ctx, sizeof(ctx));
  memcpy(b + 32, &glue, sizeof(glue));
}
