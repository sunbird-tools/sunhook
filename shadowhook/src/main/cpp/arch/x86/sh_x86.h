#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__i386__) && !defined(SH_X86_MODE32)
#define SH_X86_MODE32
#endif

#define SH_X86_INST_MAX_LEN 15

// jmp rel32
#define SH_X86_REL_JMP_LEN 5
#ifdef SH_X86_MODE32
#define SH_X86_ABS_JMP_LEN SH_X86_REL_JMP_LEN
#else
// jmp qword ptr [rip + 0]; .quad addr
#define SH_X86_ABS_JMP_LEN 14
#endif

typedef enum {
  SH_X86_KIND_PLAIN,
  SH_X86_KIND_JCC,
  SH_X86_KIND_JMP,
  SH_X86_KIND_CALL,
  SH_X86_KIND_LOOP,  // loop, loope, loopne, jrcxz: rel8 only
} sh_x86_kind_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct {
  sh_x86_kind_t kind;
  size_t len;
  size_t rel_off;   // offset of the branch displacement, for every kind except PLAIN
  size_t disp_off;  // offset of a rip-relative disp32, 0 when there is none
  int64_t rel;
  uint8_t cc;
  bool is_term;
} sh_x86_inst_t;
#pragma clang diagnostic pop

bool sh_x86_decode(const uint8_t *code, sh_x86_inst_t *inst);

size_t sh_x86_rewrite_len(const sh_x86_inst_t *inst);
size_t sh_x86_rewrite(uint8_t *buf, const uint8_t *code, const sh_x86_inst_t *inst, uintptr_t target,
                      uintptr_t pc, bool *ok);

size_t sh_x86_abs_jmp(uint8_t *buf, uintptr_t addr, uintptr_t pc);
size_t sh_x86_rel_jmp(uint8_t *buf, uintptr_t addr, uintptr_t pc);
bool sh_x86_is_padding(const uint8_t *code, const sh_x86_inst_t *inst);
