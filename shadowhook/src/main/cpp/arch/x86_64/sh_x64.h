#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SH_X64_INST_MAX_LEN 15

// jmp qword ptr [rip + 0]; .quad addr
#define SH_X64_ABS_JMP_LEN 14
// jmp rel32
#define SH_X64_REL_JMP_LEN 5

typedef enum {
  SH_X64_KIND_PLAIN,
  SH_X64_KIND_JCC,
  SH_X64_KIND_JMP,
  SH_X64_KIND_CALL,
  SH_X64_KIND_LOOP,  // loop, loope, loopne, jrcxz: rel8 only
} sh_x64_kind_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct {
  sh_x64_kind_t kind;
  size_t len;
  size_t rel_off;   // offset of the branch displacement, for every kind except PLAIN
  size_t disp_off;  // offset of a rip-relative disp32, 0 when there is none
  int64_t rel;
  uint8_t cc;
  bool is_term;
} sh_x64_inst_t;
#pragma clang diagnostic pop

bool sh_x64_decode(const uint8_t *code, sh_x64_inst_t *inst);

size_t sh_x64_rewrite_len(const sh_x64_inst_t *inst);
size_t sh_x64_rewrite(uint8_t *buf, const uint8_t *code, const sh_x64_inst_t *inst, uintptr_t target,
                      uintptr_t pc, bool *ok);

size_t sh_x64_abs_jmp(uint8_t *buf, uintptr_t addr);
size_t sh_x64_rel_jmp(uint8_t *buf, uintptr_t addr, uintptr_t pc);
bool sh_x64_is_padding(const uint8_t *code, const sh_x64_inst_t *inst);
