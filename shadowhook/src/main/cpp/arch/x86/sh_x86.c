#include "sh_x86.h"

#include <string.h>

static bool sh_x86_decode_modrm(const uint8_t *code, size_t *i, bool addr32, sh_x86_inst_t *inst) {
  uint8_t modrm = code[*i];
  uint8_t mod = modrm >> 6;
  uint8_t rm = modrm & 7;
  size_t disp = 0;
  *i += 1;

  if (3 != mod) {
    if (4 == rm) {
      uint8_t sib = code[*i];
      *i += 1;
      if (0 == mod && 5 == (sib & 7)) disp = 4;
    } else if (0 == mod && 5 == rm) {
      if (addr32) return false;
#ifdef SH_X86_MODE32
      (void)inst;
#else
      inst->disp_off = *i;
#endif
      disp = 4;
    }
    if (1 == mod) disp = 1;
    if (2 == mod) disp = 4;
  }

  *i += disp;
  return true;
}

static uint8_t sh_x86_modrm_reg(const uint8_t *code, size_t i) {
  return (code[i] >> 3) & 7;
}

static bool sh_x86_decode_vex(const uint8_t *code, size_t *i, bool addr32, sh_x86_inst_t *inst) {
  uint8_t prefix = code[*i];
  uint8_t map;

  if (0xC5 == prefix) {
    map = 1;
    *i += 2;
  } else if (0xC4 == prefix) {
    map = code[*i + 1] & 0x1F;
    *i += 3;
  } else {
    map = code[*i + 1] & 0x07;
    *i += 4;
  }

  uint8_t op = code[*i];
  *i += 1;
  if (1 == map && 0x77 == op) return true;
  if (!sh_x86_decode_modrm(code, i, addr32, inst)) return false;

  switch (map) {
    case 1:
      if ((0x70 <= op && op <= 0x73) || 0xC2 == op || 0xC4 == op || 0xC5 == op || 0xC6 == op) *i += 1;
      return true;
    case 2:
    case 5:
    case 6:
      return true;
    case 3:
      *i += 1;
      return true;
    default:
      return false;
  }
}

static bool sh_x86_decode_0f(const uint8_t *code, size_t *i, bool p66, bool addr32, sh_x86_inst_t *inst) {
  uint8_t op = code[*i];
  *i += 1;

  if (0x38 == op || 0x3A == op) {
    *i += 1;
    if (!sh_x86_decode_modrm(code, i, addr32, inst)) return false;
    if (0x3A == op) *i += 1;
    return true;
  }

  if (0x80 <= op && op <= 0x8F) {
    if (p66) return false;
    inst->kind = SH_X86_KIND_JCC;
    inst->cc = op & 0x0F;
    inst->rel_off = *i;
    int32_t rel;
    memcpy(&rel, code + *i, sizeof(rel));
    inst->rel = rel;
    *i += 4;
    return true;
  }

  switch (op) {
    case 0x0B:
      inst->is_term = true;
      return true;
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0E:
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x37:
    case 0x77:
    case 0xA0:
    case 0xA1:
    case 0xA2:
    case 0xA8:
    case 0xA9:
    case 0xAA:
      return true;
    case 0x0F:
      return false;
    default:
      break;
  }
  if (0xC8 <= op && op <= 0xCF) return true;

  if (!sh_x86_decode_modrm(code, i, addr32, inst)) return false;
  if ((0x70 <= op && op <= 0x73) || 0xA4 == op || 0xAC == op || 0xBA == op || 0xC2 == op || 0xC4 == op ||
      0xC5 == op || 0xC6 == op)
    *i += 1;
  return true;
}

static void sh_x86_set_rel8(const uint8_t *code, size_t *i, sh_x86_inst_t *inst, sh_x86_kind_t kind) {
  inst->kind = kind;
  inst->rel_off = *i;
  inst->rel = (int8_t)code[*i];
  *i += 1;
}

static void sh_x86_set_rel32(const uint8_t *code, size_t *i, sh_x86_inst_t *inst, sh_x86_kind_t kind) {
  int32_t rel;
  memcpy(&rel, code + *i, sizeof(rel));
  inst->kind = kind;
  inst->rel_off = *i;
  inst->rel = rel;
  *i += 4;
}

bool sh_x86_decode(const uint8_t *code, sh_x86_inst_t *inst) {
  memset(inst, 0, sizeof(*inst));
  inst->kind = SH_X86_KIND_PLAIN;

  bool p66 = false, addr32 = false, rex_w = false;
  size_t i = 0;

  for (;; i++) {
    if (i >= SH_X86_INST_MAX_LEN) return false;
    uint8_t b = code[i];
    if (0x66 == b)
      p66 = true;
    else if (0x67 == b)
      addr32 = true;
    else if (!(0xF0 == b || 0xF2 == b || 0xF3 == b || 0x2E == b || 0x36 == b || 0x3E == b || 0x26 == b ||
               0x64 == b || 0x65 == b))
      break;
  }

#ifdef SH_X86_MODE32
  // 0x67 switches to 16-bit addressing, which has its own ModRM table.
  if (addr32) return false;
#else
  if (0x40 == (code[i] & 0xF0)) {
    rex_w = (code[i] & 0x08) != 0;
    i++;
  }
#endif

  // REX.W overrides 0x66, as in the "66 66 48 e8" call of the TLS general-dynamic sequence.
  if (rex_w) p66 = false;

  size_t imm_z = p66 ? 2 : 4;
  uint8_t op = code[i];

#ifdef SH_X86_MODE32
  bool is_vex = (0xC4 == op || 0xC5 == op || 0x62 == op) && 0xC0 == (code[i + 1] & 0xC0);
#else
  bool is_vex = 0xC4 == op || 0xC5 == op || 0x62 == op;
#endif
  if (is_vex) {
    if (!sh_x86_decode_vex(code, &i, addr32, inst)) return false;
    goto done;
  }

  i++;
#ifdef SH_X86_MODE32
  if ((0x40 <= op && op <= 0x4F) || 0x60 == op || 0x61 == op || 0xCE == op || 0xD6 == op || 0x06 == op ||
      0x07 == op || 0x0E == op || 0x16 == op || 0x17 == op || 0x1E == op || 0x1F == op || 0x27 == op ||
      0x2F == op || 0x37 == op || 0x3F == op)
    goto done;
  if (0x62 == op || 0xC4 == op || 0xC5 == op) {
    if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
    goto done;
  }
  if (0x82 == op) {
    if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
    i += 1;
    goto done;
  }
  if (0xD4 == op || 0xD5 == op) {
    i += 1;
    goto done;
  }
#endif
  if (op < 0x40) {
    uint8_t lo = op & 7;
    if (0x0F == op) {
      if (!sh_x86_decode_0f(code, &i, p66, addr32, inst)) return false;
    } else if (lo <= 3) {
      if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
    } else if (4 == lo) {
      i += 1;
    } else if (5 == lo) {
      i += imm_z;
    } else {
      return false;
    }
    goto done;
  }

  if ((0x50 <= op && op <= 0x5F) || (0x90 <= op && op <= 0x99) || (0x9B <= op && op <= 0x9F) ||
      (0x6C <= op && op <= 0x6F) || (0xA4 <= op && op <= 0xA7) || (0xAA <= op && op <= 0xAF) ||
      (0xEC <= op && op <= 0xEF) || (0xF8 <= op && op <= 0xFD) || 0xC9 == op || 0xD7 == op || 0xF1 == op ||
      0xF5 == op)
    goto done;

  if (0x70 <= op && op <= 0x7F) {
    inst->cc = op & 0x0F;
    sh_x86_set_rel8(code, &i, inst, SH_X86_KIND_JCC);
    goto done;
  }
  if (0xE0 <= op && op <= 0xE3) {
    sh_x86_set_rel8(code, &i, inst, SH_X86_KIND_LOOP);
    goto done;
  }
  if ((0x84 <= op && op <= 0x8F) || 0x63 == op || (0xD0 <= op && op <= 0xD3) || (0xD8 <= op && op <= 0xDF) ||
      0xFE == op) {
    if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
    goto done;
  }
  if (0xB0 <= op && op <= 0xB7) {
    i += 1;
    goto done;
  }
  if (0xB8 <= op && op <= 0xBF) {
    i += rex_w ? 8 : imm_z;
    goto done;
  }
  if (0xA0 <= op && op <= 0xA3) {
#ifdef SH_X86_MODE32
    i += 4;
#else
    i += addr32 ? 4 : 8;
#endif
    goto done;
  }

  switch (op) {
    case 0x68:
      i += imm_z;
      break;
    case 0x6A:
    case 0xA8:
    case 0xCD:
    case 0xE4:
    case 0xE5:
    case 0xE6:
    case 0xE7:
      i += 1;
      break;
    case 0xA9:
      i += imm_z;
      break;
    case 0x69:
    case 0x81:
    case 0xC7:
      if (0xC7 == op && 0xF8 == code[i]) return false;
      if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
      i += imm_z;
      break;
    case 0x6B:
    case 0x80:
    case 0x83:
    case 0xC0:
    case 0xC1:
    case 0xC6:
      if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
      i += 1;
      break;
    case 0xC2:
    case 0xCA:
      i += 2;
      inst->is_term = true;
      break;
    case 0xC3:
    case 0xCB:
    case 0xCC:
    case 0xCF:
    case 0xF4:
      inst->is_term = true;
      break;
    case 0xC8:
      i += 3;
      break;
    case 0xE8:
      if (p66) return false;
      sh_x86_set_rel32(code, &i, inst, SH_X86_KIND_CALL);
      break;
    case 0xE9:
      if (p66) return false;
      sh_x86_set_rel32(code, &i, inst, SH_X86_KIND_JMP);
      inst->is_term = true;
      break;
    case 0xEB:
      sh_x86_set_rel8(code, &i, inst, SH_X86_KIND_JMP);
      inst->is_term = true;
      break;
    case 0xF6:
    case 0xF7: {
      uint8_t reg = sh_x86_modrm_reg(code, i);
      if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
      if (reg < 2) i += (0xF6 == op ? 1 : imm_z);
      break;
    }
    case 0xFF: {
      uint8_t reg = sh_x86_modrm_reg(code, i);
      if (!sh_x86_decode_modrm(code, &i, addr32, inst)) return false;
      if (4 == reg || 5 == reg) inst->is_term = true;
      break;
    }
    default:
      return false;
  }

done:
  if (i > SH_X86_INST_MAX_LEN) return false;
  inst->len = i;
  return true;
}

bool sh_x86_is_padding(const uint8_t *code, const sh_x86_inst_t *inst) {
  if (SH_X86_KIND_PLAIN != inst->kind || 0 != inst->disp_off) return false;
  if (1 == inst->len) return 0xCC == code[0] || 0x90 == code[0];

  size_t i = 0;
  while (i < inst->len && (0x66 == code[i] || 0x2E == code[i]))
    i++;
  return i + 1 < inst->len && 0x0F == code[i] && 0x1F == code[i + 1];
}

size_t sh_x86_abs_jmp(uint8_t *buf, uintptr_t addr, uintptr_t pc) {
#ifdef SH_X86_MODE32
  return sh_x86_rel_jmp(buf, addr, pc);
#else
  (void)pc;
  static const uint8_t jmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
  memcpy(buf, jmp, sizeof(jmp));
  memcpy(buf + sizeof(jmp), &addr, sizeof(addr));
  return SH_X86_ABS_JMP_LEN;
#endif
}

size_t sh_x86_rel_jmp(uint8_t *buf, uintptr_t addr, uintptr_t pc) {
  int32_t rel = (int32_t)((intptr_t)addr - (intptr_t)(pc + SH_X86_REL_JMP_LEN));
  buf[0] = 0xE9;
  memcpy(buf + 1, &rel, sizeof(rel));
  return SH_X86_REL_JMP_LEN;
}

#ifdef SH_X86_MODE32
#define SH_X86_JCC_LEN  6
#define SH_X86_CALL_LEN 10
#else
#define SH_X86_JCC_LEN  (2 + SH_X86_ABS_JMP_LEN)
#define SH_X86_CALL_LEN 16
#endif

size_t sh_x86_rewrite_len(const sh_x86_inst_t *inst) {
  if (SH_X86_KIND_JCC == inst->kind) return SH_X86_JCC_LEN;
  if (SH_X86_KIND_CALL == inst->kind) return SH_X86_CALL_LEN;
  if (SH_X86_KIND_JMP == inst->kind) return SH_X86_ABS_JMP_LEN;
  if (SH_X86_KIND_LOOP == inst->kind) return inst->rel_off + 1 + 2 + SH_X86_ABS_JMP_LEN;
  return inst->len;
}

// target is the absolute branch or rip-relative destination, pc is where buf will run.
size_t sh_x86_rewrite(uint8_t *buf, const uint8_t *code, const sh_x86_inst_t *inst, uintptr_t target,
                      uintptr_t pc, bool *ok) {
  *ok = true;

  if (SH_X86_KIND_JCC == inst->kind) {
#ifdef SH_X86_MODE32
    int32_t rel = (int32_t)(target - (pc + SH_X86_JCC_LEN));
    buf[0] = 0x0F;
    buf[1] = (uint8_t)(0x80 | inst->cc);
    memcpy(buf + 2, &rel, sizeof(rel));
    return SH_X86_JCC_LEN;
#else
    buf[0] = (uint8_t)(0x70 | (inst->cc ^ 1));
    buf[1] = SH_X86_ABS_JMP_LEN;
    return 2 + sh_x86_abs_jmp(buf + 2, target, pc + 2);
#endif
  }

  if (SH_X86_KIND_JMP == inst->kind) return sh_x86_abs_jmp(buf, target, pc);

  if (SH_X86_KIND_CALL == inst->kind) {
#ifdef SH_X86_MODE32
    // __x86.get_pc_thunk reads its return address, so the callee must see the original one.
    uintptr_t ret = (uintptr_t)code + inst->len;
    buf[0] = 0x68;
    memcpy(buf + 1, &ret, sizeof(ret));
    return 5 + sh_x86_rel_jmp(buf + 5, target, pc + 5);
#else
    static const uint8_t call[] = {0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08};
    memcpy(buf, call, sizeof(call));
    memcpy(buf + sizeof(call), &target, sizeof(target));
    return sizeof(call) + sizeof(target);
#endif
  }

  if (SH_X86_KIND_LOOP == inst->kind) {
    size_t n = inst->rel_off;
    memcpy(buf, code, n);
    buf[n++] = 0x02;
    buf[n++] = 0xEB;
    buf[n++] = SH_X86_ABS_JMP_LEN;
    return n + sh_x86_abs_jmp(buf + n, target, pc + n);
  }

  memcpy(buf, code, inst->len);
  if (0 != inst->disp_off) {
    int64_t disp = (intptr_t)target - (intptr_t)(pc + inst->len);
    if (disp < INT32_MIN || disp > INT32_MAX) {
      *ok = false;
      return 0;
    }
    int32_t disp32 = (int32_t)disp;
    memcpy(buf + inst->disp_off, &disp32, sizeof(disp32));
  }
  return inst->len;
}
