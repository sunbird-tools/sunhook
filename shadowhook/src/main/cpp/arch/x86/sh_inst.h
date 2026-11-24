#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "sh_island.h"
#include "sh_linker.h"
#include "sh_recorder.h"

typedef struct {
  uint8_t backup[32];
  size_t backup_len;
  uint8_t exit[32];  // length = backup_len
  uintptr_t enter;
  size_t enter_len;
  sh_island_t island_exit;  // .size = 16
  size_t fixup_cnt;
  uint16_t fixup_offs[16];      // instructions that start inside the exit jump
  uint16_t fixup_new_offs[16];  // where each of them sits in the enter
} sh_inst_t;

typedef void (*sh_inst_set_orig_addr_t)(uintptr_t orig_addr, void *arg);

int sh_inst_hook(sh_inst_t *self, uintptr_t target_addr, sh_addr_info_t *addr_info, uintptr_t new_addr,
                 bool is_to_interceptor, sh_inst_set_orig_addr_t set_orig_addr, void *set_orig_addr_arg,
                 sh_recorder_trace_t *trace);
int sh_inst_rehook(sh_inst_t *self, uintptr_t target_addr, sh_addr_info_t *addr_info, uintptr_t new_addr,
                   bool is_to_interceptor, sh_recorder_trace_t *trace);
int sh_inst_unhook(sh_inst_t *self, uintptr_t target_addr, uintptr_t load_bias);

void sh_inst_free_after_dlclose(sh_inst_t *self, uintptr_t target_addr);

void sh_inst_build_glue_launcher(void *buf, void *ctx);
