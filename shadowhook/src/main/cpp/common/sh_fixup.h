#pragma once
#include <stddef.h>
#include <stdint.h>

#define SH_FIXUP_MAX 16

// A multi-instruction patch is written between these two calls. sh_fixup_stop() parks every other thread
// in a signal handler, and sh_fixup_resume() moves each parked thread found at from[i] to to[i] before
// releasing it.
void sh_fixup_stop(void);
void sh_fixup_resume(const uintptr_t *from, const uintptr_t *to, size_t cnt);
