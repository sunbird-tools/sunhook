#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// A fault inside the guarded block resumes at the RtlCaptureContext() call with faulted set, the
// way sigsetjmp() returns twice, so locals changed in the block and read after it are volatile.
typedef struct sh_sig_frame {
  CONTEXT ctx;
  volatile LONG faulted;
  struct sh_sig_frame *prev;
} sh_sig_frame_t;

int sh_sig_init(void);
void sh_sig_enter(sh_sig_frame_t *frame);
void sh_sig_leave(sh_sig_frame_t *frame);
