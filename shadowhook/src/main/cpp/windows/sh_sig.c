#include "sh_sig_win.h"
#include <string.h>

static DWORD sh_sig_tls = TLS_OUT_OF_INDEXES;

// Copies only what RtlCaptureContext() saved and the guarded frame relies on, so the extended
// state the fault's context may carry stays consistent with its ContextFlags.
static void sh_sig_resume(CONTEXT *to, const CONTEXT *from) {
  to->Rip = from->Rip;
  to->Rsp = from->Rsp;
  to->Rbp = from->Rbp;
  to->Rbx = from->Rbx;
  to->Rsi = from->Rsi;
  to->Rdi = from->Rdi;
  to->R12 = from->R12;
  to->R13 = from->R13;
  to->R14 = from->R14;
  to->R15 = from->R15;
  to->EFlags = from->EFlags;
  to->MxCsr = from->MxCsr;
  memcpy(&to->Xmm6, &from->Xmm6, sizeof(M128A) * 10);
}

static LONG CALLBACK sh_sig_handler(EXCEPTION_POINTERS *info) {
  DWORD code = info->ExceptionRecord->ExceptionCode;
  if (EXCEPTION_ACCESS_VIOLATION != code && EXCEPTION_IN_PAGE_ERROR != code) return EXCEPTION_CONTINUE_SEARCH;

  DWORD last_error = GetLastError();
  sh_sig_frame_t *frame = TlsGetValue(sh_sig_tls);
  SetLastError(last_error);
  if (NULL == frame) return EXCEPTION_CONTINUE_SEARCH;

  frame->faulted = 1;
  sh_sig_resume(info->ContextRecord, &frame->ctx);
  return EXCEPTION_CONTINUE_EXECUTION;
}

int sh_sig_init(void) {
  if (TLS_OUT_OF_INDEXES == (sh_sig_tls = TlsAlloc())) return -1;
  if (NULL == AddVectoredExceptionHandler(1, sh_sig_handler)) {
    TlsFree(sh_sig_tls);
    sh_sig_tls = TLS_OUT_OF_INDEXES;
    return -1;
  }
  return 0;
}

void sh_sig_enter(sh_sig_frame_t *frame) {
  frame->faulted = 0;
  frame->prev = NULL;
  if (TLS_OUT_OF_INDEXES == sh_sig_tls) return;
  frame->prev = TlsGetValue(sh_sig_tls);
  TlsSetValue(sh_sig_tls, frame);
}

void sh_sig_leave(sh_sig_frame_t *frame) {
  if (TLS_OUT_OF_INDEXES != sh_sig_tls) TlsSetValue(sh_sig_tls, frame->prev);
}
