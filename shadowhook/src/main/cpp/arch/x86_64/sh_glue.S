// Entry: rsp = original rsp - 0x88, switch context pointer at (%rsp). That slot later holds
// next_hop, so "ret $0x80" leaves with every register and flag restored. The address of the
// pushed rflags is kept at CTX_SIZE.
//
// struct cpu_context (shadowhook_cpu_context_t)
//   0x000 regs[16]: rax rcx rdx rbx rsp rbp rsi rdi r8-r15
//   0x080 rip
//   0x088 rflags
//   0x090 vregs[16]: xmm0-xmm15
//   0x190 mxcsr

#define CTX_SIZE 0x1a0

  .text
  .globl shadowhook_interceptor_glue
  .balign 16
  .type shadowhook_interceptor_glue, @function
shadowhook_interceptor_glue:
  .cfi_startproc
  .cfi_undefined rip
  // A signal may land on any instruction, so nothing is stored below rsp.
  pushfq
  push    %rbx
  mov     %rsp, %rbx
  lea     -(CTX_SIZE + 0x10)(%rsp), %rsp
  and     $-16, %rsp
  mov     %rax, 0x00(%rsp)
  mov     (%rbx), %rax
  mov     %rax, 0x18(%rsp)
  lea     0x8(%rbx), %rax
  mov     %rax, CTX_SIZE(%rsp)

  mov     %rcx, 0x08(%rsp)
  mov     %rdx, 0x10(%rsp)
  mov     %rbp, 0x28(%rsp)
  mov     %rsi, 0x30(%rsp)
  mov     %rdi, 0x38(%rsp)
  mov     %r8,  0x40(%rsp)
  mov     %r9,  0x48(%rsp)
  mov     %r10, 0x50(%rsp)
  mov     %r11, 0x58(%rsp)
  mov     %r12, 0x60(%rsp)
  mov     %r13, 0x68(%rsp)
  mov     %r14, 0x70(%rsp)
  mov     %r15, 0x78(%rsp)
  mov     CTX_SIZE(%rsp), %rcx
  lea     0x90(%rcx), %rax
  mov     %rax, 0x20(%rsp)
  mov     (%rcx), %rax
  mov     %rax, 0x88(%rsp)

  movdqu  %xmm0,  0x090(%rsp)
  movdqu  %xmm1,  0x0a0(%rsp)
  movdqu  %xmm2,  0x0b0(%rsp)
  movdqu  %xmm3,  0x0c0(%rsp)
  movdqu  %xmm4,  0x0d0(%rsp)
  movdqu  %xmm5,  0x0e0(%rsp)
  movdqu  %xmm6,  0x0f0(%rsp)
  movdqu  %xmm7,  0x100(%rsp)
  movdqu  %xmm8,  0x110(%rsp)
  movdqu  %xmm9,  0x120(%rsp)
  movdqu  %xmm10, 0x130(%rsp)
  movdqu  %xmm11, 0x140(%rsp)
  movdqu  %xmm12, 0x150(%rsp)
  movdqu  %xmm13, 0x160(%rsp)
  movdqu  %xmm14, 0x170(%rsp)
  movdqu  %xmm15, 0x180(%rsp)
  movq    $0, 0x190(%rsp)
  stmxcsr 0x190(%rsp)

  mov     0x8(%rcx), %rdi
  mov     %rsp, %rsi
  lea     0x8(%rcx), %rdx
  cld
  call    shadowhook_interceptor_caller@PLT

  ldmxcsr 0x190(%rsp)
  movdqu  0x090(%rsp), %xmm0
  movdqu  0x0a0(%rsp), %xmm1
  movdqu  0x0b0(%rsp), %xmm2
  movdqu  0x0c0(%rsp), %xmm3
  movdqu  0x0d0(%rsp), %xmm4
  movdqu  0x0e0(%rsp), %xmm5
  movdqu  0x0f0(%rsp), %xmm6
  movdqu  0x100(%rsp), %xmm7
  movdqu  0x110(%rsp), %xmm8
  movdqu  0x120(%rsp), %xmm9
  movdqu  0x130(%rsp), %xmm10
  movdqu  0x140(%rsp), %xmm11
  movdqu  0x150(%rsp), %xmm12
  movdqu  0x160(%rsp), %xmm13
  movdqu  0x170(%rsp), %xmm14
  movdqu  0x180(%rsp), %xmm15

  mov     CTX_SIZE(%rsp), %rcx
  mov     0x88(%rsp), %rax
  mov     %rax, (%rcx)
  mov     0x00(%rsp), %rax
  mov     0x08(%rsp), %rcx
  mov     0x10(%rsp), %rdx
  mov     0x18(%rsp), %rbx
  mov     0x28(%rsp), %rbp
  mov     0x30(%rsp), %rsi
  mov     0x38(%rsp), %rdi
  mov     0x40(%rsp), %r8
  mov     0x48(%rsp), %r9
  mov     0x50(%rsp), %r10
  mov     0x58(%rsp), %r11
  mov     0x60(%rsp), %r12
  mov     0x68(%rsp), %r13
  mov     0x70(%rsp), %r14
  mov     0x78(%rsp), %r15

  mov     CTX_SIZE(%rsp), %rsp
  popfq
  ret     $0x80
  .cfi_endproc
  .size shadowhook_interceptor_glue, . - shadowhook_interceptor_glue

  .section .note.GNU-stack, "", @progbits
