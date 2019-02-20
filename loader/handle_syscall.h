#ifndef HANDLE_SYSCALL_H
#define HANDLE_SYSCALL_H

#include "compiler.h"

// Stack frame built by handle_syscall and in the patching code in library.c
struct syscall_stackframe {
  void *rbp_stackalign;
  void *r15;
  void *r14;
  void *r13;
  void *r12;
  void *r11;
  void *r10;
  void *r8;
  void *rdi;
  void *rsi;
  void *rdx;
  void *rcx;
  void *rbx;
  void *rbp_prologue;
  // trampoline
  void *fake_ret;
  void *ret;
} __packed;

void handle_syscall() __internal;

#endif /* !HANDLE_SYSCALL_H */
