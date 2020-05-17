/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

  .file "clone_syscall.s"
  .text
  .globl clone_syscall
  .type clone_syscall, @function

# long clone (unsigned long flags,
#             void *child_stack,	# %rsi
#             int *ptid, int *ctid,
#             unsigned long newtls,
#             void* ret_addr			# %r9
#             );
clone_syscall:
  pushq %rbp
  movq %rsp, %rbp

  # Set up child arguments, including return address
  movq %r9, -8(%rsi)
  movq 0x10(%rsp), %rax
  movq %rax, -0x10(%rsi)

  # Adjust the arguments
  movq $56, %rax
  movq %rcx, %r10
  syscall            # syscall

  # Both child and parent return here
  testq  %rax, %rax
  jnz    1f

  # Child
  movq -8(%rsp), %r11
  pushq %rdi # Save rdi before we edit it
  movq -8(%rsp), %rdi

  # Save the registers
  pushq %rax
  pushq %rcx
  pushq %rdx
  pushq %rsi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11

  call *post_sabre_clone@GOTPCREL(%rip)

  # Restore registers
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rsi
  popq %rdx
  popq %rcx
  popq %rax
  popq %rdi

  subq $128, %rsp
  jmp *%r11

1:
  # Parent
  popq %rbp
  ret

  .size clone_syscall, .-clone_syscall
  .section .note.GNU-stack,"",@progbits
