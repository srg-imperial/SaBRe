/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

  .file "clone_syscall.s"
  .text
  .globl clone_syscall
  .type clone_syscall, @function

# long clone (unsigned long flags,  # %rdi
#             void *child_stack,    # %rsi
#             int *ptid,            # %rdx
#             int *ctid,            # %rcx
#             unsigned long newtls, # %r8
#             void* ret_addr        # %r9
#            );

clone_syscall:
  pushq %rbp
  movq %rsp, %rbp

  # Adjust the arguments
  movq $56, %rax
  movq %rcx, %r10
  syscall            # syscall

  # Both child and parent return here
  testq  %rax, %rax
  jnz    1f

  # Child

  # TODO: Return to the plugin after a new child and not directly to client.

  pushq %rdi
  pushq %rsi
  pushq %rdx
  pushq %r10 # %rcx
  pushq %r8
  pushq %r9

  call *post_clone_hook@GOTPCREL(%rip)
  call *exit_plugin@GOTPCREL(%rip)

  popq %r9
  popq %r8
  popq %r10 # %rcx
  popq %rdx
  popq %rsi
  popq %rdi

  # The child always returns 0.
  movq $0, %rax

  subq $0x80, %rsp
  jmp *%r9

1:
  # Parent
  popq %rbp
  ret

  .size clone_syscall, .-clone_syscall
  .section .note.GNU-stack,"",@progbits
