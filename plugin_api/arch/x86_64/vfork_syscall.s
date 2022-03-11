/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

  .file "vfork_syscall.s"
  .text
  .globl vfork_syscall
  .type vfork_syscall, @function

# long vfork_syscall();

vfork_syscall:

  popq	%rdi

  # Adjust the arguments
  movq $58, %rax     # sc_no
  syscall            # syscall

  pushq	%rdi

  # This is an ideponent opperation for the child process
  # but it is mandatory for the parent. When the child exits,
  # we might be outside of the plugin guard. This might be
  # the case because child and parent share memory. Here we
  # make sure we re-enter.
  pushq %rax
  call *enter_plugin@GOTPCREL(%rip)
  popq %rax

  ret # We are going back to the plugin.

  .size vfork_syscall, .-vfork_syscall
  .section .note.GNU-stack,"",@progbits
