/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

  .file "handle_rdtsc.s"
  .text
  .globl rdtsc_entrypoint
  .internal rdtsc_entrypoint
  .type rdtsc_entrypoint, @function

rdtsc_entrypoint:
  .cfi_startproc
  .cfi_def_cfa rsp, 0x88
  .cfi_offset rip, -0x88
  .cfi_remember_state

  # Prologue
  push %rbp
  .cfi_adjust_cfa_offset 8
  mov %rsp, %rbp
  .cfi_def_cfa_register rbp
  .cfi_remember_state

  # Save the registers
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rsi
  pushq %rdi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15

  # Align the stack on a 16-byte boundary before the call
  push %rbp
  mov %rsp, %rbp
  .cfi_adjust_cfa_offset 0x70
  and $0xfffffffffffffff0, %rsp

  # Call the actual handler
  call *plugin_rdtsc_handler(%rip)

  # Move high part of rax to rdx
  mov %rax, %rdx
  mov $0x00000000FFFFFFFF, %r15
  and %r15, %rax
  shr $32, %rdx
  and %r15, %rdx
  mov %rdx, 88(%rsp) # Save rdx on right position on the stack

  # Restore the stack
  mov %rbp, %rsp
  pop %rbp
  .cfi_restore_state

  # Reload registers
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rdi
  popq %rsi
  popq %rdx
  popq %rcx
  popq %rbx

  # Epilogue
  pop %rbp
  .cfi_restore_state
  addq $8, %rsp	# drop fake return address
  .cfi_undefined rip
  ret
  .cfi_endproc
  .size rdtsc_entrypoint, .-rdtsc_entrypoint
  .section .note.GNU-stack,"",@progbits
