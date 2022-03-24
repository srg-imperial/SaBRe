/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -nostdlib -nostartfiles %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1
 */

/* The purpose of this test is to ensure that when Varan encounters a non-relocatable instruction
   it inserts an illegal instruction that will trigger a SIGILL */

.global _start
_start:
mov $39, %rax /* __NR_getpid */
jmp 1f	/* source of jump 1 */
nop
nop
nop
1:
not %edi	/* destination of jump 1 => non relocatable*/
syscall	/* syscall instruction cannot be rewritten with jump*/
lea 0(%rip), %rax	/* PC-relative addressing => non relocatable */
jmp 2f	/* source of jump 2 */
nop
nop
nop
2:
nop	/* destination of jump 2 */
rdtsc	/* RDTSC instruction cannot be rewritten with jump*/
lea 0(%rip), %rax	/* PC-relative addressing => non relocatable */
nop
nop
mov $0, %rdi
mov $60, %rax /* __NR_exit */
syscall
