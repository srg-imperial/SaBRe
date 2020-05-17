/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef REAL_SYSCALL_H
#define REAL_SYSCALL_H
long real_syscall(long sc_no,
                  long arg1,
                  long arg2,
                  long arg3,
                  long arg4,
                  long arg5,
                  long arg6);

long clone_syscall(unsigned long flags, void *child_stack, int *ptid, int *ctid,
                   unsigned long newtls, void **args, void *new_sabre_tlv);

long sabre_clone(unsigned long flags, void *child_stack, int *ptid, int *ctid,
                 unsigned long newtls, void *ret_addr);

#endif /* !REAL_SYSCALL_H */
