/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <asm/prctl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

// This is an amazing hack to directly call libc's loader in: glibc/elf/dl-tls.c
void *_dl_allocate_tls(void *mem);

struct dtv_pointer { // From: glibc/sysdeps/generic/dl-dtv.h
  void *val;         /* Pointer to data, or TLS_DTV_UNALLOCATED.  */
  void *to_free;     /* Unaligned pointer, for deallocation.  */
};

/* Type for the dtv.  */
typedef union dtv { // From: glibc/sysdeps/generic/dl-dtv.h
  size_t counter;
  struct dtv_pointer pointer;
} dtv_t;

/* Replacement type for __m128 since this file is included by ld.so,
   which is compiled with -mno-sse.  It must not change the alignment
   of rtld_savespace_sse.  */
typedef struct { // From: glibc/sysdeps/x86_64/nptl/tls.h
  int i[4];
} __128bits;

typedef struct { // From: glibc/sysdeps/x86_64/nptl/tls.h
  void *tcb;     /* Pointer to the TCB.  Not necessarily the
                thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self; /* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  unsigned long int vgetcpu_cache[2];
  /* Bit 0: X86_FEATURE_1_IBT.
     Bit 1: X86_FEATURE_1_SHSTK.
   */
  unsigned int feature_1;
  int __glibc_unused1;
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[4];
  /* GCC split stack support.  */
  void *__private_ss;
  /* The lowest address of shadow stack,  */
  unsigned long long int ssp_base;
  /* Must be kept even if it is no longer used by glibc since programs,
     like AddressSanitizer, depend on the size of tcbhead_t.  */
  __128bits __glibc_unused2[8][4] __attribute__((aligned(32)));
  void *__padding[8];
} tcbhead_t;

uintptr_t new_tls(uintptr_t cst) {
  // TODO: This will malloc the TLS. How will we deallocate this?
  tcbhead_t *new_sabre_tls = (tcbhead_t *)_dl_allocate_tls(NULL);

  // Get current TLS so we can copy stuff.
  tcbhead_t *cur_sabre_tls = (tcbhead_t *)cst;

  // For the following see: glibc/nptl/pthread_create.c

  /* Reference to the TCB itself.  */
  // pd->header.self = pd;
  new_sabre_tls->self = new_sabre_tls;

  /* Self-reference for TLS.  */
  // pd->header.tcb = pd;
  new_sabre_tls->tcb = new_sabre_tls;

  /* Copy the stack guard canary.  */
  // THREAD_COPY_STACK_GUARD (pd);
  new_sabre_tls->stack_guard = cur_sabre_tls->stack_guard;

  /* Copy the pointer guard value.  */
  // THREAD_COPY_POINTER_GUARD (pd);
  new_sabre_tls->pointer_guard = cur_sabre_tls->pointer_guard;

  /* Setup tcbhead.  */
  // tls_setup_tcbhead (pd);
  new_sabre_tls->feature_1 = cur_sabre_tls->feature_1;

  // End of: glibc/nptl/pthread_create.c

  return (uintptr_t)new_sabre_tls;
}
