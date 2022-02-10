/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef FUTEX_H_
#define FUTEX_H_

#include <errno.h>
#include <linux/futex.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

__BEGIN_DECLS

// This works for syscalls made through libc which sets errno when fail.  This
// does not work for syscalls made directly to the kernel, which signals errors
// by returning a negative value
#define NOINTR_LIBC(x)                                                         \
  ({                                                                           \
    typeof(x) __i;                                                             \
    while ((__i = (x)) < 0 && errno == EINTR)                                  \
      ;                                                                        \
    __i;                                                                       \
  })

// This works for syscalls made directly to the kernel (adapted from glibc)
#define NOINTR_RAW(expression)                                                 \
  ({                                                                           \
    long int __result;                                                         \
    do                                                                         \
      __result = (long int)(expression);                                       \
    while (__result == -EINTR);                                                \
    __result;                                                                  \
  })

typedef struct {
  int l;
  int n;
} futex_t;

#define FUTEX_INIT(n) ((futex_t){0, (n)})
#define FUTEX(name, n) futex_t name = FUTEX_INIT(n)

static inline void INIT_FUTEX(futex_t *self, int n) {
  self->l = 0;
  self->n = n;
}

static int futex(int *uaddr, int futex_op, int val,
                 const struct timespec *timeout, int *uaddr2, int val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/*
 * Suspends the caller until it can down the futex. There can be at
 * most n callers that are currently holding the futex down.
 * Returns the slot [0..n-1] that was acquired when downing the futex.
 */
static __attribute__((unused)) int futex_down(futex_t *self) {
  uint32_t v;

  for (v = self->l;;) {
    int b = __builtin_ffs(~(v >> (32 - self->n)));
    if (b <= self->n) {
      // There is an available slot. Try to down it.
      uint32_t n = v | (1 << (31 - self->n + b));
      uint32_t o = __sync_val_compare_and_swap(&self->l, v, n);
      if (o == v) {
        // We successfully set the new bit and thus marked this slot as downed.
        return b - 1;
      } else {
        v = o;
      }
    } else {
      // There do not appear to be any available slots. Increment the
      // count of waiting processes.
      uint32_t n = v + 1;
      uint32_t o = __sync_val_compare_and_swap(&self->l, v, n);
      if (o == v) {
        // Wait for slots to become available.
        NOINTR_LIBC(futex(&self->l, FUTEX_WAIT, n, NULL, NULL, 0));
        v = self->l;
      } else {
        v = o;
      }
    }
  }
}

/*
 * Ups a previously downed mutex. If n is greater than one, the caller
 * must pass in the return value that it got when calling down().
 */
static __attribute__((unused)) void futex_up(futex_t *self, int bit) {
  uint32_t v;

  for (v = self->l;;) {
    int n = v & ~(1 << (32 - self->n + bit));
    if (v & ((1 << (32 - self->n)) - 1)) {
      // If there were any waiters, we are going to notify them now.
      uint32_t o = __sync_val_compare_and_swap(&self->l, v, n - 1);
      if (o == v) {
        futex(&self->l, FUTEX_WAKE, self->n, NULL, NULL, 0);
        return;
      } else {
        v = o;
      }
    } else {
      // There were no waiters. So, nobody needs to be woken up, either.
      uint32_t o = __sync_val_compare_and_swap(&self->l, v, n);
      if (o == v) {
        return;
      } else {
        v = o;
      }
    }
  }
}

__END_DECLS

#endif // FUTEX_H_
