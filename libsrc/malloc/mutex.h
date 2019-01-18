#ifndef MUTEX_H_
#define MUTEX_H_

#include <stdbool.h>
#include <stdint.h>

#include "futex.h"
#include "linux_syscall_support.h"

__BEGIN_DECLS

typedef int mutex_t;

static __attribute__((unused)) void mutex_init(mutex_t *mutex) { *mutex = 0; }

/*static void mutex_lock(mutex_t *mutex)
{
  int c;
  if ((c = __sync_val_compare_and_swap(*mutex, 0, 1)) != 0) {
    if (c != 2) {
      c = __sync_lock_test_and_set(*mutex, 2);
    }
    while (c != 0) {
      sys_futex(*mutex, FUTEX_WAIT, 2, NULL);
      c = __sync_lock_test_and_set(*mutex, 2);
    }
  }
}

static void mutex_unlock(mutex_t *mutex)
{
  if (__sync_fetch_and_sub(*mutex, 1) != 1) {
    *mutex = 0;
    sys_futex(*mutex, FUTEX_WAKE, 1, NULL);
  }
}*/

static __attribute__((__used__)) void mutex_unlock(mutex_t *mutex) {
  char status;
// Unlock the mutex.
#if defined(__x86_64__) || defined(__i386__)
  asm volatile(
      "lock; addl %2, %0\n"
      "setz %1"
      : "=m"(*mutex), "=qm"(status)
      : "ir"(0x80000000), "m"(*mutex));
#else
#error Unsupported target platform
#endif
  if (status) {
    // Mutex is zero now, no other waiters.
    return;
  }
  // Wake up other waiters
  sys_futex(mutex, FUTEX_WAKE, 1, NULL, NULL, 0);
}

static __attribute__((__used__)) bool mutex_lock(mutex_t *mutex, int timeout) {
  bool ret = true;
// Increment mutex to add ourselves to the list of waiters.
#if defined(__x86_64__) || defined(__i386__)
  asm volatile("lock; incl %0\n" : "=m"(*mutex) : "m"(*mutex));
#else
#error Unsupported target platform
#endif
  for (;;) {
    // Atomically check whether the mutex is available and if so, acquire it.
    char status;
#if defined(__x86_64__) || defined(__i386__)
    asm volatile(
        "lock; btsl %3, %1\n"
        "setc %0"
        : "=q"(status), "=m"(*mutex)
        : "m"(*mutex), "ir"(31));
#else
#error Unsupported target platform
#endif
    if (!status) {
    done:
// if the mutex was available, remove ourselves from list of waiters
#if defined(__x86_64__) || defined(__i386__)
      asm volatile("lock; decl %0\n" : "=m"(*mutex) : "m"(*mutex));
#else
#error Unsupported target platform
#endif
      return ret;
    }
    int value = *mutex;
    if (value >= 0) {
      // Mutex has just become available, no need to call kernel.
      continue;
    }

    struct kernel_timespec tm;
    if (timeout != 0) {
      tm.tv_sec = timeout / 1000;
      tm.tv_nsec = (timeout % 1000) * 1000 * 1000;
    } else {
      tm.tv_sec = 0;
      tm.tv_nsec = 0;
    }

    if (NOINTR_RAW(sys_futex(mutex, FUTEX_WAIT, value, &tm, NULL, 0)) &&
        errno == ETIMEDOUT) {
      ret = false;
      goto done;
    }
  }
}

static __attribute__((__used__)) bool mutex_wait_for_unlock(mutex_t *mutex,
                                                            int timeout) {
  bool ret = true;
// Increment mutex to add ourselves to the list of waiters
#if defined(__x86_64__) || defined(__i386__)
  asm volatile("lock; incl %0\n" : "=m"(*mutex) : "m"(*mutex));
#else
#error Unsupported target platform
#endif
  for (;;) {
    mutex_t value = *mutex;
    if (value >= 0) {
    done:
// Mutex was not locked, remove ourselves and notify other waiters.
#if defined(__x86_64__) || defined(__i386__)
      asm volatile("lock; decl %0\n" : "=m"(*mutex) : "m"(*mutex));
#else
#error Unsupported target platform
#endif
      (void)NOINTR_RAW(sys_futex(mutex, FUTEX_WAKE, 1, NULL, NULL, 0));
      return ret;
    }

    // wait for mutex to become unlocked
    struct kernel_timespec tm;
    if (timeout) {
      tm.tv_sec = timeout / 1000;
      tm.tv_nsec = (timeout % 1000) * 1000 * 1000;
    } else {
      tm.tv_sec = 0;
      tm.tv_nsec = 0;
    }

    if (NOINTR_RAW(sys_futex(mutex, FUTEX_WAIT, value, &tm, NULL, 0)) &&
        errno == ETIMEDOUT) {
      ret = false;
      goto done;
    }
  }
}

__END_DECLS

#endif /* MUTEX_H_ */
