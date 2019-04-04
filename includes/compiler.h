/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef COMPILER_H_
#define COMPILER_H_

#ifndef __same_type
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif
#define __must_be_array(a) __same_type((a), &(a)[0])

#define __deprecated __attribute__((deprecated))
#define __packed __attribute__((packed))
#define __weak __attribute__((weak))
#define __pure __attribute__((pure))

#define __noreturn __attribute__((noreturn))
#define __unused __attribute__((unused))

#define __aligned(x) __attribute__((aligned(x)))
#define __printf(a, b) __attribute__((format(printf, a, b)))
#define __scanf(a, b) __attribute__((format(scanf, a, b)))

#define __constructor __attribute__((constructor))
#define __destructor __attribute__((destructor))
#define __cleanup(f) __attribute__((cleanup(f)))

#define internal_function __attribute__((regparm(3), stdcall))
#define attribute_hidden __attribute__((visibility("hidden")))
#define attribute_relro __attribute__((section(".data.rel.ro")))

#define __hidden __attribute__((visibility("hidden")))
#define __internal __attribute__((visibility("internal")))
#define __protected __attribute__((visibility("protected")))

#define uninitialized_var(x) x = x
#define unreferenced_var(x) \
  do {                      \
    (void) x;               \
  } while (0)
#define ignore_result(x) \
  do {                   \
    __typeof__(x) z = x; \
    (void)sizeof z;      \
  } while (0)

#define __const __attribute__((__const__))
#define __used __attribute__((__used__))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define unreachable() __builtin_unreachable()

#endif /* COMPILER_H_ */
