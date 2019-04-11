/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef NX_MALLOC_H_
#define NX_MALLOC_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include "compiler.h"

__BEGIN_DECLS

#define __malloc __attribute__((malloc))
#define __warn_unused_result __attribute__((malloc))

__hidden void *_nx_malloc(size_t byte_count) __malloc __warn_unused_result
    __attribute__((alloc_size(1)));
__hidden void *_nx_calloc(size_t item_count,
                      size_t item_size) __malloc __warn_unused_result
    __attribute__((alloc_size(1, 2)));
__hidden void *_nx_realloc(void *p, size_t byte_count) __malloc __warn_unused_result
    __attribute__((alloc_size(2)));
__hidden void _nx_free(void *p);

__hidden void *_nx_memalign(size_t alignment,
                        size_t byte_count) __malloc __warn_unused_result
    __attribute__((alloc_size(2)));
__hidden size_t _nx_malloc_usable_size(const void *p);

__hidden void *_nx_valloc(size_t byte_count) __malloc __warn_unused_result
    __attribute__((alloc_size(1)));
__hidden void *_nx_pvalloc(size_t byte_count) __malloc __warn_unused_result
    __attribute__((alloc_size(1)));

#ifndef STRUCT_MALLINFO_DECLARED
#define STRUCT_MALLINFO_DECLARED 1
struct _nx_mallinfo {
  size_t arena; /* Total number of non-mmapped bytes currently allocated from
                   OS. */
  size_t ordblks; /* Number of free chunks. */
  size_t smblks;  /* (Unused.) */
  size_t hblks;   /* (Unused.) */
  size_t hblkhd;  /* Total number of bytes in mmapped regions. */
  size_t usmblks; /* Maximum total allocated space; greater than total if
                     trimming has occurred. */
  size_t fsmblks;  /* (Unused.) */
  size_t uordblks; /* Total allocated space (normal or mmapped.) */
  size_t fordblks; /* Total free space. */
  size_t
      keepcost; /* Upper bound on number of bytes releasable by malloc_trim. */
};
#endif /* STRUCT_MALLINFO_DECLARED */

__hidden struct _nx_mallinfo _nx_mallinfo(void);

__END_DECLS

#endif /* NX_MALLOC_H_ */
