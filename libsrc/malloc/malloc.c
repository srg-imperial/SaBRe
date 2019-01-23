/*
 * Copyright (c) 2012, 2013 ARM Ltd
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the company may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY ARM LTD ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL ARM LTD BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Implementation of <<malloc>> <<free>> <<calloc>> <<realloc>>, optional
 * as to be reenterable.
 *
 * Interface documentation refer to malloc.c.
 */

#include "_nx_malloc.h"

#define DEFINE_MALLOC 1
#define DEFINE_FREE 1
#define DEFINE_CFREE 1
#define DEFINE_CALLOC 1
#define DEFINE_REALLOC 1
#define DEFINE_MALLINFO 1
#define DEFINE_MALLOC_STATS 1
#define DEFINE_MALLOC_USABLE_SIZE 1
#define DEFINE_MEMALIGN 1
//#define DEFINE_MALLOPT 1
#define DEFINE_VALLOC 1
#define DEFINE_PVALLOC 1

#include <assert.h>

#include "kernel.h"
#include "linux_syscall_support.h"

#ifndef MAX
#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#endif

#define SYS_ERRNO errno

__hidden extern void __malloc_lock();
__hidden extern void __malloc_unlock();

#if 0
#define MALLOC_LOCK
#define MALLOC_UNLOCK
#else
#define MALLOC_LOCK (void) __malloc_lock()
#define MALLOC_UNLOCK __malloc_unlock()
#endif
#ifndef SYS_ERRNO
#define MALLOC_ERRNO SYS_ERRNO
#else
#define MALLOC_ERRNO errno
#endif

/* Redefine names to avoid conflict with glibc */
#define malloc _nx_malloc
#define free _nx_free
#define realloc _nx_realloc
#define memalign _nx_memalign
#define valloc _nx_valloc
#define pvalloc p_nx_valloc
#define calloc _nx_calloc
#define cfree _nx_cfree
#define malloc_usable_size _nx_malloc_usable_size
#define malloc_stats _nx_malloc_stats
#define mallinfo _nx_mallinfo
#define mallopt _nx_mallopt

/* Redefine names to avoid conflict with user names */
#define free_list __malloc_free_list
#define sbrk_start __malloc_sbrk_start
#define current_mallinfo __malloc_current_mallinfo

#define ALIGN_TO(size, align) (((size) + (align) - 1) & ~((align) - 1))

/* Alignment of allocated block */
#define MALLOC_ALIGN (8U)
#define CHUNK_ALIGN (sizeof(void *))
#define MALLOC_PADDING ((MAX(MALLOC_ALIGN, CHUNK_ALIGN)) - CHUNK_ALIGN)

/* as well as the minimal allocation size
 * to hold a free pointer */
#define MALLOC_MINSIZE (sizeof(void *))
#define MALLOC_PAGE_ALIGN (0x1000)
#define MAX_ALLOC_SIZE (0x80000000U)

typedef struct malloc_chunk {
  /*          ------------------
   *   chunk->| size (4 bytes) |
   *          ------------------
   *          | Padding for    |
   *          | alignment      |
   *          | holding neg    |
   *          | offset to size |
   *          ------------------
   * mem_ptr->| point to next  |
   *          | free when freed|
   *          | or data load   |
   *          | when allocated |
   *          ------------------
   */
  /* size of the allocated payload area, including size before
     CHUNK_OFFSET */
  long size;

  /* since here, the memory is either the next free block, or data load */
  struct malloc_chunk *next;
} chunk;

#define CHUNK_OFFSET ((size_t)(&(((struct malloc_chunk *)0)->next)))

/* size of smallest possible chunk. A memory piece smaller than this size
 * won't be able to create a chunk */
#define MALLOC_MINCHUNK (CHUNK_OFFSET + MALLOC_PADDING + MALLOC_MINSIZE)

static inline chunk *get_chunk_from_ptr(void *ptr) {
  chunk *c = (chunk *)((char *)ptr - CHUNK_OFFSET);
  /* Skip the padding area */
  if (c->size < 0)
    c = (chunk *)((char *)c + c->size);
  return c;
}

#define MALLOC_QUANTUM (0x1000)

#ifdef DEFINE_MALLOC
/* List list header of free blocks */
static chunk *free_list = NULL;

/** Function sbrk_aligned
  * Algorithm:
  *   Use sbrk() to obtain more memory and ensure it is CHUNK_ALIGN aligned
  *   Optimise for the case that it is already aligned - only ask for extra
  *   padding after we know we need it
  */
static void *sbrk_aligned(size_t *s) {
  void *result;
  size_t length;

  /* mmap requires the size to be page aligned */
  length = (size_t)ALIGN_TO(*s, MALLOC_QUANTUM);

  /* allocate new block using mmap */
  result = sys_mmap(
      0, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  /* mmap failed to allocate the block */
  if (result == MAP_FAILED) {
    return (void *)-1;
  }

  *s = length;
  return result;
}

/** Function malloc
  * Algorithm:
  *   Walk through the free list to find the first match. If fails to find
  *   one, call sbrk to allocate a new chunk.
  */
void *_nx_malloc(size_t s) {
  chunk *p, *r;
  char *ptr, *align_ptr;
  int offset;

  size_t alloc_size;

  alloc_size = ALIGN_TO(s, CHUNK_ALIGN); /* size of aligned data load */
  alloc_size += MALLOC_PADDING;          /* padding */
  alloc_size += CHUNK_OFFSET;            /* size of chunk head */
  alloc_size = MAX(alloc_size, MALLOC_MINCHUNK);

  if (alloc_size >= MAX_ALLOC_SIZE || alloc_size < s) {
    MALLOC_ERRNO = ENOMEM;
    return NULL;
  }

  MALLOC_LOCK;

  p = free_list;
  r = p;

  while (r) {
    int rem = r->size - alloc_size;
    if (rem >= 0) {
      if ((size_t)rem >= MALLOC_MINCHUNK) {
        /* Find a chunk that much larger than required size, break
        * it into two chunks and return the second one */
        r->size = rem;
        r = (chunk *)((char *)r + rem);
        r->size = alloc_size;
      }
      /* Find a chunk that is exactly the size or slightly bigger
       * than requested size, just return this chunk */
      else if (p == r) {
        /* Now it implies p==r==free_list. Move the free_list
         * to next chunk */
        free_list = r->next;
      } else {
        /* Normal case. Remove it from free_list */
        p->next = r->next;
      }
      break;
    }
    p = r;
    r = r->next;
  }

  /* Failed to find a appropriate chunk. Ask for more memory */
  if (r == NULL) {
    size_t size = alloc_size;
    r = sbrk_aligned(&size);

    /* sbrk returns -1 if fail to allocate */
    if (r == (void *)-1) {
      MALLOC_ERRNO = ENOMEM;
      MALLOC_UNLOCK;
      return NULL;
    }

    int rem = size - alloc_size;
    memset(r, 0, size);
    if ((size_t)rem >= MALLOC_MINCHUNK) {
      r->size = rem;
      if (free_list == NULL) {
        r->next = free_list;
        free_list = r;
      } else {
        r->next = p->next;
        p->next = r;
      }
      r = (chunk *)((char *)r + rem);
    }
    r->size = alloc_size;
  }
  MALLOC_UNLOCK;

  ptr = (char *)r + CHUNK_OFFSET;

  align_ptr = PTR_ALIGN(ptr, MALLOC_ALIGN);
  offset = align_ptr - ptr;
  memset(align_ptr, 0, s);

  if (offset) {
    *(int *)((char *)r + offset) = -offset;
  }

  assert(align_ptr + s <= (char *)r + alloc_size);

  return align_ptr;
}
#endif /* DEFINE_MALLOC */

#ifdef DEFINE_FREE
#define MALLOC_CHECK_DOUBLE_FREE

/** Function free
  * Implementation of libc free.
  * Algorithm:
  *  Maintain a global free chunk single link list, headed by global
  *  variable free_list.
  *  When free, insert the to-be-freed chunk into free list. The place to
  *  insert should make sure all chunks are sorted by address from low to
  *  high.  Then merge with neighbor chunks if adjacent.
  */
void _nx_free(void *free_p) {
  chunk *p_to_free;
  chunk *p, *q;

  if (free_p == NULL)
    return;

  p_to_free = get_chunk_from_ptr(free_p);

  MALLOC_LOCK;
  if (free_list == NULL) {
    /* Set first free list element */
    p_to_free->next = free_list;
    free_list = p_to_free;
    MALLOC_UNLOCK;
    return;
  }

  if (p_to_free < free_list) {
    if ((char *)p_to_free + p_to_free->size == (char *)free_list) {
      /* Chunk to free is just before the first element of
       * free list  */
      p_to_free->size += free_list->size;
      p_to_free->next = free_list->next;
    } else {
      /* Insert before current free_list */
      p_to_free->next = free_list;
    }
    free_list = p_to_free;
    MALLOC_UNLOCK;
    return;
  }

  q = free_list;
  /* Walk through the free list to find the place for insert. */
  do {
    p = q;
    q = q->next;
  } while (q && q <= p_to_free);

  /* Now p <= p_to_free and either q == NULL or q > p_to_free
   * Try to merge with chunks immediately before/after it. */

  if ((char *)p + p->size == (char *)p_to_free) {
    /* Chunk to be freed is adjacent
     * to a free chunk before it */
    p->size += p_to_free->size;
    /* If the merged chunk is also adjacent
     * to the chunk after it, merge again */
    if ((char *)p + p->size == (char *)q) {
      p->size += q->size;
      p->next = q->next;
    }
  }
#ifdef MALLOC_CHECK_DOUBLE_FREE
  else if ((char *)p + p->size > (char *)p_to_free) {
    /* Report double free fault */
    MALLOC_ERRNO = ENOMEM;
    MALLOC_UNLOCK;
    return;
  }
#endif
  else if ((char *)p_to_free + p_to_free->size == (char *)q) {
    /* Chunk to be freed is adjacent
     * to a free chunk after it */
    p_to_free->size += q->size;
    p_to_free->next = q->next;
    p->next = p_to_free;
  } else {
    /* Not adjacent to any chunk. Just insert it. Resulting
     * a fragment. */
    p_to_free->next = q;
    p->next = p_to_free;
  }
  MALLOC_UNLOCK;
}
#endif /* DEFINE_FREE */

#ifdef DEFINE_CFREE
void _nx_cfree(void *ptr) { free(ptr); }
#endif /* DEFINE_CFREE */

#ifdef DEFINE_CALLOC
/* Function _nx_calloc
 * Implement calloc simply by calling malloc and set zero */
void *_nx_calloc(size_t n, size_t elem) {
  void *mem = malloc(n * elem);
  if (mem != NULL) {
    asm ("":"+r"(mem)); // Keep GCC from optimizing (malloc+memset = calloc) here
    memset(mem, 0, n * elem);
  }
  return mem;
}
#endif /* DEFINE_CALLOC */

#ifdef DEFINE_REALLOC
/* Function _nx_realloc
 * Implement realloc by malloc + memcpy */
void *_nx_realloc(void *ptr, size_t size) {
  void *mem;

  if (ptr == NULL)
    return malloc(size);

  if (size == 0) {
    free(ptr);
    return NULL;
  }

  /* TODO: There is chance to shrink the chunk if newly requested
   * size is much small */
  if (malloc_usable_size(ptr) >= size)
    return ptr;

  mem = malloc(size);
  if (mem != NULL) {
    memcpy(mem, ptr, malloc_usable_size(ptr));
    free(ptr);
  }
  return mem;
}
#endif /* DEFINE_REALLOC */

#ifdef DEFINE_MALLINFO
static struct mallinfo current_mallinfo = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

struct mallinfo _nx_mallinfo(void) { return current_mallinfo; }
#endif /* DEFINE_MALLINFO */

#ifdef DEFINE_MALLOC_STATS
void _nx_malloc_stats(void) {}
#endif /* DEFINE_MALLOC_STATS */

#ifdef DEFINE_MALLOC_USABLE_SIZE
size_t _nx_malloc_usable_size(const void *ptr) {
  chunk *c = (chunk *)((char *)ptr - CHUNK_OFFSET);
  int size_or_offset = c->size;

  if (size_or_offset < 0) {
    /* Padding is used. Excluding the padding size */
    c = (chunk *)((char *)c + c->size);
    return c->size - CHUNK_OFFSET + size_or_offset;
  }
  return c->size - CHUNK_OFFSET;
}
#endif /* DEFINE_MALLOC_USABLE_SIZE */

#ifdef DEFINE_MEMALIGN
/* Function _nx_memalign
 * Allocate memory block aligned at specific boundary.
 *   align: required alignment. Must be power of 2. Return NULL
 *          if not power of 2. Undefined behavior is bigger than
 *          pointer value range.
 *   s: required size.
 * Return: allocated memory pointer aligned to align
 * Algorithm: Malloc a big enough block, padding pointer to aligned
 *            address, then truncate and free the tail if too big.
 *            Record the offset of align pointer and original pointer
 *            in the padding area.
 */
void *_nx_memalign(size_t align, size_t s) {
  chunk *chunk_p;
  size_t size_allocated, offset, ma_size, size_with_padding;
  char *allocated, *aligned_p;

  /* Return NULL if align isn't power of 2 */
  if ((align & (align - 1)) != 0)
    return NULL;

  align = MAX(align, MALLOC_ALIGN);
  ma_size = ALIGN_TO(MAX(s, MALLOC_MINSIZE), CHUNK_ALIGN);
  size_with_padding = ma_size + align - MALLOC_ALIGN;

  allocated = malloc(size_with_padding);
  if (allocated == NULL)
    return NULL;

  chunk_p = get_chunk_from_ptr(allocated);
  aligned_p = (char *)ALIGN_TO((unsigned long)((char *)chunk_p + CHUNK_OFFSET),
                               (unsigned long)align);
  offset = aligned_p - ((char *)chunk_p + CHUNK_OFFSET);

  if (offset) {
    if (offset >= MALLOC_MINCHUNK) {
      /* Padding is too large, free it */
      chunk *front_chunk = chunk_p;
      chunk_p = (chunk *)((char *)chunk_p + offset);
      chunk_p->size = front_chunk->size - offset;
      front_chunk->size = offset;
      free((char *)front_chunk + CHUNK_OFFSET);
    } else {
      /* Padding is used. Need to set a jump offset for aligned pointer
      * to get back to chunk head */
      assert(offset >= sizeof(int));
      *(int *)((char *)chunk_p + offset) = -offset;
    }
  }

  size_allocated = chunk_p->size;
  if ((char *)chunk_p + size_allocated >
      (aligned_p + ma_size + MALLOC_MINCHUNK)) {
    /* allocated much more than what's required for padding, free
     * tail part */
    chunk *tail_chunk = (chunk *)(aligned_p + ma_size);
    chunk_p->size = aligned_p + ma_size - (char *)chunk_p;
    tail_chunk->size = size_allocated - chunk_p->size;
    free((char *)tail_chunk + CHUNK_OFFSET);
  }
  return aligned_p;
}
#endif /* DEFINE_MEMALIGN */

#ifdef DEFINE_MALLOPT
int _nx_mallopt(int parameter_number, int parameter_value) { return 0; }
#endif /* DEFINE_MALLOPT */

#ifdef DEFINE_VALLOC
void *_nx_valloc(size_t s) { return _nx_memalign(MALLOC_PAGE_ALIGN, s); }
#endif /* DEFINE_VALLOC */

#ifdef DEFINE_PVALLOC
void *_nx_pvalloc(size_t s) {
  return _nx_valloc(ALIGN_TO(s, MALLOC_PAGE_ALIGN));
}
#endif /* DEFINE_PVALLOC */
