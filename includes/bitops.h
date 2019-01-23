#ifndef BITOPS_H_
#define BITOPS_H_

#include "kernel.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#if defined(__x86_64__) && !defined(__ILP32__)
#define __WORDSIZE 64
#else
#define __WORDSIZE 32
#endif

#define BITS_PER_LONG __WORDSIZE
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE 8
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

/**
 * Returns the hamming weight of a 32-bit word.
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 *
 * @param x word to weight
 */
static inline unsigned int hweight32(unsigned int w) {
  unsigned int res = w - ((w >> 1) & 0x55555555);
  res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
  res = (res + (res >> 4)) & 0x0F0F0F0F;
  res = res + (res >> 8);
  return (res + (res >> 16)) & 0x000000FF;
}

/**
 * Returns the hamming weight of a 64-bit word.
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 *
 * @param x word to weight
 */
static inline long hweight64(uint64_t w) {
#if __WORDSIZE == 32
  return hweight32((unsigned int)(w >> 32)) + hweight32((unsigned int)w);
#elif __WORDSIZE == 64
  uint64_t res = w - ((w >> 1) & 0x5555555555555555ul);
  res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
  res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
  res = res + (res >> 8);
  res = res + (res >> 16);
  return (res + (res >> 32)) & 0x00000000000000FFul;
#endif
}

static inline void set_bit(int nr, unsigned long *addr) {
  addr[nr / BITS_PER_LONG] |= 1UL << (nr % BITS_PER_LONG);
}

static inline void clear_bit(int nr, unsigned long *addr) {
  addr[nr / BITS_PER_LONG] &= ~(1UL << (nr % BITS_PER_LONG));
}

static inline bool test_bit(unsigned int nr, const unsigned long *addr) {
  return ((1UL << (nr % BITS_PER_LONG)) &
          (((unsigned long *)addr)[nr / BITS_PER_LONG])) != 0;
}

/**
 * Find first bit set.
 *
 * This is defined the same way as the libc and compiler builtin ffs routines,
 * therefore differs in spirit from the above ffz (man ffs).
 *
 * @param x the word to search
 */
/*static inline int ffs(int x) {
#ifdef __GNUC__
  return __builtin_ffs(x);
#else
  int r = 1;

  if (!x)
    return 0;
  if (!(x & 0xffff)) {
    x >>= 16;
    r += 16;
  }
  if (!(x & 0xff)) {
    x >>= 8;
    r += 8;
  }
  if (!(x & 0xf)) {
    x >>= 4;
    r += 4;
  }
  if (!(x & 3)) {
    x >>= 2;
    r += 2;
  }
  if (!(x & 1)) {
    x >>= 1;
    r += 1;
  }
  return r;
#endif
}*/

/**
 * Find first bit in word.
 *
 * The result is not defined if no bit exists.
 *
 * @param word the word to search
 */
static inline unsigned long __ffs(unsigned long word) {
#ifdef __GNUC__
  return __builtin_ctzl(word);
#else
  int num = 0;

#if __WORDSIZE == 64
  if ((word & 0xffffffff) == 0) {
    num += 32;
    word >>= 32;
  }
#endif
  if ((word & 0xffff) == 0) {
    num += 16;
    word >>= 16;
  }
  if ((word & 0xff) == 0) {
    num += 8;
    word >>= 8;
  }
  if ((word & 0xf) == 0) {
    num += 4;
    word >>= 4;
  }
  if ((word & 0x3) == 0) {
    num += 2;
    word >>= 2;
  }
  if ((word & 0x1) == 0)
    num += 1;
  return num;
#endif
}

/**
 * Find first set bit in a 64 bit word.
 *
 * The result is not defined if no bits are set.
 *
 * @param word 64 bit word
 */
static inline unsigned long __ffs64(uint64_t word) {
#if __WORDSIZE == 32
  if (((u32)word) == 0UL)
    return ffs((u32)(word >> 32)) + 32;
#elif __WORDSIZE != 64
#endif
  return __ffs((unsigned long)word);
}

/**
 * Find first zero in word.
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 *
 * @param word the word to search
 */
#define ffz(x) __ffs(~(x))

/**
 * Find last (most-significant) bit set.
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 *
 * @param x the word to search
 */
static inline int fls(int x) {
#ifdef __GNUC__
  return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
#else
  int r = 32;

  if (!x)
    return 0;
  if (!(x & 0xffff0000u)) {
    x <<= 16;
    r -= 16;
  }
  if (!(x & 0xff000000u)) {
    x <<= 8;
    r -= 8;
  }
  if (!(x & 0xf0000000u)) {
    x <<= 4;
    r -= 4;
  }
  if (!(x & 0xc0000000u)) {
    x <<= 2;
    r -= 2;
  }
  if (!(x & 0x80000000u)) {
    x <<= 1;
    r -= 1;
  }
  return r;
#endif
}

/**
 * Find last (most-significant) set bit in a long word.
 *
 * Undefined if no set bit exists, so code should check against 0 first.
 *
 * @param word the word to search
 */
static inline unsigned long __fls(unsigned long word) {
#ifdef __GNUC__
  return (sizeof(word) * 8) - 1 - __builtin_clzl(word);
#else
  int num = BITS_PER_LONG - 1;

#if BITS_PER_LONG == 64
  if (!(word & (~0ul << 32))) {
    num -= 32;
    word <<= 32;
  }
#endif
  if (!(word & (~0ul << (BITS_PER_LONG - 16)))) {
    num -= 16;
    word <<= 16;
  }
  if (!(word & (~0ul << (BITS_PER_LONG - 8)))) {
    num -= 8;
    word <<= 8;
  }
  if (!(word & (~0ul << (BITS_PER_LONG - 4)))) {
    num -= 4;
    word <<= 4;
  }
  if (!(word & (~0ul << (BITS_PER_LONG - 2)))) {
    num -= 2;
    word <<= 2;
  }
  if (!(word & (~0ul << (BITS_PER_LONG - 1))))
    num -= 1;
  return num;
#endif
}

#if __WORDSIZE == 32
static inline int fls64(uint64_t x) {
  __u32 h = x >> 32;
  if (h)
    return fls(h) + 32;
  return fls(x);
}
#elif __WORDSIZE == 64
static inline int fls64(uint64_t x) {
  if (x == 0)
    return 0;
  return __fls(x) + 1;
}
#endif

static inline unsigned fls_long(unsigned long l) {
  if (sizeof(l) == 4)
    return fls(l);
  return fls64(l);
}

static inline int get_bitmask_order(unsigned int count) { return fls(count); }

static inline int get_count_order(unsigned int count) {
  int order;

  order = fls(count) - 1;
  if (count & (count - 1))
    order++;
  return order;
}

static inline unsigned long hweight_long(unsigned long w) {
  return sizeof(w) == 4 ? hweight32(w) : hweight64(w);
}

/**
 * Rotate a 32-bit value left.
 * @param word value to rotate
 * @param shift bits to roll
 */
static inline uint32_t rol32(uint32_t word, unsigned int shift) {
  return (word << shift) | (word >> (32 - shift));
}

/**
 * Rotate a 32-bit value right.
 * @param word value to rotate
 * @param shift bits to roll
 */
static inline uint32_t ror32(uint32_t word, unsigned int shift) {
  return (word >> shift) | (word << (32 - shift));
}

/**
 * Rotate a 16-bit value left.
 * @param word value to rotate
 * @param shift bits to roll
 */
static inline uint16_t rol16(uint16_t word, unsigned int shift) {
  return (word << shift) | (word >> (16 - shift));
}

/**
 * Rotate a 16-bit value right.
 * @param word value to rotate
 * @param shift bits to roll
 */
static inline uint16_t ror16(uint16_t word, unsigned int shift) {
  return (word >> shift) | (word << (16 - shift));
}

/**
 * Rotate an 8-bit value left.
 * @param word value to rotate
 * @param shift bits to roll
 */
static inline uint8_t rol8(uint8_t word, unsigned int shift) {
  return (word << shift) | (word >> (8 - shift));
}

/**
 * Rotate an 8-bit value right.
 * @param word value to rotate
 * @param shift bits to roll
 */
static inline uint8_t ror8(uint8_t word, unsigned int shift) {
  return (word >> shift) | (word << (8 - shift));
}

#define for_each_set_bit(bit, addr, size)                      \
  for ((bit) = find_first_bit((addr), (size)); (bit) < (size); \
       (bit) = find_next_bit((addr), (size), (bit) + 1))

extern unsigned long find_first_bit(const unsigned long *addr,
                                    unsigned long size);
extern unsigned long find_first_zero_bit(const unsigned long *addr,
                                         unsigned long size);
extern unsigned long find_last_bit(const unsigned long *addr,
                                   unsigned long size);
extern unsigned long find_next_bit(const unsigned long *addr,
                                   unsigned long size,
                                   unsigned long offset);
extern unsigned long find_next_zero_bit(const unsigned long *addr,
                                        unsigned long size,
                                        unsigned long offset);

#endif /* BITOPS_H_ */
