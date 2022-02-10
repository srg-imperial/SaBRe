/* SPDX-License-Identifier: GPL-2.0 */

#ifndef JHASH_H_
#define JHASH_H_

#include <stdint.h>
#include <unistd.h>

#include "bitops.h"

/* Best hash sizes are of power of two */
#define jhash_size(n) ((uint32_t)1 << (n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n) (jhash_size(n) - 1)

/** Mix 3 32-bit values reversibly */
#define __jhash_mix(a, b, c)                                                   \
  ({                                                                           \
    a -= c;                                                                    \
    a ^= rol32(c, 4);                                                          \
    c += b;                                                                    \
    b -= a;                                                                    \
    b ^= rol32(a, 6);                                                          \
    a += c;                                                                    \
    c -= b;                                                                    \
    c ^= rol32(b, 8);                                                          \
    b += a;                                                                    \
    a -= c;                                                                    \
    a ^= rol32(c, 16);                                                         \
    c += b;                                                                    \
    b -= a;                                                                    \
    b ^= rol32(a, 19);                                                         \
    a += c;                                                                    \
    c -= b;                                                                    \
    c ^= rol32(b, 4);                                                          \
    b += a;                                                                    \
  })

/** Final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)                                                 \
  ({                                                                           \
    c ^= b;                                                                    \
    c -= rol32(b, 14);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 11);                                                         \
    b ^= a;                                                                    \
    b -= rol32(a, 25);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 16);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 4);                                                          \
    b ^= a;                                                                    \
    b -= rol32(a, 14);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 24);                                                         \
  })

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

/**
 * Hash an arbitrary key
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * @param k sequence of bytes as key
 * @param length the length of the key
 * @param initval the previous hash, or an arbitray value
 * @return the hash value of the key
 */
static inline uint32_t jhash(const void *key, uint32_t length,
                             uint32_t initval) {
  uint32_t a, b, c;
  const uint8_t *k = key;

  /* Set up the internal state */
  a = b = c = JHASH_INITVAL + length + initval;

  /* All but the last block: affect some 32 bits of (a,b,c) */
  while (length > 12) {
    a += (k[0] + ((uint32_t)k[1] << 8) + ((uint32_t)k[2] << 16) +
          ((uint32_t)k[3] << 24));
    b += (k[4] + ((uint32_t)k[5] << 8) + ((uint32_t)k[6] << 16) +
          ((uint32_t)k[7] << 24));
    c += (k[8] + ((uint32_t)k[9] << 8) + ((uint32_t)k[10] << 16) +
          ((uint32_t)k[11] << 24));
    __jhash_mix(a, b, c);
    length -= 12;
    k += 12;
  }
  /* Last block: affect all 32 bits of (c) */
  /* All the case statements fall through */
  switch (length) {
  case 12:
    c += (uint32_t)k[11] << 24;
    // fall through
  case 11:
    c += (uint32_t)k[10] << 16;
    // fall through
  case 10:
    c += (uint32_t)k[9] << 8;
    // fall through
  case 9:
    c += k[8];
    // fall through
  case 8:
    b += (uint32_t)k[7] << 24;
    // fall through
  case 7:
    b += (uint32_t)k[6] << 16;
    // fall through
  case 6:
    b += (uint32_t)k[5] << 8;
    // fall through
  case 5:
    b += k[4];
    // fall through
  case 4:
    a += (uint32_t)k[3] << 24;
    // fall through
  case 3:
    a += (uint32_t)k[2] << 16;
    // fall through
  case 2:
    a += (uint32_t)k[1] << 8;
    // fall through
  case 1:
    a += k[0];
    __jhash_final(a, b, c);
    // fall through
  case 0: /* Nothing left to add */
    break;
  }

  return c;
}

/**
 * Hash an array of uint32_t's
 *
 * @param k the key which must be an array of uint32_t's
 * @param length the number of uint32_t's in the key
 * @param initval the previous hash, or an arbitray value
 * @return the hash value of the key
 */
static inline uint32_t jhash2(const uint32_t *k, uint32_t length,
                              uint32_t initval) {
  uint32_t a, b, c;

  /* Set up the internal state */
  a = b = c = JHASH_INITVAL + (length << 2) + initval;

  /* Handle most of the key */
  while (length > 3) {
    a += k[0];
    b += k[1];
    c += k[2];
    __jhash_mix(a, b, c);
    length -= 3;
    k += 3;
  }

  /* Handle the last 3 uint32_t's: all the case statements fall through */
  switch (length) {
  case 3:
    c += k[2];
  case 2:
    b += k[1];
  case 1:
    a += k[0];
    __jhash_final(a, b, c);
  case 0: /* Nothing left to add */
    break;
  }

  return c;
}

/**
 * Hash exactly 3, 2 or 1 word(s)
 */
static inline uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c,
                                    uint32_t initval) {
  a += JHASH_INITVAL;
  b += JHASH_INITVAL;
  c += initval;

  __jhash_final(a, b, c);

  return c;
}

static inline uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t initval) {
  return jhash_3words(a, b, 0, initval);
}

static inline uint32_t jhash_1word(uint32_t a, uint32_t initval) {
  return jhash_3words(a, 0, 0, initval);
}

#endif /* JHASH_H_ */
