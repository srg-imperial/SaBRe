/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "_nx_malloc.h"
#include "mutex.h"
//#include "futex.h"

static mutex_t lock = 0;
// static futex_t lock = FUTEX_INIT(1);

void __malloc_lock() {
  (void)mutex_lock(&lock, 0);
  //(void)futex_down(&lock);
}

void __malloc_unlock() {
  (void)mutex_unlock(&lock);
  // futex_up(&lock, 0);
}
