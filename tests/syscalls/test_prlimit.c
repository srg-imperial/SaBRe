/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

// RUN: %{cc} %s -o %t1
// RUN: %{sbr} %t1 2>&1

#define _GNU_SOURCE
#include <stddef.h>
#include <sys/time.h>
#include <sys/resource.h>

int main (void)
{
  struct rlimit limit;

  if (prlimit(0, RLIMIT_STACK, NULL, &limit) != 0)
    return 1;

  limit.rlim_cur = limit.rlim_cur * 8 <= limit.rlim_max
                 ? limit.rlim_cur * 8
                 : limit.rlim_cur / 8;

  if (prlimit(0, RLIMIT_STACK, &limit, NULL) != 0)
    return 2;

  return 0;
}
