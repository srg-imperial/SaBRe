/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef HANDLE_RDTSC_H
#define HANDLE_RDTSC_H

#include "compiler.h"

void rdtsc_entrypoint(void) __internal;

#endif /* !HANDLE_RDTSC_H */
