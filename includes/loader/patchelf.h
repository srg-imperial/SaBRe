/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PATHELF_H
#define PATHELF_H

#include <stdbool.h>

void inject_needed_lib(const char *, const char *, bool);

#endif /* !PATHELF_H */
