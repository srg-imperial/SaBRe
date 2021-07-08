/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PROXY_FUNCS_H
#define PROXY_FUNCS_H

#include "plugins/sbr_api_defs.h"

void_void_fn proxy_vdso_callback(long, void_void_fn);

#endif /* !PROXY_FUNCS */
