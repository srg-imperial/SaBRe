/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef CUSTOM_TLS_H
#define CUSTOM_TLS_H

#include <stdbool.h>
#include <sys/types.h>

typedef struct thread_local_vars {
  bool calling_from_plugin;
  unsigned long sabre_tls_addr;
  unsigned long client_tls_addr;
} thread_local_vars_s;

void register_first_tid();
void register_ctls_with_tlv(thread_local_vars_s *);

thread_local_vars_s *get_ctls();
thread_local_vars_s *new_ctls_storage();

#endif /* !CUSTOM_TLS */
