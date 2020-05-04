/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include "arch/rewriter_tools.h"
#include "global_vars.h"
#include "loader/custom_tls.h"
#include "loader/ld_sc_handler.h"

// The plugin uses SaBRe's malloc, so we need to switch TLS before we enter the
// plugin and switch back to the client's TLS before we return back to the
// client.
// TODO(andronat): This is currently very slow as we add 2 syscalls for every
// client syscall. Ideally, we should link the plugin with the client's libc so
// plugin libraries that use malloc, pthreads, etc will work in harmony with the
// client.

bool are_we_a_child_after_fork(long sc_no, long arg2, long rc) {
  if (sc_no == SYS_clone && rc == 0) {
    return true;
  } else if (sc_no == SYS_fork && rc == 0) {
    assert(arg2 == 0);
    return true;
  }
  return false;
}

long proxy_plugin_sc_handler(long sc_no, long arg1, long arg2, long arg3,
                             long arg4, long arg5, long arg6,
                             void *wrapper_sp) {
  thread_local_vars_s *ctls = get_ctls();
  assert(ctls != NULL);

  if (ctls->calling_from_plugin == true) {
    return syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  }

  load_sabre_tls();
  ctls->calling_from_plugin = true;
  long fd =
      plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6, wrapper_sp);

  // We just forked and we are the child, we need to setup a new custom_tls.
  if (are_we_a_child_after_fork(sc_no, arg2, fd)) {
    setup_default_ctls();
    return fd;
  }

  ctls->calling_from_plugin = false;
  load_client_tls();
  return fd;
}

typedef long clock_gettime_fn(clockid_t, struct timespec *);
static clock_gettime_fn *plugin_vdso_clock_gettime;
static clock_gettime_fn *real_vdso_clock_gettime;

long proxy_vdso_clock_gettime(clockid_t arg1, struct timespec *arg2) {
  thread_local_vars_s *ctls = get_ctls();
  assert(ctls != NULL);

  if (ctls->calling_from_plugin == true) {
    return real_vdso_clock_gettime(arg1, arg2);
  }

  load_sabre_tls();
  ctls->calling_from_plugin = true;
  long ret = plugin_vdso_clock_gettime(arg1, arg2);
  ctls->calling_from_plugin = false;
  load_client_tls();
  return ret;
}

// arg3 has type: struct getcpu_cache *
typedef long getcpu_fn(unsigned *, unsigned *, void *);
static getcpu_fn *plugin_vdso_getcpu;
static getcpu_fn *real_vdso_getcpu;

long proxy_vdso_getcpu(unsigned *arg1, unsigned *arg2, void *arg3) {
  thread_local_vars_s *ctls = get_ctls();
  assert(ctls != NULL);

  if (ctls->calling_from_plugin == true) {
    return real_vdso_getcpu(arg1, arg2, arg3);
  }

  load_sabre_tls();
  ctls->calling_from_plugin = true;
  long ret = plugin_vdso_getcpu(arg1, arg2, arg3);
  ctls->calling_from_plugin = false;
  load_client_tls();
  return ret;
}

typedef long gettimeofday_fn(struct timeval *, struct timezone *);
static gettimeofday_fn *plugin_vdso_gettimeofday;
static gettimeofday_fn *real_vdso_gettimeofday;

long proxy_vdso_gettimeofday(struct timeval *arg1, struct timezone *arg2) {
  thread_local_vars_s *ctls = get_ctls();
  assert(ctls != NULL);

  if (ctls->calling_from_plugin == true) {
    return real_vdso_gettimeofday(arg1, arg2);
  }

  load_sabre_tls();
  ctls->calling_from_plugin = true;
  long ret = plugin_vdso_gettimeofday(arg1, arg2);
  ctls->calling_from_plugin = false;
  load_client_tls();
  return ret;
}

#ifdef __x86_64__
typedef long time_fn(time_t *);
static time_fn *plugin_vdso_time;
static time_fn *real_vdso_time;

long proxy_vdso_time(time_t *arg1) {
  thread_local_vars_s *ctls = get_ctls();
  assert(ctls != NULL);

  if (ctls->calling_from_plugin == true) {
    return real_vdso_time(arg1);
  }

  load_sabre_tls();
  ctls->calling_from_plugin = true;
  long ret = plugin_vdso_time(arg1);
  ctls->calling_from_plugin = false;
  load_client_tls();
  return ret;
}
#endif // __x86_64__

void_void_fn proxy_vdso_callback(long sc_no, void_void_fn actual_fn) {
  switch (sc_no) {
  case SYS_clock_gettime:
    real_vdso_clock_gettime = (clock_gettime_fn *)actual_fn;
    plugin_vdso_clock_gettime =
        (clock_gettime_fn *)vdso_callback(sc_no, actual_fn);
    if (plugin_vdso_clock_gettime == NULL)
      return NULL;
    return (void_void_fn)proxy_vdso_clock_gettime;
  case SYS_getcpu:
    real_vdso_getcpu = (getcpu_fn *)actual_fn;
    plugin_vdso_getcpu = (getcpu_fn *)vdso_callback(sc_no, actual_fn);
    if (plugin_vdso_getcpu == NULL)
      return NULL;
    return (void_void_fn)proxy_vdso_getcpu;
  case SYS_gettimeofday:
    real_vdso_gettimeofday = (gettimeofday_fn *)actual_fn;
    plugin_vdso_gettimeofday =
        (gettimeofday_fn *)vdso_callback(sc_no, actual_fn);
    if (plugin_vdso_gettimeofday == NULL)
      return NULL;
    return (void_void_fn)proxy_vdso_gettimeofday;
#ifdef __x86_64__
  case SYS_time:
    real_vdso_time = (time_fn *)actual_fn;
    plugin_vdso_time = (time_fn *)vdso_callback(sc_no, actual_fn);
    if (plugin_vdso_time == NULL)
      return NULL;
    return (void_void_fn)proxy_vdso_time;
#endif // __x86_64__
  default:
    return (void_void_fn)NULL;
  }
}
