/*
   This plugin simply intercepts all system calls and vDSO calls and
   reissues them.
*/

#include "real_syscall.h"
#include "vx_api_defs.h"

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

long handle_syscall(long sc_no,
                    long arg1,
                    long arg2,
                    long arg3,
                    long arg4,
                    long arg5,
                    long arg6,
                    void* wrapper_sp) {
  if (sc_no == 56 && arg2 != 0) { // clone
    void *ret_addr = get_syscall_return_address(wrapper_sp);
    return clone_syscall(arg1, (void*)arg2, (void*)arg3, (void*)arg4, arg5, ret_addr);
  }
  else
    return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
}

void_void_fn actual_clock_gettime = NULL;
void_void_fn actual_getcpu = NULL;
void_void_fn actual_gettimeofday = NULL;
void_void_fn actual_time = NULL;

typedef int clock_gettime_fn(clockid_t, struct timespec *);
int handle_vdso_clock_gettime(clockid_t arg1, struct timespec *arg2) {
  return ((clock_gettime_fn*)actual_clock_gettime)(arg1, arg2);
}

// arg3 has type: struct getcpu_cache *
typedef int getcpu_fn(unsigned *, unsigned *, void *);
int handle_vdso_getcpu(unsigned *arg1, unsigned *arg2, void *arg3) {
  return ((getcpu_fn*)actual_getcpu)(arg1, arg2, arg3);
}

typedef int gettimeofday_fn(struct timeval *, struct timezone *);
int handle_vdso_gettimeofday(struct timeval *arg1, struct timezone *arg2) {
  return ((gettimeofday_fn*)actual_gettimeofday)(arg1, arg2);
}

typedef int time_fn(time_t *);
int handle_vdso_time(time_t *arg1) {
  return ((time_fn*)actual_time)(arg1);
}

void_void_fn handle_vdso(long sc_no, void_void_fn actual_fn) {
  (void)actual_fn;
  switch (sc_no) {
    case __NR_clock_gettime:
      actual_clock_gettime = actual_fn;
      return (void_void_fn)handle_vdso_clock_gettime;
    case __NR_getcpu:
      actual_getcpu = actual_fn;
      return (void_void_fn)handle_vdso_getcpu;
    case __NR_gettimeofday:
      actual_gettimeofday = actual_fn;
      return (void_void_fn)handle_vdso_gettimeofday;
    case __NR_time:
      actual_time = actual_fn;
      return (void_void_fn)handle_vdso_time;
    default:
      return (void_void_fn)NULL;
  }
}

long handle_rdtsc() {
  long high, low;

  asm volatile ("rdtsc;" :"=a"(low), "=d"(high) : : );

  long ret = high;
  ret <<= 32;
  ret |= low;

  return ret;
}

void vx_init(int *argc, char **argv[],
             vx_icept_reg_fn fn_icept_reg,
             vx_icept_vdso_callback_fn *vdso_callback,
             vx_sc_handler_fn *syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
             vx_rdtsc_handler_fn *rdtsc_handler,
#endif
             vx_post_load_fn *post_load) {
  (void)fn_icept_reg;  // unused
  (void)post_load;     // unused

  *syscall_handler = handle_syscall;
  *vdso_callback = handle_vdso;

#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = handle_rdtsc;
#endif

  (*argc)--;
  (*argv)++;
}
