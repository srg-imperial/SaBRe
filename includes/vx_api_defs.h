#ifndef VX_API_DEFS_H
#define VX_API_DEFS_H

#include <stdbool.h>

// Helper typedef to simplify definition of vx_icept_callback_fn
typedef void (*void_void_fn)(void);
typedef void_void_fn (*vx_icept_callback_fn)(void_void_fn);

/*
 * Structure passed to the loader by the Varan (or any other plugin) during
 * initialisation (in vx_init).
 *
 * It contains two strings (library name as well as the name of the function
 * to be intercepted) and a callback function that loader calls while
 * intercepting the function.
 *
 * The callback function takes a function as an argument (which points to
 * relocated head of the function being intercepted) and returns a function
 * that is actually called instead of the function being intercepted.
 */
typedef struct vx_fn_icept {
  const char *lib_name;
  const char *fn_name;
  /*
   * This is ugly - typedefs might help, but oh well.  icept_callback is a
   * pointer to a function that takes a pointer to a function that takes
   * nothing ant returns nothing and returns a function that takes nothing and
   * returns nothing. Reason for that is intercepted functions will all have
   * different parameters anyway, so we might as well use ANY function pointer
   * to keep the compiler happy and cast them to whatever is required.
   */
  //void (*(*icept_callback)(void (*)(void)))(void);
  vx_icept_callback_fn icept_callback;
} vx_fn_icept_struct;

// Signature for the syscall handler
typedef long (*vx_sc_handler_fn)(long, long, long, long, long, long, long, void *);

#ifdef __NX_INTERCEPT_RDTSC
// Signature for the RDTSC handler
typedef long (*vx_rdtsc_handler_fn)();
#endif

// Signature for vDSO callback function
typedef void_void_fn (*vx_icept_vdso_callback_fn)(long, void_void_fn);

// Signature for the callback registration function
typedef void (*vx_icept_reg_fn)(const vx_fn_icept_struct *);

typedef void (*vx_post_load_fn)(bool);

typedef void_void_fn vx_premain_fn;

// Signature for the vx_init function
typedef void (*vx_init_fn)(int *,
                           char ***,
                           //vx_segfault_handler_fn *segfault_handler, // - TBD
                           vx_icept_reg_fn,
                           vx_icept_vdso_callback_fn *,
                           vx_sc_handler_fn *,
#ifdef __NX_INTERCEPT_RDTSC
                           vx_rdtsc_handler_fn *,
#endif
                           vx_post_load_fn *);

struct syscall_stackframe;
void *get_syscall_return_address (struct syscall_stackframe* stack_frame);

#endif /* !VX_API_DEFS_H */
