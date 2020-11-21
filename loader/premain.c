/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <syscall.h>

#include "elf_loading.h"
#include "global_vars.h"
#include "ld_sc_handler.h"
#include "loader/rewriter.h"
#include "maps.h"
#include "premain.h"

// TODO(andronat): This is currently a hack. We intercept the loader in order to
// edit the internal representation of its link-map. More specifically we edit
// the preinit_array loaded from the client's elf file, by prepending our shim
// in this array. The advantage of function calls made by the .preinit_array is
// that we can safely use arbitrary function calls to client libraries as GOT
// and all that jazz is ready.

// TODO(andronat): Write a tests that check client always gets client argv.
static void preinit_shim_init_sbr_plugin(int argc, char **argv, char **env) {
  unreferenced_var(argc);
  unreferenced_var(argv);
  unreferenced_var(env);

  load_sabre_tls();

  uintptr_t lib_base = first_region(abs_plugin_path);
  if (lib_base == 0)
    errx(EXIT_FAILURE, "Couldn't find memory base of %s.", abs_plugin_path);

  ElfW(Addr) sym_addr;
  // TODO(andronat): add vaddr?
  sym_addr = addr_of_elf_symbol(abs_plugin_path, "sbr_init");
  assert(sym_addr != 0);
  sbr_init_fn plugin_init = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "calling_from_plugin");
  assert(sym_addr != 0);
  calling_from_plugin = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "enter_plugin");
  assert(sym_addr != 0);
  enter_plugin = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "exit_plugin");
  assert(sym_addr != 0);
  exit_plugin = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "is_vdso_ready");
  assert(sym_addr != 0);
  is_vdso_ready = (void *)lib_base + sym_addr;

  load_client_tls();

  // TODO(andronat): We need to split plugins into loadtime and runtime. In case
  // of splitting, how do we transfer state between loadtime and runtime
  // plugins?

  // TODO(andronat): Support client argv editing.
  enter_plugin();

  // char **orig_plugin_argv = plugin_argv; // Read below.
  sbr_post_load_fn post_load = NULL;
  sbr_icept_vdso_callback_fn plugin_vdso_callback = NULL;

  plugin_init(&plugin_argc, &plugin_argv, &register_function_intercepts,
              &plugin_vdso_callback, &plugin_sc_handler,
#ifdef __NX_INTERCEPT_RDTSC
              &plugin_rdtsc_handler,
#endif
              &post_load);

  if (post_load != NULL)
    post_load(NULL);

  // Rewrite vDSO handlers as they cannot be switched dynamically.
  // TODO: Rewriting the vDSO functions for a second time didn't work. The
  // rewriter is not idempotent.
  if (plugin_vdso_callback != NULL)
    setup_plugin_vdso(plugin_vdso_callback);

  // TODO: To free `plugin_argv` we need to switch TLSs, it doesn't worth it.
  // load_sabre_tls();
  // free(orig_plugin_argv);
  // load_client_tls();

  exit_plugin();
}

static ElfW(Dyn) new_dyn_entries[2] = {{.d_tag = DT_PREINIT_ARRAY},
                                       {.d_tag = DT_PREINIT_ARRAYSZ}};

typedef void (*_dl_init_fn)(struct ld_link_map *, int, char **, char **);
static _dl_init_fn real_dl_init;
static bool sbr_preinit_done = false;

// TODO: The following mechanism is very fragile. This should be ideally
// replaced by elfutils altering the elf headers and injecting the
// .preinit_array section.
void sbr_dl_init(struct ld_link_map *main_map, int ac, char **av, char **e) {
  if (sbr_preinit_done)
    return real_dl_init(main_map, ac, av, e);

  // Make sure this function shouldn't use the %fs register. e.g. don't use
  // printf.
  assert(main_map != NULL);

  ElfW(Dyn) *preinit_array_p = main_map->l_info[DT_PREINIT_ARRAY];
  ElfW(Dyn) *preinit_array_size_p = main_map->l_info[DT_PREINIT_ARRAYSZ];
  if (preinit_array_p != NULL) {
    // Get the current size of preinit_array. Default is 0.
    new_dyn_entries[1].d_un.d_val = preinit_array_size_p->d_un.d_val;
  }

  // Copy the ElfW(Dyn) structs to our own space and update main_map.
  main_map->l_info[DT_PREINIT_ARRAY] = &new_dyn_entries[0];
  main_map->l_info[DT_PREINIT_ARRAYSZ] = &new_dyn_entries[1];

  // We will add one more entry to the preinit array.
  new_dyn_entries[1].d_un.d_val += sizeof(ElfW(Addr));

  // We need the newly allocated space to be after main_map->l_addr because
  // look here: https://code.woboq.org/userspace/glibc/elf/dl-init.c.html#102.
  // Memory addresses are unsigned integers and thus we need the
  // new_preinit_array to be allocated to a higher address than main_map->l_addr
  // or else there will be undefined behaviour with wrapping around unsigned
  // integer values.
  void *hint = (void *)main_map->l_addr;
  ElfW(Addr) *new_preinit_array = (ElfW(Addr) *)mmap(
      hint, new_dyn_entries[1].d_un.d_val, PROT_READ | PROT_WRITE,
      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if ((void *)new_preinit_array < hint) {
    // Free the previous area.
    assert(munmap(new_preinit_array, new_dyn_entries[1].d_un.d_val) == 0);

    // Try again with a hint from the area just before the stack.
    load_sabre_tls();
    void *hint2 = (void *)end_of_stack_region();

    new_preinit_array = (ElfW(Addr) *)mmap(hint2, new_dyn_entries[1].d_un.d_val,
                                           PROT_READ | PROT_WRITE,
                                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert((void *)new_preinit_array >= hint2);
    load_client_tls();
  }

  // If there is a preinit_array already, append it.
  if (preinit_array_p != NULL) {
    ElfW(Addr) *preinit_array =
        (ElfW(Addr) *)(preinit_array_p->d_un.d_ptr + main_map->l_addr);
    memcpy(&new_preinit_array[0], preinit_array,
           preinit_array_size_p->d_un.d_val);
  }

  // Append our plugin so it initializes after pthreads and LLVM sanitizers.
  int pos = new_dyn_entries[1].d_un.d_val / sizeof(ElfW(Addr)) - 1;
  new_preinit_array[pos] = (ElfW(Addr))preinit_shim_init_sbr_plugin;

  new_dyn_entries[0].d_un.d_val =
      (ElfW(Addr))new_preinit_array - main_map->l_addr;

  // We need to make sure we won't call this again as there are cases were libc
  // might call _dl_init multiple times. e.g. when loading libnss.
  sbr_preinit_done = true;

  // Interesting Trivia: glibc initializes the pthread library first with a
  // dirty hack as shown here:
  // https://code.woboq.org/userspace/glibc/elf/dl-init.c.html#84.
  // DF_1_INITFIRST is a specialized flag available only to libpthread as
  // suggested here:
  // https://stackoverflow.com/questions/53001746/in-what-order-are-shared-libraries-initialized-and-finalized#comment92968938_53005162

  return real_dl_init(main_map, ac, av, e);
}

static void_void_fn premain_icept_callback(void_void_fn r_dl_init) {
  real_dl_init = (_dl_init_fn)r_dl_init;
  return (void_void_fn)sbr_dl_init;
}

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
static clock_gettime_fn real_clock_gettime;

int sabre_clock_gettime(clockid_t clockid, struct timespec *tp) {
  if (is_vdso_ready())
    return real_clock_gettime(clockid, tp);
  return syscall(SYS_clock_gettime, clockid, tp);
}

static void_void_fn vdso_guard_icept_callback(void_void_fn r_clock_gettime) {
  real_clock_gettime = (clock_gettime_fn)r_clock_gettime;
  return (void_void_fn)sabre_clock_gettime;
}

void setup_sbr_premain(sbr_icept_reg_fn fn_icept_reg) {
  sbr_fn_icept_struct premain = {.lib_name = "ld",
                                 .fn_name = "_dl_init",
                                 .icept_callback = premain_icept_callback};
  fn_icept_reg(&premain);
  sbr_fn_icept_struct vdso_guard = {.lib_name = "libc",
                                    .fn_name = "__clock_gettime",
                                    .icept_callback =
                                        vdso_guard_icept_callback};
  fn_icept_reg(&vdso_guard);
}
