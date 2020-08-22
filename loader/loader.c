/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <malloc.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arch/handle_syscall.h"
#include "arch/rewriter_tools.h"
#include "compiler.h"
#include "elf_loading.h"
#include "global_vars.h"
#include "ld_sc_handler.h"
#include "macros.h"
#include "patchelf.h"
#include "plugins/sbr_api_defs.h"
#include "premain.h"
#ifdef __NX_INTERCEPT_RDTSC
#include "arch/handle_rdtsc.h"
#endif
#include "arch/syscall_stackframe.h"

#define MAX_BUF_SIZE PATH_MAX + 1024

typedef uintptr_t __attribute__((may_alias)) stack_val_t;

// Global variables
int plugin_argc = 0;
char **plugin_argv = NULL;
char abs_plugin_path[PATH_MAX];
sbr_fn_icept_local_struct intercept_records[MAX_ICEPT_RECORDS];
int registered_icept_cnt = 0;
sbr_sc_handler_fn plugin_sc_handler = NULL;
sbr_icept_vdso_callback_fn vdso_callback = ld_vdso_callback;
#ifdef __NX_INTERCEPT_RDTSC
sbr_rdtsc_handler_fn plugin_rdtsc_handler;
#endif
calling_from_plugin_fn calling_from_plugin = NULL;
enter_plugin_fn enter_plugin = NULL;
exit_plugin_fn exit_plugin = NULL;
is_vdso_ready_fn is_vdso_ready = NULL;

void register_function_intercepts(const sbr_fn_icept_struct *r_struct)
{
  assert(strlen(r_struct->lib_name) < MAX_ICEPT_STRLEN);
  assert(strlen(r_struct->fn_name) < MAX_ICEPT_STRLEN);

  strcpy(intercept_records[registered_icept_cnt].lib_name,
         r_struct->lib_name);
  strcpy(intercept_records[registered_icept_cnt].fn_name,
         r_struct->fn_name);
  intercept_records[registered_icept_cnt].callback = r_struct->icept_callback;

  ++registered_icept_cnt;
}
void *find_auxv(void *argv) {
  char **search_ptr;

  for (search_ptr = (char **)argv; *search_ptr; ++search_ptr)
    ;

  for (++search_ptr; *search_ptr; ++search_ptr)
    ;

  return (void *)(search_ptr + 1);
}

#ifdef __x86_64__
static void sigill_handler (int sig __unused, siginfo_t* info, void* ucontext) {
  assert(sig == SIGILL);
  ucontext_t* ctx = ucontext;
  uint16_t faulting_insn = *(uint16_t*) info->si_addr;
  // WARNING endianness
  if (faulting_insn == 0xFF0F) { // syscall
    // call syscall handler with proper arguments
    greg_t* regs = ctx->uc_mcontext.gregs;
    uintptr_t ret_addr = regs[REG_RIP] + 2;
    // simulate a syscall stack frame, as would be built by handle_syscall
    void *wrapper_sp = (void *)((intptr_t)&ret_addr - get_offsetof_syscall_return_address());
    regs[REG_RAX] = plugin_sc_handler(regs[REG_RAX], regs[REG_RDI], regs[REG_RSI], regs[REG_RDX],
               regs[REG_R10], regs[REG_R8], regs[REG_R9], wrapper_sp);
#ifdef __NX_INTERCEPT_RDTSC
  } else if (faulting_insn == 0x0B0F) { // RDTSC
    plugin_rdtsc_handler();
#endif
  } else {
    // not from SaBRe, so use default handler
    const struct sigaction dfl_sa = {.sa_handler = SIG_DFL};
    sigaction(SIGILL, &dfl_sa, NULL);
    raise(SIGILL);

    // wait for SIGILL to be delivered
    sigset_t consume_mask;
    sigfillset(&consume_mask);
    sigdelset(&consume_mask, SIGILL);
    sigsuspend(&consume_mask);
  }

  // Skip UD insn to point to return address
  ctx->uc_mcontext.gregs[REG_RIP] += 2;
}
#elif defined __riscv
static void sigill_handler (int sig __unused, siginfo_t* info, void* ucontext) {
  assert(sig == SIGILL);
  ucontext_t* ctx = ucontext;
  uint32_t faulting_insn = *(uint32_t*) info->si_addr;

  if (faulting_insn == 0) { // syscall
    // call syscall handler with proper arguments
    greg_t* regs = ctx->uc_mcontext.__gregs;
    uintptr_t ret_addr = regs[REG_PC] + 4;
    // simulate a syscall stack frame, as would be built by handle_syscall
    void *wrapper_sp = (void *)((intptr_t)&ret_addr - get_offsetof_syscall_return_address());
    regs[REG_A0] = plugin_sc_handler(regs[REG_A0+7], regs[REG_A0], regs[REG_A0+1], regs[REG_A0+2],
               regs[REG_A0+3], regs[REG_A0+4], regs[REG_A0+5], wrapper_sp);
  } else {
    // not from SaBRe, so use default handler
    const struct sigaction dfl_sa = {.sa_handler = SIG_DFL};
    sigaction(SIGILL, &dfl_sa, NULL);
    raise(SIGILL);

    // wait for SIGILL to be delivered
    sigset_t consume_mask;
    sigfillset(&consume_mask);
    sigdelset(&consume_mask, SIGILL);
    sigsuspend(&consume_mask);
  }

  // Skip illegal insn to point to return address
  ctx->uc_mcontext.__gregs[REG_PC] += 4;
}
#endif // __x86_64__ / __riscv

static void print_usage (void)
{
  static const char *usage =
      "Usage:\n"
      "\tSaBRe <PLUGIN> [<PLUGIN_OPTIONS>] -- <CLIENT> [<CLIENT_OPTIONS>]\n"
      "<PLUGIN> is the full path to the desired plugin library\n"
      "<CLIENT> is the full path to the client binary to be run under SaBRe\n"
      "<PLUGIN_OPTIONS> and <CLIENT_OPTIONS> depend on the plugin and the "
      "client\n";
  puts(usage);
}

static size_t find_client_path_idx(char **argv) {
  for (size_t i = 0; argv[i] != NULL; i++) {
    if (strlen(argv[i]) == 2 && strncmp(argv[i], "--", 2) == 0)
      return ++i;
  }
  errx(EXIT_FAILURE, "Missing -- from CLI. Please check --help.");
}

static void copy_fresh_client_elf(const char *source_path,
                                  const char *target_path) {
  FILE *source, *target;

  source = fopen(source_path, "rb");
  if (source == NULL)
    errx(EXIT_FAILURE, "fopen: Couldn't find: %s.", source_path);
  target = fopen(target_path, "wb");
  assert(target != NULL);

  size_t n, m;
  unsigned char buff[8192];
  do {
    n = fread(buff, 1, sizeof buff, source);
    if (n != 0)
      m = fwrite(buff, 1, n, target);
    else
      m = 0;
  } while ((n > 0) && (n == m));
  assert(m == 0);

  assert(fclose(target) == 0);
  assert(fclose(source) == 0);

  chmod(target_path, S_IRWXU | S_IRWXG);
}

// Returns the address of entry point and also populates a pointer
// for the top of the new stack
void load(int argc, char *argv[], void **new_entry, void **new_stack_top)
{
  if (argc < 4) {
    print_usage();
    exit(EXIT_FAILURE);
  }

  // There 2 mallocs in memory because SaBRe loads 2 libcs (one for SaBRe) and
  // one for the client (which is intercepted). These two mallocs will overlap
  // their arenas as malloc uses brk(NULL) to initialize its arena, and this
  // brk(NULL) will always return the same pointer. To avoid this we force
  // SaBRe's malloc to completely skip the arena initialization and keep objects
  // into separate mmap() pages. This of course comes with a small performance
  // decrease, and the potential to OOM if we allocate too many items.
  int ret = mallopt(M_MMAP_THRESHOLD, 0);
  assert(ret == 1);

  stack_val_t *argv_null = (stack_val_t *)&argv[argc];

  // Sort out the auxiliary vector stuff
  ElfW(auxv_t) *auxv = find_auxv(argv);
  ElfW(auxv_t) *av_entry = NULL;
  ElfW(auxv_t) *av_phdr = NULL;
  ElfW(auxv_t) *av_phnum = NULL;
  size_t pagesize = 0;

  ElfW(auxv_t) *av;
  for (av = auxv;
       av_entry == NULL || av_phdr == NULL || av_phnum == NULL || pagesize == 0;
       ++av) {
    switch (av->a_type) {
      case AT_NULL:
        _nx_fatal_printf("Failed to find AT_ENTRY, AT_PHDR, AT_PHNUM, or AT_PAGESZ!");
        /*NOTREACHED*/
      case AT_ENTRY:
        av_entry = av;
        break;
      case AT_PAGESZ:
        pagesize = av->a_un.a_val;
        break;
      case AT_PHDR:
        av_phdr = av;
        break;
      case AT_PHNUM:
        av_phnum = av;
        break;
    }
  }

  // Load the plugin
  // void *plugin_handle = dlopen(argv[1], RTLD_NOW);
  // if (!plugin_handle)
  //   _nx_fatal_printf("Unable to open plugin: %s\n", dlerror());

  // dlerror();    /* Clear any existing error */

  // sbr_init_fn plugin_init = dlsym(plugin_handle, "sbr_init");
  // if (!plugin_init) {
  //   char *error = dlerror();
  //   if (error)
  //     _nx_fatal_printf("%s\n", error);
  //   else
  //     dprintf(2, "WARNING: plugin_init seems to be NULL. It is required by
  //     the API.\n");
  // }

  // Drop irrelevant args before passing them to the init
  --argc;
  ++argv;

  //   char ** const argv_plugin = argv;
  //   sbr_post_load_fn post_load = NULL;
  //   plugin_init(&argc,
  //               &argv,
  //               &register_function_intercepts,
  //               &vdso_callback,
  //               &plugin_sc_handler,
  // #ifdef __NX_INTERCEPT_RDTSC
  //               &plugin_rdtsc_handler,
  // #endif
  //               &post_load);

  //   if (argv == argv_plugin)
  //     _nx_fatal_printf("argv[0] must point to the client ELF path.\n");

  //   if (!plugin_sc_handler)
  //     _nx_fatal_printf("No syscall handler provided by plugin.\n");

  // #ifdef __NX_INTERCEPT_RDTSC
  //   if (!plugin_rdtsc_handler)
  //     _nx_fatal_printf("No RDTSC handler provided by plugin.\n");
  // #endif

  // Get the absolute path of the plugin so we can add it as DT_NEEDED
  // dependency in the client's elf file.
  realpath(argv[0], abs_plugin_path);

  // Find client's path. It should be right after `--`.
  size_t client_path_idx = find_client_path_idx(argv);

  // Create the new client elf file with the rewritten elf headers in a unique
  // path.
  pid_t pid = getpid();
  char pid_s[10];
  sprintf(pid_s, "%d", pid);

  char new_client_elf_path[30] = {0};
  strcpy(new_client_elf_path, "/tmp/sbr_client.");
  strcat(new_client_elf_path, pid_s);

  // Check if the file already exists and delete it.
  if (access(new_client_elf_path, F_OK) != -1) {
    if (remove(new_client_elf_path) != 0)
      errx(EXIT_FAILURE, "Failed to remove file %s.", new_client_elf_path);
  }

  copy_fresh_client_elf(argv[client_path_idx], new_client_elf_path);
  inject_needed_lib(abs_plugin_path, new_client_elf_path, false);

  setup_sbr_premain(&register_function_intercepts);

  // Switch the client's binary path in the stack.
  // argv[client_path_idx] = new_client_elf_path;

  // Separate client and plugin arguments.
  plugin_argc = client_path_idx - 1;
  argv[plugin_argc] = NULL;
  plugin_argv = (char **)malloc(sizeof(char *) * (plugin_argc + 1));
  memcpy(plugin_argv, argv, sizeof(char *) * (plugin_argc + 1));

  // Skip plugin arguments
  argv += client_path_idx;
  argc -= client_path_idx;

  // Mask out loader and plugin
  binrw_rd_init_maps();

  int elf_fd = open(new_client_elf_path, O_RDONLY);
  if (elf_fd < 0)
    _nx_fatal_printf("Cannot open ELF file %s\n", new_client_elf_path);

  ElfW(Ehdr) ehdr;
  if (elfld_getehdr(elf_fd, &ehdr) != 0)
    _nx_fatal_printf("Failed to get ELF header from %s\n", new_client_elf_path);

  /* Load the program and point the auxv elements at its phdrs and entry.  */
  const char *interp = NULL;
  av_entry->a_un.a_val = elfld_load_elf(elf_fd,
                                        &ehdr,
                                        pagesize,
                                        &av_phdr->a_un.a_val,
                                        &av_phnum->a_un.a_val,
                                        &interp);

  close(elf_fd);

  ElfW(Addr) entry;
  if (interp)
  {
    // There was a PT_INTERP, so we have a dynamic linker to load.

    int elf_fd = open(interp, O_RDONLY, 0);
    if (elf_fd < 0)
      _nx_fatal_printf("Cannot open ELF file %s\n", interp);

    if (elfld_getehdr(elf_fd, &ehdr) != 0)
      _nx_fatal_printf("Failed to get ELF header from file\n");

    entry = elfld_load_elf(elf_fd, &ehdr, pagesize, NULL, NULL, NULL);
    close(elf_fd);

    const char *libs[] = {"ld", NULL};
    memorymaps_rewrite_all(libs, new_client_elf_path, true);
  }

  else
  {
    // TODO(andronat): We don't support statically linked binaries for now.
    assert(false);
    entry = av_entry->a_un.a_val;

    // No dynamic libraries, rewrite the libraries know to have syscalls
    // The binary itself probably has syscalls too, re-write it
    const char *libs[] = {"ld", "libc", "librt", "libpthread", "libresolv", NULL};
    memorymaps_rewrite_all(libs, new_client_elf_path, false);
  }

  // if (post_load != NULL)
  //   post_load(interp);

  // Set up SIGILL handler for dealing with RDTSC instructions and system calls
  // that have been rewritten to use UD
  struct sigaction sa_ill = {.sa_sigaction = sigill_handler, .sa_flags = SA_SIGINFO | SA_NODEFER};
  sigaction(SIGILL, &sa_ill, NULL);

  // Modify the original process stack to represent arguments modified
  // by the plugin.

  _nx_debug_printf("start rewriting stack\n");
  stack_val_t *src = (stack_val_t *)&argv[0];
  stack_val_t *dst = argv_null - argc;

  // Check alignment on 16-byte boundary
  if (((uintptr_t)(dst-1) & 0xF) != 0) {
    // Move everything down 8 bytes
    dst--;

    // We need to move the whole initial stack frame to restore proper alignment
    ElfW(auxv_t) *auxv_null = av;
    while (auxv_null->a_type != AT_NULL)
      ++auxv_null;
    size_t size = (uintptr_t)auxv_null - (uintptr_t)argv_null + sizeof *auxv_null;
    memmove(argv_null, argv_null+1, size);
  }

  size_t size = sizeof(stack_val_t) * argc;
  memmove(dst, src, size);
  dst[argc] = 0; // restore argv_null that might have been overwritten by alignment
  *new_stack_top = dst - 1;
  *((stack_val_t *)*new_stack_top) = argc;
  _nx_debug_printf("done rewriting stack\n");

  *new_entry = (void *)entry;
}
