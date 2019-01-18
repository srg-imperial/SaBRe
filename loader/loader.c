#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <dlfcn.h>

#include "compiler.h"
#include "macros.h"
#include "elf_loading.h"
#include "library.h"
#include "vx_api_defs.h"
#include "global_vars.h"
#include "handle_syscall.h"

#define MAX_BUF_SIZE PATH_MAX + 1024

typedef uintptr_t __attribute__((may_alias)) stack_val_t;

// Global variables
vx_fn_icept_local_struct intercept_records[MAX_ICEPT_RECORDS];
int registered_icept_cnt = 0;
vx_sc_handler_fn sc_handler = NULL;
vx_icept_vdso_callback_fn vdso_callback = NULL;
#ifdef __NX_INTERCEPT_RDTSC
vx_rdtsc_handler_fn rdtsc_handler;
#endif

void *get_syscall_return_address (struct syscall_stackframe* stack_frame) {
  return stack_frame->ret;
}

void register_function_intercepts(const vx_fn_icept_struct *r_struct)
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

// Returns the address of entry point and also populates a pointer
// for the top of the new stack
void load(int argc, char *argv[], void **new_entry, void **new_stack_top)
{
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
  void *plugin_handle = dlopen(argv[1], RTLD_NOW);
  if (!plugin_handle)
    _nx_fatal_printf("Unable to open plugin: %s\n", dlerror());

  dlerror();    /* Clear any existing error */

  vx_init_fn plugin_init = dlsym(plugin_handle, "vx_init");
  if (!plugin_init) {
    char *error = dlerror();
    if (error)
      _nx_fatal_printf("%s\n", error);
    else
      dprintf(2, "WARNING: plugin_init seems to be NULL. It is required by the API.\n");
  }

  // Drop irrelevant args before passing them to the init
  --argc;
  ++argv;

  char ** const argv_plugin = argv;
  vx_post_load_fn post_load = NULL;
  plugin_init(&argc,
              &argv,
              &register_function_intercepts,
              &vdso_callback,
              &sc_handler,
#ifdef __NX_INTERCEPT_RDTSC
              &rdtsc_handler,
#endif
              &post_load);

  if (argv == argv_plugin)
    _nx_fatal_printf("argv[0] must point to the client ELF path.\n");

  if (!sc_handler)
    _nx_fatal_printf("No syscall handler provided by plugin.\n");

  // Mask out loader and plugin
  binrw_rd_init_maps();

  int elf_fd = open(argv[0], O_RDONLY);
  if (elf_fd < 0)
    _nx_fatal_printf("Cannot open ELF file %s\n", argv[0]);

  ElfW(Ehdr) ehdr;
  if (elfld_getehdr(elf_fd, &ehdr) != 0)
    _nx_fatal_printf("Failed to get ELF header from %s\n", argv[0]);

  /* Load the program and point the auxv elements at its phdrs and entry.  */
  const char *interp = NULL;
  ElfW(Addr) load_bias;
  av_entry->a_un.a_val = elfld_load_elf(elf_fd,
                                        &ehdr,
                                        pagesize,
                                        &av_phdr->a_un.a_val,
                                        &av_phnum->a_un.a_val,
                                        &load_bias,
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

    entry = elfld_load_elf(elf_fd, &ehdr, pagesize, NULL, NULL, NULL, NULL);
    close(elf_fd);

    const char *libs[] = {"ld", NULL};
    memorymaps_rewrite_all(libs, argv[0], true);
  }

  else
  {
    entry = av_entry->a_un.a_val;

    // No dynamic libraries, rewrite the libraries know to have syscalls
    // The binary itself probably has syscalls too, re-write it
    const char *libs[] = {"ld", "libc", "librt", "libpthread", "libresolv", NULL};
    memorymaps_rewrite_all(libs, argv[0], false);
  }

  if (post_load != NULL)
    post_load(interp);

  // Modify the original process stack to represent arguments modified
  // by the plugin.
  
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

  *new_entry = (void *)entry;
}

