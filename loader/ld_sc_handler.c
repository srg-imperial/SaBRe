#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "compiler.h"
#include "global_vars.h"
#include "macros.h"
#include "arch/rewriter.h"

// TODO: This code needs refactoring. Split open and mmap syscalls. Find a more
// elegant way for interesting_libs and the other static variables
// THIS IS RACING IN CASE WE HAVE MULTIPLE THREADS OPEN-MMAP LIBS
// WRITE A UNIT TEST
#define NO_FD -1
static int interesting_fd  = NO_FD;
static int interesting_lib = NO_FD;

// Libraries known to have syscalls
// ld is not here because it is processed elsewhere (loader.c)
const char *known_syscall_libs[] __hidden = {
    "libc",
    "librt",
    "libpthread",
    "libresolv",
    NULL
};

#define SBR_SEGMENTS 4
static uintptr_t start_sbr [SBR_SEGMENTS], end_sbr [SBR_SEGMENTS];

static void hide_sbr_maps(int from_fd, int to_fd) {
  // TODO This code is extracted from maps.c, function maps_read
  //      Refactor that function to be generic instead of copying the code here

  // Go over each line of /proc/self/maps and consider each mapped region one
  // at a time, looking for a gap between regions to allocate.
  char buf[1024] = {'\0'};
  char *from = buf, *to = buf, *next = buf;
  char *bufend = buf + sizeof(buf) - 1;

  int sbr_segment = 0;

  do {
    from = next; /* advance to the start of the next line */
    next = (char *)memchr(
        from, '\n', to - from); /* check if we have another line */
    if (!next) {
      /* shift/fill the buffer */
      size_t len = to - from;
      /* move the current text to the start of the buffer */
      memmove(buf, from, len);
      from = buf;
      to = buf + len;
      /* fill up buffer with text */
      size_t nread = 0;
      while (to < bufend) {
        nread = read(from_fd, to, bufend - to);
        if (nread > 0)
          to += nread;
        else
          break;
      }
      if (to != bufend && !nread)
        memset(to, 0, bufend - to); /* zero-out remaining space */
      *to = '\n';                   /* sentinel */
      next = (char *)memchr(from, '\n', to + 1 - from);
    }
    *next = 0;                 /* turn newline into 0 */
    next += next < to ? 1 : 0; /* skip NULL if not end of text */

    uintptr_t gap_end, map_end;
    int name;

    // Parse each line of /proc/<pid>/maps file.
    if (sscanf(from,
               "%" SCNxPTR "-%" SCNxPTR " %*4s %*d %*x:%*x %*d %n",
               &gap_end,
               &map_end,
               &name) > 1) {
      char *pathname = from + name;
      int len = strlen(pathname);
      if (strcmp(pathname+len-2, "vx")) {
        if (to_fd) {
          if (write(to_fd, from, strlen(from)) == -1) {
            _nx_fatal_printf("write maps failed\n");
          }
          if (write(to_fd, "\n", 1) == -1) {
            _nx_fatal_printf("write maps failed\n");
          }
        }
      } else { // SaBRe segment found
    assert(sbr_segment < SBR_SEGMENTS);
    start_sbr[sbr_segment] = gap_end;
    end_sbr[sbr_segment] = map_end;
    sbr_segment++;
      }
    }
  } while (to > buf);
}

static long process_fd(long fd, const char * pathname, int flags, mode_t mode) {
  if (fd < 0)
    return (long) fd;

  // Q: Why not just copy pathname and pass it to memorymaps_rewrite_lib()?
  // A: Linux uses links for some libraries and the user might give
  // a pathname = /lib/x86_64-linux-gnu/libc.so.6 and the ld will load
  // a /lib/x86_64-linux-gnu/libc-2.26.so. Thus we need to stem the
  // library names anyway.

  int l = which_lib_name_interesting(known_syscall_libs, pathname);
  if (l >= 0) {
    if (interesting_fd == NO_FD && interesting_lib == NO_FD) {
      interesting_fd = fd;
      interesting_lib = l;
    } else
      _nx_fatal_printf("ld opened two binaries without mmaping\n");
  }

  _nx_debug_printf("open: exit loader syscall (%lu)\n", (long) fd);

  // TODO: TSan scans /proc/self/maps and quits if it finds anything not listed
  //       on the ELF headers.  This hack works by hiding SaBRe from
  //       /proc/self/maps, but we could trick TSan by adding SaBRe to the ELF
  //       headers as a dynamic library
  if (!strcmp("/proc/self/maps", pathname)) {
    // Hide SaBRe from TSan

    // Create dummy file
    char buf[] = "/tmp/sbrXXXXXX";
    int to = mkstemp(buf);

    // Copy '/proc/self/maps' to dummy except for SaBRe entries
    hide_sbr_maps(fd, to);

    // Close all files
    close(fd);
    close(to);

    // Reopen dummy file and delete it
    to = open(buf, flags, mode);
    unlink(buf);

    // When this fd goes away, file gets deleted
    return to;
  }

  return (long) fd;
}


struct mem_chunk {
  uintptr_t start;
  uintptr_t end;
};

static int intercept_sbr (struct mem_chunk mmaps []) {
  int c = 0;
  uintptr_t start_mmap = mmaps[c].start;
  uintptr_t end_mmap = mmaps[c].end;

  for (int seg = 0; seg < SBR_SEGMENTS; seg++) {
    bool before_sbr = end_mmap <= start_sbr[seg];
    bool after_sbr = start_mmap >= end_sbr[seg];

    if (!(before_sbr || after_sbr)) {
      if (mmaps[c].start > start_sbr[seg])
        mmaps[c].start = end_sbr[seg];
      else if (mmaps[c].end < end_sbr[seg])
        mmaps[c].end = start_sbr[seg];
      else {
        mmaps[c++].end = start_sbr[seg];
        assert(c < SBR_SEGMENTS + 1);
        mmaps[c].start = end_sbr[seg];
        mmaps[c].end = end_mmap;
      }
    }
  }

  return c;
}

static unsigned long loader_tls_addr;
static unsigned long client_tls_addr;

// %fs holds the TLS start address, so ARCH_SET_FS must be handled specially
long arch_set_fs_handler (unsigned long addr) {
  if (loader_tls_addr == 0) {
    assert(client_tls_addr == 0);

    // Save SaBRe TLS
    if (syscall(__NR_arch_prctl, ARCH_GET_FS, &loader_tls_addr) == -1)
      _nx_fatal_printf("Failed to get loader TLS address\n");
    client_tls_addr = addr;

    // Copy SaBRe stack guard value to the client TLS
    const size_t stack_guard_tls_offset = 0x28; // see glibc-2.27/sysdeps/x86_64/nptl/tls.h
    uintptr_t loader_stack_guard_value = *(uintptr_t *)(loader_tls_addr + stack_guard_tls_offset);
    *(uintptr_t *)(client_tls_addr + stack_guard_tls_offset) = loader_stack_guard_value;
  }
  else
    _nx_fatal_printf("ARCH_SET_FS called more than once from client\n");

  return plugin_sc_handler(__NR_arch_prctl, ARCH_SET_FS, addr, 0, 0, 0, 0, NULL);
}

long ld_sc_handler(long sc_no,
                   long arg1,
                   long arg2,
                   long arg3,
                   long arg4,
                   long arg5,
                   long arg6,
                   void *wrapper_sp)
{
  if (loader_tls_addr != 0) {
    if (syscall(__NR_arch_prctl, ARCH_SET_FS, loader_tls_addr) == -1)
      _nx_fatal_printf("Failed to switch to loader TLS\n");
  }

  long ret;
  switch (sc_no)
  {
    case __NR_open:
    {
      const char *pathname = (const char *)arg1;
      int flags = arg2;
      mode_t mode = arg3;

      _nx_debug_printf("open: enter loader syscall\n");

      long fd = plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6, wrapper_sp);

      ret = process_fd(fd, pathname, flags, mode);
      break;
    }

    // Since glibc 2.26, the glibc wrapper function for open()  employs  the
    // openat() system call, rather than the kernel's open() system call.
    case __NR_openat:
    {
      //int dirfd = arg1;
      const char *pathname = (const char *)arg2;
      int flags = arg3;
      mode_t mode = arg4;

      _nx_debug_printf("openat: enter loader syscall\n");

      long fd = plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6, wrapper_sp);

      ret = process_fd(fd, pathname, flags, mode);
      break;
    }

    case __NR_mmap:
    {
      void *addr = (void *)arg1;
      size_t length = arg2;
      int prot = arg3;
      int flags = arg4;
      int fd = arg5;
      off_t offset = arg6;

      _nx_debug_printf("mmap: enter loader syscall (%u)\n", fd);

      // Populate start_sbr and end_sbr
      if (start_sbr[0] == 0 || end_sbr[0] == 0) {
        int fd = open("/proc/self/maps", O_RDONLY, 0);
        hide_sbr_maps(fd, 0);
        close(fd);
      }

      void * mmap_addr = NULL;

      if (flags & MAP_FIXED) {
        uintptr_t start_mmap = (uintptr_t) addr;
        uintptr_t end_mmap = start_mmap + length;

        struct mem_chunk mmaps [SBR_SEGMENTS + 1] = {[0] = {.start = start_mmap, .end = end_mmap}};
        int nb_chunks = intercept_sbr(mmaps);

        int c = 0;
        mmap_addr = (void *)plugin_sc_handler(sc_no, mmaps[c].start, (mmaps[c].end - mmaps[c].start), prot, flags, fd, offset, wrapper_sp);

        for (c = 1; c < nb_chunks; c++) {
          plugin_sc_handler(sc_no, mmaps[c].start, (mmaps[c].end - mmaps[c].start), prot, flags, fd, offset, wrapper_sp);
        }
      } else {
        mmap_addr = (void *)plugin_sc_handler(sc_no, (long)addr, length, prot, flags, fd, offset, wrapper_sp);
      }

      if (fd > 0 && fd == interesting_fd && (prot & PROT_EXEC)) {
        // TODO(andronat): It would be much more efficient to directly work on
        // memory addresses but it is also much harder.
        memorymaps_rewrite_lib(known_syscall_libs[interesting_lib]);
        interesting_fd  = NO_FD;
        interesting_lib = NO_FD;
      }

      _nx_debug_printf("mmap: exit loader syscall (%lu)\n", (long) mmap_addr);

      ret =  (long) mmap_addr;
      break;
    }
    case __NR_arch_prctl:
    {
      int code = arg1;
      unsigned long addr = arg2;
      if (code == ARCH_SET_FS)
        return arch_set_fs_handler(addr);
      else
        return plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6, wrapper_sp);
    }

    default:
      ret = plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6, wrapper_sp);
  }

  if (client_tls_addr != 0) {
    if (syscall(__NR_arch_prctl, ARCH_SET_FS, client_tls_addr) == -1)
      _nx_fatal_printf("Failed to switch to client TLS\n");
  }

  return ret;
}
