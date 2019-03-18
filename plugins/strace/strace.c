#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define __USE_GNU
#include <fcntl.h>
#include <sys/mman.h>
#undef __USE_GNU

#include "sbr_api.h"
#include "real_syscall.h"
#include "sysent.h"

enum vdso_flags {
  VDSO_STRACE,
  VDSO_SYSCALL,
  VDSO_SPECIAL
};

// Global state - not the nicest, but this is a tiny application
static bool raw_out = false;
static enum vdso_flags vdso_arg_flag = VDSO_SYSCALL;
static FILE *out_stream = NULL;

static const struct_sysent sysent[] = {
#include "syscallent.h"
};

#define RAW_ARG raw
#define OUT_ARG output
#define VDSO_ARG handle-vdso
#define ARG_PATTERN2(s) "--" #s "="
#define ARG_PATTERN(s) ARG_PATTERN2(s)
#define ARG_PATTERN_NO_PARAM2(s) "--" #s
#define ARG_PATTERN_NO_PARAM(s) ARG_PATTERN_NO_PARAM2(s)

static void print_help(void) {
  fputs("Arguments passed to the sbr_strace "
        "shared object should follow the following syntax:\n",
        out_stream);
  fputs("[SBR_STRACE_ARGS] -- EXE_PATH [EXE_ARGS]\n", out_stream);
  fputs("SBR_STRACE_ARGS:\n", out_stream);
  fputs(ARG_PATTERN(OUT_ARG) "stream|filename - redirect output to either "
        "stream or file; default value is stderr\n",
        out_stream);
  fputs(ARG_PATTERN(VDSO_ARG) "strace|syscall|special - how to handle vDSO calls; default value is syscall\n",
        out_stream);
}

// We don't want to use ctype since it accesses TLS,
// which messes with %fs and causes segfault
static bool my_isprint(char ch) { return ((ch >= ' ') && (ch <= '~')); }

static void print_prot(long flags, FILE *stream) {
  if (!flags)
    fputs("PROT_NONE", stream);

  else {
    bool first_flag = true;

    if (flags & PROT_EXEC) {
      fputs("PROT_EXEC", stream);
      first_flag = false;
    }

    if (flags & PROT_READ) {
      if (!first_flag)
        fputc('|', stream);
      else
        first_flag = false;
      fputs("PROT_READ", stream);
    }

    if (flags & PROT_WRITE) {
      if (!first_flag)
        fputc('|', stream);
      else
        first_flag = false;
      fputs("PROT_WRITE", stream);
    }
  }
}

static void print_mmap_flags(long flags, FILE *stream) {
  if (flags & MAP_SHARED)
    fputs("MAP_SHARED", stream);
  else
    fputs("MAP_PRIVATE", stream);

  if (flags & MAP_32BIT)
    fputs("|MAP_32BIT", stream);

  if (flags & MAP_ANONYMOUS)
    fputs("|MAP_ANONYMOUS", stream);

  if (flags & MAP_DENYWRITE)
    fputs("|MAP_DENYWRITE", stream);

  if (flags & MAP_EXECUTABLE)
    fputs("|MAP_EXECUTABLE", stream);

  if (flags & MAP_FILE)
    fputs("|MAP_FILE", stream);

  if (flags & MAP_FIXED)
    fputs("|MAP_FIXED", stream);

  if (flags & MAP_GROWSDOWN)
    fputs("|MAP_GROWSDOWN", stream);

  if (flags & MAP_HUGETLB)
    fputs("|MAP_HUGETLB", stream);

  if (flags & MAP_LOCKED)
    fputs("|MAP_LOCKED", stream);

  if (flags & MAP_NONBLOCK)
    fputs("|MAP_NONBLOCK", stream);

  if (flags & MAP_NORESERVE)
    fputs("|MAP_NORESERVE", stream);

  if (flags & MAP_POPULATE)
    fputs("|MAP_POPULATE", stream);

  if (flags & MAP_STACK)
    fputs("|MAP_STACK", stream);

  // if (flags & MAP_UNINITIALIZED)
  //    fputs("|MAP_UNINITIALIZED", stream);
}

static bool print_open_flags(long flags, FILE *stream) {
  bool res = false;

  if (flags & O_RDWR)
    fputs("O_RDWR", stream);

  else if (flags & O_WRONLY)
    fputs("O_WRONLY", stream);

  else
    fputs("O_RDONLY", stream);

  // Creation and file status flags
  if (flags & O_APPEND)
    fputs("|O_APPEND", stream);

  if (flags & O_ASYNC)
    fputs("|O_ASYNC", stream);

  if (flags & O_CLOEXEC)
    fputs("|O_CLOEXEC", stream);

  if (flags & O_CREAT) {
    fputs("|O_CREAT", stream);
    res = true;
  }

  if (flags & O_DIRECT)
    fputs("|O_DIRECT", stream);

  if (flags & O_DIRECTORY)
    fputs("|O_DIRECTORY", stream);

  if (flags & O_DSYNC)
    fputs("|O_DSYNC", stream);

  if (flags & O_EXCL)
    fputs("|O_EXCL", stream);

  if (flags & O_NOATIME)
    fputs("|O_NOATIME", stream);

  if (flags & O_NOCTTY)
    fputs("|O_NOCTTY", stream);

  if (flags & O_NOFOLLOW)
    fputs("|O_NOFOLLOW", stream);

  if (flags & O_NONBLOCK)
    fputs("|O_NONBLOCK", stream);

  if (flags & O_PATH)
    fputs("|O_PATH", stream);

  if (flags & O_SYNC)
    fputs("|O_SYNC", stream);

  if (flags & O_TMPFILE) {
    fputs("|O_TMPFILE", stream);
    res = true;
  }

  if (flags & O_TRUNC)
    fputs("|O_TRUNC", stream);

  return res;
}

static void print_nonprintable(char ch, FILE *stream) {
  switch (ch) {
    case '\n':
      fputs("\\n", stream);
      break;
    case '\t':
      fputs("\\t", stream);
      break;
    default:
      fprintf(stream, "\\x%02X", ch);
      break;
  }
}

static void printstr(const char *str_ptr, long len, FILE *stream) {
  fputc('\"', stream);

  for (int i = 0; (len ? (i < len) : true) && str_ptr[i]; ++i) {
    if (my_isprint(str_ptr[i]))
      fputc(str_ptr[i], stream);
    else
      print_nonprintable(str_ptr[i], stream);
  }
  fputc('\"', stream);
}

static void pre_decode_args(long sc, const long args[], FILE *stream) {
  if (!raw_out) {
    switch (sc) {
      case SYS_mprotect:
        fprintf(stream, "0x%lX, 0x%lX, ", args[0], args[1]);
        print_prot(args[2], stream);
        break;

      case SYS_access:
        printstr((char *)args[0], 0, stream);
        fprintf(stream, ", %lX", args[1]);
        break;

      case SYS_mmap:
        for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
          if (!argno)
            fprintf(stream, "0x%lX", args[argno]);

          else if (argno == 2) {
            fputs(", ", stream);
            print_prot(args[2], stream);
          } else if (argno == 3) {
            fputs(", ", stream);
            print_mmap_flags(args[3], stream);
          } else
            fprintf(stream, ", 0x%lX", args[argno]);
        }
        break;

      case SYS_open:
        printstr((char *)args[0], 0, stream);
        fputs(", ", stream);
        if (print_open_flags(args[1], stream)) {
          fprintf(stream, ", %lo", args[2]);
        }
        break;

      case SYS_write:
        for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
          if (!argno)
            fprintf(stream, "0x%lX", args[argno]);

          else if (argno == 1) {
            fputs(", ", stream);
            printstr((char *)args[argno], args[argno + 1], stream);
          } else
            fprintf(stream, ", 0x%lX", args[argno]);
        }
        break;

      case SYS_read:
        fprintf(stream, "0x%lX", args[0]);
        break;

      default:
        for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
          if (!argno)
            fprintf(stream, "0x%lX", args[argno]);
          else
            fprintf(stream, ", 0x%lX", args[argno]);
        }
        break;
    }
  } else {
    for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
      if (!argno)
        fprintf(stream, "0x%lX", args[argno]);
      else
        fprintf(stream, ", 0x%lX", args[argno]);
    }
  }
}

static void post_decode_args(long sc,
                             const long args[],
                             FILE *stream,
                             long rtn) {
  (void)rtn;  // unused
  if (!raw_out) {
    switch (sc) {
      case SYS_read:
        for (int argno = 1; argno < sysent[sc].nargs; ++argno) {
          if (argno == 1) {
            fputs(", ", stream);
            printstr((char *)args[argno], args[argno + 1], stream);
          } else
            fprintf(stream, ", 0x%lX", args[argno]);
        }
        break;

      default:
        break;
    }
  }
}

long handle_syscall_real(long sc_no,
                         long arg1,
                         long arg2,
                         long arg3,
                         long arg4,
                         long arg5,
                         long arg6,
                         bool vdso) {
  long local_args[] = {arg1, arg2, arg3, arg4, arg5, arg6};
  long syscall_rtn;
  static bool outfd_close = false;

  if (vdso)
    fputs("(vDSO): ", out_stream);
  fprintf(out_stream, "%s(", sysent[sc_no].sys_name);

  // Special-case the exit syscalls
  if ((sc_no == SYS_exit) || (sc_no == SYS_exit_group)) {
    fprintf(out_stream, "%ld) = ?\n", arg1);
    fflush(out_stream);

    if (outfd_close)
      (void)real_syscall(
          SYS_close, (long)fileno(out_stream), arg2, arg3, arg4, arg5, arg6);

    // More sophisticated checks should be implemented at some point -
    // what if target app doesn't use output streams at all, and we
    // use stderr? But not closing a stream is not catastrophic.
    else if ((out_stream != stdout) && (out_stream != stderr))
      fclose(out_stream);

    return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  } else {
    pre_decode_args(sc_no, local_args, out_stream);

    // If the sandboxed app is closing our output FD
    if ((sc_no == SYS_close) && ((int)arg1 == fileno(out_stream))) {
      // A bit hacky - what if there was an error? We can't see in the future
      // though, so...
      syscall_rtn = 0;
      outfd_close = true;
    } else
      syscall_rtn = real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);

    post_decode_args(sc_no, local_args, out_stream, syscall_rtn);

    if (syscall_rtn > -1)
      fprintf(out_stream, ") = 0x%lX\n", syscall_rtn);
    else
      fprintf(out_stream, ") = %ld (error)\n", syscall_rtn);

    return syscall_rtn;
  }
}

long handle_syscall(long sc_no,
                    long arg1,
                    long arg2,
                    long arg3,
                    long arg4,
                    long arg5,
                    long arg6,
                    void *wrapper_sp) {
  (void)wrapper_sp;  // unused
  return handle_syscall_real(sc_no, arg1, arg2, arg3, arg4, arg5, arg6, false);
}

long handle_syscall_clock_gettime(long arg1, long arg2) {
  return handle_syscall_real(SYS_clock_gettime, arg1, arg2, 0, 0, 0, 0, true);
}

long handle_syscall_getcpu(long arg1, long arg2, long arg3) {
  return handle_syscall_real(SYS_getcpu, arg1, arg2, arg3, 0, 0, 0, true);
}

long handle_syscall_gettimeofday(long arg1, long arg2) {
  return handle_syscall_real(SYS_gettimeofday, arg1, arg2, 0, 0, 0, 0, true);
}

#ifdef __x86_64__
long handle_syscall_time(long arg1) {
  return handle_syscall_real(SYS_time, arg1, 0, 0, 0, 0, 0, true);
}
#endif // __x86_64__

void handle_args(int *argc, char **argv[]) {
  bool sep_found = false;

  while (**argv) {
    // Handle the output
    if (!strncmp(ARG_PATTERN(OUT_ARG), **argv, strlen(ARG_PATTERN(OUT_ARG)))) {
      char *out_file = (**argv + strlen(ARG_PATTERN(OUT_ARG)));

      if (!strcmp(out_file, "stdout"))
        out_stream = stdout;

      else if (!strcmp(out_file, "stderr"))
        out_stream = stderr;

      else {
        if (*out_file) {
          out_stream = fopen(out_file, "w");

          if (!out_stream) {
            fputs("Could not open file ", stderr);
            fputs(out_file, stderr);
            fputs(" for sbr_strace output.\n", stderr);

            exit(1);
          }
        } else {
          fputs("Output file is null.\n", stderr);
          exit(1);
        }
      }
    }

    // Handle the vdso arg
    if (!strncmp(ARG_PATTERN(VDSO_ARG), **argv,
                 strlen(ARG_PATTERN(VDSO_ARG)))) {
      char *string_selection = (**argv + strlen(ARG_PATTERN(VDSO_ARG)));

      if (!strcmp(string_selection, "strace"))
        vdso_arg_flag = VDSO_STRACE;

      else if (!strcmp(string_selection, "syscall"))
        vdso_arg_flag = VDSO_SYSCALL;

      else if (!strcmp(string_selection, "special"))
        vdso_arg_flag = VDSO_SPECIAL;

      else {
        fputs("Unsupported vDSO handling option: ", out_stream);
        fputs(string_selection, out_stream);
        fputc('\n', out_stream);
        exit(1);
      }
    }

    // Handle raw output
    if (!strcmp(ARG_PATTERN_NO_PARAM(RAW_ARG), **argv))
      raw_out = true;

    if ((strlen(**argv) == 2) && !strncmp("--", **argv, 3)) {
      sep_found = true;
    }

    --(*argc);
    ++(*argv);

    if (sep_found)
      break;
  }

  if (!sep_found) {
    fputs("Invalid arguments, missing \"--\" separator\n", out_stream);
    print_help();
    exit(1);
  }
}

void_void_fn vdso_callback_imp(long sc_no, void_void_fn actual_fn) {
  (void)actual_fn;  // unused
  switch (sc_no) {
    case SYS_clock_gettime:
      return (void_void_fn)handle_syscall_clock_gettime;
    case SYS_getcpu:
      return (void_void_fn)handle_syscall_getcpu;
    case SYS_gettimeofday:
      return (void_void_fn)handle_syscall_gettimeofday;
#ifdef __x86_64__
    case SYS_time:
      return (void_void_fn)handle_syscall_time;
#endif // __x86_64__
    default:
      return (void_void_fn)NULL;
  }
}

void_void_fn vdso_callback_none_imp(long sc_no, void_void_fn actual_fn) {
  (void)sc_no;  // unused
  return actual_fn;
}

void sbr_init(int *argc,
             char **argv[],
             sbr_icept_reg_fn fn_icept_reg,
             sbr_icept_vdso_callback_fn *vdso_callback,
             sbr_sc_handler_fn *syscall_handler,
             sbr_post_load_fn *post_load) {
  (void)fn_icept_reg;  // unused
  (void)post_load;     // unused

  // For error messages before handling the args
  out_stream = stderr;

  handle_args(argc, argv);

  *syscall_handler = handle_syscall;

  // Deal with vDSO calls
  switch (vdso_arg_flag) {
    case VDSO_SYSCALL:
      *vdso_callback = NULL;
      break;
    case VDSO_SPECIAL:
      *vdso_callback = vdso_callback_imp;
      break;
    case VDSO_STRACE:
      *vdso_callback = vdso_callback_none_imp;
      break;
  }
}
