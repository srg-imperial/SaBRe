/*
  This plugin simply intercepts all system calls and vDSO calls and
  reissues them at a user supplied probability for various syscall families.
*/

#include "real_syscall.h"
#include "vx_api_defs.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

struct syscall_chances {
  int file;
  int network;
  int process;
  int memory;
};

static struct syscall_chances failure_probabilities = { 0 };
static int verbose_flag = 0;

static void print_arguments() {
  fprintf(stderr,
"The failure probabilities are:\n\
{\n\
  file: %d\n\
  network: %d\n\
  process: %d\n\
  memory: %d\n\
}\n",
          failure_probabilities.file, failure_probabilities.network,
          failure_probabilities.process, failure_probabilities.memory);
}

static void display_help() {
  fprintf(stderr,
"Plugin to SaBRe that probabilistically fails system calls for usage in fuzzing applications.\n\
USAGE: sabre libsc-fuzzer.so [OPTIONS] -- <CLIENT APP> [CLIENT ARGUMENTS] ...\n\
  Options:\n\
    -v, --verbose                       Enable some additional information unspecified information.\n\
    -h, --help                          Prints this help message and exits.\n\
    -f, --file-operations [0-100]       Sets the failure probability for file I/O system calls.\n\
    -n, --network-operations [0-100]    Sets the failure probability for network I/O system calls.\n\
    -p, --process-management [0-100]    Sets the failure probability for process management system calls.\n\
    -m, --memory-allocation [0-100]     Sets the failure probability for memory allocation system calls.\n\
");
}

static const char *opt_string = "f:n:p:m:vh";

static struct option long_opts[] = {
    /* These options set a flag. */
    {"file-operations", required_argument, NULL, 'f'},
    {"network-operations", required_argument, NULL, 'n'},
    {"process-management", required_argument, NULL, 'p'},
    {"memory-allocation", required_argument, NULL, 'm'},
    {"verbose", no_argument, &verbose_flag, 1},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}};

static int extract_probability(const char *probability_str) {
  errno = 0;
  intmax_t probability = strtoimax(probability_str, NULL, 0);
  if (errno || probability < 0 || probability > 100) {
    perror("Received an invalid probability on the command line");
    display_help();
    exit(EXIT_FAILURE);
  }
  return (int) probability;
}

static void handle_arguments(int *argc, char **argv[]) {
  int opt_index = 0;
  int ch = 0;

  while ((ch= getopt_long(*argc, *argv, opt_string, long_opts, &opt_index)) != -1) {
    switch (ch) {
      case 'f':
        failure_probabilities.file = extract_probability(optarg);
        break;
      case 'n':
        failure_probabilities.network = extract_probability(optarg);
        break;
      case 'p':
        failure_probabilities.process = extract_probability(optarg);
        break;
      case 'm':
        failure_probabilities.memory = extract_probability(optarg);
        break;
      case 'h':
        display_help();
        exit(EXIT_SUCCESS);
        break;
      case '?': /* Display usage and exit with failure. */
        break;
      case 0:
        // getopt_long will already have handled this
        if (long_opts[opt_index].flag != NULL)
          break;

        __attribute__ ((fallthrough));
      default:
        fprintf(stderr, "Unknown or bad arguments!\n");
        display_help();
        exit(EXIT_FAILURE);
    }
  }

  // Update the arguments to point to client program and its arguments
  *argc -= optind;
  *argv += optind;
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
  return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
}

void_void_fn handle_vdso(long sc_no, void_void_fn actual_fn) {
  (void)(sc_no);  // unused
  return actual_fn;
}

void vx_init(int *argc, char **argv[],
             vx_icept_reg_fn fn_icept_reg,
             vx_icept_vdso_callback_fn *vdso_callback,
             vx_sc_handler_fn *syscall_handler,
             vx_post_load_fn *post_load) {
  (void)fn_icept_reg;  // unused
  (void)post_load;     // unused

  *syscall_handler = handle_syscall;
  *vdso_callback = handle_vdso;

  /* (*argc)--; */
  /* (*argv)++; */
  handle_arguments(argc, argv);
  if (verbose_flag) print_arguments();
}
