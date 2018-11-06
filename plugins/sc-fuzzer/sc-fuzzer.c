/*
  This plugin simply intercepts all system calls and vDSO calls and
  reissues them at a user supplied probability for various syscall families.
*/

#include "real_syscall.h"
#include "vx_api_defs.h"
#include "sysent.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <execinfo.h>
#include <limits.h>
#undef _GNU_SOURCE

struct syscall_chances {
  int unassigned;
  int device;
  int file;
  int network;
  int process;
  int memory;
};

static struct syscall_chances failure_probabilities = { .unassigned = 50 };
static int verbose_flag = 0;

static unsigned int random_seed = 0;

static long default_handler(long sc_no,
                            long a1,
                            long a2,
                            long a3,
                            long a4,
                            long a5,
                            long a6,
                            void **aux);

static const struct sysent sys_entries[] =
    {
#define X(sc_no, nargs, name, default_errno, families) \
  [sc_no] = {nargs, name, default_handler, \
        default_errno, families, NULL},
                    SYSENT_SYSCALL_LIST
#undef X
};

static void print_arguments(void) {
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

static void display_help(void) {
  fprintf(stderr,
"Plugin to SaBRe that probabilistically fails system calls for usage in fuzzing applications.\n\
USAGE: sabre libsc-fuzzer.so [OPTIONS] -- <CLIENT APP> [CLIENT ARGUMENTS] ...\n\
  Options:\n\
    -v, --verbose                       Enable some additional information unspecified information.\n\
    -h, --help                          Prints this help message and exits.\n\
    -s, --seed [1-UINT_MAX]             Sets the seed to use for srand(). The default is the current epoch.\n\
    -u, --unassigned [0-100]            Sets the default probability for system calls not assigned a family.\n\
    -d, --device-operations [0-100]     Sets the default probability operating on devices.\n\
    -f, --file-operations [0-100]       Sets the failure probability for file I/O system calls.\n\
    -n, --network-operations [0-100]    Sets the failure probability for network I/O system calls.\n\
    -p, --process-management [0-100]    Sets the failure probability for process management system calls.\n\
    -m, --memory-allocation [0-100]     Sets the failure probability for memory allocation system calls.\n\
");
}

static const char *opt_string = "u:d:f:n:p:m:s:vh";

static struct option long_opts[] = {
    {"unassigned", required_argument, NULL, 'u'},
    {"device-operations", required_argument, NULL, 'd'},
    {"file-operations", required_argument, NULL, 'f'},
    {"network-operations", required_argument, NULL, 'n'},
    {"process-management", required_argument, NULL, 'p'},
    {"memory-allocation", required_argument, NULL, 'm'},
    {"seed", required_argument, NULL, 's'},
    {"verbose", no_argument, &verbose_flag, 1},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}};

static int extract_probability(const char *probability_str) {
  errno = 0;
  intmax_t probability = strtoimax(probability_str, NULL, 0);
  if (errno) {
    perror("Received an invalid probability on the command line");
    display_help();
    exit(EXIT_FAILURE);
  }
  if (probability < 0 || probability > 100) {
    fprintf(stderr,
            "Received an out of range probability on the command line. The "
            "value was %jd.\n", probability);
    display_help();
    exit(EXIT_FAILURE);
  }
  return (int)probability;
}

static void handle_arguments(int *argc, char **argv[]) {
  int opt_index = 0;
  int ch = 0;

  while ((ch = getopt_long(*argc, *argv, opt_string, long_opts, &opt_index)) !=
         -1) {
    switch (ch) {
      case 'd':
        failure_probabilities.device = extract_probability(optarg);
        break;
      case 'u':
        failure_probabilities.unassigned = extract_probability(optarg);
        break;
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
      case 's':
        errno = 0;
        uintmax_t seed = (unsigned) strtoumax(optarg, NULL, 0);
        if (errno || !seed || seed > (uintmax_t) UINT_MAX) {
          perror("Received an invalid seed on the command line");
          display_help();
          exit(EXIT_FAILURE);
        }
        random_seed = (unsigned int) seed;
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
        __attribute__((fallthrough));
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

/*
 * Does a "random trial" against the advertised failure probabilities. If the
 * trial succeeds  returns the default errno value for this syscall. Otherwise
 * it will let the system call go through. The probabilities for families are
 * checked for a first match, with the ordering:
 *  - SYS_FAMILY_DEVICE
 *  - SYS_FAMILY_FILE
 *  - SYS_FAMILY_NETWORK
 *  - SYS_FAMILY_PROCESS
 *  - SYS_FAMILY_MEMORY
 *  - SYS_FAMILY_UNASSIGNED
 */
static long default_handler(long sc_no,
                            long a1,
                            long a2,
                            long a3,
                            long a4,
                            long a5,
                            long a6,
                            void **aux) {
  (void)aux;  // unused
  int random = rand() % 100 + 1;
  const struct sysent *entry = &sys_entries[sc_no];

  if (entry->families & SYS_FAMILY_DEVICE) {
    if (random <= failure_probabilities.device)
      return -entry->default_errno;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_FILE) {
    if (random <= failure_probabilities.file)
    if (random <= failure_probabilities.file)
      return -entry->default_errno;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_NETWORK) {
    if (random <= failure_probabilities.network)
      return -entry->default_errno;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_PROCESS) {
    if (random <= failure_probabilities.process)
      return -entry->default_errno;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_MEMORY) {
    if (random <= failure_probabilities.memory)
      return -entry->default_errno;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (random <= failure_probabilities.unassigned)
    return -entry->default_errno;

  return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
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

  const struct sysent *entry = &sys_entries[sc_no];

  return entry->handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
                        (void *)&entry->handler_state);
}

void_void_fn handle_vdso(long sc_no, void_void_fn actual_fn) {
  (void)(sc_no);  // unused
  return actual_fn;
}

static void segv_handler(int sig) {
  if (write(STDERR_FILENO, "Caught SIGSEGV at:\n", 19) == -1) {
    // Not async signal safe but oh well this already did not go well
    perror("Failed to write signal error");
  }

  void *array = alloca(256 * sizeof(void *));
  int cnt = backtrace(array, 256);
  backtrace_symbols_fd(array, cnt, STDERR_FILENO);

  /* Pass on the signal (so that a core file is produced). */
  struct sigaction sa;
  sa.sa_handler = SIG_DFL;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(sig, &sa, NULL);
  raise(sig);
}

void vx_init(int *argc,
             char **argv[],
             vx_icept_reg_fn fn_icept_reg,
             vx_icept_vdso_callback_fn *vdso_callback,
             vx_sc_handler_fn *syscall_handler,
             vx_post_load_fn *post_load) {
  (void)fn_icept_reg;  // unused
  (void)post_load;     // unused

  struct sigaction sig_act;
  sig_act.sa_handler = &segv_handler;
  sigemptyset(&sig_act.sa_mask);
  sig_act.sa_flags = SA_RESTART;

  void *stack = malloc(2 * SIGSTKSZ);
  stack_t ss;
  ss.ss_sp = stack;
  ss.ss_flags = 0;
  ss.ss_size = 2 * SIGSTKSZ;

  if (sigaltstack(&ss, NULL) == 0)
    sig_act.sa_flags |= SA_ONSTACK;

  sigaction(SIGSEGV, &sig_act, NULL);

  *syscall_handler = handle_syscall;
  *vdso_callback = handle_vdso;

  handle_arguments(argc, argv);

  random_seed = random_seed ? random_seed : time(NULL);
  srand(random_seed);

  if (verbose_flag)
    print_arguments();
}
