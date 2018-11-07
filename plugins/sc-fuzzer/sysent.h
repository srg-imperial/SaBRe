#ifndef SC_FUZZER_SYSENT_H
#define SC_FUZZER_SYSENT_H

#define _GNU_SOURCE
#include <errno.h>
#undef _GNU_SOURCE

typedef long (*syscall_handler_fn)(long sc_no,
                                   long a1,
                                   long a2,
                                   long a3,
                                   long a4,
                                   long a5,
                                   long a6,
                                   void **aux);

enum syscall_family {
  SYS_FAMILY_UNASSIGNED = 0,
  SYS_FAMILY_DEVICE = (1 << 0),
  SYS_FAMILY_FILE = (1 << 1),
  SYS_FAMILY_NETWORK = (1 << 2),
  SYS_FAMILY_PROCESS = (1 << 3),
  SYS_FAMILY_MEMORY = (1 << 4),
};

struct sysent {
  int nargs;
  const char *sys_name;
  syscall_handler_fn handler;
  int default_errno;
  enum syscall_family families;
  void *handler_state;
};

// TODO: Come up with more sensible default ERRNO
#define SYSENT_SYSCALL_LIST                                        \
  X(0, 3, "read", EBADF,                                           \
    SYS_FAMILY_DEVICE | SYS_FAMILY_FILE | SYS_FAMILY_NETWORK)      \
  X(1, 3, "write", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(2, 3, "open", EBADF, SYS_FAMILY_UNASSIGNED)                    \
  X(3, 1, "close", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(4, 2, "stat", EBADF, SYS_FAMILY_UNASSIGNED)                    \
  X(5, 2, "fstat", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(6, 2, "lstat", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(7, 3, "poll", EBADF, SYS_FAMILY_UNASSIGNED)                    \
  X(8, 3, "lseek", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(9, 6, "mmap", EBADF, SYS_FAMILY_UNASSIGNED)                    \
  X(10, 3, "mprotect", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(11, 2, "munmap", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(12, 1, "brk", EBADF, SYS_FAMILY_UNASSIGNED)                    \
  X(13, 4, "rt_sigaction", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(14, 4, "rt_sigprocmask", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(15, 0, "rt_sigreturn", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(16, 3, "ioctl", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(17, 4, "pread64", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(18, 4, "pwrite64", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(19, 3, "readv", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(20, 3, "writev", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(21, 2, "access", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(22, 1, "pipe", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(23, 5, "select", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(24, 0, "sched_yield", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(25, 5, "mremap", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(26, 3, "msync", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(27, 3, "mincore", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(28, 3, "madvise", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(29, 3, "shmget", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(30, 3, "shmat", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(31, 3, "shmctl", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(32, 1, "dup", EBADF, SYS_FAMILY_UNASSIGNED)                    \
  X(33, 2, "dup2", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(34, 0, "pause", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(35, 2, "nanosleep", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(36, 2, "getitimer", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(37, 1, "alarm", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(38, 3, "setitimer", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(39, 0, "getpid", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(40, 4, "sendfile", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(41, 3, "socket", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(42, 3, "connect", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(43, 3, "accept", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(44, 6, "sendto", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(45, 6, "recvfrom", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(46, 3, "sendmsg", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(47, 3, "recvmsg", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(48, 2, "shutdown", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(49, 3, "bind", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(50, 2, "listen", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(51, 3, "getsockname", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(52, 3, "getpeername", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(53, 4, "socketpair", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(54, 5, "setsockopt", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(55, 5, "getsockopt", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(56, 5, "clone", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(57, 0, "fork", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(58, 0, "vfork", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(59, 3, "execve", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(60, 1, "exit", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(61, 4, "wait4", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(62, 2, "kill", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(63, 1, "uname", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(64, 3, "semget", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(65, 3, "semop", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(66, 4, "semctl", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(67, 1, "shmdt", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(68, 2, "msgget", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(69, 4, "msgsnd", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(70, 5, "msgrcv", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(71, 3, "msgctl", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(72, 3, "fcntl", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(73, 2, "flock", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(74, 1, "fsync", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(75, 1, "fdatasync", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(76, 2, "truncate", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(77, 2, "ftruncate", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(78, 3, "getdents", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(79, 2, "getcwd", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(80, 1, "chdir", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(81, 1, "fchdir", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(82, 2, "rename", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(83, 2, "mkdir", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(84, 1, "rmdir", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(85, 2, "creat", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(86, 2, "link", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(87, 1, "unlink", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(88, 2, "symlink", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(89, 3, "readlink", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(90, 2, "chmod", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(91, 2, "fchmod", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(92, 3, "chown", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(93, 3, "fchown", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(94, 3, "lchown", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(95, 1, "umask", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(96, 2, "gettimeofday", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(97, 2, "getrlimit", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(98, 2, "getrusage", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(99, 1, "sysinfo", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(100, 1, "times", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(101, 4, "ptrace", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(102, 0, "getuid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(103, 3, "syslog", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(104, 0, "getgid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(105, 1, "setuid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(106, 1, "setgid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(107, 0, "geteuid", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(108, 0, "getegid", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(109, 2, "setpgid", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(110, 0, "getppid", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(111, 0, "getpgrp", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(112, 0, "setsid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(113, 2, "setreuid", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(114, 2, "setregid", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(115, 2, "getgroups", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(116, 2, "setgroups", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(117, 3, "setresuid", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(118, 3, "getresuid", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(119, 3, "setresgid", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(120, 3, "getresgid", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(121, 1, "getpgid", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(122, 1, "setfsuid", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(123, 1, "setfsgid", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(124, 1, "getsid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(125, 2, "capget", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(126, 2, "capset", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(127, 2, "rt_sigpending", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(128, 4, "rt_sigtimedwait", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(129, 3, "rt_sigqueueinfo", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(130, 2, "rt_sigsuspend", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(131, 2, "sigaltstack", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(132, 2, "utime", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(133, 3, "mknod", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(134, 1, "uselib", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(135, 1, "personality", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(136, 2, "ustat", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(137, 2, "statfs", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(138, 2, "fstatfs", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(139, 3, "sysfs", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(140, 2, "getpriority", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(141, 3, "setpriority", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(142, 2, "sched_setparam", EBADF, SYS_FAMILY_UNASSIGNED)        \
  X(143, 2, "sched_getparam", EBADF, SYS_FAMILY_UNASSIGNED)        \
  X(144, 3, "sched_setscheduler", EBADF, SYS_FAMILY_UNASSIGNED)    \
  X(145, 1, "sched_getscheduler", EBADF, SYS_FAMILY_UNASSIGNED)    \
  X(146, 1, "sched_get_priority_m", EBADF, SYS_FAMILY_UNASSIGNED)  \
  X(147, 1, "sched_get_priority_m", EBADF, SYS_FAMILY_UNASSIGNED)  \
  X(148, 2, "sched_rr_get_interval", EBADF, SYS_FAMILY_UNASSIGNED) \
  X(149, 2, "mlock", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(150, 2, "munlock", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(151, 1, "mlockall", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(152, 0, "munlockall", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(153, 0, "vhangup", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(154, 3, "modify_ldt", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(155, 2, "pivot_root", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(156, 1, "_sysctl", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(157, 5, "prctl", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(158, 2, "arch_prctl", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(159, 1, "adjtimex", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(160, 2, "setrlimit", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(161, 1, "chroot", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(162, 0, "sync", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(163, 1, "acct", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(164, 2, "settimeofday", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(165, 5, "mount", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(166, 2, "umount2", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(167, 2, "swapon", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(168, 1, "swapoff", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(169, 4, "reboot", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(170, 2, "sethostname", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(171, 2, "setdomainname", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(172, 1, "iopl", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(173, 3, "ioperm", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(174, 2, "create_module", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(175, 3, "init_module", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(176, 2, "delete_module", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(177, 1, "get_kernel_syms", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(178, 5, "query_module", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(179, 4, "quotactl", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(180, 3, "nfsservctl", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(181, 5, "getpmsg", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(182, 5, "putpmsg", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(183, 5, "afs_syscall", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(184, 3, "tuxcall", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(185, 3, "security", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(186, 0, "gettid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(187, 3, "readahead", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(188, 5, "setxattr", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(189, 5, "lsetxattr", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(190, 5, "fsetxattr", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(191, 4, "getxattr", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(192, 4, "lgetxattr", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(193, 4, "fgetxattr", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(194, 3, "listxattr", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(195, 3, "llistxattr", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(196, 3, "flistxattr", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(197, 2, "removexattr", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(198, 2, "lremovexattr", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(199, 2, "fremovexattr", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(200, 2, "tkill", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(201, 1, "time", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(202, 6, "futex", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(203, 3, "sched_setaffinity", EBADF, SYS_FAMILY_UNASSIGNED)     \
  X(204, 3, "sched_getaffinity", EBADF, SYS_FAMILY_UNASSIGNED)     \
  X(205, 1, "set_thread_area", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(206, 2, "io_setup", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(207, 1, "io_destroy", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(208, 5, "io_getevents", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(209, 3, "io_submit", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(210, 3, "io_cancel", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(211, 1, "get_thread_area", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(212, 3, "lookup_dcookie", EBADF, SYS_FAMILY_UNASSIGNED)        \
  X(213, 1, "epoll_create", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(214, 4, "epoll_ctl_old", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(215, 4, "epoll_wait_old", EBADF, SYS_FAMILY_UNASSIGNED)        \
  X(216, 5, "remap_file_pages", EBADF, SYS_FAMILY_UNASSIGNED)      \
  X(217, 3, "getdents64", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(218, 1, "set_tid_address", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(219, 0, "restart_syscall", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(220, 4, "semtimedop", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(221, 4, "fadvise64", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(222, 3, "timer_create", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(223, 4, "timer_settime", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(224, 2, "timer_gettime", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(225, 1, "timer_getoverrun", EBADF, SYS_FAMILY_UNASSIGNED)      \
  X(226, 1, "timer_delete", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(227, 2, "clock_settime", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(228, 2, "clock_gettime", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(229, 2, "clock_getres", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(230, 4, "clock_nanosleep", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(231, 1, "exit_group", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(232, 4, "epoll_wait", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(233, 4, "epoll_ctl", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(234, 3, "tgkill", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(235, 2, "utimes", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(236, 5, "vserver", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(237, 6, "mbind", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(238, 3, "set_mempolicy", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(239, 5, "get_mempolicy", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(240, 4, "mq_open", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(241, 1, "mq_unlink", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(242, 5, "mq_timedsend", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(243, 5, "mq_timedreceive", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(244, 2, "mq_notify", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(245, 3, "mq_getsetattr", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(246, 4, "kexec_load", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(247, 5, "waitid", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(248, 5, "add_key", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(249, 4, "request_key", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(250, 5, "keyctl", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(251, 3, "ioprio_set", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(252, 2, "ioprio_get", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(253, 0, "inotify_init", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(254, 3, "inotify_add_watch", EBADF, SYS_FAMILY_UNASSIGNED)     \
  X(255, 2, "inotify_rm_watch", EBADF, SYS_FAMILY_UNASSIGNED)      \
  X(256, 4, "migrate_pages", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(257, 4, "openat", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(258, 3, "mkdirat", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(259, 4, "mknodat", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(260, 5, "fchownat", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(261, 3, "futimesat", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(262, 4, "newfstatat", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(263, 3, "unlinkat", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(264, 4, "renameat", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(265, 5, "linkat", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(266, 3, "symlinkat", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(267, 4, "readlinkat", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(268, 3, "fchmodat", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(269, 3, "faccessat", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(270, 6, "pselect6", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(271, 5, "ppoll", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(272, 1, "unshare", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(273, 2, "set_robust_list", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(274, 3, "get_robust_list", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(275, 6, "splice", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(276, 4, "tee", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(277, 4, "sync_file_range", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(278, 4, "vmsplice", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(279, 6, "move_pages", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(280, 4, "utimensat", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(281, 6, "epoll_pwait", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(282, 3, "signalfd", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(283, 2, "timerfd_create", EBADF, SYS_FAMILY_UNASSIGNED)        \
  X(284, 1, "eventfd", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(285, 4, "fallocate", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(286, 4, "timerfd_settime", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(287, 2, "timerfd_gettime", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(288, 4, "accept4", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(289, 4, "signalfd4", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(290, 2, "eventfd2", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(291, 1, "epoll_create1", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(292, 3, "dup3", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(293, 2, "pipe2", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(294, 1, "inotify_init1", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(295, 4, "preadv", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(296, 4, "pwritev", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(297, 4, "rt_tgsigqueueinfo", EBADF, SYS_FAMILY_UNASSIGNED)     \
  X(298, 5, "perf_event_open", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(299, 5, "recvmmsg", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(300, 2, "fanotify_init", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(301, 5, "fanotify_mark", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(302, 4, "prlimit64", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(303, 5, "name_to_handle_at", EBADF, SYS_FAMILY_UNASSIGNED)     \
  X(304, 3, "open_by_handle_at", EBADF, SYS_FAMILY_UNASSIGNED)     \
  X(305, 2, "clock_adjtime", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(306, 1, "syncfs", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(307, 4, "sendmmsg", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(308, 2, "setns", EBADF, SYS_FAMILY_UNASSIGNED)                 \
  X(309, 3, "getcpu", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(310, 6, "process_vm_readv", EBADF, SYS_FAMILY_UNASSIGNED)      \
  X(311, 6, "process_vm_writev", EBADF, SYS_FAMILY_UNASSIGNED)     \
  X(312, 5, "kcmp", EBADF, SYS_FAMILY_UNASSIGNED)                  \
  X(313, 3, "finit_module", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(314, 3, "sched_setattr", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(315, 4, "sched_getattr", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(316, 5, "renameat2", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(317, 3, "seccomp", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(318, 3, "getrandom", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(319, 2, "memfd_create", EBADF, SYS_FAMILY_UNASSIGNED)          \
  X(320, 5, "kexec_file_load", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(321, 3, "bpf", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(322, 5, "execveat", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(323, 1, "userfaultfd", EBADF, SYS_FAMILY_UNASSIGNED)           \
  X(324, 2, "membarrier", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(325, 3, "mlock2", EBADF, SYS_FAMILY_UNASSIGNED)                \
  X(326, 6, "copy_file_range", EBADF, SYS_FAMILY_UNASSIGNED)       \
  X(327, 6, "preadv2", EBADF, SYS_FAMILY_UNASSIGNED)               \
  X(328, 6, "pwritev2", EBADF, SYS_FAMILY_UNASSIGNED)              \
  X(329, 4, "pkey_mprotect", EBADF, SYS_FAMILY_UNASSIGNED)         \
  X(330, 2, "pkey_alloc", EBADF, SYS_FAMILY_UNASSIGNED)            \
  X(331, 1, "pkey_free", EBADF, SYS_FAMILY_UNASSIGNED)             \
  X(332, 5, "statx", EBADF, SYS_FAMILY_UNASSIGNED)

#endif /* !SC_FUZZER_SYSENT_H */
