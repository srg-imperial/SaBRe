/* This file includes Linux-specific support functions common to the
 * coredumper and the thread lister; primarily, this is a collection
 * of direct system calls, and a couple of symbols missing from
 * standard header files.
 * There are a few options that the including file can set to control
 * the behavior of this file:
 *
 * SYS_ERRNO:
 *   All system calls will update "errno" unless overriden by setting the
 *   SYS_ERRNO macro prior to including this file. SYS_ERRNO should be
 *   an l-value.
 *
 * SYS_INLINE:
 *   New symbols will be defined "static inline", unless overridden by
 *   the SYS_INLINE macro.
 *
 * SYS_LINUX_SYSCALL_SUPPORT_H
 *   This macro is used to avoid multiple inclusions of this header file.
 *   If you need to include this file more than once, make sure to
 *   unset SYS_LINUX_SYSCALL_SUPPORT_H before each inclusion.
 *
 * SYS_PREFIX:
 *   New system calls will have a prefix of "sys_" unless overridden by
 *   the SYS_PREFIX macro. Valid values for this macro are [0..9] which
 *   results in prefixes "sys[0..9]_". It is also possible to set this
 *   macro to -1, which avoids all prefixes.
 *
 * SYS_SYSCALL_ENTRYPOINT:
 *   Some applications (such as sandboxes that filter system calls), need
 *   to be able to run custom-code each time a system call is made. If this
 *   macro is defined, it expands to the name of a "common" symbol. If
 *   this symbol is assigned a non-NULL pointer value, it is used as the
 *   address of the system call entrypoint.
 *   A pointer to this symbol can be obtained by calling
 *   get_syscall_entrypoint()
 *
 * This file defines a few internal symbols that all start with "LSS_".
 * Do not access these symbols from outside this file. They are not part
 * of the supported API.
 */
#ifndef LINUX_SYSCALL_SUPPORT_H_
#define LINUX_SYSCALL_SUPPORT_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <stdint.h>
//#include <endian.h>
//#include <machine/types.h>

// typedef __uint32_t uintptr_t;
//#if !defined(__off64_t)
// typedef _off64_t __off64_t;
//#endif
// typedef __loff_t loff_t;

#ifndef PROT_READ
#define PROT_READ 0x1 /* page can be read */
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2 /* page can be written */
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x4 /* page can be executed */
#endif
#ifndef PROT_SEM
#define PROT_SEM 0x8 /* page may be used for atomic ops */
#endif
#ifndef PROT_NONE
#define PROT_NONE 0x0 /* page can not be accessed */
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif
#ifndef MAP_SHARED
#define MAP_SHARED 0x01 /* Share changes */
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02 /* Changes are private */
#endif
#ifndef MAP_TYPE
#define MAP_TYPE 0x0f /* Mask for type of mapping */
#endif
#ifndef MAP_FIXED
#define MAP_FIXED 0x10 /* Interpret addr exactly */
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20 /* don't use a file */
#endif

#ifndef RLIMIT_CPU
#define RLIMIT_CPU 0
#endif
#ifndef RLIMIT_FSIZE
#define RLIMIT_FSIZE 1
#endif
#ifndef RLIMIT_DATA
#define RLIMIT_DATA 2
#endif
#ifndef RLIMIT_STACK
#define RLIMIT_STACK 3
#endif
#ifndef RLIMIT_CORE
#define RLIMIT_CORE 4
#endif
#ifndef RLIMIT_RSS
#define RLIMIT_RSS 5
#endif
#ifndef RLIMIT_NPROC
#define RLIMIT_NPROC 6
#endif
#ifndef RLIMIT_NOFILE
#define RLIMIT_NOFILE 7
#endif
#ifndef RLIMIT_MEMLOCK
#define RLIMIT_MEMLOCK 8
#endif
#ifndef RLIMIT_AS
#define RLIMIT_AS 9
#endif
#ifndef RLIMIT_LOCKS
#define RLIMIT_LOCKS 10
#endif
#ifndef RLIMIT_SIGPENDING
#define RLIMIT_SIGPENDING 11
#endif
#ifndef RLIMIT_MSGQUEUE
#define RLIMIT_MSGQUEUE 12
#endif
#ifndef RLIMIT_NICE
#define RLIMIT_NICE 13
#endif
#ifndef RLIMIT_RTPRIO
#define RLIMIT_RTPRIO 14
#endif
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif
#ifndef RLIM_NLIMITS
#define RLIM_NLIMITS 16
#endif
#ifndef RLIM_INFINITY
#define RLIM_INFINITY (~0UL)
#endif

#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif
#ifndef AF_LOCAL
#define AF_LOCAL 1
#endif
#ifndef AF_UNIX
#define AF_UNIX AF_LOCAL
#endif
#ifndef AF_FILE
#define AF_FILE AF_LOCAL
#endif
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif
#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif
#ifndef SOCK_RDM
#define SOCK_RDM 4
#endif
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET 5
#endif

#ifndef MSG_TRUNC
#define MSG_TRUNC 0x20
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif
#ifndef MSG_CTRUNC
#define MSG_CTRUNC 0x08
#endif

#ifndef POLLIN
#define POLLIN 0x001
#endif
#ifndef POLLPRI
#define POLLPRI 0x002
#endif
#ifndef POLLOUT
#define POLLOUT 0x004
#endif

#ifndef POLLERR
#define POLLERR 0x008
#endif
#ifndef POLLHUP
#define POLLHUP 0x010
#endif
#ifndef POLLNVAL
#define POLLNVAL 0x020
#endif

#ifndef SA_NOCLDSTOP
#define SA_NOCLDSTOP 0x00000001u
#endif
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0x00000002u
#endif
#ifndef SA_SIGINFO
#define SA_SIGINFO 0x00000004u
#endif
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000u
#endif
#ifndef SA_ONSTACK
#define SA_ONSTACK 0x08000000u
#endif
#ifndef SA_RESTART
#define SA_RESTART 0x10000000u
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0x40000000u
#endif
#ifndef SA_RESETHAND
#define SA_RESETHAND 0x80000000u
#endif

#ifndef __socklen_t_defined
typedef unsigned int socklen_t;
#define __socklen_t_defined
#endif

#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif

#ifndef SCM_RIGHTS
#define SCM_RIGHTS 0x01
#endif
#ifndef SCM_CREDENTIALS
#define SCM_CREDENTIALS 0x02
#endif

#ifndef CMSG_DATA
#define CMSG_DATA(cmsg) \
  ((unsigned char *)(cmsg) + CMSG_ALIGN(sizeof(struct kernel_cmsghdr)))
#endif
#ifndef CMSG_NXTHDR
#define CMSG_NXTHDR(mhdr, cmsg)                                          \
  (((unsigned char *)cmsg + CMSG_ALIGN(cmsg->cmsg_len)) +                \
               CMSG_ALIGN(sizeof(struct kernel_cmsghdr)) >               \
           (unsigned char *)(mhdr)->msg_control + (mhdr)->msg_controllen \
       ? (struct kernel_cmsghdr *)NULL                                   \
       : (struct kernel_cmsghdr *)((unsigned char *)(cmsg) +             \
                                   CMSG_ALIGN((cmsg)->cmsg_len)))
#endif
#ifndef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR(mhdr) ((struct kernel_cmsghdr *)(mhdr)->msg_control)
#endif
#ifndef CMSG_ALIGN
#define CMSG_ALIGN(len)                  \
  (((len) + sizeof(unsigned long) - 1) & \
   (unsigned long) ~(sizeof(unsigned long) - 1))
#endif
#ifndef CMSG_SPACE
#define CMSG_SPACE(len) \
  (CMSG_ALIGN(sizeof(struct kernel_cmsghdr)) + CMSG_ALIGN(len))
#endif
#ifndef CMSG_LEN
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct kernel_cmsghdr)) + (len))
#endif

/* include/bits/clone.h                                                   */
#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif
#ifndef CLONE_FS
#define CLONE_FS 0x00000200
#endif
#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif
#ifndef CLONE_SIGHAND
#define CLONE_SIGHAND 0x00000800
#endif
#ifndef CLONE_PTRACE
#define CLONE_PTRACE 0x00002000
#endif
#ifndef CLONE_VFORK
#define CLONE_VFORK 0x00004000
#endif
#ifndef CLONE_PARENT
#define CLONE_PARENT 0x00008000
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_SYSVSEM
#define CLONE_SYSVSEM 0x00040000
#endif
#ifndef CLONE_SETTLS
#define CLONE_SETTLS 0x00080000
#endif
#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x00100000
#endif
#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000
#endif
#ifndef CLONE_DETACHED
#define CLONE_DETACHED 0x00400000
#endif
#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED 0x00800000
#endif
#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID 0x01000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef CLONE_IO
#define CLONE_IO 0x80000000
#endif

/* As glibc often provides subtly incompatible data structures (and implicit
 * wrapper functions that convert them), we provide our own kernel data
 * structures for use by the system calls.
 * These structures have been developed by using Linux 2.6.23 headers for
 * reference. Note though, we do not care about exact API compatibility
 * with the kernel, and in fact the kernel often does not have a single
 * API that works across architectures. Instead, we try to mimic the glibc
 * API where reasonable, and only guarantee ABI compatibility with the
 * kernel headers.
 * Most notably, here are a few changes that were made to the structures
 * defined by kernel headers:
 *
 * - we only define structures, but not symbolic names for kernel data
 *   types. For the latter, we directly use the native C datatype
 *   (i.e. "unsigned" instead of "mode_t").
 * - in a few cases, it is possible to define identical structures for
 *   both 32bit (e.g. i386) and 64bit (e.g. x86-64) platforms by
 *   standardizing on the 64bit version of the data types. In particular,
 *   this means that we use "unsigned" where the 32bit headers say
 *   "unsigned long".
 * - overall, we try to minimize the number of cases where we need to
 *   conditionally define different structures.
 * - the "struct kernel_sigaction" class of structures have been
 *   modified to more closely mimic glibc's API by introducing an
 *   anonymous union for the function pointer.
 * - a small number of field names had to have an underscore appended to
 *   them, because glibc defines a global macro by the same name.
 */

/* include/linux/dirent.h                                                    */
struct kernel_dirent64 {
  unsigned long long d_ino;
  long long d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[256];
};

/* include/linux/dirent.h                                                    */
struct kernel_dirent {
  long d_ino;
  long d_off;
  unsigned short d_reclen;
  char d_name[256];
};

/* include/linux/uio.h                                                       */
struct kernel_iovec {
  void *iov_base;
  unsigned long iov_len;
};

/* include/linux/epoll.h                                                     */
struct kernel_epoll_event {
  uint32_t events;
  uint64_t data;
} __attribute__((packed));

/* include/linux/socket.h                                                    */
struct kernel_msghdr {
  void *msg_name;
  int msg_namelen;
  struct kernel_iovec *msg_iov;
  unsigned long msg_iovlen;
  void *msg_control;
  unsigned long msg_controllen;
  unsigned msg_flags;
};
struct kernel_mmsghdr {
  struct kernel_msghdr msg_hdr;
  unsigned int         msg_len;
};

/* include/bits/socket.h                                                     */
struct kernel_cmsghdr {
  unsigned long cmsg_len;
  int cmsg_level;
  int cmsg_type;
  unsigned char cmsg_data[];
};

#define KERNEL_FD_SETSIZE   1024
#define BITS_IN_LONG (8 * sizeof(long))

/* include/linux/posix_types.h                                               */
struct kernel_fd_set {
  unsigned long fds_bits[KERNEL_FD_SETSIZE / BITS_IN_LONG];
};

/* include/asm-generic/poll.h                                                */
struct kernel_pollfd {
  int fd;
  short events;
  short revents;
};

/* include/linux/resource.h                                                  */
struct kernel_rlimit {
  unsigned long rlim_cur;
  unsigned long rlim_max;
};

/* include/linux/time.h                                                      */
struct kernel_timespec {
  long tv_sec;
  long tv_nsec;
};

/* include/linux/time.h                                                      */
struct kernel_timeval {
  long tv_sec;
  long tv_usec;
};

/* include/linux/time.h                                                      */
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME			7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9
#define CLOCK_SGI_CYCLE			10	/* Hardware specific */
#define CLOCK_TAI			11

#define MAX_CLOCKS			16
#define CLOCKS_MASK			(CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO			CLOCK_MONOTONIC

/* include/linux/times.h                                                     */
struct kernel_tms {
  clock_t tms_utime;
  clock_t tms_stime;
  clock_t tms_cutime;
  clock_t tms_cstime;
};

/* include/linux/utime.h                                                     */
struct kernel_utimbuf {
  time_t actime;
  time_t modtime;
};

/* include/linux/resource.h                                                  */
struct kernel_rusage {
  struct kernel_timeval ru_utime;
  struct kernel_timeval ru_stime;
  long ru_maxrss;
  long ru_ixrss;
  long ru_idrss;
  long ru_isrss;
  long ru_minflt;
  long ru_majflt;
  long ru_nswap;
  long ru_inblock;
  long ru_oublock;
  long ru_msgsnd;
  long ru_msgrcv;
  long ru_nsignals;
  long ru_nvcsw;
  long ru_nivcsw;
};

/* include/bits/sigstack.h                                                   */
struct kernel_stack_t {
  void *ss_sp;
  int ss_flags;
  size_t ss_size;
};

/* include_linux/ipc.h */
struct kernel_ipc_perm {
  int key;
  uid_t uid;
  gid_t gid;
  uid_t cuid;
  gid_t cgid;
  int mode;
  unsigned short seq;
};

/* include/linux/shm.h */
struct kernel_shmid_ds {
  struct kernel_ipc_perm shm_perm;
  int shm_segz;
  unsigned shm_atime;
  unsigned shm_dtime;
  unsigned shm_ctime;
  int shm_cpid;
  int shm_lpid;
  unsigned short shm_nattch;
  unsigned short shm_unused;
  void *shm_unused2;
  void *shm_unused3;
};

/* include/linux/sys/sysinfo.h */
struct kernel_sysinfo {
	long uptime;		/* Seconds since boot */
	unsigned long  loads[3];	/* 1, 5, and 15 minute load averages */
	unsigned long  totalram;	/* Total usable main memory size */
	unsigned long  freeram;	  /* Available memory size */
	unsigned long  sharedram;	/* Amount of shared memory */
	unsigned long  bufferram;	/* Memory used by buffers */
	unsigned long  totalswap;	/* Total swap space size */
	unsigned long  freeswap;	/* swap space still available */
	unsigned short procs;		  /* Number of current processes */
	unsigned short pad;		   	/* Explicit padding for m68k */
	unsigned long  totalhigh;	/* Total high memory size */
	unsigned long  freehigh;	/* Available high memory size */
	unsigned int   mem_unit;	/* Memory unit size in bytes */
	char _f[20-2*sizeof(long)-sizeof(unsigned int)];	/* Padding: libc5 uses this.. */
};

/* include/sys/utsname.h                                                    */
struct kernel_utsname {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};

#if defined(__i386__)
/* include/asm-i386/signal.h                                  */
struct kernel_old_sigaction {
  union {
    void (*sa_handler_)(int);
    void (*sa_sigaction_)(int, siginfo_t *, void *);
  };
  unsigned long sa_mask;
  unsigned long sa_flags;
  void (*sa_restorer)(void);
} __attribute__((packed, aligned(4)));
#endif

/* Some kernel functions (e.g. sigaction() in 2.6.23) require that the
 * exactly match the size of the signal set, even though the API was
 * intended to be extensible. We define our own KERNEL_NSIG to deal with
 * this.
 * Please note that glibc provides signals [1.._NSIG-1], whereas the
 * kernel (and this header) provides the range [1..KERNEL_NSIG]. The
 * actual number of signals is obviously the same, but the constants
 * differ by one.
 */
#define KERNEL_NSIG 64
#define SIGSET_LEN\
  (KERNEL_NSIG + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))

/* include/asm/signal.h */
#ifdef __i386__
# define _NSIG_BPW	32
#else
# define _NSIG_BPW	64
#endif

#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

/* include/asm-{arm,i386,mips,x86_64}/signal.h                               */
struct kernel_sigset_t {
  unsigned long sig[SIGSET_LEN];
};

/* include/asm-{arm,i386,mips,x86_64,ppc}/signal.h                           */
struct kernel_sigaction {
  union {
    void (*sa_handler_)(int);
    void (*sa_sigaction_)(int, siginfo_t *, void *);
  };
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  struct kernel_sigset_t sa_mask;
};

/* include/linux/signal.h */
static inline void k_sigemptyset(struct kernel_sigset_t* set) {
	switch (_NSIG_WORDS) {
	default:
		memset(set, 0, sizeof(struct kernel_sigset_t));
		break;
	case 2: set->sig[1] = 0;
          // fall through
	case 1:	set->sig[0] = 0;
		break;
	}
}

static inline void k_sigfillset(struct kernel_sigset_t* set) {
	switch (_NSIG_WORDS) {
	default:
		memset(set, -1, sizeof(struct kernel_sigset_t));
		break;
	case 2: set->sig[1] = -1;
          // fall through
	case 1:	set->sig[0] = -1;
		break;
	}
}

static inline void k_sigaddset(struct kernel_sigset_t* set, int _sig) {
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		set->sig[0] |= 1UL << sig;
	else
		set->sig[sig / _NSIG_BPW] |= 1UL << (sig % _NSIG_BPW);
}

static inline void k_sigdelset(struct kernel_sigset_t* set, int _sig) {
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		set->sig[0] &= ~(1UL << sig);
	else
		set->sig[sig / _NSIG_BPW] &= ~(1UL << (sig % _NSIG_BPW));
}

/* include/linux/socket.h                                                    */
struct kernel_sockaddr {
  unsigned short sa_family;
  char sa_data[14];
};

/* include/linux/capability.h                                                */
typedef struct kernel__user_cap_header_struct {
	unsigned int version;
	int pid;
} *kernel_cap_user_header_t;

typedef struct kernel__user_cap_data_struct {
        unsigned int effective;
        unsigned int permitted;
        unsigned int inheritable;
} *kernel_cap_user_data_t;


/* include/asm-{arm,i386,mips,ppc}/stat.h                                    */
struct kernel_stat64 {
  unsigned long long st_dev;
  unsigned char __pad0[4];
  unsigned __st_ino;
  unsigned st_mode;
  unsigned st_nlink;
  unsigned st_uid;
  unsigned st_gid;
  unsigned long long st_rdev;
  unsigned char __pad3[4];
  long long st_size;
  unsigned st_blksize;
  unsigned long long st_blocks;
  unsigned st_atime_;
  unsigned st_atime_nsec_;
  unsigned st_mtime_;
  unsigned st_mtime_nsec_;
  unsigned st_ctime_;
  unsigned st_ctime_nsec_;
  unsigned long long st_ino;
};

/* include/asm-{arm,i386,mips,x86_64,ppc}/stat.h                             */
#if defined(__i386__)
struct kernel_stat {
  /* The kernel headers suggest that st_dev and st_rdev should be 32bit
   * quantities encoding 12bit major and 20bit minor numbers in an interleaved
   * format. In reality, we do not see useful data in the top bits. So,
   * we'll leave the padding in here, until we find a better solution.
   */
  unsigned short st_dev;
  short pad1;
  unsigned st_ino;
  unsigned short st_mode;
  unsigned short st_nlink;
  unsigned short st_uid;
  unsigned short st_gid;
  unsigned short st_rdev;
  short pad2;
  unsigned st_size;
  unsigned st_blksize;
  unsigned st_blocks;
  unsigned st_atime_;
  unsigned st_atime_nsec_;
  unsigned st_mtime_;
  unsigned st_mtime_nsec_;
  unsigned st_ctime_;
  unsigned st_ctime_nsec_;
  unsigned __unused4;
  unsigned __unused5;
};
#elif defined(__x86_64__)
struct kernel_stat {
  unsigned long st_dev;
  unsigned long st_ino;
  unsigned long st_nlink;
  unsigned st_mode;
  unsigned st_uid;
  unsigned st_gid;
  unsigned __pad0;
  unsigned long st_rdev;
  long st_size;
  long st_blksize;
  long st_blocks;
  unsigned long st_atime_;
  unsigned long st_atime_nsec_;
  unsigned long st_mtime_;
  unsigned long st_mtime_nsec_;
  unsigned long st_ctime_;
  unsigned long st_ctime_nsec_;
  long __unused4[3];
};
#endif

/* include/asm-{arm,i386,mips,x86_64,ppc}/statfs.h                           */
#if !defined(__x86_64__)
struct kernel_statfs64 {
  unsigned long f_type;
  unsigned long f_bsize;
  unsigned long long f_blocks;
  unsigned long long f_bfree;
  unsigned long long f_bavail;
  unsigned long long f_files;
  unsigned long long f_ffree;
  struct {
    int val[2];
  } f_fsid;
  unsigned long f_namelen;
  unsigned long f_frsize;
  unsigned long f_spare[5];
};
#endif

/* include/asm-{arm,i386,mips,x86_64,ppc,generic}/statfs.h                   */
struct kernel_statfs {
  /* x86_64 actually defines all these fields as signed, whereas all other  */
  /* platforms define them as unsigned. Leaving them at unsigned should not */
  /* cause any problems.                                                    */
  unsigned long f_type;
  unsigned long f_bsize;
  unsigned long f_blocks;
  unsigned long f_bfree;
  unsigned long f_bavail;
  unsigned long f_files;
  unsigned long f_ffree;
  struct {
    int val[2];
  } f_fsid;
  unsigned long f_namelen;
  unsigned long f_frsize;
  unsigned long f_spare[5];
};

/* Definitions missing from the standard header files                        */
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000
#endif
#ifndef NT_PRXFPREG
#define NT_PRXFPREG 0x46e62b7f
#endif
#ifndef PTRACE_GETFPXREGS
#define PTRACE_GETFPXREGS ((enum __ptrace_request)18)
#endif
#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif
#ifndef CPUCLOCK_PROF
#define CPUCLOCK_PROF 0
#endif
#ifndef CPUCLOCK_VIRT
#define CPUCLOCK_VIRT 1
#endif
#ifndef CPUCLOCK_SCHED
#define CPUCLOCK_SCHED 2
#endif
#ifndef CPUCLOCK_PERTHREAD_MASK
#define CPUCLOCK_PERTHREAD_MASK 4
#endif
#ifndef MAKE_PROCESS_CPUCLOCK
#define MAKE_PROCESS_CPUCLOCK(pid, clock) ((~(int)(pid) << 3) | (int)(clock))
#endif
#ifndef MAKE_THREAD_CPUCLOCK
#define MAKE_THREAD_CPUCLOCK(tid, clock) \
  ((~(int)(tid) << 3) | (int)((clock) | CPUCLOCK_PERTHREAD_MASK))
#endif

#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#endif
#ifndef FUTEX_WAKE
#define FUTEX_WAKE 1
#endif
#ifndef FUTEX_FD
#define FUTEX_FD 2
#endif
#ifndef FUTEX_REQUEUE
#define FUTEX_REQUEUE 3
#endif
#ifndef FUTEX_CMP_REQUEUE
#define FUTEX_CMP_REQUEUE 4
#endif
#ifndef FUTEX_WAKE_OP
#define FUTEX_WAKE_OP 5
#endif
#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI 6
#endif
#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI 7
#endif
#ifndef FUTEX_TRYLOCK_PI
#define FUTEX_TRYLOCK_PI 8
#endif
#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif
#ifndef FUTEX_CMD_MASK
#define FUTEX_CMD_MASK ~FUTEX_PRIVATE_FLAG
#endif
#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_REQUEUE_PRIVATE
#define FUTEX_REQUEUE_PRIVATE (FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_CMP_REQUEUE_PRIVATE
#define FUTEX_CMP_REQUEUE_PRIVATE (FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAKE_OP_PRIVATE
#define FUTEX_WAKE_OP_PRIVATE (FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_LOCK_PI_PRIVATE
#define FUTEX_LOCK_PI_PRIVATE (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_UNLOCK_PI_PRIVATE
#define FUTEX_UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_TRYLOCK_PI_PRIVATE
#define FUTEX_TRYLOCK_PI_PRIVATE (FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG)
#endif

#ifndef FD_ZERO
#define FD_ZERO(set)                                                     \
  do {                                                                   \
    int __i;                                                             \
    for (__i = 0; __i < (KERNEL_FD_SETSIZE / BITS_IN_LONG); __i++) \
      (set)->fd_bits[__i] = 0;                                           \
  } while (0)
#endif
#ifndef FD_SET
#define FD_SET(b, set)                       \
  ((set)->fd_bits[b / BITS_IN_LONG] |= \
   (1 << (b & (BITS_IN_LONG - 1))))
#endif
#ifndef FD_CLR
#define FD_CLR(b, set)                       \
  ((set)->fd_bits[b / BITS_IN_LONG] &= \
   ~(1 << (b & (BITS_IN_LONG - 1))))
#endif
#ifndef FD_ISSET
#define FD_ISSET(b, set)                    \
  ((set)->fd_bits[b / BITS_IN_LONG] & \
   (1 << (b &(BITS_IN_LONG - 1))))
#endif

#if 0
#ifndef EPOLL_CLOEXEC
#define EPOLL_CLOEXEC O_CLOEXEC
#endif
#endif

#ifndef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD 1
#endif
#ifndef EPOLL_CTL_DEL
#define EPOLL_CTL_DEL 2
#endif
#ifndef EPOLL_CTL_MOD
#define EPOLL_CTL_MOD 3
#endif

#if 0
#ifndef EPOLLWAKEUP
#define EPOLLWAKEUP (1 << 29)
#endif
#ifndef EPOLLONESHOT
#define EPOLLONESHOT (1 << 30)
#endif
#ifndef EPOLLET
#define EPOLLET (1 << 31)
#endif
#endif

#if defined(__x86_64__)
#ifndef ARCH_SET_GS
#define ARCH_SET_GS 0x1001
#endif
#ifndef ARCH_GET_GS
#define ARCH_GET_GS 0x1004
#endif
#endif

#if defined(__i386__)
#ifndef __NR_quotactl
#define __NR_quotactl 131
#endif
#ifndef __NR_setresuid
#define __NR_setresuid 164
#define __NR_getresuid 165
#define __NR_setresgid 170
#define __NR_getresgid 171
#endif
#ifndef __NR_rt_sigaction
#define __NR_rt_sigreturn 173
#define __NR_rt_sigaction 174
#define __NR_rt_sigprocmask 175
#define __NR_rt_sigpending 176
#define __NR_rt_sigsuspend 179
#endif
#ifndef __NR_pread64
#define __NR_pread64 180
#endif
#ifndef __NR_pwrite64
#define __NR_pwrite64 181
#endif
#ifndef __NR_ugetrlimit
#define __NR_ugetrlimit 191
#endif
#ifndef __NR_stat64
#define __NR_stat64 195
#endif
#ifndef __NR_fstat64
#define __NR_fstat64 197
#endif
#ifndef __NR_setresuid32
#define __NR_setresuid32 208
#define __NR_getresuid32 209
#define __NR_setresgid32 210
#define __NR_getresgid32 211
#endif
#ifndef __NR_setfsuid32
#define __NR_setfsuid32 215
#define __NR_setfsgid32 216
#endif
#ifndef __NR_getdents64
#define __NR_getdents64 220
#endif
#ifndef __NR_gettid
#define __NR_gettid 224
#endif
#ifndef __NR_readahead
#define __NR_readahead 225
#endif
#ifndef __NR_setxattr
#define __NR_setxattr 226
#endif
#ifndef __NR_lsetxattr
#define __NR_lsetxattr 227
#endif
#ifndef __NR_getxattr
#define __NR_getxattr 229
#endif
#ifndef __NR_lgetxattr
#define __NR_lgetxattr 230
#endif
#ifndef __NR_listxattr
#define __NR_listxattr 232
#endif
#ifndef __NR_llistxattr
#define __NR_llistxattr 233
#endif
#ifndef __NR_tkill
#define __NR_tkill 238
#endif
#ifndef __NR_futex
#define __NR_futex 240
#endif
#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 241
#define __NR_sched_getaffinity 242
#endif
#ifndef __NR_set_tid_address
#define __NR_set_tid_address 258
#endif
#ifndef __NR_clock_gettime
#define __NR_clock_gettime 265
#endif
#ifndef __NR_clock_getres
#define __NR_clock_getres 266
#endif
#ifndef __NR_statfs64
#define __NR_statfs64 268
#endif
#ifndef __NR_fstatfs64
#define __NR_fstatfs64 269
#endif
#ifndef __NR_fadvise64_64
#define __NR_fadvise64_64 272
#endif
#ifndef __NR_ioprio_set
#define __NR_ioprio_set 289
#endif
#ifndef __NR_ioprio_get
#define __NR_ioprio_get 290
#endif
#ifndef __NR_openat
#define __NR_openat 295
#endif
#ifndef __NR_fstatat64
#define __NR_fstatat64 300
#endif
#ifndef __NR_unlinkat
#define __NR_unlinkat 301
#endif
#ifndef __NR_move_pages
#define __NR_move_pages 317
#endif
#ifndef __NR_getcpu
#define __NR_getcpu 318
#endif
#ifndef __NR_fallocate
#define __NR_fallocate 324
#endif
/* End of i386 definitions                                                   */
#elif defined(__x86_64__)
#ifndef __NR_pread64
#define __NR_pread64 17
#endif
#ifndef __NR_pwrite64
#define __NR_pwrite64 18
#endif
#ifndef __NR_setresuid
#define __NR_setresuid 117
#define __NR_getresuid 118
#define __NR_setresgid 119
#define __NR_getresgid 120
#endif
#ifndef __NR_quotactl
#define __NR_quotactl 179
#endif
#ifndef __NR_gettid
#define __NR_gettid 186
#endif
#ifndef __NR_readahead
#define __NR_readahead 187
#endif
#ifndef __NR_setxattr
#define __NR_setxattr 188
#endif
#ifndef __NR_lsetxattr
#define __NR_lsetxattr 189
#endif
#ifndef __NR_getxattr
#define __NR_getxattr 191
#endif
#ifndef __NR_lgetxattr
#define __NR_lgetxattr 192
#endif
#ifndef __NR_listxattr
#define __NR_listxattr 194
#endif
#ifndef __NR_llistxattr
#define __NR_llistxattr 195
#endif
#ifndef __NR_tkill
#define __NR_tkill 200
#endif
#ifndef __NR_futex
#define __NR_futex 202
#endif
#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 203
#define __NR_sched_getaffinity 204
#endif
#ifndef __NR_getdents64
#define __NR_getdents64 217
#endif
#ifndef __NR_set_tid_address
#define __NR_set_tid_address 218
#endif
#ifndef __NR_fadvise64
#define __NR_fadvise64 221
#endif
#ifndef __NR_clock_gettime
#define __NR_clock_gettime 228
#endif
#ifndef __NR_clock_getres
#define __NR_clock_getres 229
#endif
#ifndef __NR_ioprio_set
#define __NR_ioprio_set 251
#endif
#ifndef __NR_ioprio_get
#define __NR_ioprio_get 252
#endif
#ifndef __NR_openat
#define __NR_openat 257
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat 262
#endif
#ifndef __NR_unlinkat
#define __NR_unlinkat 263
#endif
#ifndef __NR_move_pages
#define __NR_move_pages 279
#endif
#ifndef __NR_fallocate
#define __NR_fallocate 285
#endif
/* End of x86-64 definitions                                                 */
#endif

/* After forking, we must make sure to only call system calls.               */
#if defined(__BOUNDED_POINTERS__)
#error "Need to port invocations of syscalls for bounded pointers"
#else
/* The core dumper and the thread lister get executed after threads
 * have been suspended. As a consequence, we cannot call any functions
 * that acquire locks. Unfortunately, libc wraps most system calls
 * (e.g. in order to implement pthread_atfork, and to make calls
 * cancellable), which means we cannot call these functions. Instead,
 * we have to call syscall() directly.
 */
#undef LSS_ERRNO
#ifdef SYS_ERRNO
/* Allow the including file to override the location of errno. This can
 * be useful when using clone() with the CLONE_VM option.
 */
#define LSS_ERRNO SYS_ERRNO
#else
#define LSS_ERRNO errno
#endif

#undef LSS_INLINE
#ifdef SYS_INLINE
#define LSS_INLINE SYS_INLINE
#else
#define LSS_INLINE static inline
#endif

/* Allow the including file to override the prefix used for all new
 * system calls. By default, it will be set to "sys_".
 */
#undef LSS_NAME
#ifndef SYS_PREFIX
#define LSS_NAME(name) sys_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX < 0
#define LSS_NAME(name) name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 0
#define LSS_NAME(name) sys0_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 1
#define LSS_NAME(name) sys1_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 2
#define LSS_NAME(name) sys2_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 3
#define LSS_NAME(name) sys3_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 4
#define LSS_NAME(name) sys4_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 5
#define LSS_NAME(name) sys5_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 6
#define LSS_NAME(name) sys6_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 7
#define LSS_NAME(name) sys7_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 8
#define LSS_NAME(name) sys8_##name
#elif defined(SYS_PREFIX) && SYS_PREFIX == 9
#define LSS_NAME(name) sys9_##name
#endif

#undef LSS_RETURN
#if (defined(__i386__) || defined(__x86_64__))
/* Failing system calls return a negative result in the range of
 * -1..-4095. These are "errno" values with the sign inverted.
 */
#if 0
#define LSS_RETURN(type, res)                             \
  do {                                                    \
    if ((unsigned long)(res) >= (unsigned long)(-4095)) { \
      LSS_ERRNO = -(res);                                 \
      res = -1;                                           \
    }                                                     \
    return (type)(res);                                   \
  } while (0)
#else
#define LSS_RETURN(type, res) return (type)(res);
#endif
#endif
#if defined(__i386__)
/* In PIC mode (e.g. when building shared libraries), gcc for i386
 * reserves ebx. Unfortunately, most distribution ship with implementations
 * of _syscallX() which clobber ebx.
 * Also, most definitions of _syscallX() neglect to mark "memory" as being
 * clobbered. This causes problems with compilers, that do a better job
 * at optimizing across __asm__ calls.
 * So, we just have to redefine all of the _syscallX() macros.
 */
#undef LSS_ENTRYPOINT
#ifdef SYS_SYSCALL_ENTRYPOINT
static inline void (**LSS_NAME(get_syscall_entrypoint)(void))(void) {
  void (**entrypoint)(void);
  asm volatile(
      ".bss\n"
      ".align 8\n"
      ".globl " SYS_SYSCALL_ENTRYPOINT
      "\n"
      ".common " SYS_SYSCALL_ENTRYPOINT
      ",8,8\n"
      ".previous\n"
      /* This logically does 'lea "SYS_SYSCALL_ENTRYPOINT", %0' */
      "call 0f\n"
      "0:pop  %0\n"
      "add  $_GLOBAL_OFFSET_TABLE_+[.-0b], %0\n"
      "mov  " SYS_SYSCALL_ENTRYPOINT "@GOT(%0), %0\n"
      : "=r"(entrypoint));
  return entrypoint;
}

#define LSS_ENTRYPOINT                               \
  ".bss\n"                                           \
  ".align 8\n"                                       \
  ".globl " SYS_SYSCALL_ENTRYPOINT                   \
  "\n"                                               \
  ".common " SYS_SYSCALL_ENTRYPOINT                  \
  ",8,8\n"                                           \
  ".previous\n"                                      \
  /* Check the SYS_SYSCALL_ENTRYPOINT vector      */ \
  "push %%eax\n"                                     \
  "call 10000f\n"                                    \
  "10000:pop  %%eax\n"                               \
  "add  $_GLOBAL_OFFSET_TABLE_+[.-10000b], %%eax\n"  \
  "mov  " SYS_SYSCALL_ENTRYPOINT                     \
  "@GOT(%%eax), %%eax\n"                             \
  "mov  0(%%eax), %%eax\n"                           \
  "test %%eax, %%eax\n"                              \
  "jz   10002f\n"                                    \
  "push %%eax\n"                                     \
  "call 10001f\n"                                    \
  "10001:pop  %%eax\n"                               \
  "add  $(10003f-10001b), %%eax\n"                   \
  "xchg 4(%%esp), %%eax\n"                           \
  "ret\n"                                            \
  "10002:pop  %%eax\n"                               \
  "int $0x80\n"                                      \
  "10003:\n"
#else
#define LSS_ENTRYPOINT "int $0x80\n"
#endif
#undef LSS_BODY
#define LSS_BODY(type, args...)                         \
  long __res;                                           \
  __asm__ __volatile__(                                 \
      "push %%ebx\n"                                    \
      "movl %2,%%ebx\n" LSS_ENTRYPOINT "pop %%ebx" args \
      : "esp", "memory");                               \
  LSS_RETURN(type, __res)
#undef _syscall0
#define _syscall0(type, name)            \
  type LSS_NAME(name)(void) {            \
    long __res;                          \
    __asm__ volatile(LSS_ENTRYPOINT      \
                     : "=a"(__res)       \
                     : "0"(__NR_##name)  \
                     : "esp", "memory"); \
    LSS_RETURN(type, __res);             \
  }
#undef _syscall1
#define _syscall1(type, name, type1, arg1)                                \
  type LSS_NAME(name)(type1 arg1) {                                       \
    LSS_BODY(type, : "=a"(__res) : "0"(__NR_##name), "ri"((long)(arg1))); \
  }
#undef _syscall2
#define _syscall2(type, name, type1, arg1, type2, arg2)                  \
  type LSS_NAME(name)(type1 arg1, type2 arg2) {                          \
    LSS_BODY(type,                                                       \
             : "=a"(__res)                                               \
             : "0"(__NR_##name), "ri"((long)(arg1)), "c"((long)(arg2))); \
  }
#undef _syscall3
#define _syscall3(type, name, type1, arg1, type2, arg2, type3, arg3) \
  type LSS_NAME(name)(type1 arg1, type2 arg2, type3 arg3) {          \
    LSS_BODY(type,                                                   \
             : "=a"(__res)                                           \
             : "0"(__NR_##name),                                     \
               "ri"((long)(arg1)),                                   \
               "c"((long)(arg2)),                                    \
               "d"((long)(arg3)));                                   \
  }
#undef _syscall4
#define _syscall4(                                                      \
    type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4)     \
  type LSS_NAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
    LSS_BODY(type,                                                      \
             : "=a"(__res)                                              \
             : "0"(__NR_##name),                                        \
               "ri"((long)(arg1)),                                      \
               "c"((long)(arg2)),                                       \
               "d"((long)(arg3)),                                       \
               "S"((long)(arg4)));                                      \
  }
#undef _syscall5
#define _syscall5(type,                                             \
                  name,                                             \
                  type1,                                            \
                  arg1,                                             \
                  type2,                                            \
                  arg2,                                             \
                  type3,                                            \
                  arg3,                                             \
                  type4,                                            \
                  arg4,                                             \
                  type5,                                            \
                  arg5)                                             \
  type LSS_NAME(name)(                                              \
      type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) { \
    long __res;                                                     \
    __asm__ __volatile__(                                           \
        "push %%ebx\n"                                              \
        "movl %2,%%ebx\n"                                           \
        "movl %1,%%eax\n" LSS_ENTRYPOINT "pop  %%ebx"               \
        : "=a"(__res)                                               \
        : "i"(__NR_##name),                                         \
          "ri"((long)(arg1)),                                       \
          "c"((long)(arg2)),                                        \
          "d"((long)(arg3)),                                        \
          "S"((long)(arg4)),                                        \
          "D"((long)(arg5))                                         \
        : "esp", "memory");                                         \
    LSS_RETURN(type, __res);                                        \
  }
#undef _syscall6
#define _syscall6(type,                  \
                  name,                  \
                  type1,                 \
                  arg1,                  \
                  type2,                 \
                  arg2,                  \
                  type3,                 \
                  arg3,                  \
                  type4,                 \
                  arg4,                  \
                  type5,                 \
                  arg5,                  \
                  type6,                 \
                  arg6)                  \
  type LSS_NAME(name)(type1 arg1,        \
                      type2 arg2,        \
                      type3 arg3,        \
                      type4 arg4,        \
                      type5 arg5,        \
                      type6 arg6) {      \
    long __res;                          \
    struct {                             \
      long __a1;                         \
      long __a6;                         \
    } __s = {(long)arg1, (long)arg6};    \
    __asm__ __volatile__(                \
        "push %%ebp\n"                   \
        "push %%ebx\n"                   \
        "leal 4(%2),%%ebp\n"             \
        "movl 0(%2),%%ebx\n"             \
        "movl %1,%%eax\n" LSS_ENTRYPOINT \
        "pop  %%ebx\n"                   \
        "pop  %%ebp"                     \
        : "=a"(__res)                    \
        : "i"(__NR_##name),              \
          "0"((long)(&__s)),             \
          "c"((long)(arg2)),             \
          "d"((long)(arg3)),             \
          "S"((long)(arg4)),             \
          "D"((long)(arg5))              \
        : "esp", "memory");              \
    LSS_RETURN(type, __res);             \
  }
LSS_INLINE int LSS_NAME(clone)(int (*fn)(void *),
                               void *child_stack,
                               int flags,
                               void *arg,
                               int *parent_tidptr,
                               void *newtls,
                               int *child_tidptr) {
  long __res;
  __asm__ __volatile__(/* if (fn == NULL)
                        *   return -EINVAL;
                        */
                       "movl   %3,%%ecx\n"
                       "jecxz  1f\n"

                       /* if (child_stack == NULL)
                        *   return -EINVAL;
                        */
                       "movl   %4,%%ecx\n"
                       "jecxz  1f\n"

                       /* Set up alignment of the child stack:
                        * child_stack = (child_stack & ~0xF) - 20;
                        */
                       "andl   $-16,%%ecx\n"
                       "subl   $20,%%ecx\n"

                       /* Push "arg" and "fn" onto the stack that will be
                        * used by the child.
                        */
                       "movl   %6,%%eax\n"
                       "movl   %%eax,4(%%ecx)\n"
                       "movl   %3,%%eax\n"
                       "movl   %%eax,(%%ecx)\n"

                       /* %eax = syscall(%eax = __NR_clone,
                        *                %ebx = flags,
                        *                %ecx = child_stack,
                        *                %edx = parent_tidptr,
                        *                %esi = newtls,
                        *                %edi = child_tidptr)
                        * Also, make sure that %ebx gets preserved as it is
                        * used in PIC mode.
                        */
                       "movl   %8,%%esi\n"
                       "movl   %7,%%edx\n"
                       "movl   %5,%%eax\n"
                       "movl   %9,%%edi\n"
                       "pushl  %%ebx\n"
                       "movl   %%eax,%%ebx\n"
                       "movl   %2,%%eax\n" LSS_ENTRYPOINT

                       /* In the parent: restore %ebx
                        * In the child:  move "fn" into %ebx
                        */
                       "popl   %%ebx\n"

                       /* if (%eax != 0)
                        *   return %eax;
                        */
                       "test   %%eax,%%eax\n"
                       "jnz    1f\n"

                       /* In the child, now. Terminate frame pointer chain.
                        */
                       "movl   $0,%%ebp\n"

                       /* Call "fn". "arg" is already on the stack.
                        */
                       "call   *%%ebx\n"

                       /* Call _exit(%ebx). Unfortunately older versions
                        * of gcc restrict the number of arguments that can
                        * be passed to asm(). So, we need to hard-code the
                        * system call number.
                        */
                       "movl   %%eax,%%ebx\n"
                       "movl   $1,%%eax\n" LSS_ENTRYPOINT

                       /* Return to parent.
                        */
                       "1:\n"
                       : "=a"(__res)
                       : "0"(-EINVAL),
                         "i"(__NR_clone),
                         "m"(fn),
                         "m"(child_stack),
                         "m"(flags),
                         "m"(arg),
                         "m"(parent_tidptr),
                         "m"(newtls),
                         "m"(child_tidptr)
                       : "esp", "memory", "ecx", "edx", "esi", "edi");
  LSS_RETURN(int, __res);
}

#define __NR__fadvise64_64 __NR_fadvise64_64
LSS_INLINE _syscall6(int,
                     _fadvise64_64,
                     int,
                     fd,
                     unsigned,
                     offset_lo,
                     unsigned,
                     offset_hi,
                     unsigned,
                     len_lo,
                     unsigned,
                     len_hi,
                     int,
                     advice) LSS_INLINE int LSS_NAME(fadvise64)(int fd,
                                                                loff_t offset,
                                                                loff_t len,
                                                                int advice) {
  return LSS_NAME(_fadvise64_64)(fd,
                                 (unsigned)offset,
                                 (unsigned)(offset >> 32),
                                 (unsigned)len,
                                 (unsigned)(len >> 32),
                                 advice);
}

#define __NR__fallocate __NR_fallocate
LSS_INLINE _syscall6(int,
                     _fallocate,
                     int,
                     fd,
                     int,
                     mode,
                     unsigned,
                     offset_lo,
                     unsigned,
                     offset_hi,
                     unsigned,
                     len_lo,
                     unsigned,
                     len_hi) LSS_INLINE int LSS_NAME(fallocate)(int fd,
                                                                int mode,
                                                                loff_t offset,
                                                                loff_t len) {
  union {
    loff_t off;
    unsigned w[2];
  } o = {offset}, l = {len};
  return LSS_NAME(_fallocate)(fd, mode, o.w[0], o.w[1], l.w[0], l.w[1]);
}

LSS_INLINE _syscall1(int, set_thread_area, void *, u)
    LSS_INLINE _syscall1(int, get_thread_area, void *, u)
    LSS_INLINE void (*LSS_NAME(restore_rt)(void))(void) {
  /* On i386, the kernel does not know how to return from a signal
   * handler. Instead, it relies on user space to provide a
   * restorer function that calls the {rt_,}sigreturn() system call.
   * Unfortunately, we cannot just reference the glibc version of this
   * function, as glibc goes out of its way to make it inaccessible.
   */
  void (*res)(void);
  __asm__ __volatile__(
      "call   2f\n"
      "0:.align 16\n"
      "1:movl   %1,%%eax\n" LSS_ENTRYPOINT
      "2:popl   %0\n"
      "addl   $(1b-0b),%0\n"
      : "=a"(res)
      : "i"(__NR_rt_sigreturn));
  return res;
}
LSS_INLINE void (*LSS_NAME(restore)(void))(void) {
  /* On i386, the kernel does not know how to return from a signal
   * handler. Instead, it relies on user space to provide a
   * restorer function that calls the {rt_,}sigreturn() system call.
   * Unfortunately, we cannot just reference the glibc version of this
   * function, as glibc goes out of its way to make it inaccessible.
   */
  void (*res)(void);
  __asm__ __volatile__(
      "call   2f\n"
      "0:.align 16\n"
      "1:pop    %%eax\n"
      "movl   %1,%%eax\n" LSS_ENTRYPOINT
      "2:popl   %0\n"
      "addl   $(1b-0b),%0\n"
      : "=a"(res)
      : "i"(__NR_sigreturn));
  return res;
}
#elif defined(__x86_64__)
/* There are no known problems with any of the _syscallX() macros
 * currently shipping for x86_64, but we still need to be able to define
 * our own version so that we can override the location of the errno
 * location (e.g. when using the clone() system call with the CLONE_VM
 * option).
 */
#undef LSS_ENTRYPOINT
#ifdef SYS_SYSCALL_ENTRYPOINT
static inline void (**LSS_NAME(get_syscall_entrypoint)(void))(void) {
  void (**entrypoint)(void);
  asm volatile(
      ".bss\n"
      ".align 8\n"
      ".globl " SYS_SYSCALL_ENTRYPOINT
      "\n"
      ".common " SYS_SYSCALL_ENTRYPOINT
      ",8,8\n"
      ".previous\n"
      "mov " SYS_SYSCALL_ENTRYPOINT "@GOTPCREL(%%rip), %0\n"
      : "=r"(entrypoint));
  return entrypoint;
}

#define LSS_ENTRYPOINT              \
  ".bss\n"                          \
  ".align 8\n"                      \
  ".globl " SYS_SYSCALL_ENTRYPOINT  \
  "\n"                              \
  ".common " SYS_SYSCALL_ENTRYPOINT \
  ",8,8\n"                          \
  ".previous\n"                     \
  "mov " SYS_SYSCALL_ENTRYPOINT     \
  "@GOTPCREL(%%rip), %%rcx\n"       \
  "mov  0(%%rcx), %%rcx\n"          \
  "test %%rcx, %%rcx\n"             \
  "jz   10001f\n"                   \
  "call *%%rcx\n"                   \
  "jmp  10002f\n"                   \
  "10001:syscall\n"                 \
  "10002:\n"

#else
#define LSS_ENTRYPOINT "syscall\n"
#endif
#undef LSS_BODY
#define LSS_BODY(type, name, ...)                        \
  long __res;                                            \
  __asm__ __volatile__(LSS_ENTRYPOINT                    \
                       : "=a"(__res)                     \
                       : "0"(__NR_##name), ##__VA_ARGS__ \
                       : "r11", "rcx", "memory");        \
  LSS_RETURN(type, __res)
#undef _syscall0
#define _syscall0(type, name) \
  type LSS_NAME(name)() { LSS_BODY(type, name); }
#undef _syscall1
#define _syscall1(type, name, type1, arg1) \
  type LSS_NAME(name)(type1 arg1) { LSS_BODY(type, name, "D"((long)(arg1))); }
#undef _syscall2
#define _syscall2(type, name, type1, arg1, type2, arg2)         \
  type LSS_NAME(name)(type1 arg1, type2 arg2) {                 \
    LSS_BODY(type, name, "D"((long)(arg1)), "S"((long)(arg2))); \
  }
#undef _syscall3
#define _syscall3(type, name, type1, arg1, type2, arg2, type3, arg3)          \
  type LSS_NAME(name)(type1 arg1, type2 arg2, type3 arg3) {                   \
    LSS_BODY(                                                                 \
        type, name, "D"((long)(arg1)), "S"((long)(arg2)), "d"((long)(arg3))); \
  }
#undef _syscall4
#define _syscall4(                                                      \
    type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4)     \
  type LSS_NAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
    long __res;                                                         \
    __asm__ __volatile__("movq %5,%%r10;" LSS_ENTRYPOINT                \
                         : "=a"(__res)                                  \
                         : "0"(__NR_##name),                            \
                           "D"((long)(arg1)),                           \
                           "S"((long)(arg2)),                           \
                           "d"((long)(arg3)),                           \
                           "r"((long)(arg4))                            \
                         : "r10", "r11", "rcx", "memory");              \
    LSS_RETURN(type, __res);                                            \
  }
#undef _syscall5
#define _syscall5(type,                                                \
                  name,                                                \
                  type1,                                               \
                  arg1,                                                \
                  type2,                                               \
                  arg2,                                                \
                  type3,                                               \
                  arg3,                                                \
                  type4,                                               \
                  arg4,                                                \
                  type5,                                               \
                  arg5)                                                \
  type LSS_NAME(name)(                                                 \
      type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {    \
    long __res;                                                        \
    __asm__ __volatile__("movq %5,%%r10; movq %6,%%r8;" LSS_ENTRYPOINT \
                         : "=a"(__res)                                 \
                         : "0"(__NR_##name),                           \
                           "D"((long)(arg1)),                          \
                           "S"((long)(arg2)),                          \
                           "d"((long)(arg3)),                          \
                           "r"((long)(arg4)),                          \
                           "r"((long)(arg5))                           \
                         : "r8", "r10", "r11", "rcx", "memory");       \
    LSS_RETURN(type, __res);                                           \
  }
#undef _syscall6
#define _syscall6(type,                                             \
                  name,                                             \
                  type1,                                            \
                  arg1,                                             \
                  type2,                                            \
                  arg2,                                             \
                  type3,                                            \
                  arg3,                                             \
                  type4,                                            \
                  arg4,                                             \
                  type5,                                            \
                  arg5,                                             \
                  type6,                                            \
                  arg6)                                             \
  type LSS_NAME(name)(type1 arg1,                                   \
                      type2 arg2,                                   \
                      type3 arg3,                                   \
                      type4 arg4,                                   \
                      type5 arg5,                                   \
                      type6 arg6) {                                 \
    long __res;                                                     \
    __asm__ __volatile__(                                           \
        "movq %5,%%r10; movq %6,%%r8; movq %7,%%r9;" LSS_ENTRYPOINT \
        : "=a"(__res)                                               \
        : "0"(__NR_##name),                                         \
          "D"((long)(arg1)),                                        \
          "S"((long)(arg2)),                                        \
          "d"((long)(arg3)),                                        \
          "r"((long)(arg4)),                                        \
          "r"((long)(arg5)),                                        \
          "r"((long)(arg6))                                         \
        : "r8", "r9", "r10", "r11", "rcx", "memory");               \
    LSS_RETURN(type, __res);                                        \
  }
LSS_INLINE int LSS_NAME(clone)(int (*fn)(void *),
                               void *child_stack,
                               int flags,
                               void *arg,
                               int *parent_tidptr,
                               void *newtls,
                               int *child_tidptr) {
  long __res;
  {
    __asm__ __volatile__(/* if (fn == NULL)
                          *   return -EINVAL;
                          */
                         "testq  %4,%4\n"
                         "jz     1f\n"

                         /* if (child_stack == NULL)
                          *   return -EINVAL;
                          */
                         "testq  %5,%5\n"
                         "jz     1f\n"

                         /* childstack -= 2*sizeof(void *);
                          */
                         "subq   $16,%5\n"

                         /* Push "arg" and "fn" onto the stack that will be
                          * used by the child.
                          */
                         "movq   %7,8(%5)\n"
                         "movq   %4,0(%5)\n"

                         /* %rax = syscall(%rax = __NR_clone,
                          *                %rdi = flags,
                          *                %rsi = child_stack,
                          *                %rdx = parent_tidptr,
                          *                %r8  = new_tls,
                          *                %r10 = child_tidptr)
                          */
                         "movq   %2,%%rax\n"
                         "movq   %9,%%r8\n"
                         "movq   %10,%%r10\n" LSS_ENTRYPOINT

                         /* if (%rax != 0)
                          *   return;
                          */
                         "testq  %%rax,%%rax\n"
                         "jnz    1f\n"

                         /* In the child. Terminate frame pointer chain.
                          */
                         "xorq   %%rbp,%%rbp\n"

                         /* Call "fn(arg)".
                          */
                         "popq   %%rax\n"
                         "popq   %%rdi\n"
                         "call   *%%rax\n"

                         /* Call _exit(%ebx).
                          */
                         "movq   %%rax,%%rdi\n"
                         "movq   %3,%%rax\n" LSS_ENTRYPOINT

                         /* Return to parent.
                          */
                         "1:\n"
                         : "=a"(__res)
                         : "0"(-EINVAL),
                           "i"(__NR_clone),
                           "i"(__NR_exit),
                           "r"(fn),
                           "S"(child_stack),
                           "D"(flags),
                           "r"(arg),
                           "d"(parent_tidptr),
                           "r"(newtls),
                           "r"(child_tidptr)
                         : "rsp", "memory", "r8", "r10", "r11", "rcx");
  }
  LSS_RETURN(int, __res);
}
LSS_INLINE _syscall2(int, arch_prctl, int, c, void *, a) LSS_INLINE _syscall4(
    int,
    fadvise64,
    int,
    fd,
    loff_t,
    offset,
    loff_t,
    len,
    int,
    advice) LSS_INLINE void (*LSS_NAME(restore_rt)(void))(void) {
  /* On x86-64, the kernel does not know how to return from
   * a signal handler. Instead, it relies on user space to provide a
   * restorer function that calls the rt_sigreturn() system call.
   * Unfortunately, we cannot just reference the glibc version of this
   * function, as glibc goes out of its way to make it inaccessible.
   */
  void (*res)(void);
  __asm__ __volatile__(
      "jmp    2f\n"
      ".align 16\n"
      "1:movq   %1,%%rax\n" LSS_ENTRYPOINT "2:leaq   1b(%%rip),%0\n"
      : "=r"(res)
      : "i"(__NR_rt_sigreturn));
  return res;
}
#endif
#define __NR__exit __NR_exit
#define __NR__gettid __NR_gettid
#define __NR__mremap __NR_mremap
LSS_INLINE _syscall2(int, access, const char *, p, int, m)
#if defined(__NR_faccessat)
    LSS_INLINE _syscall3(int, faccessat, int, dfd, const char *, filename, int, mode)
#endif
    LSS_INLINE _syscall1(unsigned int, alarm, unsigned int, seconds)
    LSS_INLINE _syscall1(void *, brk, void *, e)
    LSS_INLINE _syscall1(int, chdir, const char *, p)
    LSS_INLINE _syscall1(int, close, int, f)
    LSS_INLINE _syscall2(int, clock_getres, int, c, struct kernel_timespec *, t)
    LSS_INLINE _syscall2(int,
                         clock_gettime,
                         int,
                         c,
                         struct kernel_timespec *,
                         t) LSS_INLINE _syscall1(int, dup, int, f)
    LSS_INLINE _syscall2(int, dup2, int, s, int, d)
    LSS_INLINE _syscall3(int, dup3, int, s, int, d, int, f)
    LSS_INLINE _syscall1(int, epoll_create, int, s)
    LSS_INLINE _syscall1(int, epoll_create1, int, f)
    LSS_INLINE _syscall4(int, epoll_ctl, int, e, int, o, int, f, struct kernel_epoll_event *, ev)
    LSS_INLINE _syscall4(int, epoll_wait, int, e, struct kernel_epoll_event*, ev, int, m, int, t)
    LSS_INLINE _syscall5(int, epoll_pwait, int, e, struct kernel_epoll_event*, ev, int, m, int, t, const sigset_t*, sigmask)
    LSS_INLINE _syscall3(int,
                         execve,
                         const char *,
                         f,
                         const char *const *,
                         a,
                         const char *const *,
                         e) LSS_INLINE _syscall1(int, _exit, int, e)
    LSS_INLINE _syscall1(int, exit_group, int, e)
    LSS_INLINE _syscall3(int, fcntl, int, f, int, c, long, a)
    LSS_INLINE _syscall1(int, fdatasync, int, f)
    LSS_INLINE _syscall2(int, flock, int, f, int, o) LSS_INLINE _syscall0(pid_t,
                                                                          fork)
    LSS_INLINE _syscall2(int, fstat, int, f, struct kernel_stat *, b)
    LSS_INLINE _syscall2(int, fstatfs, int, f, struct kernel_statfs *, b)
    LSS_INLINE _syscall1(int, fsync, int, f)
    LSS_INLINE _syscall2(int, ftruncate, int, f, off_t, l) LSS_INLINE _syscall6(
        int,
        futex,
        int *,
        a,
        int,
        o,
        int,
        v,
        struct kernel_timespec *,
        t,
        int *,
        a2,
        int,
        v3) LSS_INLINE _syscall2(int, getcwd, char *, b, size_t, s)
    LSS_INLINE _syscall3(int,
                         getdents,
                         int,
                         f,
                         struct kernel_dirent *,
                         d,
                         int,
                         c) LSS_INLINE _syscall3(int,
                                                 getdents64,
                                                 int,
                                                 f,
                                                 struct kernel_dirent64 *,
                                                 d,
                                                 int,
                                                 c)
    LSS_INLINE _syscall0(gid_t, getegid) LSS_INLINE _syscall0(gid_t, getgid)
    LSS_INLINE _syscall0(uid_t, geteuid) LSS_INLINE _syscall0(uid_t, getuid)
    LSS_INLINE _syscall0(pid_t, getpgrp) LSS_INLINE _syscall0(pid_t, getpid)
    LSS_INLINE _syscall0(pid_t, getppid)
    LSS_INLINE _syscall2(int, getpriority, int, a, int, b)
    LSS_INLINE _syscall3(int, getresgid, gid_t *, r, gid_t *, e, gid_t *, s)
    LSS_INLINE _syscall3(int, getresuid, uid_t *, r, uid_t *, e, uid_t *, s)
    LSS_INLINE _syscall2(int, getrlimit, int, r, struct kernel_rlimit *, l)
    LSS_INLINE _syscall1(pid_t, getsid, pid_t, p)
    LSS_INLINE _syscall0(pid_t, _gettid) LSS_INLINE _syscall2(
        pid_t,
        gettimeofday,
        struct kernel_timeval *,
        t,
        void *,
        tz) LSS_INLINE _syscall5(int,
                                 setxattr,
                                 const char *,
                                 p,
                                 const char *,
                                 n,
                                 const void *,
                                 v,
                                 size_t,
                                 s,
                                 int,
                                 f) LSS_INLINE _syscall5(int,
                                                         lsetxattr,
                                                         const char *,
                                                         p,
                                                         const char *,
                                                         n,
                                                         const void *,
                                                         v,
                                                         size_t,
                                                         s,
                                                         int,
                                                         f)
    LSS_INLINE _syscall4(ssize_t,
                         getxattr,
                         const char *,
                         p,
                         const char *,
                         n,
                         void *,
                         v,
                         size_t,
                         s) LSS_INLINE _syscall4(ssize_t,
                                                 lgetxattr,
                                                 const char *,
                                                 p,
                                                 const char *,
                                                 n,
                                                 void *,
                                                 v,
                                                 size_t,
                                                 s)
    LSS_INLINE _syscall3(ssize_t,
                         listxattr,
                         const char *,
                         p,
                         char *,
                         l,
                         size_t,
                         s) LSS_INLINE _syscall3(ssize_t,
                                                 llistxattr,
                                                 const char *,
                                                 p,
                                                 char *,
                                                 l,
                                                 size_t,
                                                 s)
    LSS_INLINE _syscall3(int, ioctl, int, d, int, r, void *, a)
    LSS_INLINE _syscall2(int, ioprio_get, int, which, int, who)
    LSS_INLINE _syscall3(int, ioprio_set, int, which, int, who, int, ioprio)
    LSS_INLINE _syscall2(int, kill, pid_t, p, int, s)
    LSS_INLINE _syscall3(off_t, lseek, int, f, off_t, o, int, w)
    LSS_INLINE _syscall2(int, lstat, const char *, f, struct kernel_stat *, b)
    LSS_INLINE _syscall6(long,
                         move_pages,
                         pid_t,
                         p,
                         unsigned long,
                         n,
                         void **,
                         g,
                         int *,
                         d,
                         int *,
                         s,
                         int,
                         f)
    LSS_INLINE _syscall2(int, mkdir, const char *, p, int, m)
    LSS_INLINE _syscall3(int, mprotect, const void *, a, size_t, l, int, p)
    LSS_INLINE _syscall5(void *,
                         _mremap,
                         void *,
                         o,
                         size_t,
                         os,
                         size_t,
                         ns,
                         unsigned long,
                         f,
                         void *,
                         a)
    LSS_INLINE _syscall2(int, munmap, void *, s, size_t, l)
    LSS_INLINE _syscall2(int,
                         nanosleep,
                         const struct kernel_timespec *,
                         req,
                         struct kernel_timespec *,
                         rem)
    LSS_INLINE _syscall3(int, open, const char *, p, int, f, int, m)
    LSS_INLINE _syscall3(int,
                         poll,
                         struct kernel_pollfd *,
                         u,
                         unsigned int,
                         n,
                         int,
                         t) LSS_INLINE _syscall5(int,
                                                 prctl,
                                                 int,
                                                 o,
                                                 unsigned long,
                                                 arg2,
                                                 unsigned long,
                                                 arg3,
                                                 unsigned long,
                                                 arg4,
                                                 unsigned long,
                                                 arg5)
    LSS_INLINE _syscall4(long, ptrace, int, r, pid_t, p, void *, a, void *, d)
#if defined(__NR_quotactl)
    // Defined on x86_64 / i386 only
    LSS_INLINE _syscall4(int,
                         quotactl,
                         int,
                         cmd,
                         const char *,
                         special,
                         int,
                         id,
                         caddr_t,
                         addr)
#endif
    LSS_INLINE _syscall3(ssize_t, read, int, f, void *, b, size_t, c)
    LSS_INLINE _syscall3(ssize_t,
                         readv,
                         int,
                         f,
                         const struct kernel_iovec *,
                         v,
                         size_t,
                         c)
    LSS_INLINE _syscall3(int, readlink, const char *, p, char *, b, size_t, s)
    LSS_INLINE _syscall2(int, rename, const char *, o, const char *, n)
    LSS_INLINE _syscall4(int,
                         rt_sigaction,
                         int,
                         s,
                         const struct kernel_sigaction *,
                         a,
                         struct kernel_sigaction *,
                         o,
                         size_t,
                         c) LSS_INLINE _syscall2(int,
                                                 rt_sigpending,
                                                 struct kernel_sigset_t *,
                                                 s,
                                                 size_t,
                                                 c)
    LSS_INLINE _syscall4(int,
                         rt_sigprocmask,
                         int,
                         h,
                         const struct kernel_sigset_t *,
                         s,
                         struct kernel_sigset_t *,
                         o,
                         size_t,
                         c) LSS_INLINE _syscall2(int,
                                                 rt_sigsuspend,
                                                 const struct kernel_sigset_t *,
                                                 s,
                                                 size_t,
                                                 c)
    LSS_INLINE _syscall3(int,
                         sched_getaffinity,
                         pid_t,
                         p,
                         unsigned int,
                         l,
                         unsigned long *,
                         m) LSS_INLINE _syscall3(int,
                                                 sched_setaffinity,
                                                 pid_t,
                                                 p,
                                                 unsigned int,
                                                 l,
                                                 unsigned long *,
                                                 m)
    LSS_INLINE _syscall0(int, sched_yield) LSS_INLINE _syscall5(
        int,
        select,
        int,
        n,
        struct kernel_fd_set *,
        r,
        struct kernel_fd_set *,
        w,
        struct kernel_fd_set *,
        e,
        struct kernel_timeval *,
        t) LSS_INLINE _syscall1(long, set_tid_address, int *, t)
    LSS_INLINE _syscall1(int, setfsgid, gid_t, g)
    LSS_INLINE _syscall1(int, setfsuid, uid_t, u)
    LSS_INLINE _syscall1(int, setuid, uid_t, u)
    LSS_INLINE _syscall1(int, setgid, gid_t, g)
    LSS_INLINE _syscall2(int, setpgid, pid_t, p, pid_t, g)
    LSS_INLINE _syscall3(int, setpriority, int, a, int, b, int, p)
    LSS_INLINE _syscall3(int, setresgid, gid_t, r, gid_t, e, gid_t, s)
    LSS_INLINE _syscall3(int, setresuid, uid_t, r, uid_t, e, uid_t, s)
    LSS_INLINE _syscall2(int,
                         setrlimit,
                         int,
                         r,
                         const struct kernel_rlimit *,
                         l) LSS_INLINE _syscall0(pid_t, setsid)
    LSS_INLINE _syscall3(void *, shmat, int, i, const void *, a, int, f)
    LSS_INLINE _syscall3(int,
                         shmctl,
                         int,
                         i,
                         int,
                         c,
                         struct kernel_shmid_ds *,
                         b) LSS_INLINE _syscall1(int, shmdt, const void *, a)
    LSS_INLINE _syscall3(int, shmget, int, k, size_t, s, int, f)
    LSS_INLINE _syscall2(int,
                         sigaltstack,
                         const struct kernel_stack_t *,
                         s,
                         const struct kernel_stack_t *,
                         o)
#if defined(__NR_sigreturn)
    LSS_INLINE _syscall1(int, sigreturn, unsigned long, u)
#endif
    LSS_INLINE _syscall2(int, stat, const char *, f, struct kernel_stat *, b)
    LSS_INLINE _syscall2(int,
                         statfs,
                         const char *,
                         f,
                         struct kernel_statfs *,
                         b)
    LSS_INLINE _syscall3(int, tgkill, pid_t, p, pid_t, t, int, s)
    LSS_INLINE _syscall1(long, time, long *, t)
    LSS_INLINE _syscall1(clock_t, times, struct kernel_tms *, b)
    LSS_INLINE _syscall2(int, tkill, pid_t, p, int, s)
    LSS_INLINE _syscall1(int, umask, int, mask)
    LSS_INLINE _syscall2(int, link, const char *, oldf, const char *, newf)
    LSS_INLINE _syscall2(int, symlink, const char *, oldf, const char *, newf)
    LSS_INLINE _syscall1(int, unlink, const char *, f)
    LSS_INLINE _syscall1(int, uname, struct kernel_utsname *, buf)
    LSS_INLINE _syscall3(ssize_t, write, int, f, const void *, b, size_t, c)
    LSS_INLINE _syscall3(ssize_t,
                         writev,
                         int,
                         f,
                         const struct kernel_iovec *,
                         v,
                         size_t,
                         c)
#if defined(__NR_getcpu)
    LSS_INLINE _syscall3(long,
                         getcpu,
                         unsigned *,
                         cpu,
                         unsigned *,
                         node,
                         void *,
                         unused)
#endif
#if defined(__NR_getrandom)
    LSS_INLINE _syscall3(int,
                         getrandom,
                         void*,
                         buf,
                         size_t,
                         buflen,
                         unsigned int,
                         flags)
#endif
#if defined(__x86_64__)
    LSS_INLINE _syscall3(int,
                         accept,
                         int,
                         s,
                         struct kernel_sockaddr *,
                         a,
                         unsigned int *,
                         l) LSS_INLINE _syscall4(int,
                                                 accept4,
                                                 int,
                                                 s,
                                                 struct kernel_sockaddr *,
                                                 a,
                                                 unsigned int *,
                                                 l,
                                                 int,
                                                 f)
    LSS_INLINE _syscall3(int,
                         bind,
                         int,
                         s,
                         const struct kernel_sockaddr *,
                         a,
                         unsigned int,
                         l) LSS_INLINE _syscall3(int,
                                                 connect,
                                                 int,
                                                 s,
                                                 const struct kernel_sockaddr *,
                                                 a,
                                                 unsigned int,
                                                 l)
    LSS_INLINE _syscall3(int,
                         getpeername,
                         int,
                         s,
                         struct kernel_sockaddr *,
                         a,
                         unsigned int *,
                         l) LSS_INLINE _syscall3(int,
                                                 getsockname,
                                                 int,
                                                 s,
                                                 struct kernel_sockaddr *,
                                                 a,
                                                 unsigned int *,
                                                 l)
    LSS_INLINE _syscall5(int,
                         getsockopt,
                         int,
                         s,
                         int,
                         l,
                         int,
                         n,
                         void *,
                         v,
                         unsigned int *,
                         o) LSS_INLINE _syscall2(int, listen, int, s, int, l)
    LSS_INLINE _syscall3(ssize_t,
                         recvmsg,
                         int,
                         s,
                         struct kernel_msghdr *,
                         m,
                         int,
                         f) LSS_INLINE _syscall6(ssize_t,
                                                 recvfrom,
                                                 int,
                                                 s,
                                                 void *,
                                                 b,
                                                 size_t,
                                                 l,
                                                 int,
                                                 f,
                                                 struct kernel_sockaddr *,
                                                 a,
                                                 unsigned int *,
                                                 t)
    LSS_INLINE _syscall4(ssize_t,
                         sendmmsg,
                         int,
                         s,
                         const struct kernel_mmsghdr *,
                         m,
                         int,
                         vlen,
                         int,
                         f)
    LSS_INLINE _syscall3(ssize_t,
                         sendmsg,
                         int,
                         s,
                         const struct kernel_msghdr *,
                         m,
                         int,
                         f) LSS_INLINE _syscall6(ssize_t,
                                                 sendto,
                                                 int,
                                                 s,
                                                 const void *,
                                                 m,
                                                 size_t,
                                                 l,
                                                 int,
                                                 f,
                                                 const struct kernel_sockaddr *,
                                                 a,
                                                 unsigned int,
                                                 t)
    LSS_INLINE _syscall5(int,
                         setsockopt,
                         int,
                         s,
                         int,
                         l,
                         int,
                         n,
                         const void *,
                         v,
                         unsigned int,
                         o) LSS_INLINE _syscall2(int, shutdown, int, s, int, h)
    LSS_INLINE _syscall3(int, socket, int, d, int, t, int, p)
    LSS_INLINE _syscall4(int, socketpair, int, d, int, t, int, p, int *, s)
#endif
    LSS_INLINE _syscall4(ssize_t,
                         sendfile,
                         int,
                         i,
                         int,
                         o,
                         off_t *,
                         off,
                         size_t,
                         c)
#if defined(__x86_64__)
    LSS_INLINE _syscall4(int,
                         fallocate,
                         int,
                         fd,
                         int,
                         mode,
                         loff_t,
                         offset,
                         loff_t,
                         len)
    LSS_INLINE int LSS_NAME(getresgid32)(gid_t *rgid,
                                         gid_t *egid,
                                         gid_t *sgid) {
  return LSS_NAME(getresgid)(rgid, egid, sgid);
}

LSS_INLINE int LSS_NAME(getresuid32)(uid_t *ruid, uid_t *euid, uid_t *suid) {
  return LSS_NAME(getresuid)(ruid, euid, suid);
}

LSS_INLINE _syscall6(void *,
                     mmap,
                     void *,
                     s,
                     size_t,
                     l,
                     int,
                     p,
                     int,
                     f,
                     int,
                     d,
                     int64_t,
                     o) LSS_INLINE _syscall4(int,
                                             newfstatat,
                                             int,
                                             d,
                                             const char *,
                                             p,
                                             struct kernel_stat *,
                                             b,
                                             int,
                                             f)
    LSS_INLINE int LSS_NAME(setfsgid32)(gid_t gid) {
  return LSS_NAME(setfsgid)(gid);
}

LSS_INLINE int LSS_NAME(setfsuid32)(uid_t uid) {
  return LSS_NAME(setfsuid)(uid);
}

LSS_INLINE int LSS_NAME(setresgid32)(gid_t rgid, gid_t egid, gid_t sgid) {
  return LSS_NAME(setresgid)(rgid, egid, sgid);
}

LSS_INLINE int LSS_NAME(setresuid32)(uid_t ruid, uid_t euid, uid_t suid) {
  return LSS_NAME(setresuid)(ruid, euid, suid);
}

LSS_INLINE int LSS_NAME(sigaction)(int signum,
                                   const struct kernel_sigaction *act,
                                   struct kernel_sigaction *oldact) {
  /* On x86_64, the kernel requires us to always set our own
   * SA_RESTORER in order to be able to return from a signal handler.
   * This function must have a "magic" signature that the "gdb"
   * (and maybe the kernel?) can recognize.
   */
  if (act != NULL && !(act->sa_flags & SA_RESTORER)) {
    struct kernel_sigaction a = *act;
    a.sa_flags |= SA_RESTORER;
    a.sa_restorer = LSS_NAME(restore_rt)();
    return LSS_NAME(rt_sigaction)(signum, &a, oldact, (KERNEL_NSIG + 7) / 8);
  } else {
    return LSS_NAME(rt_sigaction)(signum, act, oldact, (KERNEL_NSIG + 7) / 8);
  }
}

LSS_INLINE int LSS_NAME(sigpending)(struct kernel_sigset_t *set) {
  return LSS_NAME(rt_sigpending)(set, (KERNEL_NSIG + 7) / 8);
}

LSS_INLINE int LSS_NAME(sigprocmask)(int how,
                                     const struct kernel_sigset_t *set,
                                     struct kernel_sigset_t *oldset) {
  return LSS_NAME(rt_sigprocmask)(how, set, oldset, (KERNEL_NSIG + 7) / 8);
}

LSS_INLINE int LSS_NAME(sigsuspend)(const struct kernel_sigset_t *set) {
  return LSS_NAME(rt_sigsuspend)(set, (KERNEL_NSIG + 7) / 8);
}
#endif
#if defined(__x86_64__)
LSS_INLINE
_syscall4(pid_t, wait4, pid_t, p, int *, s, int, o, struct kernel_rusage *, r)
    LSS_INLINE pid_t LSS_NAME(waitpid)(pid_t pid, int *status, int options) {
  return LSS_NAME(wait4)(pid, status, options, 0);
}
#endif
LSS_INLINE _syscall4(int, openat, int, d, const char *, p, int, f, int, m)
    LSS_INLINE _syscall3(int, unlinkat, int, d, const char *, p, int, f)
#if defined(__i386__)
#define __NR__getresgid32 __NR_getresgid32
#define __NR__getresuid32 __NR_getresuid32
#define __NR__setfsgid32 __NR_setfsgid32
#define __NR__setfsuid32 __NR_setfsuid32
#define __NR__setresgid32 __NR_setresgid32
#define __NR__setresuid32 __NR_setresuid32
    LSS_INLINE _syscall3(int, _getresgid32, gid_t *, r, gid_t *, e, gid_t *, s)
    LSS_INLINE _syscall3(int, _getresuid32, uid_t *, r, uid_t *, e, uid_t *, s)
    LSS_INLINE _syscall1(int, _setfsgid32, gid_t, f)
    LSS_INLINE _syscall1(int, _setfsuid32, uid_t, f)
    LSS_INLINE _syscall3(int, _setresgid32, gid_t, r, gid_t, e, gid_t, s)
    LSS_INLINE _syscall3(int, _setresuid32, uid_t, r, uid_t, e, uid_t, s)
    LSS_INLINE int LSS_NAME(getresgid32)(gid_t *rgid,
                                         gid_t *egid,
                                         gid_t *sgid) {
  int rc;
  if ((rc = LSS_NAME(_getresgid32)(rgid, egid, sgid)) < 0 &&
      LSS_ERRNO == ENOSYS) {
    if ((rgid == NULL) || (egid == NULL) || (sgid == NULL)) {
      return EFAULT;
    }
    // Clear the high bits first, since getresgid only sets 16 bits
    *rgid = *egid = *sgid = 0;
    rc = LSS_NAME(getresgid)(rgid, egid, sgid);
  }
  return rc;
}

LSS_INLINE int LSS_NAME(getresuid32)(uid_t *ruid, uid_t *euid, uid_t *suid) {
  int rc;
  if ((rc = LSS_NAME(_getresuid32)(ruid, euid, suid)) < 0 &&
      LSS_ERRNO == ENOSYS) {
    if ((ruid == NULL) || (euid == NULL) || (suid == NULL)) {
      return EFAULT;
    }
    // Clear the high bits first, since getresuid only sets 16 bits
    *ruid = *euid = *suid = 0;
    rc = LSS_NAME(getresuid)(ruid, euid, suid);
  }
  return rc;
}

LSS_INLINE int LSS_NAME(setfsgid32)(gid_t gid) {
  int rc;
  if ((rc = LSS_NAME(_setfsgid32)(gid)) < 0 && LSS_ERRNO == ENOSYS) {
    if ((unsigned int)gid & ~0xFFFFu) {
      rc = EINVAL;
    } else {
      rc = LSS_NAME(setfsgid)(gid);
    }
  }
  return rc;
}

LSS_INLINE int LSS_NAME(setfsuid32)(uid_t uid) {
  int rc;
  if ((rc = LSS_NAME(_setfsuid32)(uid)) < 0 && LSS_ERRNO == ENOSYS) {
    if ((unsigned int)uid & ~0xFFFFu) {
      rc = EINVAL;
    } else {
      rc = LSS_NAME(setfsuid)(uid);
    }
  }
  return rc;
}

LSS_INLINE int LSS_NAME(setresgid32)(gid_t rgid, gid_t egid, gid_t sgid) {
  int rc;
  if ((rc = LSS_NAME(_setresgid32)(rgid, egid, sgid)) < 0 &&
      LSS_ERRNO == ENOSYS) {
    if ((unsigned int)rgid & ~0xFFFFu || (unsigned int)egid & ~0xFFFFu ||
        (unsigned int)sgid & ~0xFFFFu) {
      rc = EINVAL;
    } else {
      rc = LSS_NAME(setresgid)(rgid, egid, sgid);
    }
  }
  return rc;
}

LSS_INLINE int LSS_NAME(setresuid32)(uid_t ruid, uid_t euid, uid_t suid) {
  int rc;
  if ((rc = LSS_NAME(_setresuid32)(ruid, euid, suid)) < 0 &&
      LSS_ERRNO == ENOSYS) {
    if ((unsigned int)ruid & ~0xFFFFu || (unsigned int)euid & ~0xFFFFu ||
        (unsigned int)suid & ~0xFFFFu) {
      rc = EINVAL;
    } else {
      rc = LSS_NAME(setresuid)(ruid, euid, suid);
    }
  }
  return rc;
}
#endif
LSS_INLINE int LSS_NAME(sigemptyset)(struct kernel_sigset_t *set) {
  memset(&set->sig, 0, sizeof(set->sig));
  return 0;
}

LSS_INLINE int LSS_NAME(sigfillset)(struct kernel_sigset_t *set) {
  memset(&set->sig, -1, sizeof(set->sig));
  return 0;
}

LSS_INLINE int LSS_NAME(sigaddset)(struct kernel_sigset_t *set, int signum) {
  if (signum < 1 || signum > (int)(8 * sizeof(set->sig))) {
    LSS_ERRNO = EINVAL;
    return -1;
  } else {
    set->sig[(signum - 1) / (8 * sizeof(set->sig[0]))] |=
        1UL << ((signum - 1) % (8 * sizeof(set->sig[0])));
    return 0;
  }
}

LSS_INLINE int LSS_NAME(sigdelset)(struct kernel_sigset_t *set, int signum) {
  if (signum < 1 || signum > (int)(8 * sizeof(set->sig))) {
    LSS_ERRNO = EINVAL;
    return -1;
  } else {
    set->sig[(signum - 1) / (8 * sizeof(set->sig[0]))] &=
        ~(1UL << ((signum - 1) % (8 * sizeof(set->sig[0]))));
    return 0;
  }
}

LSS_INLINE int LSS_NAME(sigismember)(struct kernel_sigset_t *set, int signum) {
  if (signum < 1 || signum > (int)(8 * sizeof(set->sig))) {
    LSS_ERRNO = EINVAL;
    return -1;
  } else {
    return !!(set->sig[(signum - 1) / (8 * sizeof(set->sig[0]))] &
              (1UL << ((signum - 1) % (8 * sizeof(set->sig[0])))));
  }
}
#if defined(__i386__)
#define __NR__sigaction __NR_sigaction
#define __NR__sigpending __NR_sigpending
#define __NR__sigprocmask __NR_sigprocmask
#define __NR__sigsuspend __NR_sigsuspend
#define __NR__socketcall __NR_socketcall
LSS_INLINE _syscall2(int, fstat64, int, f, struct kernel_stat64 *, b)
    LSS_INLINE _syscall5(int,
                         _llseek,
                         uint,
                         fd,
                         unsigned long,
                         hi,
                         unsigned long,
                         lo,
                         loff_t *,
                         res,
                         uint,
                         wh) LSS_INLINE _syscall1(void *, mmap, void *, a)
    LSS_INLINE _syscall6(void *,
                         mmap2,
                         void *,
                         s,
                         size_t,
                         l,
                         int,
                         p,
                         int,
                         f,
                         int,
                         d,
                         off_t,
                         o)
    LSS_INLINE _syscall3(int,
                         _sigaction,
                         int,
                         s,
                         const struct kernel_old_sigaction *,
                         a,
                         struct kernel_old_sigaction *,
                         o)
    LSS_INLINE _syscall1(int, _sigpending, unsigned long *, s)
    LSS_INLINE _syscall3(int,
                         _sigprocmask,
                         int,
                         h,
                         const unsigned long *,
                         s,
                         unsigned long *,
                         o) LSS_INLINE _syscall3(int,
                                                 _sigsuspend,
                                                 const void *,
                                                 a,
                                                 int,
                                                 b,
                                                 unsigned long,
                                                 s)
    LSS_INLINE _syscall2(int,
                         stat64,
                         const char *,
                         p,
                         struct kernel_stat64 *,
                         b)
    LSS_INLINE int LSS_NAME(sigaction)(int signum,
                                       const struct kernel_sigaction *act,
                                       struct kernel_sigaction *oldact) {
  int old_errno = LSS_ERRNO;
  int rc;
  struct kernel_sigaction a;
  if (act != NULL) {
    a = *act;
#ifdef __i386__
    /* On i386, the kernel requires us to always set our own
     * SA_RESTORER when using realtime signals. Otherwise, it does not
     * know how to return from a signal handler. This function must have
     * a "magic" signature that the "gdb" (and maybe the kernel?) can
     * recognize.
     * Apparently, a SA_RESTORER is implicitly set by the kernel, when
     * using non-realtime signals.
     */
    if (!(a.sa_flags & SA_RESTORER)) {
      a.sa_flags |= SA_RESTORER;
      a.sa_restorer = (a.sa_flags & SA_SIGINFO) ? LSS_NAME(restore_rt)()
                                                : LSS_NAME(restore)();
    }
#endif
  }
  rc = LSS_NAME(rt_sigaction)(
      signum, act ? &a : act, oldact, (KERNEL_NSIG + 7) / 8);
  if (rc < 0 && LSS_ERRNO == ENOSYS) {
    struct kernel_old_sigaction oa, ooa, *ptr_a = &oa, *ptr_oa = &ooa;
    if (!act) {
      ptr_a = NULL;
    } else {
      oa.sa_handler_ = act->sa_handler_;
      memcpy(&oa.sa_mask, &act->sa_mask, sizeof(oa.sa_mask));
      oa.sa_restorer = act->sa_restorer;
      oa.sa_flags = act->sa_flags;
    }
    if (!oldact) {
      ptr_oa = NULL;
    }
    LSS_ERRNO = old_errno;
    rc = LSS_NAME(_sigaction)(signum, ptr_a, ptr_oa);
    if (rc == 0 && oldact) {
      if (act) {
        memcpy(oldact, act, sizeof(*act));
      } else {
        memset(oldact, 0, sizeof(*oldact));
      }
      oldact->sa_handler_ = ptr_oa->sa_handler_;
      oldact->sa_flags = ptr_oa->sa_flags;
      memcpy(&oldact->sa_mask, &ptr_oa->sa_mask, sizeof(ptr_oa->sa_mask));
      oldact->sa_restorer = ptr_oa->sa_restorer;
    }
  }
  return rc;
}

LSS_INLINE int LSS_NAME(sigpending)(struct kernel_sigset_t *set) {
  int old_errno = LSS_ERRNO;
  int rc = LSS_NAME(rt_sigpending)(set, (KERNEL_NSIG + 7) / 8);
  if (rc < 0 && LSS_ERRNO == ENOSYS) {
    LSS_ERRNO = old_errno;
    LSS_NAME(sigemptyset)(set);
    rc = LSS_NAME(_sigpending)(&set->sig[0]);
  }
  return rc;
}

LSS_INLINE int LSS_NAME(sigprocmask)(int how,
                                     const struct kernel_sigset_t *set,
                                     struct kernel_sigset_t *oldset) {
  int olderrno = LSS_ERRNO;
  int rc = LSS_NAME(rt_sigprocmask)(how, set, oldset, (KERNEL_NSIG + 7) / 8);
  if (rc < 0 && LSS_ERRNO == ENOSYS) {
    LSS_ERRNO = olderrno;
    if (oldset) {
      LSS_NAME(sigemptyset)(oldset);
    }
    rc = LSS_NAME(_sigprocmask)(
        how, set ? &set->sig[0] : NULL, oldset ? &oldset->sig[0] : NULL);
  }
  return rc;
}

LSS_INLINE int LSS_NAME(sigsuspend)(const struct kernel_sigset_t *set) {
  int olderrno = LSS_ERRNO;
  int rc = LSS_NAME(rt_sigsuspend)(set, (KERNEL_NSIG + 7) / 8);
  if (rc < 0 && LSS_ERRNO == ENOSYS) {
    LSS_ERRNO = olderrno;
    rc = LSS_NAME(_sigsuspend)(set, 0, set->sig[0]);
  }
  return rc;
}
#endif
#if defined(__i386__)
#define __NR__socketcall __NR_socketcall
LSS_INLINE _syscall2(int, _socketcall, int, c, va_list, a)
    LSS_INLINE int LSS_NAME(socketcall)(int op, ...) {
  int rc;
  va_list ap;
  va_start(ap, op);
  rc = LSS_NAME(_socketcall)(op, ap);
  va_end(ap);
  return rc;
}

LSS_INLINE int LSS_NAME(accept)(int s,
                                struct kernel_sockaddr *addr,
                                unsigned int *len) {
  return LSS_NAME(socketcall)(5, s, addr, len);
}

LSS_INLINE int LSS_NAME(accept4)(int s,
                                 struct kernel_sockaddr *addr,
                                 unsigned int *len,
                                 int flags) {
  return LSS_NAME(socketcall)(18, s, addr, len, flags);
}

LSS_INLINE int LSS_NAME(bind)(int s,
                              const struct kernel_sockaddr *addr,
                              unsigned int len) {
  return LSS_NAME(socketcall)(2, s, addr, len);
}

LSS_INLINE int LSS_NAME(connect)(int s,
                                 const struct kernel_sockaddr *addr,
                                 unsigned int len) {
  return LSS_NAME(socketcall)(3, s, addr, len);
}

LSS_INLINE int LSS_NAME(getpeername)(int s,
                                     struct kernel_sockaddr *addr,
                                     unsigned int *len) {
  return LSS_NAME(socketcall)(7, s, addr, len);
}

LSS_INLINE int LSS_NAME(getsockname)(int s,
                                     struct kernel_sockaddr *addr,
                                     unsigned int *len) {
  return LSS_NAME(socketcall)(6, s, addr, len);
}

LSS_INLINE int LSS_NAME(
    getsockopt)(int s, int level, int name, void *val, unsigned int *len) {
  return LSS_NAME(socketcall)(15, s, level, name, val, len);
}

LSS_INLINE int LSS_NAME(listen)(int s, int log) {
  return LSS_NAME(socketcall)(4, s, log);
}

LSS_INLINE ssize_t LSS_NAME(recv)(int s, void *buf, size_t len, int flags) {
  return (ssize_t)LSS_NAME(socketcall)(10, s, buf, len, flags);
}

LSS_INLINE ssize_t LSS_NAME(recvfrom)(int s,
                                      void *buf,
                                      size_t len,
                                      int flags,
                                      struct kernel_sockaddr *from,
                                      unsigned int *fromlen) {
  return (ssize_t)LSS_NAME(socketcall)(12, s, buf, len, flags, from, fromlen);
}

LSS_INLINE ssize_t
LSS_NAME(recvmsg)(int s, struct kernel_msghdr *msg, int flags) {
  return (ssize_t)LSS_NAME(socketcall)(17, s, msg, flags);
}

LSS_INLINE ssize_t
LSS_NAME(send)(int s, const void *buf, size_t len, int flags) {
  return (ssize_t)LSS_NAME(socketcall)(9, s, buf, len, flags);
}

LSS_INLINE ssize_t
LSS_NAME(sendmsg)(int s, const struct kernel_msghdr *msg, int flags) {
  return (ssize_t)LSS_NAME(socketcall)(16, s, msg, flags);
}

LSS_INLINE ssize_t LSS_NAME(sendto)(int s,
                                    const void *buf,
                                    size_t len,
                                    int flags,
                                    const struct kernel_sockaddr *to,
                                    unsigned int tolen) {
  return (ssize_t)LSS_NAME(socketcall)(11, s, buf, len, flags, to, tolen);
}

LSS_INLINE int LSS_NAME(
    setsockopt)(int s, int level, int name, const void *val, unsigned int len) {
  return LSS_NAME(socketcall)(14, s, level, name, val, len);
}

LSS_INLINE int LSS_NAME(shutdown)(int s, int how) {
  return LSS_NAME(socketcall)(13, s, how);
}

LSS_INLINE int LSS_NAME(socket)(int domain, int type, int protocol) {
  return LSS_NAME(socketcall)(1, domain, type, protocol);
}

LSS_INLINE int LSS_NAME(socketpair)(int d, int type, int protocol, int sv[2]) {
  return LSS_NAME(socketcall)(8, d, type, protocol, sv);
}
#endif
#if defined(__i386__)
LSS_INLINE _syscall4(int,
                     fstatat64,
                     int,
                     d,
                     const char *,
                     p,
                     struct kernel_stat64 *,
                     b,
                     int,
                     f)
#endif
#if defined(__i386__)
    LSS_INLINE _syscall3(pid_t, waitpid, pid_t, p, int *, s, int, o)
#endif
    LSS_INLINE _syscall1(int, pipe, int *, p)
#if defined(__i386__)
#define __NR__statfs64 __NR_statfs64
#define __NR__fstatfs64 __NR_fstatfs64
    LSS_INLINE _syscall3(int,
                         _statfs64,
                         const char *,
                         p,
                         size_t,
                         s,
                         struct kernel_statfs64 *,
                         b) LSS_INLINE _syscall3(int,
                                                 _fstatfs64,
                                                 int,
                                                 f,
                                                 size_t,
                                                 s,
                                                 struct kernel_statfs64 *,
                                                 b)
    LSS_INLINE int LSS_NAME(statfs64)(const char *p,
                                      struct kernel_statfs64 *b) {
  return LSS_NAME(_statfs64)(p, sizeof(*b), b);
}
LSS_INLINE int LSS_NAME(fstatfs64)(int f, struct kernel_statfs64 *b) {
  return LSS_NAME(_fstatfs64)(f, sizeof(*b), b);
}
#endif

LSS_INLINE int LSS_NAME(execv)(const char *path, const char *const argv[]) {
  extern char **environ;
  return LSS_NAME(execve)(path, argv, (const char * const *)environ);
}

LSS_INLINE pid_t LSS_NAME(gettid)() {
  pid_t tid = LSS_NAME(_gettid)();
  if (tid != -1) {
    return tid;
  }
  return LSS_NAME(getpid)();
}

LSS_INLINE void *LSS_NAME(mremap)(void *old_address,
                                  size_t old_size,
                                  size_t new_size,
                                  int flags,
                                  ...) {
  va_list ap;
  void *new_address, *rc;
  va_start(ap, flags);
  new_address = va_arg(ap, void *);
  rc = LSS_NAME(_mremap)(old_address, old_size, new_size, flags, new_address);
  va_end(ap);
  return rc;
}

LSS_INLINE int LSS_NAME(ptrace_detach)(pid_t pid) {
  /* PTRACE_DETACH can sometimes forget to wake up the tracee and it
   * then sends job control signals to the real parent, rather than to
   * the tracer. We reduce the risk of this happening by starting a
   * whole new time slice, and then quickly sending a SIGCONT signal
   * right after detaching from the tracee.
   *
   * We use tkill to ensure that we only issue a wakeup for the thread being
   * detached.  Large multi threaded apps can take a long time in the kernel
   * processing SIGCONT.
   */
  int rc, err;
  LSS_NAME(sched_yield)();
  rc = LSS_NAME(ptrace)(PTRACE_DETACH, pid, (void *)0, (void *)0);
  err = LSS_ERRNO;
  LSS_NAME(tkill)(pid, SIGCONT);
  /* Old systems don't have tkill */
  if (LSS_ERRNO == ENOSYS)
    LSS_NAME(kill)(pid, SIGCONT);
  LSS_ERRNO = err;
  return rc;
}

LSS_INLINE int LSS_NAME(raise)(int sig) {
  return LSS_NAME(kill)(LSS_NAME(getpid)(), sig);
}

LSS_INLINE int LSS_NAME(setpgrp)() { return LSS_NAME(setpgid)(0, 0); }

LSS_INLINE int LSS_NAME(sysconf)(int name) {
  extern int __getpagesize(void);
  switch (name) {
    case _SC_OPEN_MAX: {
      struct kernel_rlimit limit;
      return LSS_NAME(getrlimit)(RLIMIT_NOFILE, &limit) < 0 ? 8192
                                                            : limit.rlim_cur;
    }
    case _SC_PAGESIZE:
      return __getpagesize();
    default:
      LSS_ERRNO = ENOSYS;
      return -1;
  }
}
#if defined(__x86_64__)
LSS_INLINE _syscall4(ssize_t, pread64, int, f, void *, b, size_t, c, loff_t, o)
    LSS_INLINE _syscall4(ssize_t,
                         pwrite64,
                         int,
                         f,
                         const void *,
                         b,
                         size_t,
                         c,
                         loff_t,
                         o)
    LSS_INLINE _syscall3(int, readahead, int, f, loff_t, o, unsigned, c)
#else
#define __NR__pread64 __NR_pread64
#define __NR__pwrite64 __NR_pwrite64
#define __NR__readahead __NR_readahead
#define LSS_LLARG_PAD
LSS_INLINE _syscall5(ssize_t,
                     _pread64,
                     int,
                     f,
                     void *,
                     b,
                     size_t,
                     c,
                     unsigned,
                     o1,
                     unsigned,
                     o2) LSS_INLINE _syscall5(ssize_t,
                                              _pwrite64,
                                              int,
                                              f,
                                              const void *,
                                              b,
                                              size_t,
                                              c,
                                              unsigned,
                                              o1,
                                              long,
                                              o2)
    LSS_INLINE _syscall4(int,
                         _readahead,
                         int,
                         f,
                         unsigned,
                         o1,
                         unsigned,
                         o2,
                         size_t,
                         c)
    /* We force 64bit-wide parameters onto the stack, then access each
     * 32-bit component individually. This guarantees that we build the
     * correct parameters independent of the native byte-order of the
     * underlying architecture.
     */
    LSS_INLINE ssize_t LSS_NAME(pread64)(int fd,
                                         void *buf,
                                         size_t count,
                                         loff_t off) {
  union {
    loff_t off;
    unsigned arg[2];
  } o = {off};
  return LSS_NAME(_pread64)(fd, buf, count, LSS_LLARG_PAD o.arg[0], o.arg[1]);
}
LSS_INLINE ssize_t
LSS_NAME(pwrite64)(int fd, const void *buf, size_t count, loff_t off) {
  union {
    loff_t off;
    unsigned arg[2];
  } o = {off};
  return LSS_NAME(_pwrite64)(fd, buf, count, LSS_LLARG_PAD o.arg[0], o.arg[1]);
}
LSS_INLINE int LSS_NAME(readahead)(int fd, loff_t off, int len) {
  union {
    loff_t off;
    unsigned arg[2];
  } o = {off};
  return LSS_NAME(_readahead)(fd, LSS_LLARG_PAD o.arg[0], o.arg[1], len);
}
#endif
#endif

__END_DECLS

#endif /* LINUX_SYSCALL_SUPPORT_H_ */
