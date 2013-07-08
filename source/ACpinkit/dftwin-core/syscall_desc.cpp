/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * 02/23/2011:
 * 	some conflict arises when numaif.h is included before syscall_desc.h
 * 	the proposed fix was done by Georgios Portokalidis
 * 	(porto@cs.columbia.edu)
 */

/*
 * TODO:
 * 	- add ioctl() handler
 * 	- add nfsservctl() handler
 */

//#include <sys/epoll.h>
//#include <sys/ipc.h>
//#include <sys/mman.h>
//#include <sys/msg.h>
//#include <sys/sem.h>
//#include <sys/shm.h>
//#include <sys/socket.h>
//#include <sys/types.h>
//#include <sys/uio.h>
//
//#include <asm/fcntl.h>
//#include <asm/stat.h>
//#include <linux/sysctl.h>
//
//#include <err.h>
//#include <poll.h>
#include <cstring>
#include "unistd_32.h"

#include "syscall_desc.h"
#include "tagmap.h"
//#include <linux/mempolicy.h>
#define __user
#define __ARCH_SI_BAND_T long

/* callbacks declaration */
static void post_read_hook(syscall_ctx_t*);
static void post_fcntl_hook(syscall_ctx_t*);
static void post_getgroups16_hook(syscall_ctx_t*);
static void post_mmap_hook(syscall_ctx_t*);
static void post_socketcall_hook(syscall_ctx_t*);
static void post_syslog_hook(syscall_ctx_t*);
static void post_ipc_hook(syscall_ctx_t*);
static void post_modify_ldt_hook(syscall_ctx_t*);
static void post_quotactl_hook(syscall_ctx_t *ctx);
static void post_readv_hook(syscall_ctx_t*);
static void post__sysctl_hook(syscall_ctx_t*);
static void post_poll_hook(syscall_ctx_t *ctx);
static void post_rt_sigpending_hook(syscall_ctx_t *ctx);
static void post_getcwd_hook(syscall_ctx_t *ctx);
static void post_getgroups_hook(syscall_ctx_t*);
static void post_mincore_hook(syscall_ctx_t *ctx);
static void post_getdents_hook(syscall_ctx_t *ctx);
static void post_getxattr_hook(syscall_ctx_t *ctx);
static void post_listxattr_hook(syscall_ctx_t *ctx);
static void post_io_getevents_hook(syscall_ctx_t *ctx);
static void post_get_mempolicy_hook(syscall_ctx_t *ctx);
static void post_lookup_dcookie_hook(syscall_ctx_t *ctx);
static void post_mq_timedreceive_hook(syscall_ctx_t *ctx);
static void post_readlinkat_hook(syscall_ctx_t*);
static void post_epoll_wait_hook(syscall_ctx_t *ctx);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static void post_recvmmsg_hook(syscall_ctx_t *ctx);
#endif

typedef unsigned int    __kernel_ino_t;
typedef unsigned int    __kernel_mode_t;
typedef unsigned int    __kernel_nlink_t;
typedef long            __kernel_off_t;
typedef long long       __kernel_loff_t;
typedef int             __kernel_pid_t;
typedef int             __kernel_ipc_pid_t;
typedef unsigned int    __kernel_uid_t;
typedef unsigned int    __kernel_gid_t;
typedef unsigned long   __kernel_size_t;
typedef long            __kernel_ssize_t;
typedef long            __kernel_ptrdiff_t;
typedef long            __kernel_time_t;
typedef long            __kernel_suseconds_t;
typedef long            __kernel_clock_t;
typedef int             __kernel_daddr_t;
typedef char *          __kernel_caddr_t;
typedef unsigned long   __kernel_sigset_t;      /* at least 32 bits */
typedef unsigned short  __kernel_uid16_t;
typedef unsigned short  __kernel_gid16_t;
typedef int             __kernel_clockid_t;
typedef int             __kernel_timer_t;


typedef __kernel_uid_t __kernel_old_uid_t;
typedef __kernel_gid_t __kernel_old_gid_t;
typedef __kernel_uid_t __kernel_uid32_t;
typedef __kernel_gid_t __kernel_gid32_t;

typedef __kernel_uid32_t        uid_t;
typedef __kernel_gid32_t        gid_t;
typedef __kernel_uid16_t        uid16_t;
typedef __kernel_gid16_t        gid16_t;

typedef __kernel_clock_t        clock_t;

struct __old_kernel_stat {
        unsigned short st_dev;
        unsigned short st_ino;
        unsigned short st_mode;
        unsigned short st_nlink;
        unsigned short st_uid;
        unsigned short st_gid;
        unsigned short st_rdev;
        unsigned int  st_size;
        unsigned int  st_atime;
        unsigned int  st_mtime;
        unsigned int  st_ctime;
};

struct tms {
        int tms_utime;
        int tms_stime;
        int tms_cutime;
        int tms_cstime;
};

struct oldold_utsname {
        char sysname[9];
        char nodename[9];
        char release[9];
        char version[9];
        char machine[9];
};

struct ustat {
        int                     f_tfree;
        unsigned int           f_tinode;
        char                    f_fname[6];
        char                    f_fpack[6];
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t(void);
typedef __restorefn_t *__sigrestore_t;

typedef unsigned long sigset_t;

struct sigaction {
        __sighandler_t sa_handler;
        unsigned long sa_flags;
        __sigrestore_t sa_restorer;
        sigset_t sa_mask;               /* mask last for extensibility */
};

struct rlimit {
        unsigned long   rlim_cur;
        unsigned long   rlim_max;
};

//typedef long __kernel_time_t;
//typedef __kernel_time_t         time_t;
typedef long __kernel_suseconds_t;
typedef __kernel_suseconds_t    suseconds_t;
struct timeval {
        time_t          tv_sec;         /* seconds */
        suseconds_t     tv_usec;        /* microseconds */
};

struct  rusage {
        struct timeval ru_utime;        /* user time used */
        struct timeval ru_stime;        /* system time used */
        long    ru_maxrss;              /* maximum resident set size */
        long    ru_ixrss;               /* integral shared memory size */
        long    ru_idrss;               /* integral unshared data size */
        long    ru_isrss;               /* integral unshared stack size */
        long    ru_minflt;              /* page reclaims */
        long    ru_majflt;              /* page faults */
        long    ru_nswap;               /* swaps */
        long    ru_inblock;             /* block input operations */
        long    ru_oublock;             /* block output operations */
        long    ru_msgsnd;              /* messages sent */
        long    ru_msgrcv;              /* messages received */
        long    ru_nsignals;            /* signals received */
        long    ru_nvcsw;               /* voluntary context switches */
        long    ru_nivcsw;              /* involuntary " */
};

struct timezone {
        int     tz_minuteswest; /* minutes west of Greenwich */
        int     tz_dsttime;     /* type of dst correction */
};


#define __NFDBITS       (8 * sizeof(unsigned long))
#define __FD_SETSIZE    1024
#define __FDSET_LONGS   (__FD_SETSIZE/__NFDBITS)

typedef struct {
        unsigned long fds_bits [__FDSET_LONGS];
} __kernel_fd_set;

typedef __kernel_fd_set         fd_set;

typedef struct {
        int     val[2];
} __kernel_fsid_t;

struct statfs {
        long f_type;
        long f_bsize;
        long f_blocks;
        long f_bfree;
        long f_bavail;
        long f_files;
        long f_ffree;
        __kernel_fsid_t f_fsid;
        long f_namelen;
        long f_frsize;
        long f_spare[5];
};

struct itimerval {
        struct timeval it_interval;     /* timer interval */
        struct timeval it_value;        /* current value */
};

struct new_utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
        char domainname[65];
};

struct vm86_regs {
/*
 * normal regs, with special meaning for the segment descriptors..
 */
        long ebx;
        long ecx;
        long edx;
        long esi;
        long edi;
        long ebp;
        long eax;
        long __null_ds;
        long __null_es;
        long __null_fs;
        long __null_gs;
        long orig_eax;
        long eip;
        unsigned short cs, __csh;
        long eflags;
        long esp;
        unsigned short ss, __ssh;
/*
 * these are specific to v86 mode:
 */
        unsigned short es, __esh;
        unsigned short ds, __dsh;
        unsigned short fs, __fsh;
        unsigned short gs, __gsh;
};

struct revectored_struct {
        unsigned long __map[8];                 /* 256 bits */
};

struct vm86_struct {
        struct vm86_regs regs;
        unsigned long flags;
        unsigned long screen_bitmap;
        unsigned long cpu_type;
        struct revectored_struct int_revectored;
        struct revectored_struct int21_revectored;
};



struct sysinfo {
        long uptime;                    /* Seconds since boot */
        unsigned long loads[3];         /* 1, 5, and 15 minute load averages */
        unsigned long totalram;         /* Total usable main memory size */
        unsigned long freeram;          /* Available memory size */
        unsigned long sharedram;        /* Amount of shared memory */
        unsigned long bufferram;        /* Memory used by buffers */
        unsigned long totalswap;        /* Total swap space size */
        unsigned long freeswap;         /* swap space still available */
        unsigned short procs;           /* Number of current processes */
        unsigned short pad;             /* explicit padding for m68k */
        unsigned long totalhigh;        /* Total high memory size */
        unsigned long freehigh;         /* Available high memory size */
        unsigned int mem_unit;          /* Memory unit size in bytes */
        char _f[20-2*sizeof(long)-sizeof(int)]; /* Padding: libc5 uses this.. */
};

struct timex {
        unsigned int modes;     /* mode selector */
        long offset;            /* time offset (usec) */
        long freq;              /* frequency offset (scaled ppm) */
        long maxerror;          /* maximum error (usec) */
        long esterror;          /* estimated error (usec) */
        int status;             /* clock command/status */
        long constant;          /* pll time constant */
        long precision;         /* clock precision (usec) (read only) */
        long tolerance;         /* clock frequency tolerance (ppm)
                                 * (read only)
                                 */
        struct timeval time;    /* (read only) */
        long tick;              /* (modified) usecs between clock ticks */

        long ppsfreq;           /* pps frequency (scaled ppm) (ro) */
        long jitter;            /* pps jitter (us) (ro) */
        int shift;              /* interval duration (s) (shift) (ro) */
        long stabil;            /* pps stability (scaled ppm) (ro) */
        long jitcnt;            /* jitter limit exceeded (ro) */
        long calcnt;            /* calibration intervals (ro) */
        long errcnt;            /* calibration errors (ro) */
        long stbcnt;            /* stability limit exceeded (ro) */

        int tai;                /* TAI offset (ro) */

        int  :32; int  :32; int  :32; int  :32;
        int  :32; int  :32; int  :32; int  :32;
        int  :32; int  :32; int  :32;
};
typedef long long       __kernel_loff_t;
typedef __kernel_loff_t         loff_t;

struct sched_param {
        int sched_priority;
};

struct timespec {
        time_t  tv_sec;         /* seconds */
        long    tv_nsec;        /* nanoseconds */
};

struct vm86plus_info_struct {
        unsigned long force_return_for_pic:1;
        unsigned long vm86dbg_active:1;       /* for debugger */
        unsigned long vm86dbg_TFpendig:1;     /* for debugger */
        unsigned long unused:28;
        unsigned long is_vm86pus:1;           /* for vm86 internal use */
        unsigned char vm86dbg_intxxtab[32];   /* for debugger */
};

struct vm86plus_struct {
        struct vm86_regs regs;
        unsigned long flags;
        unsigned long screen_bitmap;
        unsigned long cpu_type;
        struct revectored_struct int_revectored;
        struct revectored_struct int21_revectored;
        struct vm86plus_info_struct vm86plus;
};


#define SI_MAX_SIZE     128
#define __ARCH_SI_PREAMBLE_SIZE (3 * sizeof(int))
#define SI_PAD_SIZE     ((SI_MAX_SIZE - __ARCH_SI_PREAMBLE_SIZE) / sizeof(int))
#define __ARCH_SI_UID_T uid_t
typedef int             __kernel_pid_t;
typedef __kernel_pid_t          pid_t;
typedef int             __kernel_timer_t;
typedef __kernel_timer_t        timer_t;
typedef union sigval {
        int sival_int;
        void *sival_ptr;
} sigval_t;

typedef struct siginfo {
        int si_signo;
        int si_errno;
        int si_code;
        union {
                int _pad[SI_PAD_SIZE];

                /* kill() */
                struct {
                        pid_t _pid;             /* sender's pid */
                        __ARCH_SI_UID_T _uid;   /* sender's uid */
                } _kill;

                /* POSIX.1b timers */
                struct {
                        timer_t _tid;           /* timer id */
                        int _overrun;           /* overrun count */
//                        char _pad[sizeof( __ARCH_SI_UID_T) - sizeof(int)];
                        sigval_t _sigval;       /* same as below */
                        int _sys_private;       /* not to be passed to user */
                } _timer;

                /* POSIX.1b signals */
                struct {
                        pid_t _pid;             /* sender's pid */
                        __ARCH_SI_UID_T _uid;   /* sender's uid */
                        sigval_t _sigval;
                } _rt;

                /* SIGCHLD */
                struct {
                        pid_t _pid;             /* which child */
                        __ARCH_SI_UID_T _uid;   /* sender's uid */
                        int _status;            /* exit code */
                        clock_t _utime;
                        clock_t _stime;
                } _sigchld;

                /* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
                struct {
                        void __user *_addr; /* faulting insn/memory ref. */
                } _sigfault;

                /* SIGPOLL */
                struct {
                        __ARCH_SI_BAND_T _band; /* POLL_IN, POLL_OUT, POLL_MSG */
                        int _fd;
                } _sigpoll;
        } _sifields;
} siginfo_t;


typedef struct sigaltstack {
        void __user *ss_sp;
        int ss_flags;
        size_t ss_size;
} stack_t;
struct stat64 {
        unsigned long long      st_dev;
        unsigned char   __pad0[4];

        unsigned long   __st_ino;

        unsigned int    st_mode;
        unsigned int    st_nlink;

        unsigned long   st_uid;
        unsigned long   st_gid;

        unsigned long long      st_rdev;
        unsigned char   __pad3[4];

        long long       st_size;
        unsigned long   st_blksize;

        /* Number 512-byte blocks allocated. */
        unsigned long long      st_blocks;

        unsigned long   st_atime;
        unsigned long   st_atime_nsec;

        unsigned long   st_mtime;
        unsigned int    st_mtime_nsec;

        unsigned long   st_ctime;
        unsigned long   st_ctime_nsec;

        unsigned long long      st_ino;
};
typedef unsigned long int __cpu_mask;

# define __CPU_SETSIZE  1024
# define __NCPUBITS     (8 * sizeof (__cpu_mask))

typedef struct
{
  __cpu_mask __bits[__CPU_SETSIZE / __NCPUBITS];
} cpu_set_t;

struct user_desc {
        unsigned int  entry_number;
        unsigned int  base_addr;
        unsigned int  limit;
        unsigned int  seg_32bit:1;
        unsigned int  contents:2;
        unsigned int  read_exec_only:1;
        unsigned int  limit_in_pages:1;
        unsigned int  seg_not_present:1;
        unsigned int  useable:1;
};

typedef unsigned long   aio_context_t;

struct io_event {
        unsigned __int64           data;           /* the data field from the iocb */
        unsigned __int64            obj;            /* what iocb this event came from */
        signed __int64            res;            /* result code for this event */
        signed __int64            res2;           /* secondary result */
};
struct itimerspec {
        struct timespec it_interval;    /* timer period */
        struct timespec it_value;       /* timer expiration */
};

struct statfs64 {
        long f_type;
        long f_bsize;
        long f_blocks;
        long f_bfree;
        long f_bavail;
        long f_files;
        long f_ffree;
        __kernel_fsid_t f_fsid;
        long f_namelen;
        long f_frsize;
        long f_spare[5];
};

struct mq_attr {
        long    mq_flags;       /* message queue flags                  */
        long    mq_maxmsg;      /* maximum number of messages           */
        long    mq_msgsize;     /* maximum message size                 */
        long    mq_curmsgs;     /* number of messages currently queued  */
        long    reserved[4];  /* ignored for input, zeroed for output */
};

#define MAP_FAILED	((void *) -1)

#define MAP_32BIT       0x40            /* only give out 32bit addresses */

#define MAP_GROWSDOWN   0x0100          /* stack-like segment */
#define MAP_DENYWRITE   0x0800          /* ETXTBSY */
#define MAP_EXECUTABLE  0x1000          /* mark it as an executable */
#define MAP_LOCKED      0x2000          /* pages are locked */
#define MAP_NORESERVE   0x4000          /* don't check for reservations */
#define MAP_POPULATE    0x8000          /* populate (prefault) pagetables */
#define MAP_NONBLOCK    0x10000         /* do not block on IO */
#define MAP_STACK       0x20000         /* give out an address that is best suited for process/thread stacks */

#define MCL_CURRENT     1               /* lock all current mappings */
#define MCL_FUTURE      2               /* lock all future mappings */

struct iovec
{
        void __user *iov_base;  /* BSD uses caddr_t (1003.1g requires void *) */
        __kernel_size_t iov_len; /* Must be size_t (1003.1g) */
};

struct epoll_event {
        unsigned int events;
        unsigned __int64 data;
} ;

struct pollfd {
        int fd;
        short events;
        short revents;
};

/* Flags for set_mempolicy */
#define MPOL_F_STATIC_NODES     (1 << 15)
#define MPOL_F_RELATIVE_NODES   (1 << 14)

/*
 * MPOL_MODE_FLAGS is the union of all possible optional mode flags passed to
 * either set_mempolicy() or mbind().
 */
#define MPOL_MODE_FLAGS (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES)

/* Flags for get_mempolicy */
#define MPOL_F_NODE     (1<<0)  /* return next IL mode instead of node mask */
#define MPOL_F_ADDR     (1<<1)  /* look up vma using address */
#define MPOL_F_MEMS_ALLOWED (1<<2) /* return allowed memories */

/* Flags for mbind */
#define MPOL_MF_STRICT  (1<<0)  /* Verify existing pages in the mapping */
#define MPOL_MF_MOVE    (1<<1)  /* Move pages owned by this process to conform to mapping */
#define MPOL_MF_MOVE_ALL (1<<2) /* Move every page to conform to mapping */
#define MPOL_MF_INTERNAL (1<<3) /* Internal flags start here */

/*
 * Internal flags that share the struct mempolicy flags word with
 * "mode flags".  These flags are allocated from bit 0 up, as they
 * are never OR'ed into the mode in mempolicy API arguments.
 */
#define MPOL_F_SHARED  (1 << 0) /* identify shared policies */
#define MPOL_F_LOCAL   (1 << 1) /* preferred local allocation */

typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned __int64 __u64;
typedef signed __int64 __s64;

/* resource get request flags */
#define IPC_CREAT  00001000   /* create if key is nonexistent */
#define IPC_EXCL   00002000   /* fail if key exists */
#define IPC_NOWAIT 00004000   /* return error on wait */

/* these fields are used by the DIPC package so the kernel as standard
   should avoid using them if possible */

#define IPC_DIPC 00010000  /* make it distributed */
#define IPC_OWN  00020000  /* this machine is the DIPC owner */

/*
 * Control commands used with semctl, msgctl and shmctl
 * see also specific commands in sem.h, msg.h and shm.h
 */
#define IPC_RMID 0     /* remove resource */
#define IPC_SET  1     /* set ipc_perm options */
#define IPC_STAT 2     /* get ipc_perm options */
#define IPC_INFO 3     /* see ipcs */

/*
 * Version flags for semctl, msgctl, and shmctl commands
 * These are passed as bitflags or-ed with the actual command
 */
#define IPC_OLD 0       /* Old version (no 32-bit UID support on many
                           architectures) */
#define IPC_64  0x0100  /* New version (support 32-bit UIDs, bigger
                           message sizes, etc. */
#define MSG_STAT 11
#define MSG_INFO 12

/* msgrcv options */
#define MSG_NOERROR     010000  /* no error if message is too big */
#define MSG_EXCEPT      020000  /* recv any msg except of specified type.*/

struct msqid_ds {
        struct ipc_perm msg_perm;
        struct msg *msg_first;          /* first message on queue,unused  */
        struct msg *msg_last;           /* last message in queue,unused */
        __kernel_time_t msg_stime;      /* last msgsnd time */
        __kernel_time_t msg_rtime;      /* last msgrcv time */
        __kernel_time_t msg_ctime;      /* last change time */
        unsigned long  msg_lcbytes;     /* Reuse junk fields for 32 bit */
        unsigned long  msg_lqbytes;     /* ditto */
        unsigned short msg_cbytes;      /* current number of bytes on queue */
        unsigned short msg_qnum;        /* number of messages in queue */
        unsigned short msg_qbytes;      /* max number of bytes on queue */
        __kernel_ipc_pid_t msg_lspid;   /* pid of last msgsnd */
        __kernel_ipc_pid_t msg_lrpid;   /* last receive pid */
};


struct msgbuf {
        long mtype;         /* type of message */
        char mtext[1];      /* message text */
};

/* buffer for msgctl calls IPC_INFO, MSG_INFO */
struct msginfo {
        int msgpool;
        int msgmap;
        int msgmax;
        int msgmnb;
        int msgmni;
        int msgssz;
        int msgtql;
        unsigned short  msgseg;
};

/*
 * Scaling factor to compute msgmni:
 * the memory dedicated to msg queues (msgmni * msgmnb) should occupy
 * at most 1/MSG_MEM_SCALE of the lowmem (see the formula in ipc/msg.c):
 * up to 8MB       : msgmni = 16 (MSGMNI)
 * 4 GB            : msgmni = 8K
 * more than 16 GB : msgmni = 32K (IPCMNI)
 */
#define MSG_MEM_SCALE 32

#define MSGMNI    16   /* <= IPCMNI */     /* max # of msg queue identifiers */
#define MSGMAX  8192   /* <= INT_MAX */   /* max size of message (bytes) */
#define MSGMNB 16384   /* <= INT_MAX */   /* default max size of a message queue */

/* unused */
#define MSGPOOL (MSGMNI * MSGMNB / 1024) /* size in kbytes of message pool */
#define MSGTQL  MSGMNB            /* number of system message headers */
#define MSGMAP  MSGMNB            /* number of entries in message map */
#define MSGSSZ  16                /* message segment size */
#define __MSGSEG ((MSGPOOL * 1024) / MSGSSZ) /* max no. of segments */
#define MSGSEG (__MSGSEG <= 0xffff ? __MSGSEG : 0xffff)

/* one msg_msg structure for each message */
struct list_head {
        struct list_head *next, *prev;
};

struct msg_msgseg {
        struct msg_msgseg* next;
        /* the next part of the message follows immediately */
};


struct msg_msg {
        struct list_head m_list;
        long  m_type;
        int m_ts;           /* message text size */
        struct msg_msgseg* next;
        void *security;
        /* the actual message follows immediately */
};

/* one msq_queue structure for each present queue on the system */
struct msg_queue {
        struct kern_ipc_perm q_perm;
        time_t q_stime;                 /* last msgsnd time */
        time_t q_rtime;                 /* last msgrcv time */
        time_t q_ctime;                 /* last change time */
        unsigned long q_cbytes;         /* current number of bytes on queue */
        unsigned long q_qnum;           /* number of messages in queue */
        unsigned long q_qbytes;         /* max number of bytes on queue */
        pid_t q_lspid;                  /* pid of last msgsnd */
        pid_t q_lrpid;                  /* last receive pid */

        struct list_head q_messages;
        struct list_head q_receivers;
        struct list_head q_senders;
};

/* permission flag for shmget */
#define SHM_R           0400    /* or S_IRUGO from <linux/stat.h> */
#define SHM_W           0200    /* or S_IWUGO from <linux/stat.h> */

/* mode for attach */
#define SHM_RDONLY      010000  /* read-only access */
#define SHM_RND         020000  /* round attach address to SHMLBA boundary */
#define SHM_REMAP       040000  /* take-over region on attach */
#define SHM_EXEC        0100000 /* execution access */

/* super user shmctl commands */
#define SHM_LOCK        11
#define SHM_UNLOCK      12

/* ipcs ctl commands */
#define SHM_STAT        13
#define SHM_INFO        14

/* Obsolete, used only for backwards compatibility */
struct  shminfo {
        int shmmax;
        int shmmin;
        int shmmni;
        int shmseg;
        int shmall;
};

struct shm_info {
        int used_ids;
        unsigned long shm_tot;  /* total allocated shm */
        unsigned long shm_rss;  /* total resident shm */
        unsigned long shm_swp;  /* total swapped shm */
        unsigned long swap_attempts;
        unsigned long swap_successes;
};

struct  seminfo {
        int semmap;
        int semmni;
        int semmns;
        int semmnu;
        int semmsl;
        int semopm;
        int semume;
        int semusz;
        int semvmx;
        int semaem;
};

#define SEMMNI  128             /* <= IPCMNI  max # of semaphore identifiers */
#define SEMMSL  250             /* <= 8 000 max num of semaphores per id */
#define SEMMNS  (SEMMNI*SEMMSL) /* <= INT_MAX max # of semaphores in system */
#define SEMOPM  32              /* <= 1 000 max num of ops per semop call */
#define SEMVMX  32767           /* <= 32767 semaphore maximum value */
#define SEMAEM  SEMVMX          /* adjust on exit max value */


#define F_DUPFD         0       /* dup */
#define F_GETFD         1       /* get close_on_exec */
#define F_SETFD         2       /* set/clear close_on_exec */
#define F_GETFL         3       /* get file->f_flags */
#define F_SETFL         4       /* set file->f_flags */
#ifndef F_GETLK
#define F_GETLK         5
#define F_SETLK         6
#define F_SETLKW        7
#endif
#ifndef F_SETOWN
#define F_SETOWN        8       /* for sockets. */
#define F_GETOWN        9       /* for sockets. */
#endif
#ifndef F_SETSIG
#define F_SETSIG        10      /* for sockets. */
#define F_GETSIG        11      /* for sockets. */
#endif

struct shmid_ds {
        struct ipc_perm         shm_perm;       /* operation perms */
        int                     shm_segsz;      /* size of segment (bytes) */
        __kernel_time_t         shm_atime;      /* last attach time */
        __kernel_time_t         shm_dtime;      /* last detach time */
        __kernel_time_t         shm_ctime;      /* last change time */
        __kernel_ipc_pid_t      shm_cpid;       /* pid of creator */
        __kernel_ipc_pid_t      shm_lpid;       /* pid of last operator */
        unsigned short          shm_nattch;     /* no. of current attaches */
        unsigned short          shm_unused;     /* compatibility */
        void                    *shm_unused2;   /* ditto - used by DIPC */
        void                    *shm_unused3;   /* unused */
};

#define SEM_UNDO        0x1000  /* undo the operation on exit */

/* semctl Command Definitions. */
#define GETPID  11       /* get sempid */
#define GETVAL  12       /* get semval */
#define GETALL  13       /* get all semval's */
#define GETNCNT 14       /* get semncnt */
#define GETZCNT 15       /* get semzcnt */
#define SETVAL  16       /* set semval */
#define SETALL  17       /* set all semval's */

/* ipcs ctl cmds */
#define SEM_STAT 18
#define SEM_INFO 19

#define __ARCH_FLOCK_PAD
struct flock {
        short   l_type;
        short   l_whence;
        off_t   l_start;
        off_t   l_len;
        pid_t   l_pid;
        __ARCH_FLOCK_PAD
};

#define F_GETLK64       12      /*  using 'struct flock64' */
#define F_SETLK64       13
#define F_SETLKW64      14
#define __ARCH_FLOCK64_PAD

struct flock64 {
        short  l_type;
        short  l_whence;
        loff_t l_start;
        loff_t l_len;
        pid_t  l_pid;
        __ARCH_FLOCK64_PAD
};

struct msghdr {
        void    *       msg_name;       /* Socket name                  */
        int             msg_namelen;    /* Length of name               */
        struct iovec *  msg_iov;        /* Data blocks                  */
        __kernel_size_t msg_iovlen;     /* Number of blocks             */
        void    *       msg_control;    /* Per protocol magic (eg BSD file descriptor passing) */
        __kernel_size_t msg_controllen; /* Length of cmsg list */
        unsigned        msg_flags;
};
struct __sysctl_args {
        int __user *name;
        int nlen;
        void __user *oldval;
        size_t __user *oldlenp;
        void __user *newval;
        size_t newlen;
        unsigned long __unused[4];
};
/* syscall descriptors */
syscall_desc_t syscall_desc[SYSCALL_MAX] = {
	/* __NR_restart_syscall */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_exit */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fork */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_read */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_read_hook },
	/* __NR_write */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_open */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_close */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_waitpid */
	{ 3, 0, 1, { 0, sizeof(int), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_creat */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_link */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_unlink */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 10 */
	/* __NR_execve */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_chdir */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_time */
	{ 1, 0, 1, { sizeof(time_t), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mknod */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_chmod */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lchown16 */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_break; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_stat */
	{ 2, 0, 1, { 0, sizeof(struct __old_kernel_stat), 0, 0, 0, 0 }, NULL,
	NULL },
	/* __NR_lseek */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getpid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 20 */
	/* __NR_mount */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_oldumount */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setuid16 */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getuid16 */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_stime */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ptrace */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_alarm */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstat */
	{ 2, 0, 1, { 0, sizeof(struct __old_kernel_stat), 0, 0, 0, 0 }, NULL,
	NULL },
	/* __NR_pause */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_utime */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 30 */
	/* __NR_stty; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_gtty; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_access */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_nice */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ftime; not implemented */
	{ 0, 0, 1, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sync */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_kill */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rename */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mkdir */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rmdir */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 40 */
	/* __NR_dup */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pipe */
	{ 1, 0, 1, { sizeof(int) * 2, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_times */
	{ 1, 0, 1, { sizeof(struct tms), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_prof; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_brk */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setgid16 */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgid16 */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_signal */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_geteuid16 */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getegid16 */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 50 */
	/* __NR_acct */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_umount */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lock; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ioctl; TODO */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fcntl */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_fcntl_hook },
	/* __NR_mpx; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setpgid */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ulimit; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_olduname */
	{ 1, 0, 1, { sizeof(struct oldold_utsname), 0, 0, 0, 0, 0 }, NULL,
	NULL },
	/* __NR_umask */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 60 */
	/* __NR_chroot */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ustat */
	{ 2, 0, 1, { 0, sizeof(struct ustat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_dup2 */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getppid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getpgrp */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setsid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigaction */
	{ 3, 0, 1, { 0, 0, sizeof(struct sigaction), 0, 0, 0 }, NULL, NULL },
	/* __NR_sgetmask */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ssetmask */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setreuid16 */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 70 */
	/* __NR_setregid16 */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigsuspend */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigpending*/
	{ 1, 0, 1, { sizeof(old_sigset_t), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sethostname */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setrlimit */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_old_getrlimit */
	{ 2, 0, 1, { 0, sizeof(struct rlimit), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getrusage */
	{ 2, 0, 1, { 0, sizeof(struct rusage), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_gettimeofday */
	{ 2, 0, 1, { sizeof(struct timeval), sizeof(struct timezone), 0,
	 0, 0, 0 }, NULL, NULL },
	/* __NR_settimeofday */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgroups */
	{ 2, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getgroups16_hook }, /* 80 */
	/* __NR_setgroups16 */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_select */
	{ 5, 0, 1, { 0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), 
	sizeof(struct timeval), 0 }, NULL, NULL },
	/* __NR_symlink */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lstat */
	{ 2, 0, 1, { 0, sizeof(struct __old_kernel_stat), 0, 0, 0, 0 }, NULL,
	NULL },
	/* __NR_readlink */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_read_hook },
	/* __NR_uselib */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_swapon */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_reboot */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_old_readdir */
	{ 3, 0, 1, { 0, sizeof(struct old_linux_dirent), 0, 0, 0, 0 }, NULL, 		NULL },
	/* __NR_old_mmap */
	{ 6, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_mmap_hook }, /* 90 */
	/* __NR_munmap */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_truncate */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ftruncate */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchmod */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchown16 */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getpriority */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setpriority */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_profil; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_statfs */
	{ 2, 0, 1, { 0, sizeof(struct statfs), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstatfs */
	{ 2, 0, 1, { 0, sizeof(struct statfs), 0, 0, 0, 0 }, NULL, NULL },
	/* 100 */
	/* __NR_ioperm */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_socketcall */
	{ 2, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_socketcall_hook },
	/* __NR_syslog */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_syslog_hook },
	/* __NR_setitimer */
	{ 3, 0, 1, { 0, 0, sizeof(struct itimerval), 0, 0, 0 }, NULL, NULL },
	/* __NR_getitimer */
	{ 2, 0, 1, { 0, sizeof(struct itimerval), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newstat */
	{ 2, 0, 1, { 0, sizeof(struct stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newlstat */
	{ 2, 0, 1, { 0, sizeof(struct stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newfstat */
	{ 2, 0, 1, { 0, sizeof(struct stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_uname */
	{ 1, 0, 1, { sizeof(struct new_utsname), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_iopl */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 110 */
	/* __NR_vhangup */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_idle; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vm86old */
	{ 2, 0, 1, { sizeof(struct vm86_struct), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_wait4 */
	{ 4, 0, 1, { 0, sizeof(int), 0, sizeof(struct rusage), 0, 0 },
	NULL, NULL },
	/* __NR_swapoff */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sysinfo */
	{ 1, 0, 1, { sizeof(struct sysinfo), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ipc */
	{ 6, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_ipc_hook },
	/* __NR_fsync */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigreturn */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clone */
	{ 5, 0, 1, { 0, 0, sizeof(int), 0, 0, 0 }, NULL, NULL },
	/* 120 */
	/* __NR_setdomainname */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newuname */
	{ 1, 0, 1, { sizeof(struct new_utsname), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_modify_ldt */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_modify_ldt_hook },
	/* __NR_adjtimex */
	{ 1, 0, 1, { sizeof(struct timex), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mprotect */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigprocmask */
	{ 3, 0, 1, { 0, 0, sizeof(old_sigset_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_create_module; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_init_module */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_delete_module */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_kernel_syms; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 130 */
	/* __NR_quotactl */
	{ 4, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_quotactl_hook },
	/* __NR_getpgid */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchdir */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_bdflush */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sysfs */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_personality */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_afs_syscall; not implemented */
        { 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsuid16 */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsgid16 */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR__llseek */
	{ 5, 0, 1, { 0, 0, 0, sizeof(loff_t), 0, 0 }, NULL, NULL },/* 140 */
	/* __NR_getdents */
	{ 3, 0, 1, { 0, sizeof(struct linux_dirent), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_select */
	{ 5, 0, 1, { 0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), 
	sizeof(struct timeval), 0 }, NULL, NULL },
	/* __NR_flock */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_msync */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_readv */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_readv_hook },
	/* __NR_writev */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getsid */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fdatasync */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR__sysctl */
	{ 1, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post__sysctl_hook },
	/* __NR_mlock */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 150 */
	/* __NR_munlock */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mlockall */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_munlockall */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_setparam */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_getparam */
	{ 2, 0, 1, { 0, sizeof(struct sched_param), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_setscheduler */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_getscheduler*/
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_yield */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_get_priority_max */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_get_priority_min */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 160 */
	/* __NR_sched_rr_get_interval */
	{ 2, 0, 1, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_nanosleep */
	{ 2, 0, 1, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mremap */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setresuid16 */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getresuid16 */
	{ 3, 0, 1, { sizeof(old_uid_t), sizeof(old_uid_t), sizeof(old_uid_t), 0,
	0, 0 }, NULL, NULL },
	/* __NR_ptregs_vm86 */
	{ 3, 0, 1, { 0, sizeof(struct vm86plus_struct), 0, 0, 0, 0 }, NULL,
	NULL },
	/* __NR_query_module; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_poll */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_poll_hook },
	/* __NR_nfsservctl; TODO */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setresgid16 */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 170 */
	/* __NR_getresgid16 */
	{ 3, 0, 1, { sizeof(old_gid_t), sizeof(old_gid_t), sizeof(old_gid_t), 0,
	0, 0 }, NULL, NULL },
	/* __NR_prctl */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigreturn */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigaction */
	{ 4, 0, 1, { 0, 0, sizeof(struct sigaction), 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigprocmask */
	{ 4, 0, 1, { 0, 0, sizeof(sigset_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigpending */
	{ 2, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_rt_sigpending_hook },
	/* __NR_rt_sigtimedwait */
	{ 4, 0, 1, { 0, sizeof(siginfo_t), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigqueueinfo */
	{ 3, 0, 1, { 0, 0, sizeof(siginfo_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigsuspend */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pread64 */
	{ 4, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_read_hook }, /* 180 */
	/* __NR_pwrite64 */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_chown16 */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getcwd */
	{ 2, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getcwd_hook },
	/* __NR_capget */
	{ 2, 0, 1, { sizeof(cap_user_header_t), sizeof(cap_user_data_t), 0, 0,
	0, 0 }, NULL, NULL },
	/* __NR_capset */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigaltstack */
	{ 2, 0, 1, { 0, sizeof(stack_t), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sendfile */
	{ 4, 0, 1, { 0, 0, sizeof(off_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_streams1; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_streams2; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vfork */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 190 */
	/* __NR_getrlimit */
	{ 2, 0, 1, { 0, sizeof(struct rlimit), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mmap2 */
	{ 6, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_mmap_hook },
	/* __NR_truncate64 */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ftruncate64 */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_stat64 */
	{ 2, 0, 1, { 0, sizeof(struct stat64), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lstat64 */
	{ 2, 0, 1, { 0, sizeof(struct stat64), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstat64 */
	{ 2, 0, 1, { 0, sizeof(struct stat64), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lchown */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getuid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 200 */
	/* __NR_geteuid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getegid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setreuid */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setregid */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgroups */
	{ 2, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getgroups_hook },
	/* __NR_setgroups */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchown */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setresuid */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getresuid */
	{ 3, 0, 1, { sizeof(uid_t), sizeof(uid_t), sizeof(uid_t), 0, 0, 0 },
	NULL, NULL },
	/* __NR_setresgid */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 210 */
	/* __NR_getresgid */
	{ 3, 0, 1, { sizeof(gid_t), sizeof(gid_t), sizeof(gid_t), 0, 0, 0 },
	NULL, NULL },
	/* __NR_chown */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setuid */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setgid */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsuid */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsgid */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pivot_root */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mincore */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_mincore_hook },
	/* __NR_madvise */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getdents */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getdents_hook }, /* 220 */
	/* __NR_fcntl64 */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_fcntl_hook },
	/* __NR_TUX; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_223 ; not implemented  */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_gettid */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_readahead */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setxattr */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lsetxattr */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fsetxattr */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getxattr */
	{ 4, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getxattr_hook },
	/* __NR_lgetxattr */
	{ 4, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getxattr_hook }, /* 230 */
	/* __NR_fgetxattr */
	{ 4, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getxattr_hook },
	/* __NR_listxattr */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_listxattr_hook },
	/* __NR_llistxattr */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_listxattr_hook },
	/* __NR_flistxattr */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_listxattr_hook },
	/* __NR_removexattr */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lremovexattr */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fremovexattr */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_tkill */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sendfile64 */
	{ 4, 0, 1, { 0, 0, sizeof(loff_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_futex */
	{ 6, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 240 */
	/* __NR_sched_setaffinity */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_getaffinity */
	{ 3, 0, 1, { 0, 0, sizeof(cpu_set_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_set_thread_area */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_thread_area */
	{ 1, 0, 1, { sizeof(struct user_desc), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_setup */
	{ 2, 0, 1, { 0, sizeof(aio_context_t), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_destroy */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_getevents */
	{ 5, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_io_getevents_hook },
	/* __NR_io_submit */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_cancel */
	{ 3, 0, 1, { 0, 0, sizeof(struct io_event), 0, 0, 0 }, NULL, NULL },
	/* __NR_fadvise64 */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 250 */
	/* __NR_251; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_exit_group */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lookup_dcookie */
	{ 3, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_lookup_dcookie_hook },
	/* __NR_epoll_create */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_ctl */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_wait */
	{ 4, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_epoll_wait_hook },
	/* __NR_remap_file_pages */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_set_tid_address */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_create */
	{ 3, 0, 1, { 0, 0, sizeof(timer_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_settime */
	{ 4, 0, 1, { 0, 0, 0, sizeof(struct itimerspec), 0, 0 }, NULL, NULL },
	/* 260 */
	/* __NR_timer_gettime */
	{ 2, 0, 1, { 0, sizeof(struct itimerspec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_getoverrun */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_delete */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_settime */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_gettime */
	{ 2, 0, 1, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_getres */
	{ 2, 0, 1, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_nanosleep */
	{ 4, 0, 1, { 0, 0, 0, sizeof(struct timespec), 0, 0 }, NULL, NULL },
	/* __NR_statfs64 */
	{ 3, 0, 1, { 0, 0, sizeof(struct statfs64), 0, 0, 0 }, NULL, NULL },
	/* __NR_fstatfs64 */
	{ 3, 0, 1, { 0, 0, sizeof(struct statfs64), 0, 0, 0 }, NULL, NULL },
	/* __NR_tgkill */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 270 */
	/* __NR_utimes */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fadvise64_64 */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vserver; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mbind */
	{ 6, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_mempolicy */
	{ 5, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_get_mempolicy_hook },
	/* __NR_set_mempolicy */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_open */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_unlink */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_timedsend */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	
	/* __NR_mq_timedreceive */
	{ 5, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_mq_timedreceive_hook },
	/* 280 */
	/* __NR_mq_notify */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_getsetattr */
	{ 3, 0, 1, { 0, 0, sizeof(struct mq_attr), 0, 0, 0 }, NULL, NULL },
	/* __NR_kexec_load */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_waitid */
	{ 4, 0, 1, { 0, 0, sizeof(siginfo_t), 0, sizeof(struct rusage), 0 },
	NULL, NULL },
	/* __NR_285; not implemented */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_add_key */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_request_key */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_keyctl */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ioprio_set */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ioprio_get */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 290 */
	/* __NR_inotify_init */
	{ 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_inotify_add_watch */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_inotify_rm_watch */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_migrate_pages */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_openat */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mkdirat */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mknodat */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchownat */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_futimesat */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstatat64 */
	{ 4, 0, 1, { 0, 0, sizeof(struct stat64), 0, 0, 0 }, NULL, NULL },
	/* 300 */
	/* __NR_unlinkat */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_renameat */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_linkat */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_symlinkat */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_readlinkat */
	{ 4, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_readlinkat_hook },
	/* __NR_fchmodat */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_faccessat */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pselect6 */
	{ 6, 0, 1, { 0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), 0, 0 }, 
	NULL, NULL },
	/* __NR_ppoll */
	{ 5, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_poll_hook },
	/* __NR_unshare */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 310 */
	/* __NR_set_robust_list */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_robust_list */
	{ 3, 0, 1, { 0, sizeof(struct robust_list_head*), sizeof(size_t), 0, 0,
	0 }, NULL, NULL },
	/* __NR_splice */
	{ 6, 0, 1, { 0, sizeof(loff_t), 0, sizeof(loff_t), 0, 0 }, NULL, NULL },
	/* __NR_sync_file_range */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_tee */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vmsplice */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_move_pages */
	{ 6, 0, 1, { 0, 0, 0, 0, sizeof(int), 0 }, NULL, NULL },
	/* __NR_getcpu */
	{ 3, 0, 1, { sizeof(unsigned), sizeof(unsigned),
	sizeof(struct getcpu_cache), 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_pwait */
	{ 6, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_epoll_wait_hook },
	/* __NR_utimensat */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 320 */
	/* __NR_signalfd */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timerfd_create */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_eventfd */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fallocate */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timerfd_settime */
	{ 4, 0, 1, { 0, 0, 0, sizeof(struct itimerspec), 0, 0 }, NULL, NULL },
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	/* __NR_timerfd_gettime */
	{ 2, 0, 1, { 0, sizeof(struct itimerspec), 0, 0, 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	/* __NR_signalfd4 */
	{ 4, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_eventfd2 */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_create1 */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_dup3 */
	{ 3, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 330 */
	/* __NR_pipe2 */
	{ 2, 0, 1, { sizeof(int) * 2, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_inotify_init1 */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	/* __NR_preadv */
	{ 5, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_readv_hook },
	/* __NR_pwritev */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,31)
	/* __NR_rt_tgsigqueueinfo */
	{ 4, 0, 1, { 0, 0, 0, sizeof(siginfo_t), 0, 0 }, NULL, NULL },
	/* __NR_perf_counter_open */
	{ 5, 0, 1, { sizeof(struct perf_counter_attr), 0, 0, 0, 0, 0 }, NULL,
	NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	/* __NR_rt_tgsigqueueinfo */
	{ 4, 0, 1, { 0, 0, 0, sizeof(siginfo_t), 0, 0 }, NULL, NULL },
	/* __NR_perf_event_open */
	{ 5, 0, 1, { sizeof(struct perf_event_attr), 0, 0, 0, 0, 0 }, NULL,
	NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	/* __NR_recvmmsg */
	{ 5, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_recvmmsg_hook },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	/* __NR_fanotify_init */
	{ 2, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fanotify_mark */
	{ 5, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pnatedmlimit64 */
	{ 4, 0, 1, { 0, 0, 0, sizeof(struct rlimit64), 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	/* __NR_name_to_handle_at */
	{ 5, 0, 1, { 0, 0, sizeof(struct file_handle), sizeof(int), 0, 0 },
	NULL, NULL },
	/* __NR_open_by_handle_at */
	{ 3, 0, 1, { 0, sizeof(struct file_handle), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_adjtime */
	{ 2, 0, 1, { 0, sizeof(struct timex), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_syncfs */
	{ 1, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
#endif
};


/*
 * add a new pre-syscall callback into a syscall descriptor
 *
 * @desc:	the syscall descriptor
 * @pre:	function pointer to the pre-syscall handler
 *
 * returns:	0 on success, 1 on error
 */
int
syscall_set_pre(syscall_desc_t *desc, void (* pre)(syscall_ctx_t*))
{
	/* sanity checks; optimized branch */
	if (unlikely((desc == NULL) | (pre == NULL)))
		/* return with failure */
		return 1;

	/* update the pre-syscall callback */
	desc->pre = pre;

	/* set the save arguments flag */
	desc->save_args = 1;

	/* success */
	return 0;
}

/*
 * add a new post-syscall callback into a syscall descriptor
 *
 * @desc:	the syscall descriptor
 * @post:	function pointer to the post-syscall handler
 *
 * returns:	0 on success, 1 on error
 */
int
syscall_set_post(syscall_desc_t *desc, void (* post)(syscall_ctx_t*))
{
	/* sanity checks; optimized branch */
	if (unlikely((desc == NULL) | (post == NULL)))
		/* return with failure */
		return 1;

	/* update the post-syscall callback */
	desc->post = post;
	
	/* set the save arguments flag */
	desc->save_args = 1;

	/* success */
	return 0;
}

/*
 * remove the pre-syscall callback from a syscall descriptor
 *
 * @desc:       the syscall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int
syscall_clr_pre(syscall_desc_t *desc)
{
	/* sanity check; optimized branch */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the pre-syscall callback */
	desc->pre = NULL;

	/* check if we need to clear the save arguments flag */
	if (desc->post == NULL)
		/* clear */
		desc->save_args = 0;

	/* return with success */
	return 0;
}

/*
 * remove the post-syscall callback from a syscall descriptor
 *
 * @desc:       the syscall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int
syscall_clr_post(syscall_desc_t *desc)
{
	/* sanity check; optimized branch */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the post-syscall callback */
	desc->post = NULL;

	/* check if we need to clear the save arguments flag */
	if (desc->pre == NULL)
		/* clear */
		desc->save_args = 0;

	/* return with success */
	return 0;
}

/* __NR_(p)read(64) and __NR_readlink post syscall hook */
static void
post_read_hook(syscall_ctx_t *ctx)
{
	/* read()/readlink() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_getgroups16 post syscall_hook */
static void
post_getgroups16_hook(syscall_ctx_t *ctx)
{
	/* getgroups16() was not successful */
	if ((long)ctx->ret <= 0 || (old_gid_t *)ctx->arg[SYSCALL_ARG1] == NULL)
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1],
			(sizeof(old_gid_t) * (size_t)ctx->ret));
}

/* __NR_getgroups post syscall_hook */
static void
post_getgroups_hook(syscall_ctx_t *ctx)
{
	/* getgroups() was not successful */
	if ((long)ctx->ret <= 0 || (gid_t *)ctx->arg[SYSCALL_ARG1] == NULL)
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1],
			(sizeof(gid_t) * (size_t)ctx->ret));
}

/* __NR_readlinkat post syscall hook */
static void
post_readlinkat_hook(syscall_ctx_t *ctx)
{
	/* readlinkat() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG2], (size_t)ctx->ret);
}

/* __NR_mmap post syscall hook */
static void
post_mmap_hook(syscall_ctx_t *ctx)
{
	/* the map offset */
	size_t offset = (size_t)ctx->arg[SYSCALL_ARG1];

	/* mmap() was not successful; optimized branch */
	if (unlikely((void *)ctx->ret == MAP_FAILED))
		return;

	/* estimate offset; optimized branch */
	if (unlikely(offset < PAGE_SZ))
		offset = PAGE_SZ;
	else
		offset = offset + PAGE_SZ - (offset % PAGE_SZ);

	/* grow downwards; optimized branch */
	if (unlikely((int)ctx->arg[SYSCALL_ARG3] & MAP_GROWSDOWN))
		/* fix starting address */
		ctx->ret = ctx->ret - offset;
	
	/* emulate the clear_tag() call */
	tagmap_clrn((size_t)ctx->ret, offset);
}

/* __NR_readv and __NR_preadv post syscall hook */
static void
post_readv_hook(syscall_ctx_t *ctx)
{
	/* iterators */
	int	i;
	struct	iovec *iov;
	
	/* bytes copied in a iovec structure */
	size_t	iov_tot;

	/* total bytes copied */
	size_t	tot = (size_t)ctx->ret;

	/* (p)readv() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* iterate the iovec structures */
	for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) {
		/* get an iovec  */
		iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;

		/* get the length of the iovec */
		iov_tot = (tot >= (size_t)iov->iov_len) ?
				(size_t)iov->iov_len : tot;
	
		/* clear the tag bits */
		tagmap_clrn((size_t)iov->iov_base, iov_tot);

		/* housekeeping */
		tot -= iov_tot;
	}
}

/* __NR_epoll_pwait post syscall hook */
static void
post_epoll_wait_hook(syscall_ctx_t *ctx)
{

	/* epoll_pwait() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1],
			sizeof(struct epoll_event) * (size_t)ctx->ret);
}

/* __NR_poll and __NR_ppoll post syscall hook */
static void
post_poll_hook(syscall_ctx_t *ctx)
{
	/* iterators */
	size_t	i;
	struct	pollfd *pfd;

	/* (p)poll() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* iterate the pollfd structures */
	for (i = 0; i < (size_t)ctx->arg[SYSCALL_ARG1]; i++) {
		/* get pollfd */
		pfd = ((struct pollfd *)ctx->arg[SYSCALL_ARG0]) + i;
	
		/* clear the tag bits */
		tagmap_clrn((size_t)&pfd->revents, sizeof(short));
	}
}

/* __NR_mq_timedreceive post syscall hook */
static void
post_mq_timedreceive_hook(syscall_ctx_t *ctx)
{
	/* mq_timedreceive() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
	
	/* priority argument is supplied */
	if ((size_t *)ctx->arg[SYSCALL_ARG3] != NULL)
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG3], sizeof(size_t));
}

/* __NR_get_mempolicy */
static void
post_get_mempolicy_hook(syscall_ctx_t *ctx)
{
	/* get_mempolicy() was not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* flags is zero */
	if ((unsigned long)ctx->arg[SYSCALL_ARG4] == 0) {
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
		tagmap_clrn(ctx->arg[SYSCALL_ARG1],
						sizeof(unsigned long));
		/* done */
		return;
	}

	/* MPOL_F_MEMS_ALLOWED is set on flags */
	if (((unsigned long)ctx->arg[SYSCALL_ARG4] &
				MPOL_F_MEMS_ALLOWED) != 0) {
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG1],
						sizeof(unsigned long));
		/* done */
		return;
	}
	
	/* MPOL_F_ADDR is set on flags */
	if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_ADDR) != 0 &&
		((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) == 0) {
		/* mode is provided */
		if ((int *)ctx->arg[SYSCALL_ARG0] != NULL)
			/* clear the tag bits */
			tagmap_clrn(ctx->arg[SYSCALL_ARG0],
							sizeof(int));

		/* nodemask is provided */
		if ((unsigned long *)ctx->arg[SYSCALL_ARG1] != NULL)
			/* clear the tag bits */
			tagmap_clrn(ctx->arg[SYSCALL_ARG1],
						sizeof(unsigned long));
		/* done */
		return;
	}
	
	/* MPOL_F_NODE & MPOL_F_ADDR is set on flags */
	if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_ADDR) != 0 && 
		((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) != 0) {
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
		/* done */
		return;
	}
	
	/* MPOL_F_NODE is set on flags */
	if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) != 0) {
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
		/* done */
		return;
	}
}

/* __NR_lookup_dcookie post syscall hook */
static void
post_lookup_dcookie_hook(syscall_ctx_t *ctx)
{
	/* lookup_dcookie() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_io_getevents post syscall hook */
static void
post_io_getevents_hook(syscall_ctx_t *ctx)
{
	/* io_getevents() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG3],
				sizeof(struct io_event) * (size_t)ctx->ret);

	/* timespec is specified */
	if ((struct timespec *)ctx->arg[SYSCALL_ARG4] != NULL)
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG4],
						sizeof(struct timespec));
}

/* __NR_(f, l)listxattr post syscall hook */
static void
post_listxattr_hook(syscall_ctx_t *ctx)
{
	/* *listxattr() was not successful; optimized branch */
	if ((long)ctx->ret <= 0 || (void *)ctx->arg[SYSCALL_ARG1] == NULL)
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_(f, l)getxattr post syscall hook */
static void
post_getxattr_hook(syscall_ctx_t *ctx)
{
	/* *getxattr() was not successful; optimized branch */
	if ((long)ctx->ret <= 0 || (void *)ctx->arg[SYSCALL_ARG2] == NULL)
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG2], (size_t)ctx->ret);
}

/* __NR_getdents post syscall hook */
static void
post_getdents_hook(syscall_ctx_t *ctx)
{
	/* getdents() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_mincore post syscall hook */
static void
post_mincore_hook(syscall_ctx_t *ctx)
{
	/* mincore() was not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG2],
		(((size_t)ctx->arg[SYSCALL_ARG1] + PAGE_SZ - 1) / PAGE_SZ));
}

/* __NR_getcwd post syscall hook */
static void
post_getcwd_hook(syscall_ctx_t *ctx)
{
	/* getcwd() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG0], (size_t)ctx->ret);
}

/* __NR_rt_sigpending post syscall hook */
static void
post_rt_sigpending_hook(syscall_ctx_t *ctx)
{
	/* rt_sigpending() was not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG0], (size_t)ctx->arg[SYSCALL_ARG1]);
}

/* __NR_quotactl post syscall hook */
static void
post_quotactl_hook(syscall_ctx_t *ctx)
{
	/* offset */
	size_t off;

	/* quotactl() was not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* different offset ranges */
	switch ((int)ctx->arg[SYSCALL_ARG0]) {
		case Q_GETFMT:
			off = sizeof(__u32); 
			break;
		case Q_GETINFO:
			off = sizeof(struct if_dqinfo);
			break;
		case Q_GETQUOTA:
			off = sizeof(struct if_dqblk);
			break;
		case Q_XGETQSTAT:
			off = sizeof(struct fs_quota_stat);
			break;
		case Q_XGETQUOTA:
			off = sizeof(struct fs_disk_quota);
			break;
		default:
			/* nothing to do */
			return;
	}

	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG3], off);
}

/* __NR_modify_ldt post syscall hook */
static void
post_modify_ldt_hook(syscall_ctx_t *ctx)
{
	/* modify_ldt() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_ipc post syscall hook */
static void
post_ipc_hook(syscall_ctx_t *ctx)
{
	/* semaphore union */
	union semun *su;

	/* ipc() is a demultiplexer for all SYSV IPC calls */
	switch ((int)ctx->arg[SYSCALL_ARG0]) {
		/* msgctl() */
		case MSGCTL:
			/* msgctl() was not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
			
			/* fix the cmd parameter */
			ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

			/* differentiate based on the cmd */
			switch ((int)ctx->arg[SYSCALL_ARG2]) {
				case IPC_STAT:
				case MSG_STAT:
					/* clear the tag bits */
					tagmap_clrn(ctx->arg[SYSCALL_ARG4],
						sizeof(struct msqid_ds));
					break;
				case IPC_INFO:
				case MSG_INFO:
					/* clear the tag bits */
					tagmap_clrn(ctx->arg[SYSCALL_ARG4],
						sizeof(struct msginfo));
					break;
				default:
					/* nothing to do */
					return;
			}
			break;
		/* shmctl() */
		case SHMCTL:
			/* shmctl() was not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
			
			/* fix the cmd parameter */
			ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

			/* differentiate based on the cmd */
			switch ((int)ctx->arg[SYSCALL_ARG2]) {
				case IPC_STAT:
				case SHM_STAT:
					/* clear the tag bits */
					tagmap_clrn(ctx->arg[SYSCALL_ARG4],
						sizeof(struct shmid_ds));
					break;
				case IPC_INFO:
				case SHM_INFO:
					/* clear the tag bits */
					tagmap_clrn(ctx->arg[SYSCALL_ARG4],
						sizeof(struct shminfo));
					break;
				default:
					/* nothing to do */
					return;
			}
			break;
		/* semctl() */
		case SEMCTL:
			/* semctl() was not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
			
			/* get the semun structure */	
			su = (union semun *)ctx->arg[SYSCALL_ARG4];
			
			/* fix the cmd parameter */
			ctx->arg[SYSCALL_ARG3] -= IPC_FIX;

			/* differentiate based on the cmd */
			switch ((int)ctx->arg[SYSCALL_ARG3]) {
				case IPC_STAT:
				case SEM_STAT:
					/* clear the tag bits */
					tagmap_clrn((size_t)su->buf,
						sizeof(struct semid_ds));
					break;
				case IPC_INFO:
				case SEM_INFO:
					/* clear the tag bits */
					tagmap_clrn((size_t)su->buf,
						sizeof(struct seminfo));
					break;
				default:
					/* nothing to do */
					return;
			}
			break;
		/* msgrcv() */
		case MSGRCV:
			/* msgrcv() was not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
			
			/* clear the tag bits */
			tagmap_clrn(ctx->arg[SYSCALL_ARG4],
					(size_t)ctx->ret + sizeof(long));
			break;
		default:
			/* nothing to do */
			return;
	}
}

/* __NR_fcntl post syscall hook */
static void
post_fcntl_hook(syscall_ctx_t *ctx)
{
	/* fcntl() was not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* differentiate based on the cmd argument */
	switch((int)ctx->arg[SYSCALL_ARG1]) {
		/* F_GETLK */
		case F_GETLK:
			/* clear the tag bits */
			tagmap_clrn(ctx->arg[SYSCALL_ARG2],
					sizeof(struct flock));
			break;
		/* F_GETLK64 */
		case F_GETLK64:
			/* clear the tag bits */
			tagmap_clrn(ctx->arg[SYSCALL_ARG2],
					sizeof(struct flock64));
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
		/* F_GETOWN_EX */
		case F_GETOWN_EX:
			/* clear the tag bits */
			tagmap_clrn(ctx->arg[SYSCALL_ARG2],
					sizeof(struct f_owner_ex));
			break;
#endif
		default:
			/* nothing to do */
			break;
	}
}

/* __NR_socketcall post syscall hook */
static void
post_socketcall_hook(syscall_ctx_t *ctx)
{
	/* message header; recvmsg(2) */
	struct	msghdr *msg;

	/* iov bytes copied; recvmsg(2) */
	size_t	iov_tot;

	/* iterators */
	size_t	i;
	struct	iovec *iov;
	
	/* total bytes received */
	size_t	tot;
	
	/* socket call arguments */
	unsigned long	*args = (unsigned long *)ctx->arg[SYSCALL_ARG1];

	/* demultiplex the socketcall */
	switch ((int)ctx->arg[SYSCALL_ARG0]) {
		case SYS_ACCEPT:
		case SYS_ACCEPT4:
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;

			/* addr argument is provided */
			if ((void *)args[SYSCALL_ARG1] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG1],
					*((int *)args[SYSCALL_ARG2]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG2], sizeof(int));
			}
			break;
		case SYS_SOCKETPAIR:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG3], (sizeof(int) * 2));
			break;
		case SYS_RECV:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG1], (size_t)ctx->ret);
			break;
		case SYS_RECVFROM:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG1], (size_t)ctx->ret);

			/* sockaddr argument is specified */
			if ((void *)args[SYSCALL_ARG4] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG4],
					*((int *)args[SYSCALL_ARG5]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG5], sizeof(int));
			}
			break;
		case SYS_GETSOCKOPT:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG3],
					*((int *)args[SYSCALL_ARG4]));
			
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG4], sizeof(int));
			break;
		case SYS_RECVMSG:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;

			/* extract the message header */
			msg = (struct msghdr *)args[SYSCALL_ARG1];

			/* source address specified */
			if (msg->msg_name != NULL) {
				/* clear the tag bits */
				tagmap_clrn((size_t)msg->msg_name,
					msg->msg_namelen);
				
				/* clear the tag bits */
				tagmap_clrn((size_t)&msg->msg_namelen,
						sizeof(int));
			}
			
			/* ancillary data specified */
			if (msg->msg_control != NULL) {
				/* clear the tag bits */
				tagmap_clrn((size_t)msg->msg_control,
					msg->msg_controllen);
				
				/* clear the tag bits */
				tagmap_clrn((size_t)&msg->msg_controllen,
						sizeof(int));
			}

			/* flags; clear the tag bits */
			tagmap_clrn((size_t)&msg->msg_flags, sizeof(int));

			/* total bytes received */	
			tot = (size_t)ctx->ret;

			/* iterate the iovec structures */
			for (i = 0; i < msg->msg_iovlen && tot > 0; i++) {
				/* get the next I/O vector */
				iov = &msg->msg_iov[i];

				/* get the length of the iovec */
				iov_tot = (tot > (size_t)iov->iov_len) ?
						(size_t)iov->iov_len : tot;
	
				/* clear the tag bits */
				tagmap_clrn((size_t)iov->iov_base, iov_tot);
		
				/* housekeeping */
				tot -= iov_tot;
			}
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
		case SYS_RECVMMSG:
			/* fix the syscall context */
			ctx->arg[SYSCALL_ARG0] = args[SYSCALL_ARG0];
			ctx->arg[SYSCALL_ARG1] = args[SYSCALL_ARG1];
			ctx->arg[SYSCALL_ARG2] = args[SYSCALL_ARG2];
			ctx->arg[SYSCALL_ARG3] = args[SYSCALL_ARG3];
			ctx->arg[SYSCALL_ARG4] = args[SYSCALL_ARG4];

			/* invoke __NR_recvmmsg post syscall hook */
			post_recvmmsg_hook(ctx);
			break;
#endif
		default:
			/* nothing to do */
			return;
	}
}

/* 
 * __NR_syslog post syscall hook
 *
 * NOTE: this is not related to syslog(3)
 * see klogctl(3)/syslog(2)
 */
static void
post_syslog_hook(syscall_ctx_t *ctx)
{
	/* syslog() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* differentiate based on the type */
	switch ((int)ctx->arg[SYSCALL_ARG0]) {
		case 2:
		case 3:
		case 4:
			/* clear the tag bits */
			tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
			break;
		default:
			/* nothing to do */
			return;
	}
}

/* __NR__sysctl post syscall hook */
static void
post__sysctl_hook(syscall_ctx_t *ctx)
{
	/* _sysctl arguments */
	struct __sysctl_args *sa;

	/* _sysctl() was not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;

	/* _sysctl arguments */
	sa = (struct __sysctl_args *)ctx->arg[SYSCALL_ARG0];

	/* clear the tag bits */
	tagmap_clrn((size_t)sa->newval, sa->newlen);

	/* save old value is specified */
	if (sa->oldval != NULL) {
		/* clear the tag bits */
		tagmap_clrn((size_t)sa->oldval, *sa->oldlenp);
		
		/* clear the tag bits */
		tagmap_clrn((size_t)sa->oldlenp, sizeof(size_t));
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
/* __NR_recvmmsg post syscall hook */
static void
post_recvmmsg_hook(syscall_ctx_t *ctx)
{
	/* message headers; recvmsg(2) recvmmsg(2) */
	struct	mmsghdr *msg;
	struct	msghdr *m;

	/* iov bytes copied; recvmsg(2) */
	size_t	iov_tot;

	/* iterators */
	size_t	i, j;
	struct	iovec *iov;
	
	/* total bytes received */
	size_t	tot;
	
	/* recvmmsg() was not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* iterate the mmsghdr structures */
	for (i = 0; i < (size_t)ctx->ret; i++) {
		/* get the next mmsghdr structure */
		msg = ((struct mmsghdr *)ctx->arg[SYSCALL_ARG1]) + i;
	
		/* extract the message header */
		m = &msg->msg_hdr;

		/* source address specified */
		if (m->msg_name != NULL) {
			/* clear the tag bits */
			tagmap_clrn((size_t)m->msg_name, m->msg_namelen);
			
			/* clear the tag bits */
			tagmap_clrn((size_t)&m->msg_namelen, sizeof(int));
		}
			
		/* ancillary data specified */
		if (m->msg_control != NULL) {
			/* clear the tag bits */
			tagmap_clrn((size_t)m->msg_control, m->msg_controllen);
				
			/* clear the tag bits */
			tagmap_clrn((size_t)&m->msg_controllen, sizeof(int));
		}

		/* flags; clear the tag bits */
		tagmap_clrn((size_t)&m->msg_flags, sizeof(int));
		
		/* total bytes received; clear the tag bits */	
		tot = (size_t)msg->msg_len;
		tagmap_clrn((size_t)&msg->msg_len, sizeof(unsigned));
		
		/* iterate the iovec structures */
		for (j = 0; j < m->msg_iovlen && tot > 0; j++) {
			/* get the next I/O vector */
			iov = &m->msg_iov[j];

			/* get the length of the iovec */
			iov_tot = (tot > (size_t)iov->iov_len) ?
					(size_t)iov->iov_len : tot;
	
			/* clear the tag bits */
			tagmap_clrn((size_t)iov->iov_base, iov_tot);
	
			/* housekeeping */
			tot -= iov_tot;
		}
	}

	/* timespec structure specified */
	if ((struct timespec *)ctx->arg[SYSCALL_ARG4] != NULL);
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(struct timespec));
}
#endif
