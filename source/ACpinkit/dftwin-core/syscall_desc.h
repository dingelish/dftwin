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

#ifndef __SYSCALL_DESC_H__
#define __SYSCALL_DESC_H__

//#include <sys/resource.h>
//#include <sys/sysinfo.h>
//#include <sys/time.h>
//#include <sys/times.h>
//#include <sys/timex.h>
//#include <sys/types.h>
//#include <sys/vfs.h>
//#include <sys/vm86.h>
//
//#include <asm/ldt.h>
//#include <asm/posix_types.h>
//#include <linux/aio_abi.h>
//#include <linux/futex.h>
//#include <linux/mqueue.h>
//#include <linux/utsname.h>
//
//#include <signal.h>
//#include <ustat.h>

#include "libdft_api.h"
#include "branch_pred.h"

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,31)
#include <linux/perf_counter.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#include <linux/perf_event.h>
#endif


/* 
 * definition of old_*, linux_*, and OS-specific types
 *
 * this might break in the future; keep it up2date
 */
typedef unsigned long old_sigset_t;

struct old_linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_offset;
	unsigned short	d_namlen;
	char		d_name[1];
};

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

typedef	unsigned short	old_uid_t;
typedef	unsigned short	old_gid_t;

struct getcpu_cache {
	unsigned long blob[128 / sizeof(long)];
};

typedef struct __user_cap_header_struct {
	unsigned int version;
	int pid;
} *cap_user_header_t;

typedef struct __user_cap_data_struct {
	unsigned int effective;
	unsigned int permitted;
	unsigned int inheritable;
} *cap_user_data_t;

#define Q_GETFMT	0x800004
#define Q_GETINFO	0x800005
#define Q_GETQUOTA	0x800007
#define Q_SETQUOTA	0x800008
#define XQM_CMD(x)	(('X'<<8)+(x))
#define Q_XGETQUOTA     XQM_CMD(3)
#define Q_XGETQSTAT     XQM_CMD(5)

struct if_dqinfo {
	unsigned __int64 dqi_bgrace;
	unsigned __int64 dqi_igrace;
	unsigned int dqi_flags;
	unsigned int dqi_valid;
};

struct if_dqblk {
	unsigned __int64 dqb_bhardlimit;
	unsigned __int64 dqb_bsoftlimit;
	unsigned __int64 dqb_curspace;
	unsigned __int64 dqb_ihardlimit;
	unsigned __int64 dqb_isoftlimit;
	unsigned __int64 dqb_curinodes;
	unsigned __int64 dqb_btime;
	unsigned __int64 dqb_itime;
	unsigned int dqb_valid;
};

typedef struct fs_qfilestat {
	unsigned __int64 qfs_ino;
	unsigned __int64 qfs_nblks;
	unsigned int qfs_nextents;
} fs_qfilestat_t;

struct fs_quota_stat {
	signed char		qs_version;
	unsigned short		qs_flag;
	signed char		qs_pad;
	fs_qfilestat_t	qs_uquota;
	fs_qfilestat_t	qs_gquota;
	unsigned int		qs_incoredqs;
	signed int		qs_btimelimit;
	signed int		qs_itimelimit;
	signed int		qs_rtbtimelimit;
	unsigned short		qs_bwarnlimit;
	unsigned short		qs_iwarnlimit;
};

struct fs_disk_quota {
	signed char	d_version;
	signed char	d_flags;
	unsigned short	d_fieldmask;
	unsigned int	d_id;
	unsigned __int64	d_blk_hardlimit;
	unsigned __int64	d_blk_softlimit;
	unsigned __int64	d_ino_hardlimit;
	unsigned __int64	d_ino_softlimit;
	unsigned __int64	d_bcount;
	unsigned __int64	d_icount;
	signed int	d_itimer;
	signed int	d_btimer;
	unsigned short	d_iwarns;
	unsigned short	d_bwarns;
	signed int	d_padding2;
	unsigned __int64	d_rtb_hardlimit;
	unsigned __int64	d_rtb_softlimit;
	unsigned __int64	d_rtbcount;
	signed int	d_rtbtimer;
	unsigned short	d_rtbwarns;
	signed short	d_padding3;
	char	d_padding4[8];
};
typedef struct {
        volatile unsigned int lock;
} raw_spinlock_t;

typedef struct {
        raw_spinlock_t raw_lock;
        unsigned int break_lock;
} spinlock_t;

struct kern_ipc_perm
{
        spinlock_t      lock;
        int             deleted;
        int             id;
        int           key;
        unsigned int           uid;
        unsigned int           gid;
        unsigned int           cuid;
        unsigned int           cgid;
        unsigned int          mode;
        unsigned long   seq;
        void            *security;
};
struct ipc_perm
{
    signed int __key;                      /* Key.  */
    unsigned int uid;                        /* Owner's user ID.  */
    unsigned int gid;                        /* Owner's group ID.  */
    unsigned int cuid;                       /* Creator's user ID.  */
    unsigned int cgid;                       /* Creator's group ID.  */
    unsigned short int mode;            /* Read/write permission.  */
    unsigned short int __pad1;
    unsigned short int __seq;           /* Sequence number.  */
    unsigned short int __pad2;
    unsigned long int __unused1;
    unsigned long int __unused2;
};

struct sem {
        int     semval;         /* current value */
        int     sempid;         /* pid of last operation */
};
struct sem_undo {
        struct sem_undo *       proc_next;      /* next entry on this process */
        struct sem_undo *       id_next;        /* next entry on this semaphore set */
        int                     semid;          /* semaphore set identifier */
        short *                 semadj;         /* array of adjustments, one per semaphore */
};

struct sembuf {
        unsigned short  sem_num;        /* semaphore index in array */
        short           sem_op;         /* semaphore operation */
        short           sem_flg;        /* operation flags */
};

struct sem_array {
        struct kern_ipc_perm    sem_perm;       /* permissions .. see ipc.h */
        time_t                  sem_otime;      /* last semop time */
        time_t                  sem_ctime;      /* last change time */
        struct sem              *sem_base;      /* ptr to first semaphore in array */
        struct sem_queue        *sem_pending;   /* pending operations to be processed */
        struct sem_queue        **sem_pending_last; /* last pending operation */
        struct sem_undo         *undo;          /* undo requests on this array */
        unsigned long           sem_nsems;      /* no. of semaphores in array */
};
struct sem_queue {
        struct sem_queue *      next;    /* next entry in the queue */
        struct sem_queue **     prev;    /* previous entry in the queue, *(q->prev) == q */
        struct task_struct*     sleeper; /* this process */
        struct sem_undo *       undo;    /* undo structure */
        int                     pid;     /* process id of requesting process */
        int                     status;  /* completion status of operation */
        struct sem_array *      sma;     /* semaphore array for operations */
        int                     id;      /* internal sem id */
        struct sembuf *         sops;    /* array of pending operations */
        int                     nsops;   /* number of operations */
        int                     alter;   /* does the operation alter the array? */
};


struct semid_ds {
        struct ipc_perm sem_perm;               /* permissions .. see ipc.h */
        long sem_otime;              /* last semop time */
        long sem_ctime;              /* last change time */
        struct sem      *sem_base;              /* ptr to first semaphore in array */
        struct sem_queue *sem_pending;          /* pending operations to be processed */
        struct sem_queue **sem_pending_last;    /* last pending operation */
        struct sem_undo *undo;                  /* undo requests on this array */
        unsigned short  sem_nsems;              /* no. of semaphores in array */
};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
struct file_handle {
	unsigned int		handle_bytes;
	int 		handle_type;
	/* file identifier */
	unsigned char	f_handle[0];
};
#endif

#define SEMCTL	3
#define MSGRCV	12
#define MSGCTL	14
#define SHMCTL	24

#define IPC_FIX	256

union semun {
	int		val;
	struct semid_ds	*buf;
	unsigned short	*array;
	struct seminfo	*__buf;
};

#define SYS_ACCEPT	5
#define SYS_GETSOCKNAME	6
#define SYS_GETPEERNAME	7
#define SYS_SOCKETPAIR	8
#define SYS_RECV	10
#define SYS_RECVFROM	12
#define SYS_GETSOCKOPT	15
#define SYS_RECVMSG	17
#define SYS_ACCEPT4	18
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#define SYS_RECVMMSG	19
#endif

/* page size in bytes */
#define PAGE_SZ		4096

/* system call descriptor */
typedef struct {
	size_t	nargs;				/* number of arguments */
	size_t	save_args;			/* flag; save arguments */
	size_t	retval_args;		/* flag; returns value in arguments */
	size_t	map_args[SYSCALL_ARG_NUM];	/* arguments map */
	void	(* pre)(syscall_ctx_t*);	/* pre-syscall callback */
	void 	(* post)(syscall_ctx_t*);	/* post-syscall callback */
} syscall_desc_t;

/* syscall API */
int	syscall_set_pre(syscall_desc_t*, void (*)(syscall_ctx_t*));
int	syscall_clr_pre(syscall_desc_t*);
int	syscall_set_post(syscall_desc_t*, void (*)(syscall_ctx_t*));
int	syscall_clr_post(syscall_desc_t*);

#endif /* __SYSCALL_DESC_H__ */
