/*-
 * Copyright (c) 2010, Columbia University
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

//#include <asm/ldt.h>
//#include <asm/posix_types.h>
//#include <linux/aio_abi.h>
//#include <linux/futex.h>
//#include <linux/mqueue.h>
//#include <linux/utsname.h>

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

typedef unsigned short	__kernel_old_uid_t;
typedef	__kernel_old_uid_t	old_uid_t;

typedef unsigned short	__kernel_old_gid_t;
typedef	__kernel_old_gid_t	old_gid_t;

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
	unsigned __int64 dqi_flags;
	unsigned __int64 dqi_valid;
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
	unsigned short		d_fieldmask;
	unsigned int	d_id;
	unsigned __int64	d_blk_hardlimit;
	unsigned __int64	d_blk_softlimit;
	unsigned __int64	d_ino_hardlimit;
	unsigned __int64	d_ino_softlimit;
	unsigned __int64	d_bcount;
	unsigned __int64	d_icount;
	signed int	d_itimer;
	signed int	d_btimer;
	unsigned short		d_iwarns;
	unsigned short		d_bwarns;
	signed int	d_padding2;
	unsigned __int64	d_rtb_hardlimit;
	unsigned __int64	d_rtb_softlimit;
	unsigned __int64	d_rtbcount;
	signed int	d_rtbtimer;
	unsigned short		d_rtbwarns;
	signed short	d_padding3;
	char	d_padding4[8];
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
