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

#include <stdio.h>
#include <cstdlib>
#include <cstring>

#include "branch_pred.h"
#include "pin.H"
#include "libdft_api.h"
#include "libdasm.h"
#include "tagmap.h"
#include "process.h"
/* thread context */
extern REG thread_ctx_ptr;
typedef unsigned int uint32_t;
#define WORD_LEN	4	/* size in bytes of a word value */
#define VCPU_MASK16 0x03
#ifdef WIN7
#define NETSYSCALL	0x006b
#else
#define NETSYSCALL	0x0042
#endif

FILE *logfile;
extern ins_desc_t ins_desc[XED_ICLASS_LAST];
typedef struct _AFD_WSABUF {
    unsigned int  len;
    char * buf;
} AFD_WSABUF, *PAFD_WSABUF;

typedef struct  _AFD_SEND_INFO {
    PAFD_WSABUF				BufferArray;
    unsigned long				BufferCount;
    unsigned long				AfdFlags;
    unsigned long				TdiFlags;
} AFD_SEND_INFO , *PAFD_SEND_INFO ;


extern struct moditem mi[200];

extern moditem * hash_mod[0x10000];

extern int totalmods;

extern bool is_inited;

extern bool require_update;

char * net_func_names[] = {
    "HANDLE FileHandle",
    "HANDLE Event OPTIONAL",
    "PIO_APC_ROUTINE ApcRoutine OPTIONAL",
    "PVOID ApcContext OPTIONAL",
    "PIO_STATUS_BLOCK IoStatusBlock",
    "ULONG IoControlCode",
    "PVOID InputBuffer OPTIONAL",
    "ULONG InputBufferLength",
    "PVOID OutputBuffer OPTIONAL",
    "ULONG OutputBufferLength",
};
//#define AFD_RECV		0x12017
//#define AFD_BIND		0x12003
//#define AFD_CONNECT		0x12007
//#define AFD_SET_CONTEXT	0x12047
//#define AFD_RECV		0x12017
//#define AFD_SEND		0x1201f
//#define AFD_SELECT		0x12024
//#define AFD_SENDTO		0x12023
//#define AFD_RECVFROM	0x1201B

/* IOCTL Generation */
#define FILE_DEVICE_NETWORK             0x0012
#define METHOD_NEITHER                  3
#define FSCTL_AFD_BASE                  FILE_DEVICE_NETWORK
#define _AFD_CONTROL_CODE(Operation,Method)   ((FSCTL_AFD_BASE)<<12 | (Operation<<2) | Method)

/* AFD Commands */
#define AFD_BIND            0
#define AFD_CONNECT              1
#define AFD_START_LISTEN         2
#define AFD_WAIT_FOR_LISTEN      3
#define AFD_ACCEPT          4
#define AFD_RECV            5
#define AFD_RECV_DATAGRAM        6
#define AFD_SEND            7
#define AFD_SEND_DATAGRAM        8
#define AFD_SELECT          9
#define AFD_DISCONNECT           10
#define AFD_GET_SOCK_NAME        11
#define AFD_GET_PEER_NAME               12
#define AFD_GET_TDI_HANDLES      13
#define AFD_SET_INFO             14
#define AFD_GET_CONTEXT          16
#define AFD_SET_CONTEXT          17
#define AFD_SET_CONNECT_DATA         18
#define AFD_SET_CONNECT_OPTIONS      19
#define AFD_SET_DISCONNECT_DATA      20
#define AFD_SET_DISCONNECT_OPTIONS   21
#define AFD_GET_CONNECT_DATA         22
#define AFD_GET_CONNECT_OPTIONS      23
#define AFD_GET_DISCONNECT_DATA      24
#define AFD_GET_DISCONNECT_OPTIONS   25
#define AFD_SET_CONNECT_DATA_SIZE       26
#define AFD_SET_CONNECT_OPTIONS_SIZE    27
#define AFD_SET_DISCONNECT_DATA_SIZE    28
#define AFD_SET_DISCONNECT_OPTIONS_SIZE 29
#define AFD_GET_INFO             30
#define AFD_EVENT_SELECT         33
#define AFD_ENUM_NETWORK_EVENTS         34
#define AFD_DEFER_ACCEPT         35
#define AFD_GET_PENDING_CONNECT_DATA 41

/* AFD IOCTLs */

#define IOCTL_AFD_BIND \
  _AFD_CONTROL_CODE(AFD_BIND, METHOD_NEITHER)
#define IOCTL_AFD_CONNECT \
  _AFD_CONTROL_CODE(AFD_CONNECT, METHOD_NEITHER)
#define IOCTL_AFD_START_LISTEN \
  _AFD_CONTROL_CODE(AFD_START_LISTEN, METHOD_NEITHER)
#define IOCTL_AFD_WAIT_FOR_LISTEN \
  _AFD_CONTROL_CODE(AFD_WAIT_FOR_LISTEN, METHOD_BUFFERED )
#define IOCTL_AFD_ACCEPT \
  _AFD_CONTROL_CODE(AFD_ACCEPT, METHOD_BUFFERED )
#define IOCTL_AFD_RECV \
  _AFD_CONTROL_CODE(AFD_RECV, METHOD_NEITHER)
#define IOCTL_AFD_RECV_DATAGRAM \
  _AFD_CONTROL_CODE(AFD_RECV_DATAGRAM, METHOD_NEITHER)
#define IOCTL_AFD_SEND \
  _AFD_CONTROL_CODE(AFD_SEND, METHOD_NEITHER)
#define IOCTL_AFD_SEND_DATAGRAM \
  _AFD_CONTROL_CODE(AFD_SEND_DATAGRAM, METHOD_NEITHER)
#define IOCTL_AFD_SELECT \
  _AFD_CONTROL_CODE(AFD_SELECT, METHOD_BUFFERED )
#define IOCTL_AFD_DISCONNECT \
  _AFD_CONTROL_CODE(AFD_DISCONNECT, METHOD_NEITHER)
#define IOCTL_AFD_GET_SOCK_NAME \
  _AFD_CONTROL_CODE(AFD_GET_SOCK_NAME, METHOD_NEITHER)
#define IOCTL_AFD_GET_PEER_NAME \
  _AFD_CONTROL_CODE(AFD_GET_PEER_NAME, METHOD_NEITHER)
#define IOCTL_AFD_GET_TDI_HANDLES \
  _AFD_CONTROL_CODE(AFD_GET_TDI_HANDLES, METHOD_NEITHER)
#define IOCTL_AFD_SET_INFO \
  _AFD_CONTROL_CODE(AFD_SET_INFO, METHOD_NEITHER)
#define IOCTL_AFD_GET_CONTEXT \
  _AFD_CONTROL_CODE(AFD_GET_CONTEXT, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONTEXT \
  _AFD_CONTROL_CODE(AFD_SET_CONTEXT, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_GET_CONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_GET_CONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_GET_CONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_GET_CONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_GET_DISCONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_GET_DISCONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_GET_DISCONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_GET_DISCONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_DATA_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_DATA_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_OPTIONS_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_OPTIONS_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_DATA_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_DATA_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_OPTIONS_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_OPTIONS_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_GET_INFO \
  _AFD_CONTROL_CODE(AFD_GET_INFO, METHOD_NEITHER)
#define IOCTL_AFD_EVENT_SELECT \
  _AFD_CONTROL_CODE(AFD_EVENT_SELECT, METHOD_NEITHER)
#define IOCTL_AFD_DEFER_ACCEPT \
  _AFD_CONTROL_CODE(AFD_DEFER_ACCEPT, METHOD_NEITHER)
#define IOCTL_AFD_GET_PENDING_CONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_GET_PENDING_CONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_ENUM_NETWORK_EVENTS \
  _AFD_CONTROL_CODE(AFD_ENUM_NETWORK_EVENTS, METHOD_NEITHER)


/*
 * DTA/DFT alert
 *
 * @ins:	address of the offending instruction
 * @bt:		address of the branch target
 */
static void PIN_FAST_ANALYSIS_CALL
alert(ADDRINT ins, ADDRINT bt)
{
    fprintf(logfile,"shit\n");
    fflush(logfile);
    fclose(logfile);
}



/*
 * 32-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg32(thread_ctx_t *thread_ctx, uint32_t reg, uint32_t addr)
{
	/*
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	return thread_ctx->vcpu.gpr[reg] | tagmap_getl(addr);
}

/*
 * 16-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg16(thread_ctx_t *thread_ctx, uint32_t reg, uint32_t addr)
{
	/*
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	return (thread_ctx->vcpu.gpr[reg] & VCPU_MASK16)
		| tagmap_getw(addr);
}

/*
 * 32-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem32(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getl(paddr) | tagmap_getl(taddr);
}

/*
 * 16-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem16(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getw(paddr) | tagmap_getw(taddr);
}

/*
 * instrument the jmp/call instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_jmp_call(INS ins)
{
	/* temporaries */
	REG reg;

	/*
	 * we only care about indirect calls;
	 * optimized branch
	 */
	if (unlikely(INS_IsIndirectBranchOrCall(ins))) {
		/* perform operand analysis */

		/* call via register */
		if (INS_OperandIsReg(ins, 0)) {
			/* extract the register from the instruction */
			reg = INS_OperandReg(ins, 0);

			/* size analysis */

			/* 32-bit register */
			if (REG_is_gr32(reg))
				/*
				 * instrument assert_reg32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
			else
				/* 16-bit register */
				/*
				 * instrument assert_reg16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg16,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
		}
		else {
		/* call via memory */
			/* size analysis */

			/* 32-bit */
			if (INS_MemoryReadSize(ins) == WORD_LEN)
				/*
				 * instrument assert_mem32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
			/* 16-bit */
			else
				/*
				 * instrument assert_mem16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem16,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
		}
		/*
		 * instrument alert() before branch;
		 * conditional instrumentation -- then
		 */
		INS_InsertThenCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)alert,
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	}
}

/*
 * instrument the ret instruction
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_ret(INS ins)
{
	/* size analysis */

	/* 32-bit */
	if (INS_MemoryReadSize(ins) == WORD_LEN)
		/*
		 * instrument assert_mem32() before ret;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)assert_mem32,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	/* 16-bit */
	else
		/*
		 * instrument assert_mem16() before ret;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)assert_mem16,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);

	/*
	 * instrument alert() before ret;
	 * conditional instrumentation -- then
	 */
	INS_InsertThenCall(ins,
		IPOINT_BEFORE,
		(AFUNPTR)alert,
		IARG_FAST_ANALYSIS_CALL,
		IARG_INST_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_END);
}









/*
 * syscall enter notification (analysis function)
 *
 * save the system call context and invoke the pre-syscall callback
 * function (if registered)
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */



 void log(unsigned int reason, unsigned long buffer, unsigned long len){
     char oneline[100];
     if(len < 100)
        _snprintf(oneline, 40, "%s", buffer);
    else
        _snprintf(oneline, 40, "%s", buffer + 100);
    fprintf(logfile, "%08X\t%08X\t%08X\t%s\n", reason, buffer, len, oneline);
    fflush(logfile);
 }

static void
sysenter_on_entry(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);
	if(syscall_nr == NETSYSCALL){
		unsigned long *reg_esp = (unsigned long *)PIN_GetContextReg(ctx, REG_ESP);
		unsigned long *parameters = reg_esp+2;
		if(parameters[5] == IOCTL_AFD_SEND || parameters[5] == IOCTL_AFD_SEND_DATAGRAM){
//        if(parameters[5] == IOCTL_AFD_SEND){
            PAFD_SEND_INFO		pAfdTcpInfo			= (PAFD_SEND_INFO)parameters[6];
            if(pAfdTcpInfo->BufferArray->len > 1)
                log(parameters[5], (unsigned long)pAfdTcpInfo->BufferArray->buf, pAfdTcpInfo->BufferArray->len);
        }
	}
	//VOID find_module_list(moditem * mi,int * total,unsigned long  fsbase)
    if(is_inited == 0){
        find_module_list(mi, &totalmods, PIN_GetContextReg(ctx,REG_SEG_FS_BASE));
        update_modhash();
        is_inited = 1;
    }
    if(require_update){
        find_module_list(mi, &totalmods, PIN_GetContextReg(ctx,REG_SEG_FS_BASE));
        update_modhash();
        require_update = 0;
    }
	return;
}

static void
sysenter_on_exit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);
	if(syscall_nr == NETSYSCALL){
		unsigned long *reg_esp = (unsigned long *)PIN_GetContextReg(ctx, REG_ESP);
		unsigned long *parameters = reg_esp+2;
        if(parameters[5] == IOCTL_AFD_RECV || parameters[5] == IOCTL_AFD_RECV_DATAGRAM){
//        if(parameters[5] == IOCTL_AFD_RECV){
            PAFD_SEND_INFO		pAfdTcpInfo			= (PAFD_SEND_INFO)parameters[6];
            if(pAfdTcpInfo->BufferArray->len > 1)
                log(parameters[5], (unsigned long)pAfdTcpInfo->BufferArray->buf, pAfdTcpInfo->BufferArray->len);
                tagmap_setn((size_t)pAfdTcpInfo->BufferArray->buf, pAfdTcpInfo->BufferArray->len);
        }
	}
	return;
}
/*
 * dftwin_init
 *
 * here should be instructions
 * @null
 */
static int
dftwin_init()
{
	int res = libdft_part_init();

	if(res == 0)
		printf("init success!\n");
	else if (res == 1){
		printf("init thread contexts failed!\n");
		exit(0);
	}
	else if(res == 2){
		printf("init tagmap failed!\n");
		exit(0);
	}

	/* instrument call */
	(void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR],
			dta_instrument_jmp_call);

	/* instrument jmp */
	(void)ins_set_post(&ins_desc[XED_ICLASS_JMP],
			dta_instrument_jmp_call);

	/* instrument ret */
	(void)ins_set_post(&ins_desc[XED_ICLASS_RET_NEAR],
			dta_instrument_ret);

	PIN_AddSyscallEntryFunction(sysenter_on_entry, NULL);
	PIN_AddSyscallEntryFunction(sysenter_on_exit, NULL);

	logfile = fopen("c:\\log.txt", "w");

	if(!logfile){
	    printf("open logfile error!");
	    exit(0);
    }

    set_logfile(logfile);

	return 0;
}

/*
 * NullPin
 *
 * used for estimating the overhead of Pin
 */
int
main(int argc, char **argv)
{
	/* initialize symbol processing */

    char data[100] = "\x83\x7d\x08\x01\x00";

	INSTRUCTION inst;
	char tempstr[100];
	get_instruction(&inst, (BYTE*) &data, MODE_32);
	get_instruction_string(&inst, FORMAT_INTEL, 0, tempstr, 100);
	printf("%s\n", tempstr);

	PIN_InitSymbols();

	/* initialize PIN; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* PIN initialization failed */
		goto err;
	dftwin_init();
	/* register trace_ins() to be called for every trace */
	//TRACE_AddInstrumentFunction(trace_inspect, NULL);

	/* start PIN */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:
	/* error handling */

	/* return */
	return EXIT_FAILURE;
}
