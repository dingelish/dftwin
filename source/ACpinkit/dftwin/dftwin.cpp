#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "pin.H"
#include "thread_helper.h"
#include "debug_helper.h"
#include "library.h"
#include "libdasm.h"
#include "net_helper.h"
#include "tagmap.h"

#include <map>
#include <set>
using namespace std;

map<ADDRINT, ADDRINT> writehash;

#ifdef AMD64
#define NtProtectVirtualMemory 0x004d
#define NtAllocateVirtualMemory 0x0015
#else
#define NtProtectVirtualMemory 0x00d7
#define NtAllocateVirtualMemory 0x0013
#endif
extern struct moditem* modhash[0x100000];
extern REG thread_ctx_ptr;

set <ADDRINT> fp_generator;
set <ADDRINT> rt_generator;



VOID ThreadDestruct(VOID *ptr){
	debugout("Thread Destruct function on ptr %08X\n", ptr);
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v){
	TLS_KEY tls_key = PIN_CreateThreadDataKey(ThreadDestruct);
	set_tls_key(tls_key);


	struct thread_local *t_local = new(struct thread_local);
	t_local ->tid = PIN_GetTid();
	t_local ->threadid = PIN_ThreadId();

	//t_local -> debug_info();
	debugout("Thread %X started!\n", PIN_GetTid());

	PIN_SetThreadData(tls_key, t_local, t_local -> threadid);
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 flags, VOID *v){
	struct thread_local *t_local = get_thread_local();

	// t_local -> debug_info();

	PIN_DeleteThreadDataKey(get_tls_key());
	debugout("Thread finished!\n");
}

//VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
//{
//	ADDRINT num = PIN_GetSyscallNumber(ctxt, std);
//	struct thread_local *t_local = get_thread_local();
//	t_local -> lastsyscall = num;
//}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	unsigned int num;
	thread_ctx_t *tctx = (thread_ctx_t *)
			PIN_GetContextReg(ctxt, thread_ctx_ptr);
	num = tctx -> syscall_ctx.nr;
	if(num == NtProtectVirtualMemory){
		// ARG 1 unsigned long ** base_address
		// ARG 2 unsigned long *  size
		// ARG 4 unsigned long *  attr
		unsigned long base_address = * (unsigned long *) PIN_GetSyscallArgument(ctxt, std, 1);
		unsigned long size = * (unsigned long *) PIN_GetSyscallArgument(ctxt, std, 2);
		unsigned long attr = (unsigned long ) PIN_GetSyscallArgument(ctxt, std, 3);

		debugdata("%08X %s[%08X, %08X] -> %s\n", PIN_GetTid(), ADDR2NAME(base_address), base_address, base_address + size, attr_to_str(attr).c_str());
	}
	else if(num == NETSYSCALL){
		unsigned long *reg_esp = (unsigned long *)PIN_GetContextReg(ctxt, REG_ESP);
		unsigned long *parameters = reg_esp+2;
		if(parameters[5] == IOCTL_AFD_RECV || parameters[5] == IOCTL_AFD_RECV_DATAGRAM){
			//        if(parameters[5] == IOCTL_AFD_RECV){
			PAFD_SEND_INFO pAfdTcpInfo = (PAFD_SEND_INFO)parameters[6];
			if(pAfdTcpInfo->BufferArray->len > 1)
				debugout("Received %d bytes at %08X\n", pAfdTcpInfo->BufferArray->len, pAfdTcpInfo->BufferArray->buf);
			tagmap_setn((size_t)pAfdTcpInfo->BufferArray->buf, pAfdTcpInfo->BufferArray->len);
		}
	}

}

VOID iscriticbranch_32(ADDRINT source, ADDRINT target) {
	//INSTRUCTION inst;
	//get_instruction(&inst, (BYTE *) source, MODE_32);
	//if(inst.type == INSTRUCTION_TYPE_RET){
	//	print_instruction(source);
	//}



	if(is_whitelisted_target(target) == 0 && (*(unsigned int*)source != 0xc015ff64)){
		debugout("target is not whitelisted!\n");
		print_instruction(source);
	}

	if(CANTEXEC(target) && (*(unsigned int*)source != 0xc015ff64)){
		if(is_whitelisted_target(target) == 0){
			debugout("critic jump %08X -> %08X\n", source, target);
			print_instruction(source);
		}
		else
			return ;
		if(writehash.find(target) != writehash.end()){
			debugdata("target is from: ");
			print_instruction(writehash[target]);
		}
		else
			debugdata("can't find writer to indirect jump target!\n");
	}
	else if(CANTEXEC(source)){
		print_instruction(source);
		print_instruction(target);
	}
	return;
}

VOID iscriticbranch_ret(ADDRINT source, ADDRINT esp) {
	//debugout("judging addr: %08X, index = %08X, ptr = %08X\n", target, target >> 12, modhash[target >> 12]);
	//debugout("critic jump %08X -> %08X\n", source, target);
	//ADDRINT target = *(unsigned int *)esp;
	//if( CANTEXEC(source)){
	//	debugout("critic jump %08X -> %08X\n", source, target);
	//}
	//return;
	//debugout("this is ret\n");
	//print_instruction(source);
}

VOID execjit(ADDRINT ip){
	debugdata("exec jit %08X", ip);
	print_instruction(ip);
}

VOID RecordMemWrite(ADDRINT ip, ADDRINT addr) {
	//print_instruction(ip);
 //   debugdata("W:%08X to %08X\n", ip, addr);
	//if(modhash[ip >> 12] != NULL &&
	//	CANTEXEC(addr) == true &&
	//	modhash[ip >> 12] -> is_generator == true)
	if(CANTEXEC(addr) == true)
	//	modhash[ip >> 12] -> is_generator == true)

	{
		// dynamically generated code
		// need to save into table
		// writehash - find generator ip by using writehash
		writehash[addr] = ip;
	}
}

int isjitcode(ADDRINT ip){
	if(CANTEXEC(ip) && ip != 0x74F62320){
		//debugdata("exec jit %08X", ip);
		//print_instruction(ip);
		return 1;
	}
	return 0;
}
VOID outputins(ADDRINT ip, char* str){

	debugdata("exec jit %08X %s\n", ip, str);
	//free(str);
}
VOID Instruction(INS ins, VOID *v)
{
	REG reg;

	if(INS_IsRet(ins)){
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)iscriticbranch_ret,
			IARG_INST_PTR ,
            IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	}
	else if(INS_IsIndirectBranchOrCall(ins)){ //  && INS_Opcode(ins) != XED_ICLASS_RET_NEAR
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)iscriticbranch_32,
			IARG_INST_PTR ,
			IARG_BRANCH_TARGET_ADDR ,
			IARG_END);
	}
	//else{
	//UINT32 memOperands = INS_MemoryOperandCount(ins);
	//for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
	//	if (INS_MemoryOperandIsWritten(ins, memOp)) {
	//		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
	//				IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_END);
	//	}
	//}
	//}
	INS_InsertIfCall(ins,
		IPOINT_BEFORE,
		(AFUNPTR)isjitcode,
		IARG_INST_PTR ,
		IARG_END);
	INS_InsertThenCall(ins,
		IPOINT_BEFORE,
		(AFUNPTR)outputins,
		IARG_INST_PTR ,
		IARG_PTR , _strdup(INS_Disassemble(ins).c_str()),
		IARG_END);

	//INS_InsertIfCall(ins,
	//	IPOINT_BEFORE,
	//    (AFUNPTR)is_g_point,
	//	IARG_INST_PTR ,
	//	IARG_END);
	if(is_g_point(INS_Address(ins))){ // needs optimization
		UINT32 memOperands = INS_MemoryOperandCount(ins);
		for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
			if (INS_MemoryOperandIsWritten(ins, memOp)) {
				INS_InsertCall( ins, IPOINT_BEFORE, 
					(AFUNPTR)make_a_jit_entry,
					IARG_MEMORYOP_EA, memOp, 
					IARG_END);
			}
		}
	}

}

VOID FiniFunction(INT32 code, VOID *V){
	set<ADDRINT>::iterator iter;

	debugdata("FP Generator:\n");

	for(iter = fp_generator.begin(); iter != fp_generator.end(); iter ++){
		debugdata("%08X\n", *iter);
	}

	debugdata("RT Generator:\n");

	for(iter = rt_generator.begin(); iter != rt_generator.end(); iter ++){
		debugdata("%08X\n", *iter);
	}

}

/* 
 * DummyTool (i.e, libdft)
 *
 * used for demonstrating libdft
 */
int
main(int argc, char **argv)
{
	debugout("Running dftwin...\n");

	/* initialize symbol processing */
	PIN_InitSymbols();
       
	/* initialize Pin; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* Pin initialization failed */
		goto err;

	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;
	
	// System call entry/exit hook
	//PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

	// Thread start/fini hook
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Module load/unload hook
    IMG_AddInstrumentFunction(ImageLoad, 0);
	IMG_AddUnloadFunction(ImageUnload, 0);


	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddFiniFunction(FiniFunction, 0);

	debugout("Starting program!\n");

	/* start Pin */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:	/* error handling */

	/* return */
	return EXIT_FAILURE;
}
