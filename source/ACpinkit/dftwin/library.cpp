#include <stdio.h>
#include <stdlib.h>

#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "pin.H"

#include "library.h"
#include "debug_helper.h"
#include "libdasm.h"
#include "pe.h"



#include <map>
#include <string>
#include <list>
#include <set>
using namespace std;

list<moditem *> modlist;

struct moditem* modhash[0x100000];
unsigned long modcount;

char *support_jit[] = 
{"flashplayer.exe", "v8test.exe", "Firefox.exe"};

map<string, unsigned int> critic_jump_whitelist;

map<string, unsigned int> jit_gpoint;
set<unsigned int> module_entry;

void init_jump_whitelist(){
	/*
	for x86 win7
	source:
	ntdll.dll+0x579d5 call [ebp+0x8] 
	USER32.dll+0x1b4e4 call [ebp+0x8]
	*/

}

void trim(char *str){

	size_t len = strlen(str);
	size_t i ;
	for(i = len - 1; i >= 0; i --){
		//printf("i = %u\n", i);
		if(str[i] == '\r' || str[i] == '\n')
			str[i] = 0;
		else
			break;
	}

}

const char* strcasestr(const char* source, const char* substr){
	unsigned int source_size = strlen(source);
	unsigned int sub_size = strlen(substr);

	if(sub_size > source_size)
		return NULL;

	if(_stricmp(source + (source_size - sub_size), substr) == 0)
		return source + (source_size - sub_size);
	else
		return NULL;

}

void check_jit_generator(struct moditem *mi){

	for(int i = 0; i < sizeof(support_jit)/sizeof(char *); i ++){
		if(strcasestr(mi->name.c_str(), support_jit[i]) != NULL){
			mi -> is_generator = true;
			return;
		}
	}
}

void add_module(IMG img){

	for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)){

		if(SEC_IsExecutable(sec)){

			ADDRINT secaddr = SEC_Address(sec);
			USIZE secsize = SEC_Size(sec);

			debugdata("%s", IMG_Name(img));
			debugdata("[%08X,%08X]\n",secaddr, secaddr + secsize);

			moditem *mi = new moditem;
			mi -> name = IMG_Name(img);
			mi -> base_address = SEC_Address(sec);
			mi -> size = SEC_Size(sec);
			mi -> is_generator = false;

			check_jit_generator(mi);

			modlist.push_back(mi);

			module_entry.insert(IMG_Entry(img));

			for(ADDRINT addr = mi -> base_address;
				addr <= mi -> base_address + mi -> size;
				addr += 0x1000){

					modhash[addr >> 12] = mi;
					//debugout("[%08X, %08X]added, index: %08X\n", addr, addr + 0x1000, addr >> 12);
			}
			modcount ++;
		}
	}

	unsigned int count = 0;

	ADDRINT start = IMG_StartAddress(img);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)start;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((unsigned char *)start + pDosHeader->e_lfanew);
	ADDRINT imagebase	= pNTHeader -> OptionalHeader.ImageBase;

	PIMAGE_OPTIONAL_HEADER pOptHeader = &pNTHeader -> OptionalHeader;

	PIMAGE_DATA_DIRECTORY pRelocTable = &(pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((unsigned char *)start + *(unsigned int *)pRelocTable);

	if(*(unsigned int *)pRelocTable == 0){
		debugdata("Not find relocations for %s\n", IMG_Name(img));
		return ;
	}

	while(pReloc->SizeOfBlock){
		//debugout("find reloc: %08X, size %08X\n", pReloc, pReloc->SizeOfBlock);
		for(int i = 0; i < (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++)
		{
			unsigned int reloc_item = pReloc->VirtualAddress + ((*(WORD*)((unsigned char *)pReloc + sizeof(IMAGE_BASE_RELOCATION) + i * 2)) & 0x0FFF) + imagebase;
			unsigned int realentry = *(unsigned int *)reloc_item;
			//debugdata("Reloc_item: %08X, %08X\n", reloc_item, realentry);
			if(modhash[realentry >> 12] != NULL){
				module_entry.insert(realentry);
				count ++;
			}
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((unsigned char *)pReloc + pReloc->SizeOfBlock);
	}

	DWORD dwExportOffset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if(dwExportOffset == 0)
		return;

	//debugout("dwExportOffset = %08X\n", dwExportOffset);

	struct IMAGE_EXPORT_DIRECTORY *pExportDir = (struct IMAGE_EXPORT_DIRECTORY *) (start + (unsigned int) dwExportOffset);
	DWORD num_of_func = pExportDir->NumberOfFunctions;

	//debugout("pExportDir = %08X\n", pExportDir);

	DWORD *export_func_list = (DWORD *) (start + (pExportDir->AddressOfFunctions));
	//debugout("pExportDir->AddressOfFunctions = %08X\n", pExportDir->AddressOfFunctions);
	//debugout("export_func_list = %08X\n", export_func_list);
	//debugout("num_of_func = %08X\n", num_of_func);

	for(DWORD i = 0; i < num_of_func; i ++){
		module_entry.insert(start + export_func_list[i]);
		//debugdata("export_func_list[%d] = %08X\n", i, export_func_list[i]);
	}
	debugout("%u reloc entries added for %s\n", count + num_of_func, IMG_Name(img));
	// printf("Modcount %d\n", modcount);
	// printf("List count: %d\n", modlist.size());
	return;
}

void remove_module(IMG img){
	string name = IMG_Name(img);
	list<moditem *>::iterator iter;
	for(iter = modlist.begin(); iter != modlist.end(); iter ++){

		while(iter != modlist.end() && (*iter)->name == name){

			unsigned long base = (*iter) -> base_address;
			unsigned long size = (*iter) -> size;
			unsigned long addr;

			// printf("Removing %s ...\n", (*iter) -> name.c_str());

			for(addr = base; addr <= base + size; addr += 0x1000){
				// printf("%08X\n", addr);
				modhash[addr >> 12] = NULL;
			}
			modcount --;
			delete (*iter);
			iter = modlist.erase(iter);
		}
	}
	//printf("Modcount %d\n", modcount);
	//printf("List count: %d\n", modlist.size());
	return;
}

VOID ImageUnload(IMG img, VOID *v)
{
	//printf("UNLoaded %s\n", IMG_Name(img).c_str());
	remove_module(img);
}

VOID ImageLoad(IMG img, VOID *v)
{
	//printf("Loaded %s\n", IMG_Name(img).c_str());
	add_module(img);
}

VOID print_instruction(ADDRINT source){
	INSTRUCTION inst;
	char buff[100];
	get_instruction(&inst, (BYTE*) source, MODE_32);
	get_instruction_string(&inst, FORMAT_INTEL, 0, buff, 100);

	if(modhash[source >> 12]){
		debugdata("%08X %02X %s + 0x%x %s\n",source, *(unsigned char *)source, ADDR2NAME(source), source - ADDR2MOD(source)->base_address, buff);
	}
	else{
		debugdata("unknown %08X %s\n", source, buff);
	}
}

VOID init_module_entry(){

}

VOID init_jit_func_generator(){
	FILE *f;
	fopen_s(&f, JITFILE, "rw");
	
	if(!f)
		exit(0);

	char *perline = new char[1000];

	fgets(perline, 1000, f);
	trim(perline);

	while(!feof(f)){
		char name[300];
		unsigned int offset;

		sscanf(perline, "%s %x", name, &offset);

		// debugout("found %s at offset %08X", name, offset);

		jit_gpoint[name] = offset;
	}

	free(perline);
	return;
}

BOOL is_g_point(ADDRINT addr){
	if(modhash[addr >> 12] != NULL){
		if(jit_gpoint[modhash[addr >> 12]->name] != 0){
			return true;
		}
	}
	return false;
}

VOID make_a_jit_entry(ADDRINT addr){
	module_entry.insert(addr);
}

/*#define PAGE_NOACCESS          0x01     
#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80     
#define PAGE_GUARD            0x100     
#define PAGE_NOCACHE          0x200     
#define PAGE_WRITECOMBINE     0x400    */ 

char *attr_str[] = 
{
	"NOACCESS",
	"READONLY",
	"READWRITE",
	"WRITECOPY",
	"EXECUTE",
	"EXECUTE_READ",
	"EXECUTE_READWRITE",
	"EXECUTE_WRITECOPY",
	"PAGE_GUARD",
	"PAGE_NOCACHE",
	"PAGE_WRITECOMBINE"};

string attr_to_str(unsigned long attr){
	string result = "";
	unsigned int i, count = 0;

	for(i = 1; i <= 0x400; i = i << 1){
		if((attr & i) != 0){
			result = result + attr_str[count];
			result = result + " ";
		}
		count ++;
	}

	return result;
}

BOOL is_whitelisted_target(ADDRINT addr){
	if(module_entry.find(addr) != module_entry.end())
		return 1;
	else
		return 0;
}
