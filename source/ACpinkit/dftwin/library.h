struct moditem{
	string name;
	unsigned long base_address;
	unsigned long size;
	bool is_generator;
};

VOID ImageUnload(IMG img, VOID *v);
VOID ImageLoad(IMG img, VOID *v);

// struct moditem* modhash[0x100000];



#define ADDR2MOD(x)		modhash[(x) >> 12]
#define CANTEXEC(x)		(modhash[(x) >> 12] == NULL) 
#define ADDR2NAME(x)	modhash[(x) >> 12] == NULL ? "Unknown dll" : modhash[(x) >> 12] -> name.c_str()

VOID print_instruction(ADDRINT source);
VOID init_module_entry();
BOOL is_whitelisted_target(ADDRINT addr);


string attr_to_str(unsigned long attr);

#define JITFILE "jit.txt"

BOOL is_g_point(ADDRINT addr);
VOID make_a_jit_entry(ADDRINT addr);