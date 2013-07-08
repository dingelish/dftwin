
#include "thread_helper.h"
#include "debug_helper.h"
// Overall threadid to tls_key array, indexed by threadid
// create and destroy on thread start and thread finish
static TLS_KEY tls_key_array[MAXTHREAD] = {0};

void set_tls_key(TLS_KEY tls_key){
	tls_key_array[PIN_ThreadId()] = tls_key;
	//debugout("set tls_key[%d] = %d\n", PIN_ThreadId(), tls_key);
}

TLS_KEY get_tls_key(){
	//debugout("get tls_key[%d] = %d\n", PIN_ThreadId(), tls_key_array[PIN_ThreadId()]);
	return tls_key_array[PIN_ThreadId()];
}

struct thread_local* get_thread_local(){
	TLS_KEY tls_key = get_tls_key();
	return (struct thread_local*) PIN_GetThreadData(tls_key, PIN_ThreadId());
}
void set_thread_local(struct thread_local *t_local){
	TLS_KEY tls_key = get_tls_key();
	PIN_SetThreadData(tls_key, t_local, t_local -> threadid);
}