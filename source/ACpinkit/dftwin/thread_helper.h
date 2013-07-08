#include <stdio.h>
#include <stdlib.h>

#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "pin.H"


#define MAXTHREAD			256

void set_tls_key(TLS_KEY tls_key);
TLS_KEY get_tls_key();

struct thread_local* get_thread_local();
void set_thread_local(struct thread_local *t_local);