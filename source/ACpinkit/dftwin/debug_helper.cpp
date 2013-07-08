#include "pin.H"
#include "debug_helper.h"


void _debugout(const char *file, const char* function, int line, const char* fmt, ...){
    va_list args;
    char buff[256];
        
    va_start(args, fmt);
    _snprintf(buff, 255, "[%9s:%03d] %s:", file, line, function);
    vsnprintf(buff + strlen(buff), 255, fmt, args);
	//printf("%s", buff);
	LOG(buff);
    va_end(args);
    return ;
}

void _debugdata(const char* fmt, ...){
    va_list args;
    char buff[256];
        
    va_start(args, fmt);
    vsnprintf(buff, 255, fmt, args);
	//printf("%s", buff);
	LOG(buff);
    va_end(args);
    return ;
}