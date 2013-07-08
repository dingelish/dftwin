#include <cstdio>
#include <cstdarg>
#include <cstring>

#define DEBUG

#ifdef DEBUG
#define debugout(...) _debugout(__FILE__, __FUNCTION__,  __LINE__, __VA_ARGS__)
#define debugdata(...) _debugdata(__VA_ARGS__);

#else
#define debugout(...)
#define debugdata(...)
#endif

void _debugout(const char *file, const char* function, int line, const char* fmt, ...);
void _debugdata(const char* fmt, ...);
