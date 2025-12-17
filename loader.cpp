#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include "ntstructs.h"
#include "syscalls.h"
#include "obfuscation.h"

#pragma comment(lib, "ntdll.lib")

#define CFG_UNHOOK      0
#define CFG_ANTIDEBUG   1
#define CFG_DELAY       0
#define CFG_SPOOF       1
#define CFG_STOMP       1
#define CFG_DEBUG       0

#if CFG_DEBUG
FILE* g_dbgfile = nullptr;
void InitDbg() {
    fopen_s(&g_dbgfile, "debug.log", "w");
}
void CloseDbg() {
    if (g_dbgfile) { fflush(g_dbgfile); fclose(g_dbgfile); }
}
#define DBG(fmt, ...) if (g_dbgfile) { fprintf(g_dbgfile, "[DBG] " fmt "\n", ##__VA_ARGS__); fflush(g_dbgfile); }
#else
#define DBG(fmt, ...) ((void)0)
inline void InitDbg() {}
inline void CloseDbg() {}
#endif

__forceinline void VolatileZero(void* ptr, size_t sz) {
    volatile char* p = (volatile char*)ptr;
    while (sz--) *p++ = 0;
}

// File is too large - this is a placeholder. Full file at local redteam folder.
// Build locally with: build.bat
