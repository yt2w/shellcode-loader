#pragma once
#include <windows.h>
#include <winternl.h>

// Missing type definitions
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Syscall Number Table - Populated at runtime via Halo's Gate
struct SyscallTable {
    DWORD NtClose;
    DWORD NtOpenProcess;
    DWORD NtAllocateVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtQueryVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtWaitForSingleObject;
    DWORD NtDelayExecution;
    DWORD NtQueryInformationProcess;
    DWORD NtOpenProcessToken;
    DWORD NtTerminateProcess;
};

extern SyscallTable g_Syscalls;
extern PVOID g_SyscallGadget;

// External ASM stubs - all take (gadget, ssn, ...) as first two params
extern "C" {
    NTSTATUS SysNtClose(
        PVOID gadget, DWORD ssn,
        HANDLE Handle
    );
    
    NTSTATUS SysNtOpenProcess(
        PVOID gadget, DWORD ssn,
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );
    
    NTSTATUS SysNtAllocateVirtualMemory(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    
    NTSTATUS SysNtFreeVirtualMemory(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );
    
    NTSTATUS SysNtProtectVirtualMemory(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
    
    NTSTATUS SysNtWriteVirtualMemory(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T Size,
        PSIZE_T BytesWritten
    );
    
    NTSTATUS SysNtReadVirtualMemory(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T Size,
        PSIZE_T BytesRead
    );
    
    NTSTATUS SysNtQueryVirtualMemory(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        DWORD MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );
    
    NTSTATUS SysNtCreateThreadEx(
        PVOID gadget, DWORD ssn,
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );
    
    NTSTATUS SysNtWaitForSingleObject(
        PVOID gadget, DWORD ssn,
        HANDLE Handle,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout
    );
    
    NTSTATUS SysNtDelayExecution(
        PVOID gadget, DWORD ssn,
        BOOLEAN Alertable,
        PLARGE_INTEGER DelayInterval
    );
    
    NTSTATUS SysNtQueryInformationProcess(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    NTSTATUS SysNtOpenProcessToken(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        PHANDLE TokenHandle
    );
    
    NTSTATUS SysNtTerminateProcess(
        PVOID gadget, DWORD ssn,
        HANDLE ProcessHandle,
        NTSTATUS ExitStatus
    );
}
