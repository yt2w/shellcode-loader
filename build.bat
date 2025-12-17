@echo off
setlocal

echo [*] Building Shellcode Loader
echo.

if not exist shellcode.h (
    echo [!] shellcode.h not found
    echo [!] Run: python embed.py -i payload.bin -o shellcode.h
    exit /b 1
)

echo [*] Compiling syscalls.asm
ml64 /c /nologo syscalls.asm
if errorlevel 1 (
    echo [!] ASM compilation failed
    exit /b 1
)

echo [*] Compiling loader.cpp
cl /nologo /O2 /MT /GS- /W3 loader.cpp syscalls.obj /Fe:loader.exe /link /SUBSYSTEM:WINDOWS /ENTRY:WinMain kernel32.lib user32.lib ntdll.lib
if errorlevel 1 (
    echo [!] C++ compilation failed
    exit /b 1
)

echo.
echo [+] Build complete: loader.exe
del /q *.obj 2>nul

endlocal
