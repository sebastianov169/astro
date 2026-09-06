#include "anti_iat.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <cstring>

#pragma comment(lib, "psapi.lib")

namespace astro { namespace security {

// Critical functions to monitor for IAT hooks.
// If any of these is redirected to a foreign module, it means hooking.
static const struct { const char* dll; const char* func; } kMonitored[] = {
    {"kernel32.dll",   "CreateFileW"},
    {"kernel32.dll",   "ReadFile"},
    {"kernel32.dll",   "WriteFile"},
    {"kernel32.dll",   "CloseHandle"},
    {"kernel32.dll",   "VirtualProtect"},
    {"kernel32.dll",   "LoadLibraryA"},
    {"kernel32.dll",   "LoadLibraryW"},
    {"kernel32.dll",   "GetProcAddress"},
    {"advapi32.dll",   "RegOpenKeyExW"},
    {"ws2_32.dll",     "send"},
    {"ws2_32.dll",     "recv"},
    {"ws2_32.dll",     "connect"},
    {"winhttp.dll",    "WinHttpSendRequest"},
    {"winhttp.dll",    "WinHttpReceiveResponse"},
    {"ntdll.dll",      "NtQueryInformationProcess"},
    {"ntdll.dll",      "NtSetInformationThread"},
};

bool AntiIat::initialize() {
    ASTRO_AI_TRAP();
    m_entries.clear();

    for (const auto& entry : kMonitored) {
        HMODULE hmod = GetModuleHandleA(entry.dll);
        if (!hmod) continue;

        FARPROC proc = GetProcAddress(hmod, entry.func);
        if (!proc) continue;

        IatEntry e;
        e.func_name = entry.func;
        e.original_addr = reinterpret_cast<void*>(proc);
        e.original_module = hmod;
        m_entries.push_back(e);
    }

    m_initialized = !m_entries.empty();
    return m_initialized;
}

bool AntiIat::addressInModule(void* addr, HMODULE hmod) {
    if (!addr || !hmod) return false;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi)))
        return false;

    uintptr_t base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
    uintptr_t end = base + mi.SizeOfImage;
    uintptr_t a = reinterpret_cast<uintptr_t>(addr);
    return a >= base && a < end;
}

bool AntiIat::isInlineHooked(void* funcAddr) {
    if (!funcAddr) return false;

    // Read first bytes to check for common inline hook patterns
    uint8_t first_byte = *reinterpret_cast<volatile uint8_t*>(funcAddr);

    // E9 = relative JMP (most common detour)
    if (first_byte == 0xE9) return true;

    // FF 25 = indirect JMP [addr] (IAT-style redirect in code)
    if (first_byte == 0xFF) {
        uint8_t second = *reinterpret_cast<volatile uint8_t*>(
            reinterpret_cast<uintptr_t>(funcAddr) + 1);
        if (second == 0x25) return true;
    }

    // CC = INT3 breakpoint
    if (first_byte == 0xCC) return true;

    return false;
}

bool AntiIat::verifyIntegrity() {
    if (!m_initialized || m_entries.empty()) return true;

    ASTRO_AI_TRAP();

    for (const auto& entry : m_entries) {
        FARPROC current = GetProcAddress(entry.original_module, entry.func_name);
        if (!current) continue; // module unloaded, skip

        void* curAddr = reinterpret_cast<void*>(current);

        // Check if function address was redirected to a different module
        if (curAddr != entry.original_addr && !addressInModule(curAddr, entry.original_module))
            return false;

        // Check if original function has been inline-hooked
        if (isInlineHooked(entry.original_addr))
            return false;
    }

    return true;
}

}} // namespace
