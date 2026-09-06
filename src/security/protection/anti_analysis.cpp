#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#include "security/protection/anti_analysis.h"
#include "security/protection/anti_debug.h"
#include "security/protection/anti_frida.h"
#include "security/protection/anti_dll.h"
#include "security/protection/anti_patch.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <intrin.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace security {

static uint64_t computeHashInternal() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (hMod == nullptr) return 0;
    uint8_t* base = reinterpret_cast<uint8_t*>(hMod);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            uint64_t hash = 0xCBF29CE484222325ULL;
            for (size_t j = 0; j < size; ++j) {
                hash ^= text[j];
                hash *= 0x100000001B3ULL;
            }
            return hash;
        }
    }
    return 0;
}

uint64_t astro_compute_text_hash() {
    return computeHashInternal();
}

bool astro_verify_text_hash(uint64_t expected) {
    return computeHashInternal() == expected;
}

bool astro_check_is_debugger_present() {
    if (AntiDebug::checkIsDebuggerPresent()) return true;
    if (AntiDebug::checkRemoteDebuggerPresent()) return true;
    return false;
}

bool astro_check_remote_debugger_present() {
    return AntiDebug::checkRemoteDebuggerPresent();
}

bool astro_check_debug_port() {
    return AntiDebug::checkNtQueryDebugPort() || AntiDebug::checkNtQueryDebugFlags() || AntiDebug::checkNtQueryDebugObjectHandle();
}

bool astro_check_peb_being_debugged() {
    return AntiDebug::checkPebBeingDebugged();
}

bool astro_check_nt_global_flag() {
    return AntiDebug::checkPebNtGlobalFlag();
}

bool astro_check_hw_breakpoints() {
    return AntiDebug::checkHardwareBreakpoints();
}

bool astro_check_timing() {
    return AntiDebug::checkTiming() || AntiDebug::checkTimingQPC();
}

bool astro_check_tool_modules() {
    if (AntiDebug::checkToolModules()) return true;
    if (AntiFrida::checkToolModules()) return true;
    if (AntiDll::checkBlockedDlls()) return true;
    return false;
}

bool astro_check_frida_threads() {
    return AntiFrida::checkFridaThreads();
}

bool astro_check_frida_ports() {
    return AntiFrida::checkFridaPorts();
}

bool astro_check_frida_pipes() {
    return AntiFrida::checkFridaNamedPipes();
}

bool astro_check_module_integrity() {
    static uint64_t expected = 0;
    static bool captured = false;
    uint64_t cur = computeHashInternal();
    if (cur == 0) return false;
    if (captured == false) {
        expected = cur;
        captured = true;
        return false;
    }
    return cur != expected;
}

bool astro_check_scyllahide() {
    if (AntiFrida::checkScyllaHide()) return true;
    if (AntiDebug::checkScyllaHide()) return true;
    return false;
}

uint32_t astro_run_all_checks(bool autokill) {
    uint32_t result = ASTRO_DETECT_NONE;
    if (astro_check_is_debugger_present()) result |= ASTRO_DETECT_DEBUGGER;
    if (astro_check_remote_debugger_present()) result |= ASTRO_DETECT_REMOTE_DEBUGGER;
    if (astro_check_debug_port()) result |= ASTRO_DETECT_DEBUG_PORT;
    if (astro_check_peb_being_debugged()) result |= ASTRO_DETECT_PEB_DEBUG;
    if (astro_check_nt_global_flag()) result |= ASTRO_DETECT_NT_GLOBAL_FLAG;
    if (astro_check_hw_breakpoints()) result |= ASTRO_DETECT_HW_BREAKPOINTS;
    if (astro_check_timing()) result |= ASTRO_DETECT_TIMING;
    if (astro_check_tool_modules()) result |= ASTRO_DETECT_TOOL_MODULE;
    if (astro_check_frida_threads()) result |= ASTRO_DETECT_FRIDA_THREAD;
    if (astro_check_frida_ports()) result |= ASTRO_DETECT_FRIDA_PORT;
    if (astro_check_frida_pipes()) result |= ASTRO_DETECT_FRIDA_PORT;
    if (astro_check_module_integrity()) result |= ASTRO_DETECT_MODULE_INTEGRITY;
    if (astro_check_scyllahide()) result |= ASTRO_DETECT_SCYLLAHIDE;
    if (autokill && result != ASTRO_DETECT_NONE) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
    }
    ASTRO_AI_TRAP();
    return result;
}

}
