#include "anti_debug.h"
#include <intrin.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>
#include <cstdlib>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
#include "security/crypto/string_encrypt.h"
#include "security/crypto/obfuscation.h"
#pragma warning(disable: 4996)
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "ntdll.lib")

namespace security {

struct PEB_BEING_DEBUGGED {
    BOOLEAN DebuggerPresent;
    BOOLEAN unused_1;
    BOOLEAN unused_2;
    BOOLEAN unused_3;
};

static AntiDebug* g_instance = nullptr;

AntiDebug::AntiDebug() = default;

AntiDebug::~AntiDebug() {
    stop();
}

void AntiDebug::start() {
    if (m_running.exchange(true))
        return;

    hideThreadFromDebugger();
    m_monitorThread = std::thread(&AntiDebug::monitorLoop, this);
}

void AntiDebug::stop() {
    if (!m_running.exchange(false))
        return;

    if (m_monitorThread.joinable())
        m_monitorThread.join();
}

void AntiDebug::setDetectionCallback(DetectionCallback cb) {
    m_callback = std::move(cb);
}

bool AntiDebug::isDebugged() const {
    return runAllChecks();
}

void AntiDebug::onDetection(const char* reason) {
    {
        char _tp[MAX_PATH]{}; GetTempPathA(MAX_PATH, _tp);
        std::string _logPath = std::string(_tp) + "astro_kill_trace.log";
        FILE* f = fopen(_logPath.c_str(), "a");
        if (f) { fprintf(f, "AntiDebug detection: %s\n", reason); fclose(f); }
    }
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
}

void AntiDebug::monitorLoop() {
    while (m_running) {
        if (runAllChecks()) {
            { FILE* _f = fopen((std::string(getenv("TEMP")?getenv("TEMP"):".") + "\\astro_det.log").c_str(), "a"); if (_f) { fprintf(_f, "DETECT[anti_debu]: %s\n", ENC("anti_debug_detected").decrypt().c_str()); fclose(_f); } }
            onDetection(ENC("anti_debug_detected").decrypt().c_str());
            return;
        }
        Sleep(CHECK_INTERVAL_MS);
    }
}

bool AntiDebug::runAllChecks() const {
    // DEBUG: per-check trace to find false positives on dev machines
    struct Check { const char* name; bool (*fn)(); };
    static const Check checks[] = {
        {"IsDebuggerPresent", &AntiDebug::checkIsDebuggerPresent},
        {"RemoteDebugger", &AntiDebug::checkRemoteDebuggerPresent},
        {"DebugPort", &AntiDebug::checkNtQueryDebugPort},
        {"DebugFlags", &AntiDebug::checkNtQueryDebugFlags},
        {"DebugObjectHandle", &AntiDebug::checkNtQueryDebugObjectHandle},
        {"PebBeingDebugged", &AntiDebug::checkPebBeingDebugged},
        {"PebNtGlobalFlag", &AntiDebug::checkPebNtGlobalFlag},
        {"HardwareBps", &AntiDebug::checkHardwareBreakpoints},
        {"Int3", &AntiDebug::checkInt3Breakpoints},
        {"Timing", &AntiDebug::checkTiming},
        {"TimingQPC", &AntiDebug::checkTimingQPC},
        // NOTE: checkDebugWindows REMOVIDO del hot path: busca ventanas globales de
        // herramientas (IDA/CE/PH) que pueden estar abiertas para OTRO trabajo y no
        // tocarnos. "Instalado/en uso ajeno" no es deteccion; lo que importa es que
        // no haya debugger ATTACHED a este proceso (checks de arriba) ni sus DLLs.
        {"ToolModules", &AntiDebug::checkToolModules},
        {"ScyllaHide", &AntiDebug::checkScyllaHide},
    };
    for (const auto& ck : checks) {
        bool hit = ck.fn();
        if (hit) {
            FILE* _f = fopen((std::string(getenv("TEMP")?getenv("TEMP"):".") + "\\astro_det.log").c_str(), "a");
            if (_f) { fprintf(_f, "SUBCHECK[anti_debu]: %s\n", ck.name); fclose(_f); }
            return true;
        }
    }
    return false;
}

bool AntiDebug::checkIsDebuggerPresent() {
    return IsDebuggerPresent() != FALSE;
}

bool AntiDebug::checkRemoteDebuggerPresent() {
    BOOL isRemote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
    return isRemote != FALSE;
}

bool AntiDebug::checkNtQueryDebugPort() {
    DWORD_PTR port = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(), (PROCESSINFOCLASS)7, &port, sizeof(port), nullptr);
    if (status >= 0 && port != 0)
        return true;
    return false;
}

bool AntiDebug::checkNtQueryDebugFlags() {
    DWORD flags = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(), (PROCESSINFOCLASS)0x1F, &flags, sizeof(flags), nullptr);
    if (status >= 0 && flags == 0)
        return true;
    return false;
}

bool AntiDebug::checkNtQueryDebugObjectHandle() {
    HANDLE objHandle = nullptr;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &objHandle, sizeof(objHandle), nullptr);
    if (status >= 0 && objHandle != nullptr)
        return true;
    return false;
}

bool AntiDebug::checkPebBeingDebugged() {
#ifdef _WIN64
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (!peb)
        return false;
    return peb->BeingDebugged != FALSE;
}

bool AntiDebug::checkPebNtGlobalFlag() {
#ifdef _WIN64
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (!peb)
        return false;

#ifdef _WIN64
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(peb) + 0xBC);
    if (ntGlobalFlag & 0x70)
        return true;
#else
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(peb) + 0x68);
    if (ntGlobalFlag & 0x70)
        return true;
#endif
    return false;
}

bool AntiDebug::checkHardwareBreakpoints() {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
}

bool AntiDebug::checkInt3Breakpoints() {
    // DISABLED (2026-08-22): byte-scanning .text for 0xCC cannot distinguish software
    // breakpoints from legitimate MSVC inter-function padding (alignment + /JMC debug
    // breaks). It false-positived on every clean MSVC+/GL build. Real user-mode INT3
    // hooks are covered by checkSelfIntegrity-style section hashing and VEH in AntiPatch.
    return false;
}


bool AntiDebug::checkTiming() {
    // FALSE-POSITIVE FIX: single-sample rdtsc/QPC deltas flag ANY preemption spike
    // (background builds, antivirus scans, sandboxed agents) and killed clean apps.
    // A real single-step debugger inflates EVERY iteration; scheduler noise only some.
    // Take the MINIMUM of 5 samples - robust on loaded machines, still catches step traps.
    UINT64 best = ~0ULL;
    for (int k = 0; k < 5; ++k) {
        UINT64 start = __rdtsc();
        for (volatile int i = 0; i < 1000; i++) {}
        UINT64 end = __rdtsc();
        UINT64 delta = end - start;
        if (delta < best) best = delta;
    }
    if (best > TIMING_THRESHOLD_RDTSC)
        return true;
    LARGE_INTEGER freq;
    if (QueryPerformanceFrequency(&freq) && freq.QuadPart != 0) {
        double bestMs = 1e18;
        for (int k = 0; k < 5; ++k) {
            LARGE_INTEGER t1, t2;
            QueryPerformanceCounter(&t1);
            for (volatile int i = 0; i < 1000; i++) {}
            QueryPerformanceCounter(&t2);
            LONGLONG elapsed = t2.QuadPart - t1.QuadPart;
            double ms = (double)elapsed * 1000.0 / (double)freq.QuadPart;
            if (ms < bestMs) bestMs = ms;
        }
        if (bestMs > 500.0)
            return true;
    }
    return false;
}

bool AntiDebug::checkTimingQPC() {
    // FALSE-POSITIVE FIX: only flag extreme overshoot (>500ms = sleep-skipping traps);
    // removed the <5ms "too fast" check - timer resolution changes by other processes
    // (timeBeginPeriod) made it unreliable.
    LARGE_INTEGER freq, s, e;
    if (!QueryPerformanceFrequency(&freq))
        return false;
    QueryPerformanceCounter(&s);
    Sleep(10);
    QueryPerformanceCounter(&e);
    double elapsed = (double)(e.QuadPart - s.QuadPart) * 1000.0 / (double)freq.QuadPart;
    if (elapsed > 500.0)
        return true;
    return false;
}

bool AntiDebug::checkDebugWindows() {
    const wchar_t* debugWindows[] = {
        L"x64dbg", L"x64dbg_window", L"ODBG", L"OLLYDBG",
        L"Cheat Engine", L"CheatEngineClass",
        L"Process Hacker", L"ProcessHackerWindow",
        L"DbgView", L"WinDbgFrameClass",
        L"-)( IDA", L"IDA64",
        L"Binary Ninja", L"Frida",
        nullptr
    };

    for (int i = 0; debugWindows[i]; i++) {
        if (FindWindowW(nullptr, debugWindows[i]))
            return true;
    }
    return false;
}

bool AntiDebug::checkToolModules() {
    const wchar_t* toolModules[] = {
        L"x64dbg.dll", L"x32dbg.dll", L"x64dbg", L"x32dbg",
        L"scylla_hide.dll", L"ScyllaHide.dll", L"scylla",
        L"TitanHide.dll", L"TitanHide.sys", L"TitanHide",
        L"frida-agent.dll", L"frida-gadget.dll", L"frida-helper.dll",
        L"frida-agent", L"ollydbg", L"ida",
        nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            for (int i = 0; toolModules[i]; i++) {
                if (wcsstr(me.szModule, toolModules[i]) || _wcsicmp(me.szModule, toolModules[i]) == 0) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

bool AntiDebug::checkScyllaHide() {
    const wchar_t* scyllaDlls[] = {
        L"ScyllaHide.dll", L"scylla_hide.dll", L"ScyllaHideX64dbg.dll",
        L"ScyllaHideOlly.dll", L"HookLibraryx64.dll", L"HookLibraryx86.dll",
        L"TitanHide.dll", nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                for (int i = 0; scyllaDlls[i]; i++) {
                    if (_wcsicmp(me.szModule, scyllaDlls[i]) == 0 || wcsstr(me.szModule, scyllaDlls[i])) {
                        CloseHandle(snap);
                        return true;
                    }
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    FARPROC pNtSetInformationThread = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    if (pNtSetInformationThread) {
        const BYTE* p = reinterpret_cast<const BYTE*>(pNtSetInformationThread);
        if (p[0] == 0xE9 || p[0] == 0xEB || (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0x15)) || p[0] == 0xCC) {
            return true;
        }
    }
    return false;
}

void AntiDebug::hideThreadFromDebugger() {
    NtSetInformationThread(
        GetCurrentThread(),
        (THREADINFOCLASS)0x11,
        nullptr,
        0);
}

void initializeAntiDebug() {
    if (!g_instance) {
        g_instance = new AntiDebug();
        g_instance->hideThreadFromDebugger();
        g_instance->start();
    }
}

void shutdownAntiDebug() {
    if (g_instance) {
        g_instance->stop();
        delete g_instance;
        g_instance = nullptr;
    }
}

}
