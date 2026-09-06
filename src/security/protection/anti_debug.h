#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <thread>
#include <atomic>
#include <functional>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace security {

class AntiDebug {
public:
    using DetectionCallback = std::function<void(const char* reason)>;

    AntiDebug();
    ~AntiDebug();

    AntiDebug(const AntiDebug&) = delete;
    AntiDebug& operator=(const AntiDebug&) = delete;

    void start();
    void stop();
    bool isDebugged() const;

    void setDetectionCallback(DetectionCallback cb);

    static bool checkIsDebuggerPresent();
    static bool checkRemoteDebuggerPresent();
    static bool checkNtQueryDebugPort();
    static bool checkNtQueryDebugFlags();
    static bool checkNtQueryDebugObjectHandle();
    static bool checkPebBeingDebugged();
    static bool checkPebNtGlobalFlag();
    static bool checkHardwareBreakpoints();
    static bool checkInt3Breakpoints();
    static bool checkTiming();
    static bool checkTimingQPC();
    static bool checkDebugWindows();
    static bool checkToolModules();
    static bool checkScyllaHide();
    void hideThreadFromDebugger();

private:
    void monitorLoop();
    void onDetection(const char* reason);
    bool runAllChecks() const;

    std::atomic<bool> m_running{false};
    std::thread m_monitorThread;
    DetectionCallback m_callback;

    static constexpr DWORD CHECK_INTERVAL_MS = 2000;
    static constexpr DWORD TIMING_THRESHOLD_RDTSC = 5000000;
};

void initializeAntiDebug();
void shutdownAntiDebug();

}
