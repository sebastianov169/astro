#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <mutex>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace security {

struct DllNotificationRecord {
    PWSTR fullDllName;
    PWSTR baseDllName;
    PVOID dllBase;
    SIZE_T dllSize;
};

using DllLoadCallback = std::function<void(const DllNotificationRecord& info)>;

class AntiDll {
public:
    using DetectionCallback = std::function<void(const char* reason)>;

    AntiDll();
    ~AntiDll();

    AntiDll(const AntiDll&) = delete;
    AntiDll& operator=(const AntiDll&) = delete;

    void start();
    void stop();
    bool isDetected() const;

    void setDetectionCallback(DetectionCallback cb);

    static bool checkBlockedDlls();
    static bool verifyImphash();
    static bool checkInjectedModules();
    static bool checkCriticalDllIntegrity();

private:
    friend void NTAPI dllLoadCallback(ULONG, PVOID, PVOID);
    void monitorLoop();
    void onDetection(const char* reason);
    void registerDllNotification();
    void unregisterDllNotification();

    std::atomic<bool> m_running{false};
    std::thread m_monitorThread;
    DetectionCallback m_callback;
    HANDLE m_dllNotificationHandle{nullptr};
    std::vector<BYTE> m_originalImphash;

    std::mutex m_moduleMutex;
    std::vector<std::wstring> m_loadedModules;

    void captureInitialModules();
    static std::vector<BYTE> computeImphash();

    static constexpr DWORD CHECK_INTERVAL_MS = 4000;
};

void initializeAntiDll();
void shutdownAntiDll();

}
