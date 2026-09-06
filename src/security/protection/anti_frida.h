#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace security {

class AntiFrida {
public:
    using DetectionCallback = std::function<void(const char* reason)>;

    AntiFrida();
    ~AntiFrida();

    AntiFrida(const AntiFrida&) = delete;
    AntiFrida& operator=(const AntiFrida&) = delete;

    void start();
    void stop();
    bool isDetected() const;

    void setDetectionCallback(DetectionCallback cb);

    static bool checkModuleNames();
    static bool scanForFridaMagic();
    static bool checkFridaThreads();
    static bool scanForFridaHooks();
    static bool checkFridaPorts();
    static bool checkFridaNamedPipes();
    static bool checkToolModules();
    static bool checkScyllaHide();
    static bool checkModuleIntegrity();
    static bool checkApiIntegrity();
    static bool checkSelfIntegrity();

private:
    void monitorLoop();
    void onDetection(const char* reason);

    std::atomic<bool> m_running{false};
    std::thread m_monitorThread;
    DetectionCallback m_callback;
    std::vector<BYTE> m_originalTextSection;
    DWORD_PTR m_textSectionRva = 0;
    DWORD m_textSectionSize = 0;

    void captureTextHash();

    static constexpr DWORD CHECK_INTERVAL_MS = 3000;
};

void initializeAntiFrida();
void shutdownAntiFrida();

}
