#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace security {

struct SectionCrc {
    DWORD_PTR rva;
    DWORD size;
    DWORD crc;
};

class AntiPatch {
public:
    using DetectionCallback = std::function<void(const char* reason)>;

    AntiPatch();
    ~AntiPatch();

    AntiPatch(const AntiPatch&) = delete;
    AntiPatch& operator=(const AntiPatch&) = delete;

    void start();
    void stop();

    void setDetectionCallback(DetectionCallback cb);

    bool verifySectionCrc();
    bool verifyImportHash();
    bool checkBreakpointPatches();
    bool checkApiHooks();
    void restorePatchedBytes();

private:
    void monitorLoop();
    void onDetection(const char* reason);

    std::atomic<bool> m_running{false};
    std::thread m_monitorThread;
    DetectionCallback m_callback;

    std::vector<SectionCrc> m_originalCrcs;
    std::vector<std::pair<FARPROC, std::vector<BYTE>>> m_originalApiBytes;

    void captureOriginalCrcs();
    void captureOriginalApis();
    DWORD calculateCrc(const BYTE* data, size_t size);

    static constexpr DWORD CHECK_INTERVAL_MS = 5000;
};

void initializeAntiPatch();
void shutdownAntiPatch();

}
