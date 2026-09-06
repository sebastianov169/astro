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

class AntiDump {
public:
    using DetectionCallback = std::function<void(const char* reason)>;

    AntiDump();
    ~AntiDump();

    AntiDump(const AntiDump&) = delete;
    AntiDump& operator=(const AntiDump&) = delete;

    void start();
    void stop();

    void setDetectionCallback(DetectionCallback cb);

    void erasePeHeaders();
    void encryptCodeSections();
    void protectCriticalSections();
    void obfuscateSectionHeaders();
    void encryptHeapData(void* data, size_t size);
    void decryptHeapData(void* data, size_t size);

private:
    void monitorLoop();
    void onDetection(const char* reason);

    std::atomic<bool> m_running{false};
    std::thread m_monitorThread;
    DetectionCallback m_callback;

    std::vector<BYTE> m_xorKey;
    std::vector<std::pair<LPVOID, SIZE_T>> m_encryptedRegions;
    std::vector<LPVOID> m_protectedRegions;

    void generateXorKey();
    void xorEncrypt(void* data, size_t size);

    static constexpr DWORD CHECK_INTERVAL_MS = 5000;
};

void initializeAntiDump();
void shutdownAntiDump();

}
