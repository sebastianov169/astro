#pragma once

#include <cstdint>
#include <atomic>
#include <thread>
#include <functional>
#include <QString>
#include <QJsonObject>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace astro {
namespace security {

struct KillContext {
    std::string license_key;
    std::string hwid;
    std::string heartbeat_url;
    uint64_t heartbeat_interval_ms = 60000;
    std::function<bool()> tamper_check;
};

enum class KillReason : int {
    LICENSE_REVOKED = 1,
    TAMPER_DETECTED = 2,
    INTEGRITY_FAIL = 3,
    HEARTBEAT_FAIL = 4,
    MANUAL_KILL = 5
};

class Autokill {
public:
    Autokill();
    ~Autokill();

    Autokill(const Autokill&) = delete;
    Autokill& operator=(const Autokill&) = delete;

    void start(const KillContext& ctx);
    void stop();
    void requestKill(KillReason reason, const std::string& detail = "");

    bool isRunning() const { return m_running.load(); }

    static bool getAntiDebugFlag();
    static void setAntiDebugFlag(bool v);
    static std::atomic<bool>& globalTamperFlag();

private:
    void killThread();
    void heartbeatLoop();
    bool performHeartbeat();
    void executeKillSequence(KillReason reason, const std::string& detail);

    void erasePEHeaders();
    void overwriteCodeSections();
    void deleteLocalAppData();
    void removeRegistryEntries();
    void deleteTempAndLicenseFiles();
    bool secureWipeFile(const QString& path);
    void secureWipeDirectory(const QString& dirPath);
    void scheduleSelfDelete();
    void cleanPrefetchAndRecent();
    [[noreturn]] void terminateSelf();

    std::thread m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_kill_requested{false};
    std::atomic<KillReason> m_kill_reason{KillReason::MANUAL_KILL};
    std::string m_kill_detail;
    KillContext m_ctx;

    static std::atomic<bool> s_anti_debug_flag;
    static std::atomic<bool> s_global_tamper;
};

} // namespace security
} // namespace astro
