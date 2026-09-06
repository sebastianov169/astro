#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <memory>
#include <functional>
#include <QByteArray>
#include <QJsonObject>
#include "security/config.h"
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace astro {
namespace security {

struct BackendApi {
    void* init_ctx = nullptr;
    std::function<void* (const char*)> get_proc;
    std::function<void ()> shutdown;
    bool valid() const { return get_proc != nullptr; }
};

struct DllManifest {
    std::string download_url;
    std::string sha256_hex;
    uint64_t version = 0;
    uint64_t size = 0;
};

class SecureLoader {
public:
    SecureLoader();
    ~SecureLoader();

    SecureLoader(const SecureLoader&) = delete;
    SecureLoader& operator=(const SecureLoader&) = delete;

    void setCredentials(const QByteArray& license_key, const QByteArray& hwid);
    void setApiBase(const std::string& url);

    BackendApi loadBackend(uint64_t current_version = 0);
    bool needsUpdate(uint64_t current_version);
    void unloadBackend();

    bool isValid() const { return m_loaded; }
    std::string lastError() const { return m_last_error; }

private:
    DllManifest fetchManifest();
    QByteArray downloadDll(const std::string& url);
    bool verifySha256(const QByteArray& data, const std::string& expected_hex);

    void* mapDllMemory(const QByteArray& raw_dll);
    bool relocateImage(uint8_t* base, ptrdiff_t delta);
    bool resolveImports(uint8_t* base);
    bool protectSections(uint8_t* base);
    void callEntryPoint(uint8_t* base);

    static std::string sha256Hex(const QByteArray& data);

    QByteArray m_license_key;
    QByteArray m_hwid;
    std::string m_api_base = astro_config::apiBase().toStdString();
    uint8_t* m_mapped_base = nullptr;
    size_t m_mapped_size = 0;
    void* m_dll_module = nullptr;
    bool m_loaded = false;
    std::string m_last_error;
    BackendApi m_api;
};

} // namespace security
} // namespace astro
