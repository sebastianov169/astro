#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <QByteArray>
#include <QJsonObject>
#include "security/config.h"
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace astro {
namespace security {

struct ChannelConfig {
    std::string base_url = astro_config::apiBase().toStdString();
    std::string pinned_cert_sha256;
    int timeout_ms = 15000;
};

class EncryptedChannel {
public:
    explicit EncryptedChannel(const ChannelConfig& cfg);
    ~EncryptedChannel();

    EncryptedChannel(const EncryptedChannel&) = delete;
    EncryptedChannel& operator=(const EncryptedChannel&) = delete;

    void setCredentials(const QByteArray& license_key, const QByteArray& hwid);

    QJsonObject postEncrypted(const std::string& endpoint, const QJsonObject& payload);
    QJsonObject postRaw(const std::string& endpoint, const QByteArray& body);

    bool verifyServerCert() const;
    bool isValid() const { return m_valid; }

private:
    void deriveKeys();
    QByteArray hkdf(const QByteArray& ikm, const QByteArray& salt, const QByteArray& info, int length);
    QByteArray aesGcmEncrypt(const uint8_t key[32],
                                           const uint8_t* plaintext, size_t pt_len,
                                           uint8_t iv_out[16], uint8_t tag_out[16]);
    QByteArray aesGcmDecrypt(const uint8_t key[32],
                             const uint8_t iv[16], const uint8_t tag[16],
                             const uint8_t* ciphertext, size_t ct_len);
    QByteArray buildSecurePayload(const QJsonObject& payload);
    QJsonObject parseSecureResponse(const QByteArray& raw);

    ChannelConfig m_cfg;
    QByteArray m_license_key;
    QByteArray m_hwid;
    std::array<uint8_t, 32> m_enc_key{};
    std::array<uint8_t, 32> m_dec_key{};
    std::array<uint8_t, 16> m_enc_salt{};
    std::array<uint8_t, 16> m_dec_salt{};
    uint64_t m_seq = 0;
    bool m_valid = false;

    static constexpr size_t kKeyLen = 32;
    static constexpr size_t kIvLen = 16;
    static constexpr size_t kTagLen = 16;
};

} // namespace security
} // namespace astro
