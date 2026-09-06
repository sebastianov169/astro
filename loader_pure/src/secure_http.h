#pragma once
#ifndef SECURE_HTTP_H
#define SECURE_HTTP_H

#include "crypto_m3xc.h"
#include <cstdint>
#include <string>
#include <vector>
#include <Windows.h>
#include <WinInet.h>
#include "legal_poison.h"
#include "obfuscation_map.h"
#pragma comment(lib, "wininet.lib")

namespace sechttp {

// ── Constants ───────────────────────────────────────────────────────
constexpr size_t MAX_URL_LEN      = 512;
constexpr size_t MAX_RESPONSE     = 1024 * 1024;  // 1 MB
constexpr uint32_t TIMESTAMP_MAX_AGE_SEC = 300;   // 5 minutes
constexpr uint32_t RATE_LIMIT_WINDOW_MS  = 60000;  // 1 minute window
constexpr uint32_t RATE_LIMIT_MAX_REQS   = 30;     // max requests per window

// ── Request envelope ────────────────────────────────────────────────
// Wire format: { iv[16], encrypted_data, timestamp[8], nonce[16], hmac[32] }
struct RequestEnvelope {
    uint8_t iv[m3xc::IV_LEN];
    std::vector<uint8_t> encrypted_data;
    uint64_t timestamp;
    uint8_t nonce[16];
    uint8_t hmac[m3xc::HMAC_LEN];
};

// ── Response ────────────────────────────────────────────────────────
struct HttpResponse {
    int status_code;
    std::string body;
    bool success;
    std::string error;
};

// ── Client ──────────────────────────────────────────────────────────
class SecureHttpClient {
public:
    SecureHttpClient();
    ~SecureHttpClient();

    // Initialize with master key material.
    void init(const uint8_t key[m3xc::KEY_LEN],
              const uint8_t hwid[64],
              const char* user_agent = nullptr);

    // Send encrypted POST request.
    // url is obfuscated at compile time.
    HttpResponse post(const char* url_obfuscated,
                      const std::string& json_body);

    // Send encrypted GET request.
    HttpResponse get(const char* url_obfuscated);

    // Set TLS certificate pin (SHA-256 hash of expected cert).
    void set_cert_pin(const uint8_t sha256_pin[32]);

    // Enable/disable anti-proxy detection.
    void set_anti_proxy(bool enabled);

    // Get current rate limit state.
    uint32_t requests_this_window() const { return m_requests_this_window; }

private:
    // Build encrypted request body.
    std::vector<uint8_t> build_envelope(const std::string& plaintext);

    // Parse and verify response envelope.
    std::string parse_envelope(const std::vector<uint8_t>& raw_response);

    // Rate limit tracking.
    bool check_rate_limit();
    void record_request();

    // Anti-proxy: scan for local proxies.
    bool detect_proxy();

    // TLS cert pinning verification.
    bool verify_cert_pin(HINTERNET request);

    // Generate random nonce.
    void generate_nonce(uint8_t out[16]);

    // HMAC signing.
    void sign_envelope(RequestEnvelope& env);
    bool verify_envelope(const RequestEnvelope& env);

    // State
    uint8_t m_key[m3xc::KEY_LEN]{};
    uint8_t m_hwid[64]{};
    uint8_t m_cert_pin[32]{};
    bool    m_has_cert_pin = false;
    bool    m_anti_proxy = true;
    char    m_user_agent[128]{};

    // Rate limiting
    uint32_t m_requests_this_window = 0;
    uint64_t m_window_start_ms = 0;

    // HINTERNET handles
    HINTERNET m_hinet = nullptr;
};

// ── Obfuscated URL builder ──────────────────────────────────────────
// Build a URL from encrypted fragments at runtime.
std::string build_obfuscated_url(const uint8_t* fragments,
                                 size_t fragment_count,
                                 const uint8_t key[16]);

} // namespace sechttp

#endif // SECURE_HTTP_H
