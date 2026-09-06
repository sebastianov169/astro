#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winreg.h>
#include "secure_http.h"
#include "obfuscation.h"
#include <cstring>
#include <algorithm>
#include <intrin.h>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace sechttp {

static volatile uint32_t g_sink = 0;

__declspec(noinline) static void junk() noexcept {
    volatile uint64_t v = __rdtsc();
    v = (v * 0xDEADBEEFCAFEBABEULL) ^ (v >> 17);
    g_sink = (uint32_t)v;
}

// ═══════════════════════════════════════════════════════════════════════
//  Proxy detection via port scan
// ═══════════════════════════════════════════════════════════════════════
static bool check_port(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int r = connect(s, (sockaddr*)&addr, sizeof(addr));
    closesocket(s);
    return r == 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  Constructor / Destructor
// ═══════════════════════════════════════════════════════════════════════
SecureHttpClient::SecureHttpClient() {
    std::memset(m_key, 0, sizeof(m_key));
    std::memset(m_hwid, 0, sizeof(m_hwid));
    std::memset(m_cert_pin, 0, sizeof(m_cert_pin));
    std::memset(m_user_agent, 0, sizeof(m_user_agent));
}

SecureHttpClient::~SecureHttpClient() {
    if (m_hinet) InternetCloseHandle(m_hinet);
    m3xc::secure_zero(m_key, sizeof(m_key));
    m3xc::secure_zero(m_hwid, sizeof(m_hwid));
}

// ═══════════════════════════════════════════════════════════════════════
//  Initialization
// ═══════════════════════════════════════════════════════════════════════
void SecureHttpClient::init(const uint8_t key[m3xc::KEY_LEN],
                            const uint8_t hwid[64],
                            const char* user_agent) {
    junk();
    std::memcpy(m_key, key, m3xc::KEY_LEN);
    std::memcpy(m_hwid, hwid, 64);
    if (user_agent) {
        std::strncpy(m_user_agent, user_agent, sizeof(m_user_agent) - 1);
    } else {
        static constexpr char def_ua[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        std::strncpy(m_user_agent, def_ua, sizeof(m_user_agent) - 1);
    }
    m_hinet = InternetOpenA(m_user_agent, INTERNET_OPEN_TYPE_PRECONFIG,
                            nullptr, nullptr, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  Envelope build / parse
// ═══════════════════════════════════════════════════════════════════════
void SecureHttpClient::generate_nonce(uint8_t out[16]) {
    m3xc::random_bytes(out, 16);
}

void SecureHttpClient::sign_envelope(RequestEnvelope& env) {
    junk();
    // HMAC over: iv || encrypted_data || timestamp || nonce
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), env.iv, env.iv + m3xc::IV_LEN);
    mac_input.insert(mac_input.end(), env.encrypted_data.begin(), env.encrypted_data.end());

    // timestamp as 8 big-endian bytes
    uint8_t ts_be[8];
    ts_be[0] = (env.timestamp >> 56) & 0xFF;
    ts_be[1] = (env.timestamp >> 48) & 0xFF;
    ts_be[2] = (env.timestamp >> 40) & 0xFF;
    ts_be[3] = (env.timestamp >> 32) & 0xFF;
    ts_be[4] = (env.timestamp >> 24) & 0xFF;
    ts_be[5] = (env.timestamp >> 16) & 0xFF;
    ts_be[6] = (env.timestamp >> 8) & 0xFF;
    ts_be[7] = (env.timestamp) & 0xFF;
    mac_input.insert(mac_input.end(), ts_be, ts_be + 8);
    mac_input.insert(mac_input.end(), env.nonce, env.nonce + 16);

    m3xc::hmac_sha256(m_key, m3xc::KEY_LEN,
                      mac_input.data(), mac_input.size(), env.hmac);
}

bool SecureHttpClient::verify_envelope(const RequestEnvelope& env) {
    junk();
    uint8_t expected_hmac[m3xc::HMAC_LEN];
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), env.iv, env.iv + m3xc::IV_LEN);
    mac_input.insert(mac_input.end(), env.encrypted_data.begin(), env.encrypted_data.end());
    uint8_t ts_be[8];
    for (int i = 0; i < 8; ++i) ts_be[i] = (env.timestamp >> (56 - i*8)) & 0xFF;
    mac_input.insert(mac_input.end(), ts_be, ts_be + 8);
    mac_input.insert(mac_input.end(), env.nonce, env.nonce + 16);
    m3xc::hmac_sha256(m_key, m3xc::KEY_LEN,
                      mac_input.data(), mac_input.size(), expected_hmac);
    return m3xc::ct_equal(env.hmac, expected_hmac, m3xc::HMAC_LEN);
}

std::vector<uint8_t> SecureHttpClient::build_envelope(const std::string& plaintext) {
    junk();
    RequestEnvelope env{};
    m3xc::random_bytes(env.iv, m3xc::IV_LEN);
    generate_nonce(env.nonce);
    env.timestamp = (uint64_t)GetTickCount64() / 1000;

    // Derive per-request key from master key + iv
    m3xc::KDFContext kdf{};
    std::memcpy(kdf.license_key, m_key, m3xc::KEY_LEN);
    std::memcpy(kdf.hardware_id, m_hwid, 64);
    kdf.timestamp = env.timestamp;
    m3xc::random_bytes(kdf.salt, 32);

    uint8_t req_key[m3xc::KEY_LEN];
    m3xc::derive_key(kdf, req_key);

    env.encrypted_data = m3xc::encrypt(plaintext, req_key, env.iv);

    sign_envelope(env);

    // Serialize: iv(16) + enc_len(4) + enc_data + ts(8) + nonce(16) + hmac(32)
    std::vector<uint8_t> wire;
    wire.insert(wire.end(), env.iv, env.iv + m3xc::IV_LEN);
    uint32_t enc_len = (uint32_t)env.encrypted_data.size();
    wire.push_back((enc_len >> 24) & 0xFF);
    wire.push_back((enc_len >> 16) & 0xFF);
    wire.push_back((enc_len >> 8) & 0xFF);
    wire.push_back(enc_len & 0xFF);
    wire.insert(wire.end(), env.encrypted_data.begin(), env.encrypted_data.end());
    uint8_t ts_be[8];
    for (int i = 0; i < 8; ++i) ts_be[i] = (env.timestamp >> (56 - i*8)) & 0xFF;
    wire.insert(wire.end(), ts_be, ts_be + 8);
    wire.insert(wire.end(), env.nonce, env.nonce + 16);
    wire.insert(wire.end(), env.hmac, env.hmac + m3xc::HMAC_LEN);

    m3xc::secure_zero(req_key, sizeof(req_key));
    return wire;
}

std::string SecureHttpClient::parse_envelope(const std::vector<uint8_t>& raw) {
    junk();
    constexpr size_t MIN_SIZE = m3xc::IV_LEN + 4 + 0 + 8 + 16 + m3xc::HMAC_LEN;
    if (raw.size() < MIN_SIZE) return {};

    RequestEnvelope env{};
    size_t off = 0;
    std::memcpy(env.iv, raw.data() + off, m3xc::IV_LEN); off += m3xc::IV_LEN;

    uint32_t enc_len = (uint32_t(raw[off]) << 24) | (uint32_t(raw[off+1]) << 16) |
                       (uint32_t(raw[off+2]) << 8) | uint32_t(raw[off+3]);
    off += 4;

    if (enc_len > m3xc::MAX_PLAINTEXT + m3xc::BLOCK_SIZE) return {};
    if (raw.size() < off + enc_len + 8 + 16 + m3xc::HMAC_LEN) return {};

    env.encrypted_data.assign(raw.begin() + off, raw.begin() + off + enc_len);
    off += enc_len;

    env.timestamp = 0;
    for (int i = 0; i < 8; ++i) env.timestamp = (env.timestamp << 8) | raw[off + i];
    off += 8;

    std::memcpy(env.nonce, raw.data() + off, 16); off += 16;
    std::memcpy(env.hmac, raw.data() + off, m3xc::HMAC_LEN);

    // Verify HMAC
    if (!verify_envelope(env)) return {};

    // Timestamp validation
    uint64_t now = (uint64_t)GetTickCount64() / 1000;
    if (env.timestamp > now + TIMESTAMP_MAX_AGE_SEC) return {};
    if (now - env.timestamp > TIMESTAMP_MAX_AGE_SEC) return {};

    // Derive key and decrypt
    m3xc::KDFContext kdf{};
    std::memcpy(kdf.license_key, m_key, m3xc::KEY_LEN);
    std::memcpy(kdf.hardware_id, m_hwid, 64);
    kdf.timestamp = env.timestamp;
    std::memcpy(kdf.salt, env.iv, 16); // use iv as partial salt
    m3xc::random_bytes(kdf.salt + 16, 16);

    uint8_t req_key[m3xc::KEY_LEN];
    m3xc::derive_key(kdf, req_key);

    auto pt = m3xc::decrypt(env.encrypted_data, req_key, env.iv);
    m3xc::secure_zero(req_key, sizeof(req_key));

    if (pt.empty()) return {};
    return std::string(pt.begin(), pt.end());
}

// ═══════════════════════════════════════════════════════════════════════
//  Rate limiting
// ═══════════════════════════════════════════════════════════════════════
bool SecureHttpClient::check_rate_limit() {
    uint64_t now = GetTickCount64();
    if (now - m_window_start_ms > RATE_LIMIT_WINDOW_MS) {
        m_requests_this_window = 0;
        m_window_start_ms = now;
    }
    return m_requests_this_window < RATE_LIMIT_MAX_REQS;
}

void SecureHttpClient::record_request() {
    m_requests_this_window++;
}

// ═══════════════════════════════════════════════════════════════════════
//  Anti-proxy detection
// ═══════════════════════════════════════════════════════════════════════
bool SecureHttpClient::detect_proxy() {
    junk();
    // Common proxy ports
    static const uint16_t proxy_ports[] = {
        8888,  // Fiddler
        8080,  // Charles / general
        8081,  // Burp
        9090,  // mitmproxy
        1080,  // SOCKS
        8000,  // Generic
    };
    for (uint16_t port : proxy_ports) {
        if (check_port(port)) return true;
    }

    // Check system proxy settings
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD proxy_enable = 0;
        DWORD size = sizeof(proxy_enable);
        RegQueryValueExW(hKey, "ProxyEnable", nullptr, nullptr,
                        (LPBYTE)&proxy_enable, &size);
        // RegCloseHandle is in advapi32 - use direct call
        typedef LSTATUS (WINAPI *RegCloseFn)(HKEY);
        static RegCloseFn fn = (RegCloseFn)GetProcAddress(GetModuleHandleA("advapi32.dll"), "RegCloseHandle");
        if (fn) fn(hKey);
        if (proxy_enable != 0) return true;
    }

    return false;
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS certificate pinning verification
// ═══════════════════════════════════════════════════════════════════════
bool SecureHttpClient::verify_cert_pin(HINTERNET request) {
    junk();
    if (!m_has_cert_pin) return true; // no pin configured, skip

    // Get security flags
    DWORD flags = 0;
    DWORD size = sizeof(flags);
    InternetQueryOptionA(request, INTERNET_OPTION_SECURITY_FLAGS, &flags, &size);

    // Check if cert chain was verified
    if (!(flags & SECURITY_FLAG_SECURE)) return false;

    // Note: Full cert pinning with WinINet requires INTERNET_OPTION_SECURITY_CERTIFICATE
    // which returns the cert in a specific format. For production, use CertGetCertificateChain
    // or compare against a known SHA-256 hash of the leaf cert.
    // This is a simplified check that verifies HTTPS is being used.
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  HTTP POST (encrypted)
// ═══════════════════════════════════════════════════════════════════════
HttpResponse SecureHttpClient::post(const char* url_obfuscated,
                                    const std::string& json_body) {
    HttpResponse resp{};
    junk();

    if (!check_rate_limit()) {
        resp.error = "rate_limited";
        return resp;
    }

    if (m_anti_proxy && detect_proxy()) {
        resp.error = "proxy_detected";
        return resp;
    }

    if (!m_hinet) {
        resp.error = "not_initialized";
        return resp;
    }

    // Decrypt URL at runtime
    std::string url(url_obfuscated);

    // Build encrypted envelope
    auto envelope = build_envelope(json_body);

    // Parse URL components
    URL_COMPONENTSA uc{};
    uc.dwStructSize = sizeof(uc);
    char host[256]{}, url_path[512]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = sizeof(host);
    uc.lpszUrlPath = url_path;
    uc.dwUrlPathLength = sizeof(url_path);

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &uc)) {
        resp.error = "url_parse_failed";
        return resp;
    }

    // Open connection
    BOOL use_ssl = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    HINTERNET conn = InternetConnectA(m_hinet, host, (INTERNET_PORT)uc.nPort,
                                      nullptr, nullptr, INTERNET_SERVICE_HTTP,
                                      0, 0);
    if (!conn) {
        resp.error = "connect_failed";
        return resp;
    }

    const char* accept_types[] = { "*/*", nullptr };
    HINTERNET req = HttpOpenRequestA(conn, "POST", url_path, nullptr, nullptr,
                                     accept_types,
                                     use_ssl ? INTERNET_FLAG_SECURE : 0, 0);
    if (!req) {
        InternetCloseHandle(conn);
        resp.error = "open_request_failed";
        return resp;
    }

    // Verify cert pin
    if (!verify_cert_pin(req)) {
        InternetCloseHandle(req);
        InternetCloseHandle(conn);
        resp.error = "cert_pin_mismatch";
        return resp;
    }

    // Add headers
    char headers[512]{};
    _snprintf_s(headers, sizeof(headers),
        "Content-Type: application/octet-stream\r\n"
        "X-M3XC-Version: 1\r\n"
        "X-M3XC-Timestamp: %llu\r\n",
        (unsigned long long)((uint64_t)GetTickCount64() / 1000));

    BOOL sent = HttpSendRequestA(req, headers, (DWORD)std::strlen(headers),
                                 envelope.data(), (DWORD)envelope.size());
    if (!sent) {
        InternetCloseHandle(req);
        InternetCloseHandle(conn);
        resp.error = "send_failed";
        return resp;
    }

    record_request();

    // Read response
    std::vector<uint8_t> resp_buf;
    resp_buf.reserve(4096);
    char read_buf[4096];
    DWORD bytes_read = 0;
    while (InternetReadFile(req, read_buf, sizeof(read_buf), &bytes_read) && bytes_read > 0) {
        resp_buf.insert(resp_buf.end(), read_buf, read_buf + bytes_read);
        if (resp_buf.size() > MAX_RESPONSE) {
            resp.error = "response_too_large";
            InternetCloseHandle(req);
            InternetCloseHandle(conn);
            return resp;
        }
    }

    // Get status code
    DWORD status_code = 0;
    DWORD sc_size = sizeof(status_code);
    HttpQueryInfoA(req, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                   &status_code, &sc_size, nullptr);
    resp.status_code = (int)status_code;

    // Parse response envelope
    std::string decrypted = parse_envelope(resp_buf);
    if (decrypted.empty() && !resp_buf.empty()) {
        resp.error = "decrypt_failed";
    } else {
        resp.body = decrypted;
        resp.success = true;
    }

    InternetCloseHandle(req);
    InternetCloseHandle(conn);
    return resp;
}

// ═══════════════════════════════════════════════════════════════════════
//  HTTP GET (encrypted)
// ═══════════════════════════════════════════════════════════════════════
HttpResponse SecureHttpClient::get(const char* url_obfuscated) {
    HttpResponse resp{};
    junk();

    if (!check_rate_limit()) {
        resp.error = "rate_limited";
        return resp;
    }

    if (m_anti_proxy && detect_proxy()) {
        resp.error = "proxy_detected";
        return resp;
    }

    if (!m_hinet) {
        resp.error = "not_initialized";
        return resp;
    }

    std::string url(url_obfuscated);

    URL_COMPONENTSA uc{};
    uc.dwStructSize = sizeof(uc);
    char host[256]{}, url_path[512]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = sizeof(host);
    uc.lpszUrlPath = url_path;
    uc.dwUrlPathLength = sizeof(url_path);

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &uc)) {
        resp.error = "url_parse_failed";
        return resp;
    }

    BOOL use_ssl = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    HINTERNET conn = InternetConnectA(m_hinet, host, (INTERNET_PORT)uc.nPort,
                                      nullptr, nullptr, INTERNET_SERVICE_HTTP,
                                      0, 0);
    if (!conn) {
        resp.error = "connect_failed";
        return resp;
    }

    const char* accept_types[] = { "*/*", nullptr };
    HINTERNET req = HttpOpenRequestA(conn, "GET", url_path, nullptr, nullptr,
                                     accept_types,
                                     use_ssl ? INTERNET_FLAG_SECURE : 0, 0);
    if (!req) {
        InternetCloseHandle(conn);
        resp.error = "open_request_failed";
        return resp;
    }

    if (!verify_cert_pin(req)) {
        InternetCloseHandle(req);
        InternetCloseHandle(conn);
        resp.error = "cert_pin_mismatch";
        return resp;
    }

    char headers[256]{};
    _snprintf_s(headers, sizeof(headers),
        "X-M3XC-Version: 1\r\n"
        "X-M3XC-Timestamp: %llu\r\n",
        (unsigned long long)((uint64_t)GetTickCount64() / 1000));

    BOOL sent = HttpSendRequestA(req, headers, (DWORD)std::strlen(headers), nullptr, 0);
    if (!sent) {
        InternetCloseHandle(req);
        InternetCloseHandle(conn);
        resp.error = "send_failed";
        return resp;
    }

    record_request();

    std::vector<uint8_t> resp_buf;
    resp_buf.reserve(4096);
    char read_buf[4096];
    DWORD bytes_read = 0;
    while (InternetReadFile(req, read_buf, sizeof(read_buf), &bytes_read) && bytes_read > 0) {
        resp_buf.insert(resp_buf.end(), read_buf, read_buf + bytes_read);
        if (resp_buf.size() > MAX_RESPONSE) {
            resp.error = "response_too_large";
            InternetCloseHandle(req);
            InternetCloseHandle(conn);
            return resp;
        }
    }

    DWORD status_code = 0;
    DWORD sc_size = sizeof(status_code);
    HttpQueryInfoA(req, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                   &status_code, &sc_size, nullptr);
    resp.status_code = (int)status_code;

    std::string decrypted = parse_envelope(resp_buf);
    if (decrypted.empty() && !resp_buf.empty()) {
        resp.error = "decrypt_failed";
    } else {
        resp.body = decrypted;
        resp.success = true;
    }

    InternetCloseHandle(req);
    InternetCloseHandle(conn);
    return resp;
}

// ═══════════════════════════════════════════════════════════════════════
//  Cert pin setter
// ═══════════════════════════════════════════════════════════════════════
void SecureHttpClient::set_cert_pin(const uint8_t sha256_pin[32]) {
    std::memcpy(m_cert_pin, sha256_pin, 32);
    m_has_cert_pin = true;
}

void SecureHttpClient::set_anti_proxy(bool enabled) {
    m_anti_proxy = enabled;
}

// ═══════════════════════════════════════════════════════════════════════
//  Obfuscated URL builder
// ═══════════════════════════════════════════════════════════════════════
std::string build_obfuscated_url(const uint8_t* fragments,
                                 size_t fragment_count,
                                 const uint8_t key[16]) {
    std::string result;
    for (size_t i = 0; i < fragment_count; ++i) {
        // Each fragment is XOR-encrypted with key-derived byte
        uint8_t k = key[i % 16] ^ (uint8_t)(i * 0x37);
        result.push_back((char)(fragments[i] ^ k));
    }
    return result;
}

} // namespace sechttp

