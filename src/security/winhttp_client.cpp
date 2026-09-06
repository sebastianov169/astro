#include "winhttp_client.h"
#include "security/crypto/string_encrypt.h"
#pragma warning(disable: 4996)
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

#pragma comment(lib, "winhttp.lib")

namespace astro { namespace security {

// SHA-256 of the server certificate's DER-encoded SubjectPublicKeyInfo (SPKI).
// Computed once from the live Cloudflare Workers cert and embedded here.
// If the cert is renewed with a new key, this must be updated.
// SHA-256 of astro-license.astro-bots.workers.dev server certificate DER.
// NOTE: Cloudflare rotates certs. If pinning breaks after cert renewal,
// update this hash or set to all-zero to disable pinning temporarily.
static const uint8_t kPinnedCertHash[32] = {
    0xc1,0x32,0xb4,0x7c,0xec,0x82,0xf7,0x55,
    0x45,0x5c,0x5f,0xc0,0xf3,0xa7,0x6f,0xd5,
    0xc9,0x02,0xd9,0x6d,0x3c,0xe8,0xa2,0x64,
    0xf6,0x15,0x85,0xc4,0xd7,0xf2,0x86,0x4e };

// Returns true if pinning is enabled AND the server cert matches.
// If pinning is not enabled (all-zero hash), returns true (dev pass-through).
static bool verifyServerCert(HINTERNET hRequest) {
    // Check if pinning hash is set (non-all-zero)
    bool hasPin = false;
    for (int i = 0; i < 32; ++i) { if (kPinnedCertHash[i] != 0) { hasPin = true; break; } }
    if (!hasPin) return true; // dev: no pinning configured

    PCERT_CONTEXT pCertCtx = nullptr;
    DWORD sz = sizeof(pCertCtx);
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                            &pCertCtx, &sz) || !pCertCtx) {
        return false;
    }

    // Hash the full DER-encoded certificate
    BYTE hash[32]; DWORD hashLen = sizeof(hash);
    if (!CryptHashCertificate(0, CALG_SHA_256, 0,
                              pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded,
                              hash, &hashLen)) {
        CertFreeCertificateContext(pCertCtx);
        return false;
    }
    CertFreeCertificateContext(pCertCtx);

    // Constant-time compare
    volatile uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= (hash[i] ^ kPinnedCertHash[i]);
    return diff == 0;
}

// Blocking HTTPS POST with hard timeout, executed on the CALLER's thread.
// Returns HTTP status code (200 = OK), 0 on transport failure/timeout.
// Uses synchronous WinHTTP with explicit resolve/connect/send/receive timeouts.
static std::mutex g_winhttp_mutex; // serialize all WinHTTP ops process-wide

int winhttpPostJson(const std::string& apiBase,
                    const std::string& path,
                    const std::string& body,
                    const std::string& tsHeader,
                    const std::string& sigHeader,
                    std::string& responseOut,
                    int timeoutMs) {
    responseOut.clear();

    // Parse apiBase: expect https://host[:port]
    std::string host = apiBase;
    const std::string scheme = "https://";
    bool https = true;
    if (host.rfind(scheme, 0) == 0) host = host.substr(scheme.size());
    else if (host.rfind("http://", 0) == 0) { host = host.substr(7); https = false; }
    INTERNET_PORT port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    const std::string portSuffix = ":";
    const size_t colon = host.find(':');
    if (colon != std::string::npos) {
        port = static_cast<INTERNET_PORT>(atoi(host.c_str() + colon + 1));
        host = host.substr(0, colon);
    }

    std::atomic<int> statusOut{0};
    std::atomic<bool> done{false};

    auto doRequest = [&]() {
        std::lock_guard<std::mutex> _lock(g_winhttp_mutex);
        FILE* _dbg = nullptr;
#ifdef ASTRO_DEBUG_TRACE
        char _tp[MAX_PATH]; GetTempPathA(MAX_PATH, _tp);
        std::string _logPath = std::string(_tp) + "astro_wh.log";
        _dbg = fopen(_logPath.c_str(), "a");
#endif
        HINTERNET hSession = WinHttpOpen(L"Astro/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (_dbg) { fprintf(_dbg, "open=%d\n", hSession ? 1 : 0); fflush(_dbg); }
        if (!hSession) { if (_dbg) fclose(_dbg); return; }
        // NO_PROXY on purpose: system proxy (HTTP Debugger etc) is exactly what stalls
        // Qt network; direct connection avoids third-party LSP hooks entirely.
        WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

        std::wstring whost(host.begin(), host.end());
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
        if (_dbg) { fprintf(_dbg, "connect=%d err=%lu\n", hConnect ? 1 : 0, GetLastError()); fflush(_dbg); }
        if (!hConnect) { WinHttpCloseHandle(hSession); if (_dbg) fclose(_dbg); return; }

        std::wstring wpath(path.begin(), path.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
                                                nullptr, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                https ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

        std::wstring wts(tsHeader.begin(), tsHeader.end());
        std::wstring wsig(sigHeader.begin(), sigHeader.end());
        std::wstring headers = L"Content-Type: application/json\r\nX-Timestamp: " + wts +
                               L"\r\nX-Signature: " + wsig + L"\r\n";

        BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L,
                                       (LPVOID)body.data(), (DWORD)body.size(),
                                       (DWORD)body.size(), 0);
        if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
            // TLS certificate pinning: verify server cert before reading response.
            if (!verifyServerCert(hRequest)) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return;
            }
            DWORD statusCode = 0, sz = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &sz, WINHTTP_NO_HEADER_INDEX);
            std::string resp;
            DWORD bytesAvail = 0, bytesRead = 0;
            char buf[4096];
            for (;;) {
                bytesAvail = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &bytesAvail) || bytesAvail == 0) break;
                if (bytesAvail > sizeof(buf)) bytesAvail = sizeof(buf);
                if (!WinHttpReadData(hRequest, buf, bytesAvail, &bytesRead) || bytesRead == 0) break;
                resp.append(buf, bytesRead);
            }
            statusOut.store((int)statusCode);
            responseOut = resp;
        }
        done.store(true);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    };

    // Thread creation can throw under resource exhaustion (LSP-injected hosts);
    // fall back to inline execution - WinHTTP timeouts keep it bounded either way.
    // THREAD-FREE EXECUTION: spawning std::thread deadlocks under LSP-injected hosts
    // (thread-creation hook never returns). Run synchronously instead - every WinHTTP
    // phase is bounded by WinHttpSetTimeouts(resolve/connect/send/receive), so this
    // always returns. Blocking is safe here: no window exists yet during validation.
    doRequest();
    return statusOut.load();
}



int winHttpGetBin(const std::string& url,
                  std::string& responseOut,
                  int timeoutMs) {
    std::lock_guard<std::mutex> _lock(g_winhttp_mutex);
    responseOut.clear();

    // Parse URL: [https://]host[:port]/path?query
    std::string rest = url;
    bool https = true;
    const std::string scheme = "https://";
    if (rest.rfind(scheme, 0) == 0) rest = rest.substr(scheme.size());
    else if (rest.rfind("http://", 0) == 0) { rest = rest.substr(7); https = false; }
    INTERNET_PORT port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    const size_t slash = rest.find('/');
    std::string host = rest.substr(0, slash == std::string::npos ? rest.size() : slash);
    std::string path = slash == std::string::npos ? "/" : rest.substr(slash);
    const size_t colon = host.find(':');
    if (colon != std::string::npos) {
        port = static_cast<INTERNET_PORT>(atoi(host.c_str() + colon + 1));
        host = host.substr(0, colon);
    }

    char _gtp[MAX_PATH]{}; GetTempPathA(MAX_PATH, _gtp);
    std::string _glp = std::string(_gtp) + "astro_getbin.log";
#ifdef ASTRO_DEBUG_TRACE
    FILE* _dbgFile = fopen(_glp.c_str(), "a"); if (_dbgFile) { fprintf(_dbgFile, "getbin host=%s port=%d pathlen=%zu https=%d\n", host.c_str(), (int)port, path.size(), (int)https); fclose(_dbgFile); }
#endif
    (void)_glp;
    HINTERNET hSession = WinHttpOpen(L"Astro/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 0;
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    std::wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession);
        { FILE* _d = fopen(_glp.c_str(), "a"); if (_d) { fprintf(_d, "fail connect err=%lu\n", GetLastError()); fclose(_d); } }
        return 0; }

    std::wstring wpath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            https ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        { FILE* _d = fopen(_glp.c_str(), "a"); if (_d) { fprintf(_d, "fail openreq err=%lu\n", GetLastError()); fclose(_d); } }
        return 0; }

    int status = 0;
    BOOL _sentOk = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    { FILE* _d = fopen(_glp.c_str(), "a"); if (_d) { fprintf(_d, "sent=%d err=%lu\n", (int)_sentOk, _sentOk ? 0 : GetLastError()); fclose(_d); } }
    if (_sentOk && WinHttpReceiveResponse(hRequest, nullptr)) {
        // TLS certificate pinning
        if (!verifyServerCert(hRequest)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return 0;
        }
        DWORD statusCode = 0, sz = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &sz, WINHTTP_NO_HEADER_INDEX);
        DWORD bytesAvail = 0, bytesRead = 0;
        char buf[65536];
        for (;;) {
            bytesAvail = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvail) || bytesAvail == 0) break;
            if (bytesAvail > sizeof(buf)) bytesAvail = sizeof(buf);
            if (!WinHttpReadData(hRequest, buf, bytesAvail, &bytesRead) || bytesRead == 0) break;
            responseOut.append(buf, bytesRead);
        }
        status = static_cast<int>(statusCode);
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return status;
}


}} // namespace
