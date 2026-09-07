#include "http_client.h"
#include "obfuscation.h"
#include "worker_crypto.h"
#include <vector>
#include <string>
#include <ctime>
#include <sstream>

static std::wstring toWideHttp(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
}

HttpClient::HttpClient() {
    std::wstring ua = toWideHttp(OBFUSCATE("AstroLoader/1.0"));
    m_session = WinHttpOpen(ua.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
}

HttpClient::~HttpClient() {
    if (m_session) WinHttpCloseHandle(m_session);
}

static bool parseUrl(const std::wstring& url, std::wstring& host, std::wstring& path, INTERNET_PORT& port, bool& useHttps) {
    std::wstring httpsPref = toWideHttp(OBFUSCATE("https://"));
    std::wstring httpPref = toWideHttp(OBFUSCATE("http://"));
    useHttps = (url.find(httpsPref) == 0);
    std::wstring trimmed = url;
    if (useHttps) trimmed = url.substr(httpsPref.size());
    else if (url.find(httpPref) == 0) trimmed = url.substr(httpPref.size());
    
    size_t slashPos = trimmed.find(L'/');
    std::wstring hostPort;
    if (slashPos != std::wstring::npos) {
        hostPort = trimmed.substr(0, slashPos);
        path = trimmed.substr(slashPos);
    } else {
        hostPort = trimmed;
        path = toWideHttp("/");
    }
    
    size_t colonPos = hostPort.find(L':');
    if (colonPos != std::wstring::npos) {
        host = hostPort.substr(0, colonPos);
        port = (INTERNET_PORT)std::stoi(hostPort.substr(colonPos + 1));
    } else {
        host = hostPort;
        port = useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    }
    return true;
}

std::string HttpClient::post(const std::wstring& url, const std::string& jsonBody) {
    return postWithHeaders(url, jsonBody, {});
}

std::string HttpClient::postWithHeaders(const std::wstring& url, const std::string& jsonBody, const std::vector<std::wstring>& extraHeaders) {
    std::wstring host, path;
    INTERNET_PORT port;
    bool https;
    if (!parseUrl(url, host, path, port, https)) return "";
    
    HINTERNET conn = WinHttpConnect(m_session, host.c_str(), port, 0);
    if (!conn) return "";
    
    std::wstring postVerb = toWideHttp("POST");
    HINTERNET req = WinHttpOpenRequest(conn, postVerb.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(conn); return ""; }
    
    std::wstring hdrStr = toWideHttp(OBFUSCATE("Content-Type: application/json"));
    for (auto &h : extraHeaders) {
        hdrStr += L"\r\n";
        hdrStr += h;
    }
    const wchar_t* headers = hdrStr.c_str();
    WinHttpSendRequest(req, headers, (DWORD)hdrStr.size(),
        (LPVOID)jsonBody.c_str(), (DWORD)jsonBody.size(),
        (DWORD)jsonBody.size(), 0);
    // Timeouts: nunca colgar mas de 10s por fase (proxy/hooks pueden bloquear)
    WinHttpSetTimeouts(req, 10000, 10000, 10000, 10000);
    WinHttpReceiveResponse(req, nullptr);
    
    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    m_lastStatus = (int)statusCode;
    
    std::string response;
    BYTE buf[4096];
    DWORD bytesRead = 0;
    while (WinHttpReadData(req, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        response.append((char*)buf, bytesRead);
        bytesRead = 0;
    }
    
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    return response;
}

std::string HttpClient::postEncrypted(const std::wstring& url, const std::string& innerJson, const std::string& encKey) {
    if (encKey.empty()) {
        return post(url, innerJson);
    }
    std::string encBody = worker_crypto::build_encrypted_body(innerJson, encKey);
    std::wstring host, path;
    INTERNET_PORT port; bool https;
    if (!parseUrl(url, host, path, port, https)) return "";
    std::string narrowPath;
    narrowPath.reserve(path.size());
    for (wchar_t c : path) narrowPath.push_back((char)c);
    std::string ts = std::to_string((long long)time(nullptr));
    std::string payload = std::string("POST:") + narrowPath + ":" + ts + ":" + encBody;
    std::string sig = worker_crypto::hmac_sha256_hex_derived(payload, encKey);
    std::vector<std::wstring> extra;
    extra.push_back(toWideHttp(std::string("X-Timestamp: ") + ts));
    extra.push_back(toWideHttp(std::string("X-Signature: ") + sig));
    std::string resp = postWithHeaders(url, encBody, extra);
    return resp;
}

std::string HttpClient::get(const std::wstring& url) {
    std::wstring host, path;
    INTERNET_PORT port;
    bool https;
    if (!parseUrl(url, host, path, port, https)) return "";
    
    HINTERNET conn = WinHttpConnect(m_session, host.c_str(), port, 0);
    if (!conn) return "";
    
    std::wstring getVerb = toWideHttp("GET");
    HINTERNET req = WinHttpOpenRequest(conn, getVerb.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(conn); return ""; }
    
    WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    // Timeouts: nunca colgar mas de 10s por fase (proxy/hooks pueden bloquear)
    WinHttpSetTimeouts(req, 10000, 10000, 10000, 10000);
    WinHttpReceiveResponse(req, nullptr);
    
    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    m_lastStatus = (int)statusCode;
    
    std::string response;
    BYTE buf[4096];
    DWORD bytesRead = 0;
    while (WinHttpReadData(req, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        response.append((char*)buf, bytesRead);
        bytesRead = 0;
    }
    
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    return response;
}

bool HttpClient::getBinary(const std::wstring& url, std::vector<BYTE>& outBytes) {
    std::wstring host, path;
    INTERNET_PORT port;
    bool https;
    if (!parseUrl(url, host, path, port, https)) return false;
    
    HINTERNET conn = WinHttpConnect(m_session, host.c_str(), port, 0);
    if (!conn) return false;
    
    std::wstring getVerb2 = toWideHttp("GET");
    HINTERNET req = WinHttpOpenRequest(conn, getVerb2.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(conn); return false; }
    
    WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    // Descargas grandes (41MB): 60s por fase. Los 10s mataban el download con
    // red variable -> zip truncado -> extraccion parcial -> Astro moria al arrancar.
    WinHttpSetTimeouts(req, 60000, 60000, 60000, 60000);
    WinHttpReceiveResponse(req, nullptr);
    
    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    m_lastStatus = (int)statusCode;
    
    if (statusCode != 200) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        return false;
    }
    
    outBytes.clear();
    BYTE buf[8192];
    DWORD bytesRead = 0;
    while (WinHttpReadData(req, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        outBytes.insert(outBytes.end(), buf, buf + bytesRead);
        bytesRead = 0;
    }
    
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    return true;
}
