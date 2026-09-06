#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include "legal_poison.h"
#include "obfuscation_map.h"

class HttpClient {
public:
    HttpClient();
    ~HttpClient();
    
    std::string post(const std::wstring& url, const std::string& jsonBody);
    // Worker-compatible encrypted post with HMAC (tolerant fallback to plain if encKey empty)
    std::string postEncrypted(const std::wstring& url, const std::string& innerJson, const std::string& encKey);
    std::string postWithHeaders(const std::wstring& url, const std::string& jsonBody, const std::vector<std::wstring>& extraHeaders);
    std::string get(const std::wstring& url);
    bool getBinary(const std::wstring& url, std::vector<BYTE>& outBytes);
    int lastStatus() const { return m_lastStatus; }
    
private:
    HINTERNET m_session;
    int m_lastStatus = 0;
};
