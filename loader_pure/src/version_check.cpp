#include "version_check.h"
#include "obfuscation.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdio>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

namespace vercheck {

std::string parseShaField(const std::string& resp, const std::string& field) {
    std::string key = "\"";
    key += field;
    key += "\":\"";
    size_t pos = resp.find(key);
    if (pos == std::string::npos) {
        return "";
    }
    pos += key.size();
    if (resp.size() < pos + 64) {
        return "";
    }
    std::string cand = resp.substr(pos, 64);
    for (size_t i = 0; i < cand.size(); ++i) {
        char c = cand[i];
        bool isHex = (c >= '0' && c <= '9') ||
                     (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F');
        if (!isHex) {
            return "";
        }
    }
    return cand;
}

std::string parseAstroSha256(const std::string& resp) {
    return parseShaField(resp, OBFUSCATE("astro_sha256"));
}

std::string parseLoaderSha256(const std::string& resp) {
    return parseShaField(resp, OBFUSCATE("loader_sha256"));
}

std::string parsePackageSha256(const std::string& resp) {
    return parseShaField(resp, OBFUSCATE("package_sha256"));
}

std::string sha256FileHex(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return "";
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    std::string result;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        CloseHandle(hFile);
        return "";
    }

    DWORD cbHashObject = 0;
    DWORD cbData = 0;
    DWORD cbHash = 0;

    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbData, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    std::vector<BYTE> hashObject(cbHashObject);
    std::vector<BYTE> hash(cbHash);

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    const DWORD kChunk = 64 * 1024;
    std::vector<BYTE> buffer(kChunk);
    BOOL ok = FALSE;
    DWORD bytesRead = 0;
    bool readError = false;
    bool hashError = false;

    for (;;) {
        ok = ReadFile(hFile, buffer.data(), kChunk, &bytesRead, NULL);
        if (!ok) {
            readError = true;
            break;
        }
        if (bytesRead == 0) {
            break;
        }
        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buffer.data(), bytesRead, 0))) {
            hashError = true;
            break;
        }
    }

    if (!readError && !hashError) {
        if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash.data(), cbHash, 0))) {
            hashError = true;
        }
    }

    if (hHash != NULL) {
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    if (readError || hashError) {
        return "";
    }

    static const char* hexChars = "0123456789abcdef";
    result.reserve(cbHash * 2);
    for (DWORD i = 0; i < cbHash; ++i) {
        result.push_back(hexChars[(hash[i] >> 4) & 0xF]);
        result.push_back(hexChars[hash[i] & 0xF]);
    }

    return result;
}

std::string sha256BytesHex(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    std::string result;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        return "";
    }
    DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0)) ||
        !BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbData, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    std::vector<BYTE> hashObject(cbHashObject);
    std::vector<BYTE> hash(cbHash);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    bool ok = BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0)) &&
              BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash.data(), cbHash, 0));
    if (hHash != NULL) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!ok) return "";
    static const char* hexChars = "0123456789abcdef";
    result.reserve(cbHash * 2);
    for (DWORD i = 0; i < cbHash; ++i) {
        result.push_back(hexChars[(hash[i] >> 4) & 0xF]);
        result.push_back(hexChars[hash[i] & 0xF]);
    }
    return result;
}

bool isCacheStale(const std::wstring& exePath, const std::string& serverSha) {
    if (serverSha.empty()) {
        return false;
    }
    std::string local = sha256FileHex(exePath);
    if (local.empty()) {
        return false;
    }
    return _stricmp(local.c_str(), serverSha.c_str()) != 0;
}

}
