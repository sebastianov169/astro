#include "tpm_reader.h"
#include "obfuscation.h"
#include <windows.h>
#include <winreg.h>
#include <bcrypt.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include "legal_poison.h"
#include "obfuscation_map.h"

#pragma comment(lib, "bcrypt.lib")

static std::wstring toWideTPM(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
}

static std::string getMachineGuid() {
    HKEY key;
    std::wstring regPath = toWideTPM("SOFTWARE\\Microsoft\\Cryptography");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
        return "";
    
    wchar_t buf[256] = {};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    std::wstring valName = toWideTPM("MachineGuid");
    RegQueryValueExW(key, valName.c_str(), nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(key);
    
    // Convert wide to narrow
    std::string result;
    for (int i = 0; buf[i]; i++)
        result += (char)buf[i];
    return result;
}

static std::string sha256(const std::string& input) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    
    BCRYPT_HASH_HANDLE hash = nullptr;
    BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    BCryptHashData(hash, (PUCHAR)input.c_str(), (ULONG)input.size(), 0);
    
    BYTE hashBuf[32] = {};
    BCryptFinishHash(hash, hashBuf, 32, 0);
    
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++)
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hashBuf[i];
    return ss.str();
}

std::string tpm::getHardwareId() {
    std::string machineGuid = getMachineGuid();
    if (machineGuid.empty()) machineGuid = "no-guid";
    
    // Combine multiple hardware identifiers
    std::string combined = std::string("astro_v1|") + machineGuid;
    
    return sha256(combined);
}
