#include <windows.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <sddl.h>
#pragma comment(lib, "bcrypt.lib")
#include <commctrl.h>
#include <shellapi.h>
#include "http_client.h"
#include "tpm_reader.h"
#include "anti_analysis.h"
#include "anti_dll.h"
#include "crypto_m3xc.h"
#include "secure_http.h"
#include "worker_crypto.h"
#include "version_check.h"
#include "obfuscation.h"
#include "deep_obfuscation.h"

DWORD WINAPI downloadThread(LPVOID);

// Cleanup any leftover zip files from previous runs (crash, task kill, etc)
static void cleanupOldZips() {
    wchar_t tp[MAX_PATH];
    GetTempPathW(MAX_PATH, tp);
    std::wstring search = std::wstring(tp) + L"astro_package*.zip";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring fp = std::wstring(tp) + fd.cFileName;
            DeleteFileW(fp.c_str());
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

// DEBUG TRACE (temporary): append stage markers to %TEMP%\\astro_loader_trace.log
static void traceStage(const char* stage) {
    char tp[MAX_PATH]; GetTempPathA(MAX_PATH, tp);
    std::string path = std::string(tp) + "astro_loader_trace.log";
    HANDLE h = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        SYSTEMTIME st; GetLocalTime(&st);
        char line[128];
        int n = snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d] %s\r\n",
                         st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, stage);
        WriteFile(h, line, (DWORD)n, &w, nullptr);
        CloseHandle(h);
    }
}


// Proper recursive delete (the old inline loop reused findData across nested enumerations -
// undefined behavior that corrupted enumeration and could crash mid-download).
static void deleteDirectoryRecursive(const std::wstring& dir) {
    std::wstring search = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DWORD attr = GetFileAttributesW(full.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY))
                SetFileAttributesW(full.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
            deleteDirectoryRecursive(full);
            RemoveDirectoryW(full.c_str());
        } else {
            DWORD attr = GetFileAttributesW(full.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY))
                SetFileAttributesW(full.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
            DeleteFileW(full.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

DWORD WINAPI downloadThreadInner();
#include <string>
#include <vector>
#include <sstream>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

static HWND hEditKey, hBtnActivate, hStaticStatus, hProgress;
static std::string g_hwid, g_licenseKey;
static std::string g_serverAstroSha;
static wchar_t g_tempPath[MAX_PATH];
static HBRUSH g_hbrBg, g_hbrEdit, g_hbrBtn;
static HFONT g_hFont, g_hFontBold, g_hFontSmall, g_hFontTitle;
static HICON g_hIcon;
static HANDLE g_hAstroJob = nullptr;  // job object binding Astro.exe to loader lifetime
static bool g_activated = false;
static std::wstring toWide(const std::string& s);  // fwd decl for helpers below
// === SECURITY FIX: session handshake restored (was lost from this source) ===
// Protocol matches worker /api/session + main_secured.cpp arg contract.
// ENCRYPTION_KEY is passed via obfuscated literal (same value as wrangler secret).
static std::string getEncKey(){
    constexpr uint8_t xk = 0x5A;
    const uint8_t p1[] = {0x6c,0x6e,0x63,0x6f,0x38,0x6d,0x62,0x6e,0x6b,0x39,0x6c,0x3f,0x6e,0x39,0x6e,0x6e};
    const uint8_t p2[] = {0x3f,0x6a,0x6b,0x6e,0x6a,0x6b,0x39,0x3b,0x38,0x69,0x69,0x69,0x38,0x6c,0x6f,0x3b};
    const uint8_t p3[] = {0x62,0x38,0x62,0x6b,0x6c,0x69,0x62,0x6f,0x63,0x63,0x69,0x39,0x63,0x6e,0x6b,0x39};
    const uint8_t p4[] = {0x3f,0x6c,0x6b,0x39,0x6c,0x6f,0x62,0x6c,0x38,0x63,0x39,0x6e,0x38,0x6d,0x6c,0x38};
    char buf[65] = {};
    for (int i = 0; i < 16; ++i) {
        buf[i]      = static_cast<char>(p1[i] ^ xk);
        buf[16 + i] = static_cast<char>(p2[i] ^ xk);
        buf[32 + i] = static_cast<char>(p3[i] ^ xk);
        buf[48 + i] = static_cast<char>(p4[i] ^ xk);
    }
    std::string result(buf, 64);
    SecureZeroMemory(buf, sizeof(buf));
    return result;
}
static std::string generateSessionToken(){
    LOADER_AI_TRAP(); JUNK_CODE;
    std::string tok; tok.reserve(64);
    BCRYPT_ALG_HANDLE hAlg=nullptr;
    if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0)!=0) return "";
    uint8_t raw[32]={0};
    if(BCryptGenRandom(hAlg, raw, sizeof(raw), 0)==0){
        char t[3];
        for(int i=0;i<32;++i){ sprintf_s(t,"%02x",raw[i]); tok+=t; }
    }
    BCryptCloseAlgorithmProvider(hAlg,0);
    SecureZeroMemory(raw,sizeof(raw));
    return tok;
}
static bool registerSession(HttpClient& http, const std::string& token){
    LOADER_AI_TRAP(); JUNK_CODE;
    std::string inner = std::string("{\"license_key\":\"") + g_licenseKey +
                        "\",\"hwid\":\"" + g_hwid +
                        "\",\"token\":\"" + token + "\"}";
    std::wstring url = toWide(OBFUSCATE("https://astro-license.astro-bots.workers.dev")) +
                       toWide(OBFUSCATE("/api/session"));
    traceStage("RS-PRE-HTTP");
    std::string resp = http.postEncrypted(url, inner, getEncKey());
    traceStage("RS-POST-HTTP");
    if(resp.empty()) return false;
    std::string plain;
    worker_crypto::try_decrypt_response(resp, getEncKey(), plain);
    traceStage("RS-DECRYPTED");
    const std::string& look = plain.empty()?resp:plain;
    bool ok = look.find("\"success\":true") != std::string::npos;
    g_serverAstroSha = vercheck::parseAstroSha256(look);
    // BUGFIX: persist the sidecar token ONLY after server confirmed the session.
    if (ok) {
        wchar_t tp[MAX_PATH]; GetTempPathW(MAX_PATH, tp);
        // NTFS file tunneling: DeleteFileW + recreate con el mismo nombre conserva el
        // ctime viejo => Astro rechaza por token "stale". Quitar HIDDEN con
        // SetFileAttributesW y usar CREATE_ALWAYS directo (trunca y refresca ctime).
        std::wstring tokPath = std::wstring(tp) + toWide(OBFUSCATE("astro_app\\session.token"));
        // CREATION TIME: CREATE_ALWAYS trunca pero PRESERVA ftCreationTime del
        // archivo existente => Astro lo rechaza como token stale. Escribir a un
        // archivo nuevo y mover con REPLACE_EXISTING => ctime fresco garantizado.
        std::wstring tmpPath = tokPath + L".new";
        DeleteFileW(tmpPath.c_str());   // borrar restos: CREATE_ALWAYS preserva ctime
        HANDLE hTok = CreateFileW(tmpPath.c_str(),
                                  GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        BOOL wok = FALSE;
        if(hTok!=INVALID_HANDLE_VALUE){
            DWORD w=0; wok = WriteFile(hTok, token.c_str(), (DWORD)token.size(), &w, nullptr);
            CloseHandle(hTok);
            SetFileAttributesW(tmpPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
            if (wok) {
                if (!MoveFileExW(tmpPath.c_str(), tokPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                    DeleteFileW(tokPath.c_str());
                    wok = MoveFileExW(tmpPath.c_str(), tokPath.c_str(), MOVEFILE_REPLACE_EXISTING);
                }
            }
            if (!wok) DeleteFileW(tmpPath.c_str());
        }
        if(!wok) traceStage("TOKEN-WRITE-FAILED");
    }
    SecureZeroMemory(inner.data(), inner.size());
    return ok;
}
// === Hardened helpers: SHA256 pin + ACL temp dir + Job Object + env launch ===
inline void secureZeroMem(void* pp, size_t nn) noexcept { if(pp) SecureZeroMemory(pp, nn); }
std::string computeSha256Hex(const std::vector<uint8_t>& data){
    BCRYPT_ALG_HANDLE hAlg=nullptr; BCRYPT_HASH_HANDLE hHash=nullptr; std::string hex;
    if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)!=0) return hex;
    DWORD hashLen=0, rr=0;
    if(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &rr, 0)!=0){ BCryptCloseAlgorithmProvider(hAlg,0); return hex; }
    std::vector<uint8_t> hh(hashLen);
    if(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0)==0){
        BCryptHashData(hHash, (PUCHAR)(data.empty()?nullptr:data.data()), (ULONG)data.size(), 0);
        BCryptFinishHash(hHash, hh.data(), (ULONG)hh.size(), 0);
        BCryptDestroyHash(hHash);
        char tbuf[3]; for(auto bb:hh){ sprintf_s(tbuf, "%02x", bb); hex+=tbuf; }
    }
    BCryptCloseAlgorithmProvider(hAlg,0); return hex;
}
std::wstring createSecureTempDir(){
    wchar_t tp[MAX_PATH]={0}; GetTempPathW(MAX_PATH, tp);
    wchar_t ff[MAX_PATH]={0}; GetTempFileNameW(tp, L"ast", 0, ff);
    DeleteFileW(ff);
    std::wstring dd=ff; dd+=L"_d";
    PSECURITY_DESCRIPTOR sdd=nullptr;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;OW)", SDDL_REVISION_1, &sdd, nullptr);
    SECURITY_ATTRIBUTES saa{sizeof(saa), sdd, FALSE};
    CreateDirectoryW(dd.c_str(), &saa);
    if(sdd) LocalFree(sdd);
    return dd;
}
HANDLE createAstroJob(){ HANDLE j=CreateJobObjectW(nullptr,nullptr); if(j){ JOBOBJECT_EXTENDED_LIMIT_INFORMATION inf{}; inf.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; SetInformationJobObject(j, JobObjectExtendedLimitInformation, &inf, sizeof(inf)); } return j; }
bool launchAstroSecure(const std::wstring& exe, const std::string& tok){
    std::wstring tokW(tok.begin(), tok.end());
    std::wstring add=L"ASTRO_SESSION_TOKEN="+tokW;
    wchar_t* ce=GetEnvironmentStringsW();
    std::wstring cee;
    if(ce){ for(wchar_t* pp=ce; *pp; pp+=wcslen(pp)+1){ cee+=pp; cee.push_back(L'\0'); } FreeEnvironmentStringsW(ce); }
    size_t cl=cee.size(); size_t tot=cl+add.size()+2;
    std::vector<wchar_t> blk(tot, L'\0');
    if(cl) memcpy(blk.data(), cee.c_str(), cl*sizeof(wchar_t));
    memcpy(blk.data()+cl, add.c_str(), add.size()*sizeof(wchar_t));
    blk[tot-2]=L'\0'; blk[tot-1]=L'\0';
    STARTUPINFOW si{}; si.cb=sizeof(si); PROCESS_INFORMATION pi{};
    std::wstring cc=L"\""+exe+L"\"";
    BOOL ok=CreateProcessW(exe.c_str(), cc.data(), nullptr,nullptr,FALSE,CREATE_UNICODE_ENVIRONMENT,blk.data(),nullptr,&si,&pi);
    SecureZeroMemory(blk.data(), blk.size()*sizeof(wchar_t));
    SecureZeroMemory(tokW.data(), tokW.size()*sizeof(wchar_t));
    if(ok){ CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return true; }
    return false;
}


static std::wstring toWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
}

static std::string jsonGet(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (pos >= json.size()) return "";
    if (json[pos] == '"') {
        pos++;
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ']') end++;
    return json.substr(pos, end - pos);
}

static void setLabel(HWND h, const std::string& text) {
    SetWindowTextA(h, text.c_str());
}

static void setLabelW(HWND h, const std::wstring& text) {
    SetWindowTextW(h, text.c_str());
}

// Rounded rect helper
static void drawRoundRect(HDC hdc, RECT* rc, int radius, HBRUSH br) {
    HRGN rgn = CreateRoundRectRgn(rc->left, rc->top, rc->right, rc->bottom, radius, radius);
    FillRgn(hdc, rgn, br);
    DeleteObject(rgn);
}

static void deleteAstroApp() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring appDir = std::wstring(tempPath) + toWide(OBFUSCATE("astro_app"));
    
    // Delete all files in directory
    WIN32_FIND_DATAW findData;
    std::wstring searchPath = appDir + toWide(OBFUSCATE("\\*"));
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(findData.cFileName, toWide(OBFUSCATE(".")).c_str()) != 0 && wcscmp(findData.cFileName, toWide(OBFUSCATE("..")).c_str()) != 0) {
                // PRESERVE the DPAPI license cache - it must survive app cleanup
                if (_wcsicmp(findData.cFileName, toWide(OBFUSCATE("license.key")).c_str()) == 0)
                    continue;
                std::wstring filePath = appDir + toWide(OBFUSCATE("\\")) + findData.cFileName;
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Recurse into subdirectories
                    std::wstring subSearch = filePath + toWide(OBFUSCATE("\\*"));
                    HANDLE hSubFind = FindFirstFileW(subSearch.c_str(), &findData);
                    if (hSubFind != INVALID_HANDLE_VALUE) {
                        do {
                            if (wcscmp(findData.cFileName, toWide(OBFUSCATE(".")).c_str()) != 0 && wcscmp(findData.cFileName, toWide(OBFUSCATE("..")).c_str()) != 0) {
                                DeleteFileW((filePath + toWide(OBFUSCATE("\\")) + findData.cFileName).c_str());
                            }
                        } while (FindNextFileW(hSubFind, &findData));
                        FindClose(hSubFind);
                    }
                    RemoveDirectoryW(filePath.c_str());
                } else {
                    DeleteFileW(filePath.c_str());
                }
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    RemoveDirectoryW(appDir.c_str());
}

// ---- License cache (DPAPI user-scoped) -------------------------------------
// La key se guarda cifrada con DPAPI: el archivo solo es util para este usuario
// de esta maquina; copiarlo a otra no sirve.
static std::wstring licenseCachePath() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    return std::wstring(tempPath) + toWide(OBFUSCATE("astro_app\\license.key"));
}

static bool dpapiProtect(const std::string& plain, std::string& out) {
    DATA_BLOB in{}, outBlob{};
    in.pbData = (BYTE*)plain.data();
    in.cbData = (DWORD)plain.size();
    if (!CryptProtectData(&in, L"astro-lic", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &outBlob))
        return false;
    out.assign((const char*)outBlob.pbData, outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

static bool dpapiUnprotect(const std::string& blob, std::string& out) {
    DATA_BLOB in{}, outBlob{};
    in.pbData = (BYTE*)blob.data();
    in.cbData = (DWORD)blob.size();
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &outBlob))
        return false;
    out.assign((const char*)outBlob.pbData, outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

static void saveLicenseCache(const std::string& key) {
    std::string enc2;
    if (!dpapiProtect(key, enc2)) return;
    HANDLE h = CreateFileW(licenseCachePath().c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, enc2.data(), (DWORD)enc2.size(), &w, nullptr);
        CloseHandle(h);
    }
}

static std::string loadLicenseCache() {
    HANDLE h = CreateFileW(licenseCachePath().c_str(), GENERIC_READ, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    char buf[1024] = {};
    DWORD rd = 0;
    ReadFile(h, buf, sizeof(buf), &rd, nullptr);
    CloseHandle(h);
    std::string blob(buf, rd);
    std::string key;
    if (!dpapiUnprotect(blob, key)) {
        // Blob ilegible (cache vieja en claro o de otro usuario): borrar
        DeleteFileW(licenseCachePath().c_str());
        return "";
    }
    return key;
}

static void clearLicenseCache() {
    DeleteFileW(licenseCachePath().c_str());
}
// ---------------------------------------------------------------------------

static DWORD WINAPI downloadThread(LPVOID) {
    // Any unhandled exception in this thread would kill the whole process; catch everything.
    try {
        downloadThreadInner();
    } catch (...) {
        setLabel(hStaticStatus, OBFUSCATE("Unexpected error - please retry"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 1;
    }
    return 0;
}

DWORD WINAPI downloadThreadInner() {
    traceStage("DT-START");
    HttpClient http;
    GetTempPathW(MAX_PATH, g_tempPath);
    traceStage("DT-HTTP-CREATED");
    
    // Check if license was previously stored (DPAPI-encrypted cache)
    std::string storedLicense = loadLicenseCache();
    
    // If we have a stored license, validate it first
    if (!storedLicense.empty() && storedLicense == g_licenseKey) {
        setLabel(hStaticStatus, OBFUSCATE("Checking license..."));
        SendMessage(hProgress, PBM_SETPOS, 5, 0);
        JUNK_CODE;
        
        std::string valInner = std::string("{\"license_key\":\"") + storedLicense + "\",\"hwid\":\"" + g_hwid + "\"}";
        std::wstring valUrl = toWide(OBFUSCATE("https://astro-license.astro-bots.workers.dev")) + toWide(OBFUSCATE("/api/validate"));
        traceStage("DT-PRE-VALIDATE");
        std::string valRespEnc = http.postEncrypted(valUrl, valInner, getEncKey());
        traceStage("DT-POST-VALIDATE");
        std::string valPlain;
        worker_crypto::try_decrypt_response(valRespEnc, getEncKey(), valPlain);
        std::string valResp = valPlain.empty() ? valRespEnc : valPlain;
                
        // If license is revoked or invalid, delete everything - but NOT on network error (empty response = offline, allow cached)
        if (valResp.empty()) {
            // Offline - allow cached license to run
            setLabel(hStaticStatus, OBFUSCATE("Offline - using cached license..."));
        } else if (OPAQUE_PRED_TRUE(g_hwid.length())) {
            if (jsonGet(valResp, OBFUSCATE("valid")) != OBFUSCATE("true")) {
                std::string err = jsonGet(valResp, OBFUSCATE("error"));
                if (err.find(OBFUSCATE("revoked")) != std::string::npos || err.find(OBFUSCATE("Revoked")) != std::string::npos) {
                    setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
                    clearLicenseCache();
                    deleteAstroApp();
                    setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
                    SendMessage(hProgress, PBM_SETPOS, 0, 0);
                    EnableWindow(hBtnActivate, TRUE);
                    return 0;
                } else if (err.find(OBFUSCATE("expired")) != std::string::npos) {
                    setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
                    clearLicenseCache();
                    SendMessage(hProgress, PBM_SETPOS, 0, 0);
                    EnableWindow(hBtnActivate, TRUE);
                    return 0;
                } else if (!err.empty()) {
                    // Other error (e.g., pending) - don't delete, just show
                    setLabel(hStaticStatus, err.c_str());
                    SendMessage(hProgress, PBM_SETPOS, 0, 0);
                    EnableWindow(hBtnActivate, TRUE);
                    return 0;
                }
                // No error field but valid != true and not empty = still invalid, but don't delete on unknown
                if (valResp.find(OBFUSCATE("pending")) == std::string::npos) {
                    setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
                    clearLicenseCache();
                    SetWindowTextW(hEditKey, L"");
                    SendMessage(hProgress, PBM_SETPOS, 0, 0);
                    EnableWindow(hBtnActivate, TRUE);
                    return 0;
                }
            }
        }
        
        // License valid - try to launch existing installation
        wchar_t tempPath2[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath2);
        std::wstring appDir = std::wstring(tempPath2) + toWide(OBFUSCATE("astro_app"));
        std::wstring astroExe = appDir + toWide(OBFUSCATE("\\Astro.exe"));
        
        DWORD attrib = GetFileAttributesW(astroExe.c_str());
        traceStage("DT-EXE-CHECK");
        // Anti-stale-cache: si R2 trae build mas nuevo, borrar y re-descargar
        if (!g_serverAstroSha.empty() && vercheck::isCacheStale(astroExe, g_serverAstroSha)) {
            traceStage("DT-STALE-CACHE");
            deleteAstroApp();
            attrib = GetFileAttributesW(astroExe.c_str());
        }
        if (attrib != INVALID_FILE_ATTRIBUTES) {
                // Self-integrity gate: refuse to launch if .text was patched
    if (!deep::textIntact()) {
        traceStage("DT-TEXT-PATCHED");
        TerminateProcess(GetCurrentProcess(), 0xDEAD11);
        return 0xDEAD11;
    }
    traceStage("DT-TEXT-OK");
setLabel(hStaticStatus, OBFUSCATE("Creating secure session..."));
            SendMessage(hProgress, PBM_SETPOS, 90, 0);
            JUNK_CODE;
            // SECURITY FIX: cached path previously launched Astro.exe directly with NO token
            // (full gatekeeper bypass). Now it MUST create a live one-time session like the fresh path.
            std::string sessionToken = generateSessionToken();
            if (sessionToken.empty() || !registerSession(http, sessionToken)) {
                // Sesión rechazada = licencia revocada/expirada server-side: invalidar cache
                clearLicenseCache();
                setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
                SetWindowTextW(hEditKey, L"");
                SendMessage(hProgress, PBM_SETPOS, 0, 0);
                EnableWindow(hBtnActivate, TRUE);
                return 0;
            }
            traceStage("LAUNCH-JOB-CREATE");
            HANDLE hJob = createAstroJob();
            traceStage("LAUNCH-PROC-CREATE");
            std::wstring tokW = toWide(sessionToken);
            SecureZeroMemory((void*)sessionToken.data(), sessionToken.size());
            std::wstring cmdLine = L"\"" + astroExe + L"\" --astro-session " + tokW +
                L" --astro-key " + toWide(g_licenseKey) + L" --astro-hwid " + toWide(g_hwid);
            STARTUPINFOW siL{}; siL.cb = sizeof(siL); PROCESS_INFORMATION piL{};
            BOOL okL = CreateProcessW(nullptr, (LPWSTR)cmdLine.data(), nullptr, nullptr, FALSE,
                                      CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, nullptr, appDir.c_str(), &siL, &piL);
            SecureZeroMemory((void*)tokW.data(), tokW.size()*sizeof(wchar_t));
            SecureZeroMemory((void*)cmdLine.data(), cmdLine.size()*sizeof(wchar_t));
            if (okL) {
                traceStage("LAUNCH-CREATED-OK");
                if (hJob) { AssignProcessToJobObject(hJob, piL.hProcess); g_hAstroJob = hJob; }
                traceStage("LAUNCH-JOB-ASSIGNED");
                ResumeThread(piL.hThread);
                traceStage("LAUNCH-RESUMED");
                CloseHandle(piL.hThread); CloseHandle(piL.hProcess);
                SendMessage(hProgress, PBM_SETPOS, 100, 0);
                g_activated = true;
                // Hide auth window - Astro is running
                ShowWindow(GetParent(hStaticStatus), SW_HIDE);
                // Wait for Astro to close, then clean up (same as fresh path)
                {
                    HANDLE hProcDup;
                    DuplicateHandle(GetCurrentProcess(), piL.hProcess,
                        GetCurrentProcess(), &hProcDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
                    WaitForSingleObject(hProcDup, INFINITE);
                    CloseHandle(hProcDup);
                    deleteAstroApp();
                    DeleteFileW((std::wstring(g_tempPath) + toWide(OBFUSCATE("astro_package.zip"))).c_str());
                    cleanupOldZips();
                }
                return 0;
            }
            if (hJob) { CloseHandle(hJob); }
        }
    }
    
    setLabel(hStaticStatus, OBFUSCATE("Validating license..."));
    SendMessage(hProgress, PBM_SETPOS, 10, 0);
    JUNK_CODE;
    
    std::string actInner = std::string("{\"license_key\":\"") + g_licenseKey + "\",\"hwid\":\"" + g_hwid + "\",\"tier\":1}";
    std::wstring url = toWide(OBFUSCATE("https://astro-license.astro-bots.workers.dev")) + toWide(OBFUSCATE("/api/activate"));
    std::string respEnc = http.postEncrypted(url, actInner, getEncKey());
    JUNK_CODE;
    std::string _plain;
    worker_crypto::try_decrypt_response(respEnc, getEncKey(), _plain);
    std::string resp = _plain.empty() ? respEnc : _plain;
    
    if (OPAQUE_PRED_TRUE(resp.length())) {
        if (jsonGet(resp, OBFUSCATE("pending")) == OBFUSCATE("true")) {
            setLabel(hStaticStatus, OBFUSCATE("Connecting..."));
            SendMessage(hProgress, PBM_SETPOS, 0, 0);
            EnableWindow(hBtnActivate, TRUE);
            return 0;
        }
    }
    
    if (jsonGet(resp, OBFUSCATE("error")).size() > 0) {
        setLabel(hStaticStatus, (std::string(OBFUSCATE("Error: ")) + jsonGet(resp, OBFUSCATE("error"))).c_str());
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    
        // Self-integrity gate: refuse to launch if .text was patched
    if (!deep::textIntact()) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD12);
        return 0xDEAD12;
    }
setLabel(hStaticStatus, OBFUSCATE("Connecting..."));
    SendMessage(hProgress, PBM_SETPOS, 20, 0);
    JUNK_LOOP(2);
    
    // Download ZIP from R2
    std::wstring dlUrl = toWide(OBFUSCATE("https://astro-license.astro-bots.workers.dev")) + 
        toWide(OBFUSCATE("/api/download?license_key=")) + toWide(g_licenseKey) + toWide(OBFUSCATE("&hwid=")) + toWide(g_hwid);
    
    std::wstring appDir = std::wstring(g_tempPath) + toWide(OBFUSCATE("astro_app"));
    
    // Save ZIP to temp root (NOT inside appDir, because we delete appDir before extraction)
    std::wstring zipPath = std::wstring(g_tempPath) + toWide(OBFUSCATE("astro_package.zip"));
    
    std::vector<BYTE> zipData;
    if (!http.getBinary(dlUrl, zipData) || zipData.size() < 100) {
        setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    JUNK_CODE;
    
    // Verify ZIP header (PK)
    if (zipData[0] != 0x50 || zipData[1] != 0x4B) {
        setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    
    // Save ZIP
    HANDLE hFile = CreateFileW(zipPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        setLabel(hStaticStatus, OBFUSCATE("Connection error"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    DWORD written = 0;
    WriteFile(hFile, zipData.data(), (DWORD)zipData.size(), &written, nullptr);
    CloseHandle(hFile);
    
    SendMessage(hProgress, PBM_SETPOS, 50, 0);
    setLabel(hStaticStatus, OBFUSCATE("Extracting..."));
    
    //     // Delete old app directory completely (proper recursion - no findData reuse)
    deleteDirectoryRecursive(appDir);

CreateDirectoryW(appDir.c_str(), nullptr);
    
    // Extract ZIP with PowerShell at ABSOLUTE path (PATH-resolved powershell = binary planting risk)
    std::wstring psCmd = toWide(OBFUSCATE("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Expand-Archive -Path '")) + zipPath + toWide(OBFUSCATE("' -DestinationPath '")) + appDir + toWide(OBFUSCATE("' -Force\""));
    
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, (LPWSTR)psCmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        setLabel(hStaticStatus, OBFUSCATE("Extraction failed to start"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    // 38 MB package can take a while; wait up to 3 minutes
    if (WaitForSingleObject(pi.hProcess, 180000) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        setLabel(hStaticStatus, OBFUSCATE("Extraction timed out"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

    // Verify extraction actually produced Astro.exe before discarding the zip
    std::wstring astroCheck = appDir + toWide(OBFUSCATE("\\Astro.exe"));
    if (GetFileAttributesW(astroCheck.c_str()) == INVALID_FILE_ATTRIBUTES) {
        setLabel(hStaticStatus, OBFUSCATE("Extracting (retry)..."));
        STARTUPINFOW si2 = { sizeof(si2) };
        si2.dwFlags = STARTF_USESHOWWINDOW; si2.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi2 = {};
        if (CreateProcessW(nullptr, (LPWSTR)psCmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si2, &pi2)) {
            WaitForSingleObject(pi2.hProcess, 180000);
            CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);
        }
        if (GetFileAttributesW(astroCheck.c_str()) == INVALID_FILE_ATTRIBUTES) {
            setLabel(hStaticStatus, OBFUSCATE("Extraction failed"));
            SendMessage(hProgress, PBM_SETPOS, 0, 0);
            EnableWindow(hBtnActivate, TRUE);
            return 0;
        }
    }

    // Delete ZIP after successful extraction
    DeleteFileW(zipPath.c_str());
    
    SendMessage(hProgress, PBM_SETPOS, 80, 0);
    setLabel(hStaticStatus, OBFUSCATE("Launching Astro..."));
    
    // Launch real Astro.exe (Qt farming app)
    std::wstring astroExe = appDir + toWide(OBFUSCATE("\\Astro.exe"));
    
    DWORD attrib2 = GetFileAttributesW(astroExe.c_str());
    if (attrib2 == INVALID_FILE_ATTRIBUTES) {
        setLabel(hStaticStatus, OBFUSCATE("Astro.exe not found"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    JUNK_CODE;
    
    // SECURITY FIX: fresh path now performs the full session handshake before launch.
    // Token is generated with BCryptGenRandom, registered one-time on the worker (HMAC+m3xc),
    // and passed to Astro.exe which validates it against /api/session/validate.
    setLabel(hStaticStatus, OBFUSCATE("Creating secure session..."));
    SendMessage(hProgress, PBM_SETPOS, 85, 0);
    std::string sessionToken = generateSessionToken();
    if (sessionToken.empty() || !registerSession(http, sessionToken)) {
        clearLicenseCache();   // licencia revocada/expirada server-side
        setLabel(hStaticStatus, OBFUSCATE("This application build is not allowed"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    LOADER_AI_TRAP();
    // Self-integrity gate (fresh path): refuse to launch if loader .text was patched
    if (!deep::textIntact()) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD13);
        return 0xDEAD13;
    }
    HANDLE hJob = createAstroJob();
    // SECURITY: pass token/key/hwid via environment block, not command-line args.
    // Command-line is readable by any process via WMI Win32_Process.CommandLine.
    std::wstring tokW = toWide(sessionToken);
    SecureZeroMemory((void*)sessionToken.data(), sessionToken.size());
    std::wstring envAdd = L"ASTRO_SESSION_TOKEN=" + tokW +
        L"\0ASTRO_KEY=" + toWide(g_licenseKey) +
        L"\0ASTRO_HWID=" + toWide(g_hwid) + L"\0";
    wchar_t* ce2=GetEnvironmentStringsW();
    std::wstring cee2;
    if(ce2){ for(wchar_t* pp2=ce2; *pp2; pp2+=wcslen(pp2)+1){ cee2+=pp2; cee2.push_back(L'\0'); } FreeEnvironmentStringsW(ce2); }
    size_t cl2=cee2.size(); size_t tot2=cl2+envAdd.size()+2;
    std::vector<wchar_t> blk2(tot2, L'\0');
    if(cl2) memcpy(blk2.data(), cee2.c_str(), cl2*sizeof(wchar_t));
    memcpy(blk2.data()+cl2, envAdd.c_str(), envAdd.size()*sizeof(wchar_t));
    blk2[tot2-2]=L'\0'; blk2[tot2-1]=L'\0';
    std::wstring cmdLine = L"\"" + astroExe + L"\"";
    STARTUPINFOW asi = { sizeof(asi) };
    asi.dwFlags = STARTF_USESHOWWINDOW; asi.wShowWindow = SW_SHOWNORMAL;
    PROCESS_INFORMATION api_{};
    if (!CreateProcessW(nullptr, (LPWSTR)cmdLine.data(), nullptr, nullptr, FALSE,
                        CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, (LPVOID)blk2.data(), appDir.c_str(), &asi, &api_)) {
        SecureZeroMemory((void*)tokW.data(), tokW.size()*sizeof(wchar_t));
        SecureZeroMemory(blk2.data(), blk2.size()*sizeof(wchar_t));
        setLabel(hStaticStatus, OBFUSCATE("Failed to start Astro"));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hBtnActivate, TRUE);
        return 0;
    }
    SecureZeroMemory((void*)tokW.data(), tokW.size()*sizeof(wchar_t));
    SecureZeroMemory(blk2.data(), blk2.size()*sizeof(wchar_t));
    if (hJob) { AssignProcessToJobObject(hJob, api_.hProcess); g_hAstroJob = hJob; }
    ResumeThread(api_.hThread);
    // Save handle to wait in background and auto-delete after close
    HANDLE hProc = api_.hProcess;
    CloseHandle(api_.hThread);
    
    // Save license key for future validation (DPAPI-encrypted cache)
    saveLicenseCache(g_licenseKey);
    
    SendMessage(hProgress, PBM_SETPOS, 100, 0);
    g_activated = true;
    // Hide auth window - Astro is running
    ShowWindow(GetParent(hStaticStatus), SW_HIDE);
    
    // Wait for Astro to close, then auto-delete everything
    WaitForSingleObject(hProc, INFINITE);
    CloseHandle(hProc);
    deleteAstroApp();
    DeleteFileW((std::wstring(g_tempPath) + toWide(OBFUSCATE("astro_package.zip"))).c_str());
    // Close auth window
    PostMessageW(FindWindowW(toWide(OBFUSCATE("AstroClass")).c_str(), toWide(OBFUSCATE("Astro")).c_str()), WM_CLOSE, 0, 0);
    ExitProcess(0);
    
    return 0;
}

// Custom button paint
static void drawButton(HWND hwnd, LPDRAWITEMSTRUCT dis) {
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    
    bool pressed = (dis->itemState & ODS_SELECTED);
    bool disabled = (dis->itemState & ODS_DISABLED);
    
    HBRUSH br;
    if (disabled) br = CreateSolidBrush(RGB(0x33, 0x33, 0x33));
    else if (pressed) br = CreateSolidBrush(RGB(0xC0, 0xA0, 0x30));
    else br = CreateSolidBrush(RGB(0xF0, 0xC0, 0x40));
    
    // Draw rounded background
    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right, rc.bottom, 8, 8);
    FillRgn(hdc, rgn, br);
    DeleteObject(rgn);
    DeleteObject(br);
    
    // Draw border
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(0xF0, 0xC0, 0x40));
    SelectObject(hdc, pen);
    SelectObject(hdc, GetStockObject(NULL_BRUSH));
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 8, 8);
    DeleteObject(pen);
    
    // Draw text
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, disabled ? RGB(0x66, 0x66, 0x66) : RGB(0x0F, 0x0F, 0x0F));
    SelectObject(hdc, g_hFontBold);
    
    wchar_t text[64] = {};
    GetWindowTextW(hwnd, text, 64);
    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND h = (HWND)lParam;
        if (h == hStaticStatus) {
            SetTextColor(hdc, RGB(0x88, 0x88, 0x88));
        } else {
            SetTextColor(hdc, RGB(0xF0, 0xC0, 0x40));
        }
        SetBkColor(hdc, RGB(0x12, 0x12, 0x18));
        return (LRESULT)g_hbrBg;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(0xFF, 0xFF, 0xFF));
        SetBkColor(hdc, RGB(0x1E, 0x1E, 0x2A));
        return (LRESULT)g_hbrEdit;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            drawButton(dis->hwndItem, dis);
            return TRUE;
        }
        break;
    }
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_hbrBg);
        
        // Draw subtle top accent line
        HPEN pen = CreatePen(PS_SOLID, 2, RGB(0xF0, 0xC0, 0x40));
        SelectObject(hdc, pen);
        MoveToEx(hdc, 0, 0, nullptr);
        LineTo(hdc, rc.right, 0);
        DeleteObject(pen);
        
        return 1;
    }
    case WM_COMMAND:
        if ((HWND)lParam == hBtnActivate && !g_activated) {
            wchar_t keyBuf[256] = {};
            GetWindowTextW(hEditKey, keyBuf, 256);
            g_licenseKey.clear();
            for (int i = 0; keyBuf[i]; i++) g_licenseKey += (char)keyBuf[i];
            
            traceStage("CMD-ACTIVATE");
            { char b[80]; snprintf(b,80,"CMD-KEYLEN=%zu",g_licenseKey.size()); traceStage(b); }
            if (g_licenseKey.size() < 10) {
                traceStage("CMD-KEY-SHORT");
                setLabel(hStaticStatus, OBFUSCATE("Enter a valid license key"));
                break;
            }
            EnableWindow(hBtnActivate, FALSE);
            SetWindowTextW(hBtnActivate, toWide(OBFUSCATE("WORKING...")).c_str());
            CreateThread(nullptr, 0, downloadThread, nullptr, 0, nullptr);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

extern "C" void StartDebugProtection(void);
extern "C" int astroScanDebugger(void);
#ifndef ASTRO_ANTIDBG_THREAD
#define ASTRO_ANTIDBG_THREAD 0
#endif

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    traceStage("START");
    // Clean up leftover zip files from previous runs (crash/kill recovery)
    cleanupOldZips();
    // Anti-debug: inline PEB check (no API call, hard to patch)
    {
        BYTE* peb = (BYTE*)__readgsqword(0x60);
        if (peb && peb[2]) {   // PEB->BeingDebugged (offset 2); [0]=InheritedAddressSpace always 1
            TerminateProcess(GetCurrentProcess(), 0xDEAD01);
            return 0xDEAD01;
        }
        DWORD* ngf = (DWORD*)(peb + 0x68);
        if (ngf && (*ngf & 0x70)) {
            TerminateProcess(GetCurrentProcess(), 0xDEAD02);
            return 0xDEAD02;
        }
    }

    // AntiDBG single-run checks en hilo dedicado (NotRequiem, MIT, parchado):
    // el modo guard completo usa instrumentation callbacks incompatibles con
    // Win11 24H2+; usamos isProgramBeingDebugged() periodico (checks syscall).
    // Kill SOLO si deteccion real (los errores NTSTATUS ya se filtran en adbg.c).
#if ASTRO_ANTIDBG_THREAD
    CreateThread(nullptr, 0, [](LPVOID)->DWORD {
        while (true) {
            if (astroScanDebugger() > 0) {   // wrapper parcheado: sin FP de NTSTATUS
                TerminateProcess(GetCurrentProcess(), 0xDEAD05);
                return 0xDEAD05;
            }
            Sleep(2500);
        }
        return 0;
    }, nullptr, 0, nullptr);
#endif
    traceStage("ANTIDBG-ON");

    // Self-integrity baseline: checksum of executable sections.
    // Verified before each launch; a patched loader refuses to run.
    deep::computeTextChecksum();
    traceStage("checksum-ok");
    
    // Junk code (obfuscation)
    volatile int _j1 = 0x12345678; _j1 ^= 0xDEADBEEF; _j1 = (_j1 << 13) | (_j1 >> 19);
    volatile int _j2 = 0x87654321; _j2 = _j1 * 0x45d9f3b; _j2 ^= _j1;
    
    // SECURITY FIX: anti-analysis was compiled but never called here (dead-code eliminated).
    { JUNK_CODE; LOADER_AI_TRAP();
      traceStage("before-run-all-checks");
      uint32_t _det = antidebug::run_all_checks(false);
      { char b[64]; snprintf(b,64,"run-all-checks det=%u",_det); traceStage(b); }
      if (_det != antidebug::DETECT_NONE) {
          TerminateProcess(GetCurrentProcess(), 0xDEAD00 + (_det & 0xFF));
          return (int)(0xDEAD00 + (_det & 0xFF));
      } }
    // Anti-DLL: static scan for blocked DLLs (monitor starts later, after all legit DLLs load)
    if (loader_dll::AntiDll::checkBlockedDlls()) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD13);
        return (int)0xDEAD13;
    }
    
    traceStage("blocked-dlls-ok");
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);
    traceStage("comctl32-loaded");
    
    traceStage("before-hwid");
    g_hwid = tpm::getHardwareId();
    traceStage("hwid-ok");
    
    // Colors
    g_hbrBg = CreateSolidBrush(RGB(0x12, 0x12, 0x18));
    g_hbrEdit = CreateSolidBrush(RGB(0x1E, 0x1E, 0x2A));
    g_hbrBtn = CreateSolidBrush(RGB(0xF0, 0xC0, 0x40));
    
    // Fonts
    g_hFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, toWide(OBFUSCATE("Segoe UI")).c_str());
    g_hFontBold = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, toWide(OBFUSCATE("Segoe UI")).c_str());
    g_hFontSmall = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, toWide(OBFUSCATE("Segoe UI")).c_str());
    g_hFontTitle = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, toWide(OBFUSCATE("Segoe UI")).c_str());
    
    // Register
    std::wstring clsNameReg = toWide(OBFUSCATE("AstroClass"));
    std::wstring winTitleReg = toWide(OBFUSCATE("Astro"));
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = clsNameReg.c_str();
    wc.hbrBackground = g_hbrBg;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);
    
    int w = 380, h = 260;
    int sx = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int sy = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    
    HWND hwnd = CreateWindowExW(0, clsNameReg.c_str(), winTitleReg.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        sx, sy, w, h, nullptr, nullptr, hInstance, nullptr);
    
    // Title
    HWND hTitle = CreateWindowW(toWide(OBFUSCATE("STATIC")).c_str(), toWide(OBFUSCATE("ASTRO")).c_str(), WS_CHILD | WS_VISIBLE | SS_CENTER,
        0, 20, w, 35, hwnd, nullptr, hInstance, nullptr);
    SendMessage(hTitle, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);
    
    // Separator line (using static)
    HWND hLine = CreateWindowW(toWide(OBFUSCATE("STATIC")).c_str(), toWide(OBFUSCATE("")).c_str(), WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        40, 58, w - 80, 2, hwnd, nullptr, hInstance, nullptr);
    
    // License key label
    HWND hKeyLabel = CreateWindowW(toWide(OBFUSCATE("STATIC")).c_str(), toWide(OBFUSCATE("LICENSE KEY")).c_str(), WS_CHILD | WS_VISIBLE,
        40, 72, 100, 18, hwnd, nullptr, hInstance, nullptr);
    SendMessage(hKeyLabel, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);
    
    // License key input
    hEditKey = CreateWindowExW(WS_EX_CLIENTEDGE, toWide(OBFUSCATE("EDIT")).c_str(), toWide(OBFUSCATE("")).c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_CENTER,
        40, 92, w - 80, 30, hwnd, nullptr, hInstance, nullptr);
    SendMessage(hEditKey, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
    SendMessage(hEditKey, EM_SETLIMITTEXT, 128, 0);
    
    // Activate button (owner-drawn for custom style)
    hBtnActivate = CreateWindowW(toWide(OBFUSCATE("BUTTON")).c_str(), toWide(OBFUSCATE("ACTIVATE")).c_str(),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
        40, 135, w - 80, 38, hwnd, nullptr, hInstance, nullptr);
    SendMessage(hBtnActivate, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
    
    // Status
    hStaticStatus = CreateWindowW(toWide(OBFUSCATE("STATIC")).c_str(), toWide(OBFUSCATE("Enter your license key")).c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        40, 182, w - 80, 18, hwnd, nullptr, hInstance, nullptr);
    SendMessage(hStaticStatus, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);
    
    // Progress bar
    hProgress = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        40, 205, w - 80, 6, hwnd, nullptr, hInstance, nullptr);
    SendMessage(hProgress, PBM_SETRANGE32, 0, 100);
    SendMessage(hProgress, PBM_SETPOS, 0, 0);
    // Color the progress bar green
    SendMessage(hProgress, PBM_SETBARCOLOR, 0, RGB(0xF0, 0xC0, 0x40));
    SendMessage(hProgress, PBM_SETBKCOLOR, 0, RGB(0x1E, 0x1E, 0x2A));
    
    traceStage("window-created");
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // License cache: si hay una key guardada (DPAPI), precargarla y lanzar el flujo
    // automaticamente (mismo camino que un click del usuario). Si el server la
    // rechaza, downloadThreadInner limpia el cache y pide tipeo manual.
    {
        std::string cachedKey = loadLicenseCache();
        if (!cachedKey.empty()) {
            std::wstring wk(cachedKey.begin(), cachedKey.end());
            SetWindowTextW(hEditKey, wk.c_str());
            traceStage("cache-hit");
            // PostMessage (async): SendMessage aqui puede deadlockear con el
            // hilo antidbg (loader lock). El WM_COMMAND se procesa en el loop.
            PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(0, BN_CLICKED), (LPARAM)hBtnActivate);
        } else {
            traceStage("cache-miss");
        }
    }
    
    // Anti-DLL monitor: start LAST so delayed system DLL loads aren't flagged as injections.
    // Monitor thread waits one interval before first check to let late loads settle.
    loader_dll::initializeAntiDll();
    traceStage("PRE-LOOP");

    MSG msg;
    traceStage("LOOP-START");
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    DeleteObject(g_hbrBg);
    DeleteObject(g_hbrEdit);
    DeleteObject(g_hbrBtn);
    DeleteObject(g_hFont);
    DeleteObject(g_hFontBold);
    DeleteObject(g_hFontSmall);
    DeleteObject(g_hFontTitle);
    return (int)msg.wParam;
}
