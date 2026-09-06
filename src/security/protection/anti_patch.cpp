#include <cstdio>
#include <string>
#include "anti_patch.h"
#include <Psapi.h>
#include <intrin.h>
#include <cstring>
#pragma warning(disable: 4996)

namespace security {

static AntiPatch* g_instance = nullptr;

AntiPatch::AntiPatch() = default;

AntiPatch::~AntiPatch() {
    stop();
}

void AntiPatch::start() {
    if (m_running.exchange(true))
        return;

    captureOriginalCrcs();
    captureOriginalApis();

    try {
        m_monitorThread = std::thread(&AntiPatch::monitorLoop, this);
    } catch (...) {
        // Thread quota exhausted (LSP-injected hosts): continue without the monitor.
        m_running = false;
    }
}

void AntiPatch::stop() {
    if (!m_running.exchange(false))
        return;

    if (m_monitorThread.joinable())
        m_monitorThread.join();
}

void AntiPatch::setDetectionCallback(DetectionCallback cb) {
    m_callback = std::move(cb);
}

void AntiPatch::onDetection(const char* reason) {
    {
        char _tp[MAX_PATH]{}; GetTempPathA(MAX_PATH,_tp); std::string _lp=std::string(_tp)+"astro_kill_trace.log"; FILE* f = fopen(_lp.c_str(), "a");
        if (f) { fprintf(f, "AntiPatch detection: %s\n", reason); fclose(f); }
    }
    // Los checks (CRC de secciones propias, breakpoints, hooks en APIs) solo se
    // disparan con MODIFICACION REAL de este proceso => kill directo.
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
}

void AntiPatch::monitorLoop() {
    while (m_running) {
        const struct { const char* n; bool (AntiPatch::*f)(); } ap_checks[] = {
            {"SectionCrc", &AntiPatch::verifySectionCrc},
            {"ImportHash", &AntiPatch::verifyImportHash},
            {"BreakpointPatches", &AntiPatch::checkBreakpointPatches},
            {"ApiHooks", &AntiPatch::checkApiHooks},
        };
        for (const auto& ck : ap_checks) {
            if ((this->*ck.f)()) {
                FILE* _f = fopen((std::string(getenv("TEMP")?getenv("TEMP"):".") + "\\astro_det.log").c_str(), "a");
                if (_f) { fprintf(_f, "SUBCHECK[anti_patc]: %s\n", ck.n); fclose(_f); }
                onDetection(ck.n);
                return;
            }
        }
        if (false) {
            { FILE* _f = fopen((std::string(getenv("TEMP")?getenv("TEMP"):".") + "\\astro_det.log").c_str(), "a"); if (_f) { fprintf(_f, "DETECT[anti_patc]: %s\n", "anti_patch_detected"); fclose(_f); } }
            onDetection("anti_patch_detected");
            return;
        }
        Sleep(CHECK_INTERVAL_MS);
    }
}

void AntiPatch::captureOriginalCrcs() {
    MODULEINFO modInfo{};
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return;

    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
        return;

    const BYTE* base = reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(
        const_cast<BYTE*>(base));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        const_cast<BYTE*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            SectionCrc sc{};
            sc.rva = sec[i].VirtualAddress;
            sc.size = sec[i].Misc.VirtualSize;
            sc.crc = calculateCrc(base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize);
            m_originalCrcs.push_back(sc);
        }
    }
}

void AntiPatch::captureOriginalApis() {
    const char* criticalApis[] = {
        "NtOpenProcess", "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory", "NtReadVirtualMemory",
        "NtCreateFile", "NtReadFile", "NtWriteFile",
        "NtProtectVirtualMemory", "NtMapViewOfSection",
        "VirtualProtect", "WriteProcessMemory",
        nullptr
    };

    for (const char* name : criticalApis) {
        FARPROC fn = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name);
        if (!fn)
            continue;

        std::vector<BYTE> originalBytes(16);
        memcpy(originalBytes.data(), reinterpret_cast<const void*>(fn), 16);
        m_originalApiBytes.push_back({fn, std::move(originalBytes)});
    }
}

DWORD AntiPatch::calculateCrc(const BYTE* data, size_t size) {
    DWORD crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return ~crc;
}

bool AntiPatch::verifySectionCrc() {
    MODULEINFO modInfo{};
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return false;

    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
        return false;

    const BYTE* base = reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll);

    for (const auto& sc : m_originalCrcs) {
        DWORD currentCrc = calculateCrc(base + sc.rva, sc.size);
        if (currentCrc != sc.crc)
            return true;
    }
    return false;
}

bool AntiPatch::verifyImportHash() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return false;

    const BYTE* base = reinterpret_cast<const BYTE*>(hMod);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(
        const_cast<BYTE*>(base));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        const_cast<BYTE*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
        return false;

    IMAGE_IMPORT_DESCRIPTOR* impDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        const_cast<BYTE*>(base) + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    DWORD importHash = 0;
    for (; impDesc->Name; impDesc++) {
        const char* dllName = reinterpret_cast<const char*>(base + impDesc->Name);
        while (*dllName) {
            importHash = _rotl(importHash, 7) ^ *dllName;
            dllName++;
        }
        importHash = _rotl(importHash, 13);

        for (IMAGE_THUNK_DATA* thunk = impDesc->OriginalFirstThunk ?
             reinterpret_cast<IMAGE_THUNK_DATA*>(const_cast<BYTE*>(base) + impDesc->OriginalFirstThunk) :
             reinterpret_cast<IMAGE_THUNK_DATA*>(const_cast<BYTE*>(base) + impDesc->FirstThunk);
             thunk->u1.AddressOfData; thunk++) {

            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                importHash = _rotr(importHash, 3) ^ (thunk->u1.Ordinal & 0xFFFF);
            } else {
                IMAGE_IMPORT_BY_NAME* impName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    const_cast<BYTE*>(base) + thunk->u1.AddressOfData);
                const char* fnName = reinterpret_cast<const char*>(impName->Name);
                while (*fnName) {
                    importHash = _rotl(importHash, 7) ^ *fnName;
                    fnName++;
                }
            }
        }
    }

    static DWORD originalHash = 0;
    if (originalHash == 0) {
        originalHash = importHash;
        return false;
    }

    return importHash != originalHash;
}

bool AntiPatch::checkBreakpointPatches() {
    for (const auto& [fn, original] : g_instance->m_originalApiBytes) {
        const BYTE* current = reinterpret_cast<const BYTE*>(fn);
        for (size_t i = 0; i < original.size(); i++) {
            if (current[i] == 0xCC)
                return true;
        }
    }
    return false;
}

bool AntiPatch::checkApiHooks() {
    for (const auto& [fn, original] : g_instance->m_originalApiBytes) {
        const BYTE* current = reinterpret_cast<const BYTE*>(fn);

        if (current[0] == 0xE9 || current[0] == 0xEB)
            return true;

        if (current[0] == 0xFF && (current[1] == 0x25 || current[1] == 0x15))
            return true;

        if (current[0] == 0x68 && current[5] == 0xC3)
            return true;

        bool bytesMatch = true;
        for (size_t i = 0; i < original.size(); i++) {
            if (current[i] != original[i]) {
                bytesMatch = false;
                break;
            }
        }
        if (!bytesMatch) {
            bool isPrologue = (current[0] == 0x48 && current[1] == 0x89 &&
                             current[2] == 0x5C && current[3] == 0x24);
            if (!isPrologue)
                return true;
        }
    }
    return false;
}

void AntiPatch::restorePatchedBytes() {
    for (const auto& [fn, original] : m_originalApiBytes) {
        DWORD oldProtect = 0;
        if (VirtualProtect(reinterpret_cast<LPVOID>(fn), original.size(),
                           PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(reinterpret_cast<LPVOID>(fn),
                   original.data(), original.size());
            VirtualProtect(reinterpret_cast<LPVOID>(fn), original.size(),
                           oldProtect, &oldProtect);
        }
    }
}

void initializeAntiPatch() {
    if (!g_instance) {
        g_instance = new AntiPatch();
        g_instance->start();
    }
}

void shutdownAntiPatch() {
    if (g_instance) {
        g_instance->stop();
        delete g_instance;
        g_instance = nullptr;
    }
}

}
