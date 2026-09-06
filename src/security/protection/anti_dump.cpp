#include <cstdio>
#include <string>
#include "anti_dump.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <intrin.h>
#include <random>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
#include "security/crypto/string_encrypt.h"
#include "security/crypto/obfuscation.h"
#pragma warning(disable: 4996)
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "bcrypt.lib")

namespace security {

static AntiDump* g_instance = nullptr;

AntiDump::AntiDump() {
    generateXorKey();
}

AntiDump::~AntiDump() {
    stop();
}

void AntiDump::start() {
    if (m_running.exchange(true))
        return;

    // CRITICAL FIX: erasePeHeaders()/obfuscateSectionHeaders() destroy the DOS/NT and
    // section headers of the RUNNING image. The Windows loader, exception dispatcher
    // (RtlDispatchException reads the image's load config), Control Flow Guard and any
    // later LoadLibrary all need those headers intact. Zeroing them caused: deadlocked
    // DLL loads (WinHTTP/QNAM), EAGAIN thread creation, and uncatchable crashes the
    // moment anything raised an exception. Self-modification of live headers is OFF.
    // protectCriticalSections() is also disabled: with the monitor threads running it
    // contributed to WinHttpSendRequest deadlocks under LSP injection (HTTP Debugger).
    // protectCriticalSections();

    try {
        m_monitorThread = std::thread(&AntiDump::monitorLoop, this);
    } catch (...) {
        // Thread quota exhausted (LSP-injected hosts): continue without the monitor;
        // header checks are best-effort hardening, not required for correct operation.
        m_running = false;
    }
}

void AntiDump::stop() {
    if (!m_running.exchange(false))
        return;

    if (m_monitorThread.joinable())
        m_monitorThread.join();
}

void AntiDump::setDetectionCallback(DetectionCallback cb) {
    m_callback = std::move(cb);
}

void AntiDump::onDetection(const char* reason) {
    {
        char _tp[MAX_PATH]{}; GetTempPathA(MAX_PATH,_tp); std::string _lp=std::string(_tp)+"astro_kill_trace.log"; FILE* f = fopen(_lp.c_str(), "a");
        if (f) { fprintf(f, "AntiDump detection: %s\n", reason); fclose(f); }
    }
    // Headers del propio exe modificados en memoria = alguien tocando el proceso
    // (dumper/hider activo) => kill directo. Herramientas instaladas no disparan esto.
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
}

void AntiDump::monitorLoop() {
    while (m_running) {
        HMODULE hMod = GetModuleHandleA(nullptr);
        if (hMod) {
            const BYTE* base = reinterpret_cast<const BYTE*>(hMod);
            if (*base != 0x4D || *(base + 1) != 0x5A) {
                { FILE* _f = fopen((std::string(getenv("TEMP")?getenv("TEMP"):".") + "\\astro_det.log").c_str(), "a"); if (_f) { fprintf(_f, "DETECT[anti_dump]: %s\n", "anti_dump_headers_tampered"); fclose(_f); } }
                onDetection("anti_dump_headers_tampered");
                return;
            }
        }
        Sleep(CHECK_INTERVAL_MS);
    }
}

void AntiDump::erasePeHeaders() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return;

    BYTE* base = reinterpret_cast<BYTE*>(hMod);

    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(base, &mbi, sizeof(mbi));

    DWORD oldProtect = 0;
    if (VirtualProtect(base, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
        memset(base, 0, mbi.RegionSize);
        VirtualProtect(base, mbi.RegionSize, oldProtect, &oldProtect);
    }
}

void AntiDump::encryptCodeSections() {
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
            LPVOID addr = const_cast<BYTE*>(base) + sec[i].VirtualAddress;
            SIZE_T size = sec[i].Misc.VirtualSize;

            DWORD oldProtect = 0;
            if (VirtualProtect(addr, size, PAGE_READWRITE, &oldProtect)) {
                xorEncrypt(addr, size);
                m_encryptedRegions.push_back({addr, size});
                VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
            }
        }
    }
}

void AntiDump::protectCriticalSections() {
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
            LPVOID addr = const_cast<BYTE*>(base) + sec[i].VirtualAddress;
            SIZE_T size = sec[i].Misc.VirtualSize;
            DWORD oldProtect = 0;

            if (VirtualProtect(addr, size, PAGE_EXECUTE_READ, &oldProtect)) {
                m_protectedRegions.push_back(addr);
            }
        }
    }
}

void AntiDump::obfuscateSectionHeaders() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return;

    BYTE* base = reinterpret_cast<BYTE*>(hMod);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD numSec = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSec; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            DWORD oldProtect = 0;
            SIZE_T size = sizeof(IMAGE_SECTION_HEADER) * (numSec - i);
            LPVOID addr = &sec[i];

            if (VirtualProtect(addr, size, PAGE_READWRITE, &oldProtect)) {
                memset(sec[i].Name, 0, 8);
                sec[i].PointerToRawData = 0;
                sec[i].SizeOfRawData = 0;
                VirtualProtect(addr, size, oldProtect, &oldProtect);
            }
            break;
        }
    }
}

void AntiDump::generateXorKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    m_xorKey.resize(32);
    for (auto& b : m_xorKey)
        b = static_cast<BYTE>(dist(gen));
}

void AntiDump::xorEncrypt(void* data, size_t size) {
    BYTE* p = static_cast<BYTE*>(data);
    for (size_t i = 0; i < size; i++)
        p[i] ^= m_xorKey[i % m_xorKey.size()];
}

void AntiDump::encryptHeapData(void* data, size_t size) {
    if (!data || size == 0)
        return;
    xorEncrypt(data, size);
}

void AntiDump::decryptHeapData(void* data, size_t size) {
    if (!data || size == 0)
        return;
    xorEncrypt(data, size);
}

void initializeAntiDump() {
    if (!g_instance) {
        g_instance = new AntiDump();
        g_instance->start();
    }
}

void shutdownAntiDump() {
    if (g_instance) {
        g_instance->stop();
        delete g_instance;
        g_instance = nullptr;
    }
}

}
