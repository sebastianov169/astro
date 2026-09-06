#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable: 4996)
#include <cstdio>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#include "anti_frida.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <algorithm>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
#include "security/crypto/string_encrypt.h"
#include "security/crypto/obfuscation.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "ws2_32.lib")

namespace security {

static AntiFrida* g_instance = nullptr;

AntiFrida::AntiFrida() = default;

AntiFrida::~AntiFrida() {
    stop();
}

static void afTrace(const char* s) {
    FILE* f = fopen((std::string(getenv("TEMP") ? getenv("TEMP") : ".") + "\\astro_af_trace.log").c_str(), "a");
    if (f) { fprintf(f, "%s\n", s); fclose(f); }
}
void AntiFrida::start() {
    if (m_running.exchange(true))
        return;
    afTrace("start-begin");
    captureTextHash();
    afTrace("capture-ok");
    // BISECT: monitor thread disabled
    // m_monitorThread = std::thread(&AntiFrida::monitorLoop, this);
    afTrace("thread-spawned");
}

void AntiFrida::stop() {
    if (!m_running.exchange(false))
        return;

    if (m_monitorThread.joinable())
        m_monitorThread.join();
}

void AntiFrida::setDetectionCallback(DetectionCallback cb) {
    m_callback = std::move(cb);
}

bool AntiFrida::isDetected() const {
    // Deteccion de ACTIVIDAD (no de instalacion): frida inyectado en este proceso
    // o su server escuchando en loopback. Los checks de threads/pipes/api son los
    // que daban falsos positivos con herramientas instaladas pero no activas.
    return checkModuleNames() || checkFridaPorts() || checkFridaNamedPipes();
}

void AntiFrida::onDetection(const char* reason) {
    // Produccion: frida inyectado = intercepcion activa => kill siempre.
    // El rastro queda para el operador.
    FILE* f = fopen((std::string(getenv("TEMP") ? getenv("TEMP") : ".") + "\\astro_frida_detect.log").c_str(), "a");
    if (f) { fprintf(f, "frida-check: %s\n", reason); fclose(f); }
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
}

void AntiFrida::monitorLoop() {
    Sleep(1000); // let startup settle before first sweep
    while (m_running) {
        if (isDetected()) {
            onDetection("anti_frida_detected");
            return;
        }
        Sleep(CHECK_INTERVAL_MS);
    }
}

bool AntiFrida::checkModuleNames() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    bool found = false;
    const wchar_t* blocked[] = {
        L"frida-agent",
        L"frida-gadget",
        L"frida-server",
        L"frida-inject",
        L"frida-helper",
        L"x64dbg",
        L"x32dbg",
        L"scylla_hide",
        L"ScyllaHide",
        L"TitanHide",
        L"titan",
        L"frida",
        L"x64dbg.dll",
        L"scylla",
        nullptr
    };

    if (Module32FirstW(snap, &me)) {
        do {
            for (int i = 0; blocked[i]; i++) {
                if (wcsstr(me.szModule, blocked[i])) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return found;
}

bool AntiFrida::scanForFridaMagic() {
    constexpr BYTE MAGIC[] = { 0x64, 0x72, 0x65, 0x65, 0x64 };
    constexpr size_t MAGIC_LEN = sizeof(MAGIC);

    MODULEINFO modInfo{};
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return false;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
        return false;

    const BYTE* base = reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll);
    MEMORY_BASIC_INFORMATION mbi{};

    for (BYTE* addr = const_cast<BYTE*>(base);
         addr < base + modInfo.SizeOfImage;
         addr += mbi.RegionSize ? mbi.RegionSize : 0x1000) {

        if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
            break;
        if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            continue;
        if (mbi.State != MEM_COMMIT)
            continue;

        // SECURITY FIX: old bound math compared absolute vs region-relative addresses and
        // could read past committed memory (AV in monitor thread = silent process death).
        const BYTE* regionStart = static_cast<const BYTE*>(mbi.BaseAddress);
        const BYTE* regionEnd = regionStart + mbi.RegionSize;
        const BYTE* limit = (base + modInfo.SizeOfImage < regionEnd)
                                ? base + modInfo.SizeOfImage : regionEnd;

        for (const BYTE* p = regionStart; p + MAGIC_LEN <= limit; ++p) {
            if (memcmp(p, MAGIC, MAGIC_LEN) == 0)
                return true;
        }
    }
    return false;
}

bool AntiFrida::checkFridaThreads() {
    const wchar_t* fridaThreadNames[] = {
        L"gmain", L"gdbus", L"gum-js-loop",
        L"gum-js-thread", L"pool-frida", L"frida",
        nullptr
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD currentPid = GetCurrentProcessId();

    bool found = false;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid)
                continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread)
                continue;

            wchar_t name[64]{};
            DWORD nameLen = 64;
            typedef LONG(WINAPI* RtlGetThreadDescription_t)(HANDLE, PWSTR*, USHORT*);
            static auto RtlGetThreadDesc = reinterpret_cast<RtlGetThreadDescription_t>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetThreadDescription"));

            if (RtlGetThreadDesc) {
                USHORT len = 0;
                PWSTR desc = nullptr;
                if (RtlGetThreadDesc(hThread, &desc, &len) >= 0 && desc && len > 0) {
                    for (int i = 0; fridaThreadNames[i]; i++) {
                        if (_wcsnicmp(desc, fridaThreadNames[i], len) == 0) {
                            found = true;
                            break;
                        }
                    }
                }
            }

            CloseHandle(hThread);
            if (found) break;
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return found;
}

bool AntiFrida::scanForFridaHooks() {
    const char* apis[] = { "NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory" };
    for (const char* name : apis) {
        FARPROC fn = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name);
        if (!fn) continue;

        const BYTE* p = reinterpret_cast<const BYTE*>(fn);
        if (p[0] == 0xE9 || p[0] == 0xFF && p[1] == 0x25)
            return true;
    }
    return false;
}

bool AntiFrida::checkFridaPorts() {
    constexpr u_short ports[] = { 27042, 27043 };
    for (u_short port : ports) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(port); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        u_long mode=1; ioctlsocket(s,FIONBIO,&mode);
        int result=connect(s,reinterpret_cast<sockaddr*>(&addr),sizeof(addr));
        if(result==0){
            char probe[]="FRIDA_PROBE"; send(s,probe,sizeof(probe),0);
            char buf[32]={0}; fd_set rs; FD_ZERO(&rs); FD_SET(s,&rs); timeval tv{0,200000};
            int sel=select(0,&rs,nullptr,nullptr,&tv);
            bool isReal=false;
            if(sel>0){
                int rec=recv(s,buf,sizeof(buf),0);
                if(rec>=0) isReal=true;
            } else {
                SOCKET tb=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
                if(tb!=INVALID_SOCKET){
                    sockaddr_in ta{}; ta.sin_family=AF_INET; ta.sin_port=htons(port); ta.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
                    int br=bind(tb,reinterpret_cast<sockaddr*>(&ta),sizeof(ta));
                    if(br==0) isReal=false; else isReal=true;
                    closesocket(tb);
                } else isReal=true;
            }
            closesocket(s);
            if(isReal) return true;
            continue;
        }
        int err=WSAGetLastError();
        if(err==WSAEWOULDBLOCK || err==WSAEINPROGRESS || err==WSAEALREADY){
            fd_set ws; FD_ZERO(&ws); FD_SET(s,&ws); timeval tv{0,200000};
            int sel=select(0,nullptr,&ws,nullptr,&tv);
            if(sel>0 && FD_ISSET(s,&ws)){
                int soErr=0; int len=sizeof(soErr); getsockopt(s,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&soErr),&len);
                if(soErr==0){
                    SOCKET tb=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
                    bool isReal=false;
                    if(tb!=INVALID_SOCKET){
                        sockaddr_in ta{}; ta.sin_family=AF_INET; ta.sin_port=htons(port); ta.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
                        int br=bind(tb,reinterpret_cast<sockaddr*>(&ta),sizeof(ta));
                        if(br!=0 && WSAGetLastError()==WSAEADDRINUSE) isReal=true;
                        else if(br==0) isReal=false;
                        else isReal=true;
                        closesocket(tb);
                    } else isReal=true;
                    if(isReal){ closesocket(s); return true; }
                }
            }
            closesocket(s);
            continue;
        }
        if(err==WSAEISCONN){ closesocket(s); return true; }
        closesocket(s);
    }
    return false;
}

bool AntiFrida::checkFridaNamedPipes() {
    const wchar_t* pipes[] = {
        L"\\\\.\\pipe\\frida",
        L"\\\\.\\pipe\\gum-js",
        L"\\\\.\\pipe\\frida-agent",
        nullptr
    };
    for (int i = 0; pipes[i]; i++) {
        HANDLE h = CreateFileW(pipes[i], GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
        if (GetLastError() == ERROR_PIPE_BUSY) {
            return true;
        }
        if (WaitNamedPipeW(pipes[i], 0) != 0) {
            return true;
        }
    }
    return false;
}

bool AntiFrida::checkToolModules() {
    const wchar_t* toolModules[] = {
        L"x64dbg.dll", L"x32dbg.dll", L"x64dbg",
        L"scylla_hide.dll", L"ScyllaHide.dll", L"scylla",
        L"TitanHide.dll", L"TitanHide.sys", L"TitanHide",
        L"frida-agent.dll", L"frida-gadget.dll", L"frida-helper",
        L"ollydbg", L"ida", L"ghidra",
        nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            for (int i = 0; toolModules[i]; i++) {
                if (wcsstr(me.szModule, toolModules[i]) || _wcsicmp(me.szModule, toolModules[i]) == 0) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

bool AntiFrida::checkScyllaHide() {
    const wchar_t* scyllaDlls[] = {
        L"ScyllaHide.dll", L"scylla_hide.dll", L"ScyllaHideX64dbg.dll",
        L"ScyllaHideOlly.dll", L"HookLibraryx64.dll", L"HookLibraryx86.dll",
        L"TitanHide.dll", nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                for (int i = 0; scyllaDlls[i]; i++) {
                    if (_wcsicmp(me.szModule, scyllaDlls[i]) == 0 || wcsstr(me.szModule, scyllaDlls[i])) {
                        CloseHandle(snap);
                        return true;
                    }
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    FARPROC pNtSetInformationThread = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    if (pNtSetInformationThread) {
        const BYTE* p = reinterpret_cast<const BYTE*>(pNtSetInformationThread);
        if (p[0] == 0xE9 || p[0] == 0xEB || (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0x15)) || p[0] == 0xCC) {
            return true;
        }
    }
    return false;
}

bool AntiFrida::checkModuleIntegrity() {
    const wchar_t* criticalDlls[] = {
        L"kernel32.dll", L"ntdll.dll", L"user32.dll",
        L"ws2_32.dll", L"advapi32.dll",
        nullptr
    };

    for (int i = 0; criticalDlls[i]; i++) {
        HMODULE hMod = GetModuleHandleW(criticalDlls[i]);
        if (!hMod) continue;

        MODULEINFO modInfo{};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
            continue;

        const BYTE* base = reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll);
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(
            const_cast<BYTE*>(base));
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return true;

        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
            const_cast<BYTE*>(base) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return true;

        WORD numSections = nt->FileHeader.NumberOfSections;
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

        for (WORD j = 0; j < numSections; j++) {
            if (sec[j].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                DWORD checksum = 0;
                const BYTE* data = base + sec[j].VirtualAddress;
                for (DWORD k = 0; k < sec[j].Misc.VirtualSize; k++)
                    checksum = _rotr(checksum, 13) ^ data[k];

                if (checksum == 0)
                    return true;
            }
        }
    }
    return false;
}

bool AntiFrida::checkApiIntegrity() {
    // FALSE POSITIVE FIX: single hooked ntdll API is common with AV/VPN/proxy software
    // (HTTP Debugger, UrbanVPN etc). Require >=2 hooked critical APIs to flag.
    const char* criticalApis[] = {
        "NtCreateFile", "NtReadFile", "NtWriteFile",
        "NtOpenProcess", "NtAllocateVirtualMemory",
        nullptr
    };

    int hooked = 0;
    for (const char* name : criticalApis) {
        FARPROC fn = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name);
        if (!fn) continue;

        const BYTE* p = reinterpret_cast<const BYTE*>(fn);
        if (p[0] == 0xE9 || p[0] == 0xEB)
            hooked++;
        else if (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0x15))
            hooked++;
        else if (p[0] == 0x68)
            hooked++;
    }
    return hooked >= 2;   // one hook = likely AV/VPN software, not frida
}

bool AntiFrida::checkSelfIntegrity() {
    if (!g_instance || g_instance->m_originalTextSection.empty())
        return false;

    MODULEINFO modInfo{};
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return false;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
        return false;

    const BYTE* base = reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll);
    const BYTE* text = base + g_instance->m_textSectionRva;

    for (DWORD i = 0; i < g_instance->m_textSectionSize; i++) {
        if (text[i] != g_instance->m_originalTextSection[i])
            return true;
    }
    return false;
}

void AntiFrida::captureTextHash() {
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
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            m_textSectionRva = sec[i].VirtualAddress;
            m_textSectionSize = sec[i].Misc.VirtualSize;

            const BYTE* text = base + m_textSectionRva;
            m_originalTextSection.assign(text, text + m_textSectionSize);
            break;
        }
    }
}

void initializeAntiFrida() {
    if (!g_instance) {
        g_instance = new AntiFrida();
        g_instance->start();
    }
}

void shutdownAntiFrida() {
    if (g_instance) {
        g_instance->stop();
        delete g_instance;
        g_instance = nullptr;
    }
}

}
