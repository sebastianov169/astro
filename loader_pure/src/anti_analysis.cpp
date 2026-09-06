#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winhttp.h>
#include <intrin.h>
#include <cstring>
#include <vector>
#include <string>
#include "anti_analysis.h"
#include "legal_poison.h"
#include "obfuscation_map.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winhttp.lib")

namespace antidebug {

static volatile uint32_t g_sink = 0;

__declspec(noinline) static void junk() noexcept {
    volatile uint64_t v = __rdtsc();
    v = (v * 0xBF58476D1CE4E5B9ULL) ^ (v >> 27);
    v *= 0x94D049BB133111EBULL;
    v ^= (v >> 31);
    g_sink = static_cast<uint32_t>(v);
    LOADER_AI_TRAP();
}

bool check_is_debugger_present() {
    junk();
    typedef BOOL(WINAPI* pIsDebuggerPresent)();
    auto fn = reinterpret_cast<pIsDebuggerPresent>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsDebuggerPresent"));
    if (fn && fn() != FALSE) {
        return true;
    }
    typedef BOOL(WINAPI* pCheckRemote)(HANDLE, PBOOL);
    auto fn2 = reinterpret_cast<pCheckRemote>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CheckRemoteDebuggerPresent"));
    if (fn2) {
        BOOL isDebugger = FALSE;
        fn2(GetCurrentProcess(), &isDebugger);
        if (isDebugger != FALSE) {
            return true;
        }
    }
    return false;
}

bool check_remote_debugger_present() {
    junk();
    typedef BOOL(WINAPI* pCheckRemote)(HANDLE, PBOOL);
    auto fn = reinterpret_cast<pCheckRemote>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CheckRemoteDebuggerPresent"));
    if (fn) {
        BOOL isDebugger = FALSE;
        fn(GetCurrentProcess(), &isDebugger);
        if (isDebugger != FALSE) {
            return true;
        }
    }
    return false;
}

bool check_debug_port() {
    junk();
    typedef LONG(NTAPI* pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto fn = reinterpret_cast<pNtQIP>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (fn) {
        DWORD_PTR debugPort = 0;
        LONG status = fn(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr);
        if (status == 0 && debugPort != 0) {
            return true;
        }
        DWORD flags = 0;
        status = fn(GetCurrentProcess(), 0x1F, &flags, sizeof(flags), nullptr);
        if (status == 0 && flags == 0) {
            return true;
        }
        HANDLE objHandle = nullptr;
        status = fn(GetCurrentProcess(), 0x1E, &objHandle, sizeof(objHandle), nullptr);
        if (status == 0 && objHandle != nullptr) {
            return true;
        }
    }
    return false;
}

bool check_peb_being_debugged() {
    junk();
#ifdef _WIN64
    uint8_t* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    if (peb && peb[2] != 0) {
        return true;
    }
#else
    uint8_t* peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
    if (peb && peb[2] != 0) {
        return true;
    }
#endif
    typedef LONG(NTAPI* pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto fn = reinterpret_cast<pNtQIP>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (fn) {
        PVOID peb2 = nullptr;
        fn(GetCurrentProcess(), 0, &peb2, sizeof(peb2), nullptr);
        if (peb2 && reinterpret_cast<uint8_t*>(peb2)[2] != 0) {
            return true;
        }
    }
    return false;
}

bool check_nt_global_flag() {
    junk();
#ifdef _WIN64
    uint8_t* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    if (peb) {
        uint32_t ntGlobalFlag = *reinterpret_cast<uint32_t*>(peb + 0xBC);
        if ((ntGlobalFlag & 0x70) != 0) {
            return true;
        }
        uint32_t ntGlobalFlag2 = *reinterpret_cast<uint32_t*>(peb + 0x68);
        if ((ntGlobalFlag2 & 0x70) != 0) {
            return true;
        }
    }
#else
    uint8_t* peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
    if (peb) {
        uint32_t ntGlobalFlag = *reinterpret_cast<uint32_t*>(peb + 0x68);
        if ((ntGlobalFlag & 0x70) != 0) {
            return true;
        }
    }
#endif
    return false;
}

bool check_hw_breakpoints() {
    junk();
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
        if (ctx.Dr6 != 0 || ctx.Dr7 != 0) {
            return true;
        }
    }
    return false;
}

bool check_timing() {
    junk();
    uint64_t start = __rdtsc();
    volatile uint64_t sink = 0;
    for (int i = 0; i < 1000; ++i) sink += static_cast<uint64_t>(i);
    uint64_t end = __rdtsc();
    uint64_t delta = end - start;
    if (delta > 5000000) {   // ofuscacion Hikari ralentiza loops legitimos; single-step real agrega ordenes de magnitud mas
        return true;
    }
    LARGE_INTEGER freq{}, t1{}, t2{};
    if (QueryPerformanceFrequency(&freq) && freq.QuadPart != 0) {
        QueryPerformanceCounter(&t1);
        volatile uint64_t s2 = 0;
        for (int i = 0; i < 1000; ++i) s2 += static_cast<uint64_t>(i);
        (void)s2;
        QueryPerformanceCounter(&t2);
        LONGLONG elapsed = t2.QuadPart - t1.QuadPart;
        double ms = static_cast<double>(elapsed) * 1000.0 / static_cast<double>(freq.QuadPart);
        if (ms > 500.0) {  // idem: umbral relajado para builds ofuscadas
            return true;
        }
    }
    LARGE_INTEGER s{}, e{};
    if (QueryPerformanceFrequency(&freq)) {
        QueryPerformanceCounter(&s);
        Sleep(10);
        QueryPerformanceCounter(&e);
        double elapsed = static_cast<double>(e.QuadPart - s.QuadPart) * 1000.0 / static_cast<double>(freq.QuadPart);
        if (elapsed > 100.0 || elapsed < 5.0) {
            return true;
        }
    }
    return false;
}

bool check_tool_modules() {
    junk();
    static const wchar_t* tool_names[] = {
        L"x64dbg.dll", L"x64dbg", L"x32dbg.dll", L"x32dbg",
        L"ollydbg.dll", L"ollydbg",
        L"scylla_hide.dll", L"ScyllaHide.dll", L"scylla",
        L"ScyllaHideX64dbg.dll", L"ScyllaHideOlly.dll",
        L"TitanHide.dll", L"TitanHide.sys", L"TitanHide",
        L"frida-agent.dll", L"frida-agent",
        L"frida-gadget.dll", L"frida-gadget",
        L"frida-helper.dll", L"frida-helper",
        L"frida-server", L"HookLibraryx64.dll", L"HookLibraryx86.dll",
        L"ida.dll", L"ida64.dll", L"ghidra",
        L"cheatengine", L"processhacker",
        L"wireshark", L"fiddler", L"procmon",
        nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            for (int i = 0; tool_names[i] != nullptr; ++i) {
                if (wcsstr(me.szModule, tool_names[i]) != nullptr || _wcsicmp(me.szModule, tool_names[i]) == 0) {
                    found = true;
                    break;
                }
                size_t modLen = wcslen(me.szModule);
                size_t patLen = wcslen(tool_names[i]);
                if (modLen >= patLen) {
                    wchar_t modLower[260]{}, patLower[260]{};
                    for (size_t a = 0; a < modLen && a < 259; ++a) modLower[a] = towlower(me.szModule[a]);
                    for (size_t b = 0; b < patLen && b < 259; ++b) patLower[b] = towlower(tool_names[i][b]);
                    if (wcsstr(modLower, patLower) != nullptr) {
                        found = true;
                        break;
                    }
                }
            }
            if (found) break;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

bool check_frida_threads() {
    junk();
    static const char* frida_threads[] = { "gmain", "gdbus", "gum-js-loop", "gum-js-thread", "pool-frida", "frida", "gportal", nullptr };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD selfPid = GetCurrentProcessId();
    DWORD selfTid = GetCurrentThreadId();
    bool found = false;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            if (te.th32ThreadID == selfTid) continue;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (th) {
                typedef HRESULT(WINAPI* pGetThreadDesc)(HANDLE, PWSTR*);
                static auto fnGetThreadDesc = reinterpret_cast<pGetThreadDesc>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetThreadDescription"));
                if (fnGetThreadDesc) {
                    PWSTR wname = nullptr;
                    if (SUCCEEDED(fnGetThreadDesc(th, &wname)) && wname) {
                        char name[128]{};
                        WideCharToMultiByte(CP_UTF8, 0, wname, -1, name, sizeof(name), nullptr, nullptr);
                        LocalFree(wname);
                        for (int i = 0; frida_threads[i] != nullptr; ++i) {
                            if (_stricmp(name, frida_threads[i]) == 0) {
                                found = true;
                                break;
                            }
                            if (strstr(name, frida_threads[i]) != nullptr) {
                                found = true;
                                break;
                            }
                        }
                    }
                }
                CloseHandle(th);
                if (found) break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (found) return true;
    const wchar_t* fridaPipes[] = { L"\\\\.\\pipe\\frida", L"\\\\.\\pipe\\gum-js", L"\\\\.\\pipe\\frida-agent", nullptr };
    for (int i = 0; fridaPipes[i] != nullptr; ++i) {
        HANDLE h = CreateFileW(fridaPipes[i], GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
        if (GetLastError() == ERROR_PIPE_BUSY) {
            return true;
        }
        if (WaitNamedPipeW(fridaPipes[i], 0) != 0) {
            return true;
        }
    }
    return false;
}

bool check_frida_ports() {
    junk();
    static const uint16_t ports[] = { 27042, 27043, 0 };
    WSADATA wsa{}; bool needCleanup=false; if(WSAStartup(MAKEWORD(2,2),&wsa)==0) needCleanup=true;
    bool detected=false;
    for(int idx=0; ports[idx]!=0; ++idx){
        uint16_t port=ports[idx];
        SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(s==INVALID_SOCKET) continue;
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(port); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        u_long mode=1; ioctlsocket(s,FIONBIO,&mode);
        int result=connect(s,reinterpret_cast<sockaddr*>(&addr),sizeof(addr));
        if(result==0){
            char probe[]="FRIDA_PROBE";
            send(s,probe,sizeof(probe),0);
            char buf[32]={0}; fd_set rs; FD_ZERO(&rs); FD_SET(s,&rs); timeval tv{0,200000};
            int sel=select(0,&rs,nullptr,nullptr,&tv);
            if(sel>0){
                int rec=recv(s,buf,sizeof(buf),0);
                if(rec>0 || rec==0){ detected=true; }
            } else {
                SOCKET testBind=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
                if(testBind!=INVALID_SOCKET){
                    sockaddr_in testAddr{}; testAddr.sin_family=AF_INET; testAddr.sin_port=htons(port); testAddr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
                    int bindRes=bind(testBind,reinterpret_cast<sockaddr*>(&testAddr),sizeof(testAddr));
                    if(bindRes==0){ detected=false; } else { detected=true; }
                    closesocket(testBind);
                }
            }
            closesocket(s);
            if(detected) break;
            continue;
        }
        int err=WSAGetLastError();
        if(err==WSAEWOULDBLOCK || err==WSAEINPROGRESS || err==WSAEALREADY){
            fd_set ws; FD_ZERO(&ws); FD_SET(s,&ws); timeval tv{0,200000};
            int sel=select(0,nullptr,&ws,nullptr,&tv);
            if(sel>0 && FD_ISSET(s,&ws)){
                int soErr=0; int len=sizeof(soErr); getsockopt(s,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&soErr),&len);
                if(soErr==0){
                    SOCKET testBind=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
                    bool isReal=false;
                    if(testBind!=INVALID_SOCKET){
                        sockaddr_in testAddr{}; testAddr.sin_family=AF_INET; testAddr.sin_port=htons(port); testAddr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
                        int bindRes=bind(testBind,reinterpret_cast<sockaddr*>(&testAddr),sizeof(testAddr));
                        if(bindRes!=0 && WSAGetLastError()==WSAEADDRINUSE) isReal=true;
                        else if(bindRes==0) isReal=false;
                        else isReal=true;
                        closesocket(testBind);
                    } else isReal=true;
                    if(isReal) detected=true;
                }
            }
            closesocket(s);
            if(detected) break;
            continue;
        }
        if(err==WSAEISCONN){ closesocket(s); detected=true; break; }
        closesocket(s);
    }
    if(needCleanup) WSACleanup();
    return detected;
}

uint64_t compute_text_hash() {
    junk();
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (hMod == nullptr) return 0;
    uint8_t* base = reinterpret_cast<uint8_t*>(hMod);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            uint64_t hash = 0xCBF29CE484222325ULL;
            for (size_t j = 0; j < size; ++j) {
                hash ^= text[j];
                hash *= 0x100000001B3ULL;
            }
            return hash;
        }
    }
    MODULEINFO modInfo{};
    if (GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) {
        uint8_t* mbase = reinterpret_cast<uint8_t*>(modInfo.lpBaseOfDll);
        size_t msize = modInfo.SizeOfImage;
        uint64_t hash = 0xCBF29CE484222325ULL;
        for (size_t j = 0; j < msize && j < 4096; ++j) {
            hash ^= mbase[j];
            hash *= 0x100000001B3ULL;
        }
        return hash;
    }
    return 0;
}

bool check_module_integrity() {
    static uint64_t expected = 0;
    static bool captured = false;
    uint64_t current = compute_text_hash();
    if (current == 0) return false;
    if (captured == false) {
        expected = current;
        captured = true;
        return false;
    }
    return current != expected;
}

bool verify_text_hash(uint64_t expected) {
    return compute_text_hash() == expected;
}

bool check_scyllahide() {
    junk();
    static const wchar_t* scylla_dlls[] = {
        L"ScyllaHide.dll", L"scylla_hide.dll",
        L"ScyllaHideX64dbg.dll", L"ScyllaHideOlly.dll",
        L"HookLibraryx64.dll", L"HookLibraryx86.dll",
        L"TitanHide.dll", L"TitanHide.sys", nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                for (int i = 0; scylla_dlls[i] != nullptr; ++i) {
                    if (_wcsicmp(me.szModule, scylla_dlls[i]) == 0 || wcsstr(me.szModule, scylla_dlls[i]) != nullptr) {
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
        if (p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25) {
            return true;
        }
    }
    FARPROC pNtQueryInformationProcess = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess) {
        const BYTE* p = reinterpret_cast<const BYTE*>(pNtQueryInformationProcess);
        if (p[0] == 0xE9 || p[0] == 0xEB || p[0] == 0xCC) {
            return true;
        }
    }
#ifdef _WIN64
    uint8_t* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
#else
    uint8_t* peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
#endif
    if (peb) {
        PVOID ldr = *reinterpret_cast<PVOID*>(peb + 0x18);
        if (ldr) {
            LIST_ENTRY* head = reinterpret_cast<LIST_ENTRY*>(reinterpret_cast<uint8_t*>(ldr) + 0x10);
            if (head && head->Flink && head->Blink) {
                int count = 0;
                for (LIST_ENTRY* cur = head->Flink; cur != head && count < 256; cur = cur->Flink, ++count) {
                    if (cur->Flink == nullptr || cur->Blink == nullptr) {
                        return true;
                    }
                    void* dllBase = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(cur) + 0x30);
                    if (dllBase == nullptr) {
                        return true;
                    }
                }
                if (count == 0) return true;
            }
        }
    }
    return false;
}

bool check_module_integrity_wrapper() {
    return check_module_integrity();
}

uint32_t run_all_checks(bool autokill) {
    uint32_t result = DETECT_NONE;
    junk();    if (check_is_debugger_present()) result |= DETECT_DEBUGGER;    if (check_remote_debugger_present()) result |= DETECT_REMOTE_DEBUGGER;    if (check_debug_port()) result |= DETECT_DEBUG_PORT;    if (check_peb_being_debugged()) result |= DETECT_PEB_DEBUG;    if (check_nt_global_flag()) result |= DETECT_NT_GLOBAL_FLAG;    if (check_hw_breakpoints()) result |= DETECT_HW_BREAKPOINTS;    if (check_timing()) result |= DETECT_TIMING;    if (check_tool_modules()) result |= DETECT_TOOL_MODULE;    if (check_frida_threads()) result |= DETECT_FRIDA_THREAD;    if (check_frida_ports()) result |= DETECT_FRIDA_PORT;    if (check_module_integrity()) result |= DETECT_MODULE_INTEGRITY;    if (check_scyllahide()) result |= DETECT_SCYLLAHIDE;
    if (autokill && result != DETECT_NONE) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
    }
    return result;
}

}
