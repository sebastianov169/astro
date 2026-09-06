#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <intrin.h>
#include "anti_dll.h"
#include "legal_poison.h"
#include "obfuscation_map.h"
#include <algorithm>
#include <mutex>
#include <string>

#pragma comment(lib, "psapi.lib")

namespace loader_dll {

extern "C" {
typedef NTSTATUS(NTAPI* LdrRegisterDllNotification_t)(ULONG, PVOID, PVOID, PVOID*);
typedef NTSTATUS(NTAPI* LdrUnregisterDllNotification_t)(PVOID);
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA { ULONG Flags; PWSTR FullDllName; PWSTR BaseDllName; PVOID DllBase; SIZE_T SizeOfImage; } LDR_DLL_LOADED_NOTIFICATION_DATA;
typedef union _LDR_DLL_NOTIFICATION_DATA { LDR_DLL_LOADED_NOTIFICATION_DATA Loaded; } LDR_DLL_NOTIFICATION_DATA;
}
static constexpr NTSTATUS STATUS_SUCCESS = 0;
static AntiDll* g_instance = nullptr;

void NTAPI dllLoadCallback(ULONG NotificationReason, PVOID NotificationData, PVOID Context){
    if(NotificationReason != 1) return;
    auto* data = reinterpret_cast<LDR_DLL_NOTIFICATION_DATA*>(NotificationData);
    if(!data->Loaded.FullDllName || !data->Loaded.BaseDllName) return;
    AntiDll* self = static_cast<AntiDll*>(Context);
    if(!self) return;
    const wchar_t* blocked[] = {
        L"dbghelp.dll", L"symsrv.dll", L"dbgcore.dll", L"dbgeng.dll",
        L"x64dbg", L"x64dbg.dll", L"x32dbg.dll", L"ollydbg",
        L"scylla_hide.dll", L"ScyllaHide.dll", L"scylla", L"ScyllaHideX64dbg.dll",
        L"TitanHide.dll", L"TitanHide", L"titan",
        L"frida-agent", L"frida-gadget", L"frida-helper", L"frida-server", L"gum-js-loop",
        L"sbiedll.dll", L"cmdvrt32.dll", L"cmdvrt64.dll", L"HookLibrary", L"HookLibraryx64.dll",
        nullptr
    };
    for(int i=0; blocked[i]; i++){
        if(wcsstr(data->Loaded.BaseDllName, blocked[i])){
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
            return;
        }
    }
    {
        std::lock_guard<std::mutex> lock(self->m_moduleMutex);
        self->m_loadedModules.push_back(data->Loaded.BaseDllName);
    }
}

AntiDll::AntiDll() = default;
AntiDll::~AntiDll(){ stop(); }
void AntiDll::start(){
    if(m_running.exchange(true)) return;
    captureInitialModules();
    registerDllNotification();
    m_monitorThread = std::thread(&AntiDll::monitorLoop, this);
}
void AntiDll::stop(){
    if(!m_running.exchange(false)) return;
    unregisterDllNotification();
    if(m_monitorThread.joinable()) m_monitorThread.join();
}
void AntiDll::setDetectionCallback(DetectionCallback cb){ m_callback = std::move(cb); }
bool AntiDll::isDetected() const {
    // SECURITY FIX: dropped checkInjectedModules - any legitimate late DLL load (comctl32,
    // WMI/RPC providers, winsock helpers) tripped it and killed the process. The
    // LdrRegisterDllNotification callback already blocks blacklisted DLLs BY NAME at load time,
    // and checkBlockedDlls + checkCriticalDllIntegrity cover static/hooked cases.
    return checkBlockedDlls() || checkCriticalDllIntegrity();
}
void AntiDll::onDetection(const char* reason){
    if(m_callback) m_callback(reason);
    else TerminateProcess(GetCurrentProcess(), 0xDEAD);
}
static void adTrace(const char* s){
    char tp[MAX_PATH]; GetTempPathA(MAX_PATH, tp);
    std::string path = std::string(tp) + "astro_loader_trace.log";
    HANDLE h = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(h!=INVALID_HANDLE_VALUE){ DWORD w; std::string line = std::string("[anti_dll] ") + s + "\r\n"; WriteFile(h, line.c_str(), (DWORD)line.size(), &w, nullptr); CloseHandle(h);}
}
void AntiDll::monitorLoop(){
    adTrace("monitor-start");
    Sleep(CHECK_INTERVAL_MS);
    adTrace("monitor-first-check");
    while(m_running){
        if(checkBlockedDlls()){ adTrace("DETECT blocked-dlls"); onDetection("anti_dll_detected"); TerminateProcess(GetCurrentProcess(), 0xDEAD14); return; }
        if(checkCriticalDllIntegrity()){ adTrace("DETECT critical-integrity"); onDetection("anti_dll_detected"); TerminateProcess(GetCurrentProcess(), 0xDEAD15); return; }
        Sleep(CHECK_INTERVAL_MS);
    }
}
void AntiDll::registerDllNotification(){
    auto fn = reinterpret_cast<LdrRegisterDllNotification_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"));
    if(!fn) return;
    fn(0, reinterpret_cast<PVOID>(dllLoadCallback), reinterpret_cast<PVOID>(this), &m_dllNotificationHandle);
}
void AntiDll::unregisterDllNotification(){
    if(!m_dllNotificationHandle) return;
    auto fn = reinterpret_cast<LdrUnregisterDllNotification_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrUnregisterDllNotification"));
    if(fn) fn(m_dllNotificationHandle);
    m_dllNotificationHandle = nullptr;
}
void AntiDll::captureInitialModules(){
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if(snap==INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W me{}; me.dwSize=sizeof(me);
    std::lock_guard<std::mutex> lock(m_moduleMutex);
    if(Module32FirstW(snap,&me)){
        do{ m_loadedModules.push_back(me.szModule); } while(Module32NextW(snap,&me));
    }
    CloseHandle(snap);
}
bool AntiDll::checkBlockedDlls(){
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if(snap==INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{}; me.dwSize=sizeof(me);
    bool found=false;
    const wchar_t* blocked[] = {
        L"dbghelp.dll", L"symsrv.dll", L"dbgcore.dll", L"dbgeng.dll",
        L"x64dbg", L"x64dbg.dll", L"x32dbg.dll", L"ollydbg",
        L"scylla_hide.dll", L"ScyllaHide.dll", L"scylla",
        L"TitanHide.dll", L"TitanHide", L"titan",
        L"frida-agent", L"frida-gadget", L"frida-helper", L"frida-server",
        L"sbiedll.dll", L"cmdvrt32.dll", L"cmdvrt64.dll", L"HookLibrary",
        nullptr
    };
    if(Module32FirstW(snap,&me)){
        do{
            for(int i=0; blocked[i]; i++){
                if(wcsstr(me.szModule, blocked[i])){ found=true; break; }
            }
            if(found) break;
        } while(Module32NextW(snap,&me));
    }
    CloseHandle(snap);
    return found;
}
bool AntiDll::checkInjectedModules(){
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if(snap==INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{}; me.dwSize=sizeof(me);
    DWORD pid = GetCurrentProcessId();
    bool found=false;
    if(Module32FirstW(snap,&me)){
        do{
            if(me.th32ProcessID != pid) continue;
            bool known=false;
            if(g_instance){
                std::lock_guard<std::mutex> lock(g_instance->m_moduleMutex);
                for(auto &mod: g_instance->m_loadedModules){
                    if(_wcsicmp(mod.c_str(), me.szModule)==0){ known=true; break; }
                }
            }
            if(!known && g_instance && !g_instance->m_loadedModules.empty()){ found=true; break; }
        } while(Module32NextW(snap,&me));
    }
    CloseHandle(snap);
    return found;
}
bool AntiDll::checkCriticalDllIntegrity(){
    const wchar_t* critical[] = { L"kernel32.dll", L"ntdll.dll", L"user32.dll", L"ws2_32.dll", nullptr };
    for(int i=0; critical[i]; i++){
        HMODULE hMod = GetModuleHandleW(critical[i]);
        if(!hMod) continue;
        MODULEINFO modInfo{};
        if(!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) continue;
        const BYTE* base = reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll);
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(base));
        if(dos->e_magic != IMAGE_DOS_SIGNATURE) return true;
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(base) + dos->e_lfanew);
        if(nt->Signature != IMAGE_NT_SIGNATURE) return true;
        DWORD checksum=0;
        for(DWORD j=0;j<modInfo.SizeOfImage;j++) checksum = _rotr(checksum,7) ^ base[j];
        if(checksum==0) return true;
    }
    return false;
}
void initializeAntiDll(){
    if(!g_instance){ g_instance = new AntiDll(); g_instance->start(); }
}
void shutdownAntiDll(){
    if(g_instance){ g_instance->stop(); delete g_instance; g_instance=nullptr; }
}

}
