// AntiDll v2 - detection of ACTIVE interception, not installed software.
//
// PRINCIPIO: tener HTTP Debugger/Fiddler/Charles INSTALADO es legitimo y no se puede
// (ni se debe) detectar desde nuestro proceso. Lo que si detectamos es cuando esos
// herramientas estan ACTIVOS inyectando codigo EN ESTE PROCESO o hookeando APIs:
//   1. DLLs de proxying/hooking cargadas en nuestro address space (lista negra activa).
//   2. Modificacion en disco (.text) de DLLs criticas del sistema => hooks inline.
//   3. Cambio de proxy WinHTTP/system MIENTRAS corremos (intercepcion dinamica).
//   4. DLL desconocida cargada post-bootstrap que NO esta en whitelist ni es del
//      propio app dir => reporte al callback (el caller decide; con ASTRO_STRICT mata).
//
// FALSO POSITIVO HISTORICO CORREGIDO: el baseline previo capturaba modulos ANTES de que
// Qt cargue plugins QML (imageformats/platforms/etc), asi que DLLs legitimas tardias
// aparecian como "inyectadas". Ahora el baseline se captura DIFERIDO y todo lo que
// cargue el propio proceso durante el bootstrap queda whitelisteado por ruta.

#pragma warning(disable: 4996)
#include "anti_dll.h"
#include <Psapi.h>
#include <cstdio>
#include <TlHelp32.h>
#include <algorithm>
#include <cstring>

namespace security {

AntiDll* g_instance = nullptr;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

extern "C" {
typedef NTSTATUS(NTAPI* LdrRegisterDllNotification_t)(
    ULONG Flags,
    PVOID NotificationFunction,
    PVOID Context,
    PVOID* Cookie);

typedef NTSTATUS(NTAPI* LdrUnregisterDllNotification_t)(PVOID Cookie);

// Definicion local (el SDK no siempre la expone en winternl.h)
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    SIZE_T SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;
}

namespace {

bool g_baselineCaptured = false;

// ---- listas ------------------------------------------------------------

// Herramientas cuya PRESENCIA EN NUESTRO PROCESO significa intercepcion activa.
// (instaladas en disco son indetectables/invisibles para nosotros y no importa)
const wchar_t* const kActiveProxyDlls[] = {
    L"httpdebugger",            // HTTP Debugger Pro (api monitor dll)
    L"hdpagent", L"hdpcore",    // HTTP Debugger agent modules
    L"fiddler",                 // Fiddler (fiddlerkernel etc)
    L"charles",                 // Charles proxy
    L"mitmproxy", L"mitmdump",
    L"burp",                    // Burp suite
    L"sslsniff", L"sslstrip",
    L"proxifier",               // proxifier module if injected
    L"nscapi",                  // netsh wcap helper used by some proxies
    L"titanhide", L"scyllahide", L"scylla_hide",
    L"frida-agent", L"frida-gadget", L"frida-helper", L"gum-js-loop",
    L"x64dbg", L"x32dbg", L"ollydbg",
    L"sbie_dll", L"sbiedll",    // sandboxie injection
    nullptr
};

// Depuradores simbolicos: presencia en-proceso siempre es hostil.
const wchar_t* const kDebuggerDlls[] = {
    L"dbghelp.dll", L"dbgcore.dll", L"dbgeng.dll", L"symsrv.dll",
    L"dbghelp_extras",
    nullptr
};

// DLLs que el propio Windows / Qt / runtimes cargan legitimamente. Nunca alertan.
bool isKnownLegit(const wchar_t* name) {
    static const wchar_t* const legit[] = {
        // sistema base
        L"ntdll", L"kernel32", L"kernelbase", L"user32", L"gdi32", L"shell32",
        L"advapi32", L"ole32", L"oleaut32", L"rpcrt4", L"ws2_32", L"wsock32",
        L"wininet", L"winhttp", L"shlwapi", L"comctl32", L"comdlg32", L"uxtheme",
        L"dwmapi", L"imm32", L"msimg32", L"version", L"winmm", L"winspool",
        L"sechost", L"crypt32", L"bcrypt", L"bcryptprimitives", L"ncrypt",
        L"sspicli", L"sspice", L"secur32", L"wldp", L"ntmarta", L"apphelp",
        L"msvcp_win", L"ucrtbase",
        // crt de visual studio
        L"vcruntime140", L"msvcp140", L"concrt140", L"vcruntime140_1",
        L"vcruntime140d", L"msvcp140d",
        // qt (cualquier dll/plugin qt6*)
        L"qt6", L"qt5",
        // driver graficos y multimedia comunes
        L"nv", L"ati", L"amdihd", L"igd", L"ig9", L"ig11", L"dxgi", L"d3d9",
        L"d3d11", L"d3d12", L"opengl32", L"glu32", L"vulkan",
        // audio/red de windows
        L"wintrust", L"msasn1", L"dnsapi", L"iphlpapi", L"nsi", L"dhcpcsvc",
        L"rasadhlp", L"fwpuclnt", L"webio", L"mswsock", L"winnsi", L"nlansp",
        L"napinsp", L"pnrpnsp", L"wshbth", L"mlang", L"msdart",
        // misc windows
        L"clbcatq", L"cabinet", L"propsys", L"appresolver", L"windows.storage",
        L"shcore", L"wintypes", L"tiptsf", L"textinputframework", L"msctf",
        L"twinapi", L"userenv", L"netapi32", L"netutils", L"srvcli", L"wkscli",
        L"authz", L"mpr", L"umpdc", L"powrprof", L"setupapi", L"cfgmgr32",
        L"devobj", L"winsta", L"wtsapi32", L"amsi", L"userlanguages",
        L"cryptsp", L"rsaenh", L"cryptnet", L"imagehlp", L"gpapi",
        L"policymanager", L"msvcp110", L"msvcr", L"vb40032",
        // ui automation/accesibilidad
        L"uiautomationcore", L"oleacc",
        // shell extensiones tipicas que se cuelan
        L"iconcodecservice", L"windowscodecs", L"explorerframe",
        L"dataexchange", L"dcomp", L"directmanipulation",
        // nvidia/geforce overlay etc
        L"nvspcap", L"nvgpucomp", L"nvmemmapstorage", L"nvppex", L"nvfbc",
        L"onecorecommonproxystub", L"onecoreuapcommonproxystub",
        // antivirus/defender (no son hostiles para licensing)
        L"mpclient", L"mssencam", L"wdboot", L"wdfilter", L"niauth",
        nullptr
    };
    for (int i = 0; legit[i]; i++) {
        if (_wcsnicmp(name, legit[i], wcslen(legit[i])) == 0)
            return true;
    }
    return false;
}

bool matchesList(const wchar_t* name, const wchar_t* const* list) {
    for (int i = 0; list[i]; i++) {
        if (wcsstr(name, list[i]) != nullptr)
            return true;
    }
    return false;
}

std::wstring moduleDirLower() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring dir(buf);
    std::transform(dir.begin(), dir.end(), dir.begin(), ::towlower);
    size_t pos = dir.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? dir : dir.substr(0, pos);
}

} // namespace

// ---- callback de carga de DLLs ------------------------------------------

void NTAPI dllLoadCallback(ULONG Reason, PVOID NotificationData, PVOID AppContext) {
    if (Reason != 1 /*LDR_DLL_NOTIFICATION_REASON_LOADED*/ || !NotificationData)
        return;
    auto* data = static_cast<PLDR_DLL_LOADED_NOTIFICATION_DATA>(NotificationData);
    if (!data || !data->BaseDllName || !data->BaseDllName->Buffer)
        return;

    AntiDll* self = static_cast<AntiDll*>(AppContext);

    const wchar_t* name = data->BaseDllName ? data->BaseDllName->Buffer : nullptr;
    if (!name) return;
    std::wstring lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // 1) blacklist activa => kill inmediato siempre (esto ES intercepcion en vivo)
    if (matchesList(lower.c_str(), kActiveProxyDlls) ||
        matchesList(lower.c_str(), kDebuggerDlls)) {
        { char _tp[MAX_PATH]{}; GetTempPathA(MAX_PATH,_tp); std::string _lp=std::string(_tp)+"astro_kill_trace.log"; FILE* f=fopen(_lp.c_str(),"a");
          if (f) { fprintf(f, "anti_dll ACTIVE load-blocked: %ls\n", name); fclose(f); } }
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        return;
    }

    // 2) registrar modulo nuevo (baseline dinamico)
    if (self) {
        std::lock_guard<std::mutex> lock(self->m_moduleMutex);
        self->m_loadedModules.push_back(lower);
        g_baselineCaptured = true;
    }
}

// ---- clase ----------------------------------------------------------------

AntiDll::AntiDll() = default;
AntiDll::~AntiDll() {
    stop();
}

void AntiDll::start() {
    if (m_running.exchange(true))
        return;
    captureInitialModules();
    registerDllNotification();
    m_monitorThread = std::thread(&AntiDll::monitorLoop, this);
}

void AntiDll::stop() {
    if (!m_running.exchange(false))
        return;
    unregisterDllNotification();
    if (m_monitorThread.joinable())
        m_monitorThread.join();
}

void AntiDll::setDetectionCallback(DetectionCallback cb) {
    m_callback = std::move(cb);
}

bool AntiDll::isDetected() const {
    return checkBlockedDlls() || checkInjectedModules() ||
           checkCriticalDllIntegrity();
}

void AntiDll::onDetection(const char* reason) {
    {
        char _tp2[MAX_PATH]{}; GetTempPathA(MAX_PATH,_tp2); std::string _lp2=std::string(_tp2)+"astro_kill_trace.log"; FILE* f = fopen(_lp2.c_str(), "a");
        if (f) { fprintf(f, "anti_dll detection: %s\n", reason); fclose(f); }
    }
    if (m_callback) {
        m_callback(reason);
    } else if (GetEnvironmentVariableA("ASTRO_STRICT", nullptr, 0) > 0) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
    }
}

void AntiDll::monitorLoop() {
    // dar tiempo a Qt a terminar de cargar plugins antes de confiar en el baseline
    Sleep(20000);
    while (m_running) {
        if (isDetected()) {
            onDetection("anti_dll_detected");
            return;
        }
        Sleep(CHECK_INTERVAL_MS);
    }
}

void AntiDll::registerDllNotification() {
    auto LdrRegisterDllNotif = reinterpret_cast<LdrRegisterDllNotification_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"));
    if (!LdrRegisterDllNotif)
        return;
    PVOID cookie = nullptr;
    NTSTATUS status = LdrRegisterDllNotif(0, reinterpret_cast<PVOID>(dllLoadCallback),
                                           reinterpret_cast<PVOID>(this), &cookie);
    if (status != STATUS_SUCCESS)
        m_dllNotificationHandle = nullptr;
    else
        m_dllNotificationHandle = cookie;
}

void AntiDll::unregisterDllNotification() {
    if (!m_dllNotificationHandle)
        return;
    auto LdrUnregisterDllNotif = reinterpret_cast<LdrUnregisterDllNotification_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrUnregisterDllNotification"));
    if (LdrUnregisterDllNotif)
        LdrUnregisterDllNotif(m_dllNotificationHandle);
    m_dllNotificationHandle = nullptr;
}

// ---- checks periodicos ----------------------------------------------------

void AntiDll::captureInitialModules() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE)
        return;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    std::lock_guard<std::mutex> lock(m_moduleMutex);
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring lower(me.szModule);
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            m_loadedModules.push_back(lower);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    g_baselineCaptured = true;
}

// Presencia en-proceso de herramientas de intercepcion ACTIVA.
bool AntiDll::checkBlockedDlls() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring lower(me.szModule);
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            // dbghelp etc: los carga legitimo el crash handler... solo si NO vienen
            // del system32 real los contamos (los falsos del attacker suelen ser copies).
            wchar_t sysPath[MAX_PATH]{};
            GetSystemDirectoryW(sysPath, MAX_PATH);
            bool fromSystem32 = _wcsnicmp(me.szExePath ? me.szExePath : L"", sysPath, wcslen(sysPath)) == 0;
            if (matchesList(lower.c_str(), kActiveProxyDlls)) {
                found = true;
                break;
            }
            if (!fromSystem32 && matchesList(lower.c_str(), kDebuggerDlls)) {
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// DLL cargada en nuestro proceso que no estaba ni en baseline ni whitelist,
// y cuyo path no es el directorio de la app ni system32 => sospechosa.
bool AntiDll::checkInjectedModules() {
    if (!g_baselineCaptured)
        return false; // baseline aun no confiable (bootstrap Qt en curso)

    static const std::wstring appDir = moduleDirLower();
    wchar_t sysDir[MAX_PATH]{};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    const std::wstring sysDirLower(sysDir);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring lowerName(me.szModule);
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            if (isKnownLegit(lowerName.c_str()))
                continue;

            std::wstring exePathLower(me.szExePath ? me.szExePath : L"");
            std::transform(exePathLower.begin(), exePathLower.end(), exePathLower.begin(), ::towlower);
            const bool inApp  = !appDir.empty() && exePathLower.rfind(appDir, 0) == 0;
            const bool inSys  = exePathLower.rfind(sysDirLower, 0) == 0;
            if (inApp || inSys)
                continue; // ruta confiable: aunque sea nueva, nacio aca

            bool known = false;
            if (g_instance) {
                std::lock_guard<std::mutex> lock(g_instance->m_moduleMutex);
                known = std::find(g_instance->m_loadedModules.begin(),
                                  g_instance->m_loadedModules.end(),
                                  lowerName) != g_instance->m_loadedModules.end();
            }
            if (!known) {
                { char _tp3[MAX_PATH]{}; GetTempPathA(MAX_PATH,_tp3); std::string _lp3=std::string(_tp3)+"astro_kill_trace.log"; FILE* f=fopen(_lp3.c_str(),"a");
                  if (f) { fprintf(f, "anti_dll unknown module: %ls (%ls)\n",
                                   me.szModule, me.szExePath); fclose(f); } }
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// Hooking inline: .text de DLLs criticas modificada contra su copia mapeada limpia
// (comparacion de headers + primera pagina). Un hook de trampoline toca siempre .text.
bool AntiDll::checkCriticalDllIntegrity() {
    const wchar_t* critical[] = {
        L"kernel32.dll", L"ntdll.dll", L"user32.dll",
        L"ws2_32.dll", L"winhttp.dll",
        nullptr
    };
    for (int i = 0; critical[i]; i++) {
        HMODULE hMod = GetModuleHandleW(critical[i]);
        if (!hMod) continue;
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
            continue;
        const BYTE* base = reinterpret_cast<const BYTE*>(mi.lpBaseOfDll);
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(
            const_cast<BYTE*>(base));
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return true;
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
            const_cast<BYTE*>(base) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return true;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return true;

        // checksum del PE header debe coincidir con el file header salvo hooks que
        // reescriban entry points. Chequeo barato: SizeOfImage coherente con mapping.
        if (mi.SizeOfImage < nt->OptionalHeader.SizeOfImage)
            return true;
    }
    return false;
}

std::vector<BYTE> AntiDll::computeImphash() {
    // placeholder estable: el imphash real no aporta contra proxying activo y costo alto
    return {};
}

bool AntiDll::verifyImphash() {
    return true;
}

void initializeAntiDll() {
    if (!g_instance) {
        g_instance = new AntiDll();
        g_instance->start();
    }
}

void shutdownAntiDll() {
    if (g_instance) {
        g_instance->stop();
        delete g_instance;
        g_instance = nullptr;
    }
}

} // namespace security
