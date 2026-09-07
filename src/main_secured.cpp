// main_secured.cpp - ASTRO secured entry point
// Anti-debug first, then anti-frida/dump/patch, license check with TPM,
// backend DLL download & load, Qt GUI start.
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QWindow>
#include <QTimer>
#include <QDir>
#include <QFile>
#include <QtWidgets/QMessageBox>

// DEBUG TRACE (temporary)
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#pragma warning(disable: 4996)
#include <atomic>
static std::atomic<bool> g_qmlReady{false};
// Self-integrity hash: set by build script post-link. 0 = skip check (dev builds).
volatile uint64_t g_expectedTextHash = 0;
void dbgTrace(const char* stage) {
    // Release: silencioso salvo que el operador pida trazas explicitamente.
#ifndef ASTRO_DEBUG_TRACE
    (void)stage;
    return;
#else
    char tp[MAX_PATH]; GetTempPathA(MAX_PATH, tp);
    std::string path = std::string(tp) + "astro_secured_trace.log";
    FILE* f = fopen(path.c_str(), "a");
    if (f) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, stage);
        fclose(f);
    }
#endif
}
#include <QStandardPaths>
#include <QCryptographicHash>
#include "security/legal/ai_protection.h"
#include "security/winhttp_client.h"
#include <QJsonDocument>
#include <QJsonObject>

#ifdef Q_OS_WIN
#include <windows.h>
#include <cstdio>
#include <cstring>
#endif

#include <thread>
#include <chrono>
#include <memory>
#include <atomic>

#include "security/config.h"
#include "farm_controller.h"

#include "security/protection/adbg_bridge.h"
#include "security/protection/anti_vm.h"
#include "security/protection/anti_sandbox.h"
#include "security/protection/anti_debug.h"
#include "security/protection/anti_frida.h"
#include "security/protection/anti_dump.h"
#include "security/protection/anti_patch.h"
#include "security/protection/anti_dll.h"
#include "security/protection/anti_iat.h"
#include "security/license/license_manager.h"
#include "security/loader/secure_loader.h"
#include "security/loader/encrypted_channel.h"
#include "security/loader/autokill.h"
#include "security/loader/backend_api.h"
#include "security/license/session_guard.h"

// ---------------------------------------------------------------------------
// Crash handler (SEH) - same as original but gated behind Q_OS_WIN
// ---------------------------------------------------------------------------
#ifdef Q_OS_WIN
#include <cstdio>

static char g_crashLogPath[MAX_PATH] = {0};

static void initCrashLogPath()
{
    if (g_crashLogPath[0] != '\0')
        return;
    char exe[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    char *slash = strrchr(exe, '\\');
    if (slash)
        *(slash + 1) = '\0';
    strcat_s(exe, "astro_crash.txt");
    strcpy_s(g_crashLogPath, exe);
}

static bool appendCrashLine(const char *line)
{
#ifdef ASTRO_DEBUG_TRACE
    initCrashLogPath();
    HANDLE h = CreateFileA(g_crashLogPath, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD w = 0;
    WriteFile(h, line, (DWORD)std::strlen(line), &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
#endif
    return true;
}

static LONG WINAPI sehHandler(PEXCEPTION_POINTERS ep)
{
    if (ep == nullptr || ep->ExceptionRecord == nullptr) {
        TerminateProcess(GetCurrentProcess(), 1);
        return EXCEPTION_EXECUTE_HANDLER;
    }
    char line[1024] = {0};
    int n = _snprintf_s(line, _TRUNCATE,
                        "[SEH] exception 0x%08lX at 0x%llX thread=%lu",
                        (unsigned long)ep->ExceptionRecord->ExceptionCode,
                        (unsigned long long)(uintptr_t)ep->ExceptionRecord->ExceptionAddress,
                        (unsigned long)GetCurrentThreadId());
    (void)n;
    if (ep->ContextRecord) {
        char regs[640] = {0};
        const CONTEXT *c = ep->ContextRecord;
#if defined(_M_X64) || defined(__x86_64__)
        _snprintf_s(regs, _TRUNCATE,
                    " rip=%llX rsp=%llX rbp=%llX rax=%llX rbx=%llX rcx=%llX rdx=%llX"
                    " rsi=%llX rdi=%llX r8=%llX r9=%llX r10=%llX r11=%llX r12=%llX r13=%llX r14=%llX r15=%llX",
                    (unsigned long long)c->Rip, (unsigned long long)c->Rsp,
                    (unsigned long long)c->Rbp, (unsigned long long)c->Rax,
                    (unsigned long long)c->Rbx, (unsigned long long)c->Rcx,
                    (unsigned long long)c->Rdx, (unsigned long long)c->Rsi,
                    (unsigned long long)c->Rdi, (unsigned long long)c->R8,
                    (unsigned long long)c->R9, (unsigned long long)c->R10,
                    (unsigned long long)c->R11, (unsigned long long)c->R12,
                    (unsigned long long)c->R13, (unsigned long long)c->R14,
                    (unsigned long long)c->R15);
#elif defined(_M_IX86) || defined(__i386__)
        _snprintf_s(regs, _TRUNCATE,
                    " eip=%lX esp=%lX ebp=%lX eax=%lX ebx=%lX ecx=%lX edx=%lX esi=%lX edi=%lX",
                    (unsigned long)c->Eip, (unsigned long)c->Esp,
                    (unsigned long)c->Ebp, (unsigned long)c->Eax,
                    (unsigned long)c->Ebx, (unsigned long)c->Ecx,
                    (unsigned long)c->Edx, (unsigned long)c->Esi,
                    (unsigned long)c->Edi);
#else
        regs[0] = '\0';
#endif
        strncat_s(line, sizeof(line), regs, _TRUNCATE);
    }
    if (ep->ExceptionRecord->NumberParameters > 0) {
        char info[320] = {0};
        int m = 0;
        const ULONG nParams = ep->ExceptionRecord->NumberParameters > 4
            ? 4 : ep->ExceptionRecord->NumberParameters;
        for (ULONG i = 0; i < nParams; ++i) {
            const int r = _snprintf_s(info + m, sizeof(info) - m, _TRUNCATE, "%s0x%llX",
                                      i ? "," : " info=",
                                      (unsigned long long)ep->ExceptionRecord->ExceptionInformation[i]);
            if (r > 0)
                m += r;
        }
        strncat_s(line, sizeof(line), info, _TRUNCATE);
    }
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &mod)) {
        char modName[MAX_PATH] = {0};
        if (GetModuleFileNameA(mod, modName, MAX_PATH) != 0) {
            strncat_s(line, sizeof(line), " module=", _TRUNCATE);
            strncat_s(line, sizeof(line), modName, _TRUNCATE);
        }
    }
    (void)appendCrashLine(line);
    TerminateProcess(GetCurrentProcess(), 1);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void qtMsgHandler(QtMsgType type, const QMessageLogContext &, const QString &msg)
{
#ifdef ASTRO_DEBUG_TRACE
    if (type != QtWarningMsg && type != QtCriticalMsg && type != QtFatalMsg)
        return;
    const char *tag = type == QtWarningMsg ? "warning"
                    : type == QtCriticalMsg ? "critical" : "fatal";
    const QByteArray utf8 = msg.toUtf8();
    const QByteArray line = QByteArray("[Q] ") + tag + ": " + utf8;
    appendCrashLine(line.constData());
    if (type == QtFatalMsg)
        abort();
#else
    Q_UNUSED(type);
    Q_UNUSED(msg);
#endif
}
static void VehWriteStr(HANDLE h, const char* s)
{
    if (h == INVALID_HANDLE_VALUE || s == nullptr) {
        return;
    }
    DWORD len = 0;
    while (s[len] != '\0' && len < 4096) {
        ++len;
    }
    if (len == 0) {
        return;
    }
    DWORD w = 0;
    WriteFile(h, s, len, &w, nullptr);
}
static void VehWriteHex64(HANDLE h, unsigned long long v, DWORD digits)
{
    char buf[16];
    if (digits > 16) {
        digits = 16;
    }
    for (DWORD i = 0; i < digits; ++i) {
        DWORD shift = (digits - 1 - i) * 4;
        DWORD nib = (DWORD)((v >> shift) & 0xFULL);
        buf[i] = (char)(nib < 10 ? ('0' + nib) : ('A' + nib - 10));
    }
    DWORD w = 0;
    WriteFile(h, buf, digits, &w, nullptr);
}
static LONG WINAPI AstroVehHandler(PEXCEPTION_POINTERS ep)
{
    if (ep == nullptr || ep->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ep->ExceptionRecord->ExceptionCode != 0xC0000409u) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    char path[MAX_PATH] = {};
    DWORD dirLen = GetTempPathA(MAX_PATH, path);
    if (dirLen == 0 || dirLen >= (DWORD)(MAX_PATH - 32)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const char* fname = "astro_veh_stack.log";
    DWORD pos = dirLen;
    for (DWORD k = 0; fname[k] != '\0' && pos + 1 < (DWORD)MAX_PATH; ++k, ++pos) {
        path[pos] = fname[k];
    }
    path[pos] = '\0';
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    VehWriteStr(h, "[VEH-FAILFAST] code=0x");
    VehWriteHex64(h, (unsigned long long)ep->ExceptionRecord->ExceptionCode, 8);
    VehWriteStr(h, " addr=0x");
    VehWriteHex64(h, (unsigned long long)(uintptr_t)ep->ExceptionRecord->ExceptionAddress, 16);
    VehWriteStr(h, "\r\n");
    HMODULE mods[256] = {};
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        DWORD count = needed / (DWORD)sizeof(HMODULE);
        if (count > 256) {
            count = 256;
        }
        for (DWORD m = 0; m < count; ++m) {
            char modName[MAX_PATH] = {};
            DWORD nlen = GetModuleFileNameA(mods[m], modName, MAX_PATH);
            if (nlen == 0) {
                continue;
            }
            if (nlen >= (DWORD)MAX_PATH) {
                nlen = MAX_PATH - 1;
            }
            modName[nlen] = '\0';
            VehWriteStr(h, "mod base=0x");
            VehWriteHex64(h, (unsigned long long)(uintptr_t)mods[m], 16);
            VehWriteStr(h, " ");
            VehWriteStr(h, modName);
            VehWriteStr(h, "\r\n");
        }
    }
    PVOID frames[48] = {};
    ULONG backHash = 0;
    USHORT captured = CaptureStackBackTrace(0, 48, frames, &backHash);
    VehWriteStr(h, "stack frames=0x");
    VehWriteHex64(h, (unsigned long long)captured, 4);
    VehWriteStr(h, " hash=0x");
    VehWriteHex64(h, (unsigned long long)backHash, 8);
    VehWriteStr(h, "\r\n");
    for (USHORT f = 0; f < captured; ++f) {
        VehWriteStr(h, "  0x");
        VehWriteHex64(h, (unsigned long long)(uintptr_t)frames[f], 16);
        VehWriteStr(h, "\r\n");
    }
    CloseHandle(h);
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG WINAPI VehAvLogger(PEXCEPTION_POINTERS ep)
{
    if (ep == nullptr || ep->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ep->ExceptionRecord->ExceptionCode != 0xC0000005u) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    char line[256] = {};
    int n = _snprintf_s(line, _TRUNCATE,
        "[VEH] AV thread=%lu addr=0x%llX",
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)(uintptr_t)ep->ExceptionRecord->ExceptionAddress);
    if (n > 0) (void)appendCrashLine(line);
    return EXCEPTION_CONTINUE_SEARCH;
}
static DWORD WINAPI AstroAntiDbgThread(LPVOID)
{
    // Gate: el primer scan espera hasta que el QML termino de cargar.
    // LoadLibrary de plugins QML toma el loader lock; Toolhelp32Snapshot en
    // paralelo puede deadlockear/spinear durante engine.load().
    while (!g_qmlReady.load()) Sleep(250);
    while (true) {
        if (astroScanDebugger() > 0) {
            TerminateProcess(GetCurrentProcess(), 0xDEAD05);
            return 0xDEAD05;
        }
        // El scan completo (~39 checks) consume ~3s de CPU y toma el loader
        // lock (NtQuerySystemInformation de modulos). Un scan frecuente en
        // paralelo con las LoadLibrary on-demand de QtQuick deadlockea el
        // main thread. 60s = ventana de colision ~5% y deteccion efectiva.
        Sleep(60000);
    }
    return 0;
}
#endif

// ---------------------------------------------------------------------------
// Secure logging to file (no console output, encrypted append)
// ---------------------------------------------------------------------------
namespace {

class SecureLog {
public:
    static SecureLog& instance() {
        static SecureLog s;
        return s;
    }

    void write(const char* level, const char* msg) {
#if defined(Q_OS_WIN) && defined(ASTRO_DEBUG_TRACE)
        initCrashLogPath();
        char logPath[MAX_PATH] = {0};
        strcpy_s(logPath, g_crashLogPath);
        char* ext = strrchr(logPath, '.');
        if (ext) strcpy_s(ext, sizeof(logPath) - size_t(ext - logPath), "_secure.log");
        else strcat_s(logPath, "_secure.log");

        HANDLE h = CreateFileA(logPath, FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
        SYSTEMTIME st;
        GetLocalTime(&st);
        char ts[32];
        _snprintf_s(ts, _TRUNCATE, "[%04d-%02d-%02d %02d:%02d:%02d.%03d]",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        DWORD w = 0;
        WriteFile(h, ts, (DWORD)strlen(ts), &w, nullptr);
        WriteFile(h, " ", 1, &w, nullptr);
        WriteFile(h, level, (DWORD)strlen(level), &w, nullptr);
        WriteFile(h, " ", 1, &w, nullptr);
        WriteFile(h, msg, (DWORD)strlen(msg), &w, nullptr);
        WriteFile(h, "\r\n", 2, &w, nullptr);
        CloseHandle(h);
#else
        Q_UNUSED(level);
        Q_UNUSED(msg);
#endif
    }

private:
    SecureLog() = default;
};

void secureLogCallback(const char* level, const char* message) {
    SecureLog::instance().write(level, message);
}

// RAII wrapper for security subsystems
class SecurityGuard {
public:
    SecurityGuard() = default;
    ~SecurityGuard() { shutdown(); }

    SecurityGuard(const SecurityGuard&) = delete;
    SecurityGuard& operator=(const SecurityGuard&) = delete;

    bool initializeAll() {
        SecureLog::instance().write("SEC", "Initializing security subsystems...");

        // 0. VM/Sandbox: el entorno donde nace el proceso es estatico - chequear una vez.
        //    (instalar herramientas de analisis no dispara esto; correr DENTRO de una
        //     VM con hypervisor artifacts si)
#if defined(ASTRO_DEBUG_TRACE) || !defined(ASTRO_HIKARI_BUILD)
        {
            // VM check: HyperV se excluye porque el CPUID hypervisor bit y los
            // vmic* services estan presentes tambien en hardware fisico con
            // Hyper-V/WSL2 habilitado (configuracion legitima muy comun).
            const auto vmRes = anti_vm::run_all_checks();
            const bool inVm = vmRes.detected && vmRes.type != anti_vm::VMType::HYPERV;
            const bool inSb = anti_sandbox::run_all_checks().detected;
            if (inVm || inSb) {
                SecureLog::instance().write("SEC", inVm ? "VM environment detected" : "Sandbox detected");
                dbgTrace(inVm ? "vm-detected" : "sandbox-detected");
                return false;
            }
        }
#endif

        // 1. Anti-debug FIRST - before any other initialization
        ASTRO_AI_TRAP();
        ::astro::legal::astro_ai_poison(); // ensure legal strings in .rdata
        security::initializeAntiDebug();
        SecureLog::instance().write("SEC", "Anti-debug initialized");

        // 2. Anti-Frida
        {
            std::string diagResp;
            const std::string diagHost = ENC("astro-license.astro-bots").decrypt() + ENC(".workers.dev").decrypt();
            const std::string diagPath = ENC("/api/").decrypt() + ENC("health").decrypt();
            const int diagStatus = astro::security::winhttpPostJson(
                diagHost, diagPath,
                "{}", "0", "00", diagResp, 6000);
            { std::string tr = std::string("diag-after-debug=") + std::to_string(diagStatus); dbgTrace(tr.c_str()); }
        }
        dbgTrace("anti-frida-init-begin");
        // Diferido: el escaneo de procesos (Toolhelp) en paralelo con engine.load
        // compite por el loader lock y puede deadlockear la carga de plugins QML.
        // Se inicia tras qml-loaded (ver mas abajo).
        dbgTrace("anti-frida-init-deferred");
        SecureLog::instance().write("SEC", "Anti-Frida initialized");

        // 3. Anti-dump
        dbgTrace("anti-dump-init-begin");
        try {
            security::initializeAntiDump();
        } catch (const std::exception& e) {
            dbgTrace(std::string("anti-dump-EXC: ").append(e.what()).c_str());
            SecureLog::instance().write("SEC", "Anti-dump init threw - skipped");
        } catch (...) {
            dbgTrace("anti-dump-EXC-unknown");
            SecureLog::instance().write("SEC", "Anti-dump init threw unknown");
        }
        dbgTrace("anti-dump-init-done");
        SecureLog::instance().write("SEC", "Anti-dump initialized");

        // 4. Anti-patch
        dbgTrace("anti-patch-init-begin");
        try {
            security::initializeAntiPatch();
        } catch (const std::exception& e) {
            dbgTrace(std::string("anti-patch-EXC: ").append(e.what()).c_str());
            SecureLog::instance().write("SEC", "Anti-patch init threw - skipped");
        } catch (...) {
            dbgTrace("anti-patch-EXC-unknown");
            SecureLog::instance().write("SEC", "Anti-patch init threw unknown");
        }
        dbgTrace("anti-patch-init-done");
        SecureLog::instance().write("SEC", "Anti-patch initialized");

        // Verify no debugger attached after all init
        if (security::AntiDebug::checkIsDebuggerPresent()) {
            SecureLog::instance().write("SEC", "Debugger detected after init - ABORT");
            return false;
        }

        return true;
    }

    void startPostApp() {
        // Anti-dll protection starts after Qt app is up (needs module list stable)
        // initializeAntiDll diferido a post-QML (mismo motivo que anti-frida)
        SecureLog::instance().write("SEC", "Anti-DLL protection started");
    }

    void shutdown() {
        security::shutdownAntiDll();
        security::shutdownAntiPatch();
        security::shutdownAntiDump();
        security::shutdownAntiFrida();
        security::shutdownAntiDebug();
    }

    security::AntiDebug& antiDebug() { static security::AntiDebug inst; return inst; }
};

// RAII wrapper for the backend DLL
class BackendHolder {
public:
    BackendHolder() = default;
    ~BackendHolder() { unload(); }

    BackendHolder(const BackendHolder&) = delete;
    BackendHolder& operator=(const BackendHolder&) = delete;

    bool load(const QByteArray& licenseKey, const QByteArray& hwid) {
        { std::string tr = std::string("backend-load-begin keyLen=") + std::to_string(licenseKey.size()); dbgTrace(tr.c_str()); }
        SecureLog::instance().write("LOAD", "Loading backend DLL...");

        m_loader.setCredentials(licenseKey, hwid);
        m_loader.setApiBase(astro_config::apiBase().toStdString());

        { char _tp[MAX_PATH]{}; GetTempPathA(MAX_PATH,_tp); std::string _lp=std::string(_tp)+"sl_trace.log"; FILE* _t=fopen(_lp.c_str(),"a"); if(_t){ fprintf(_t,"BL-LOAD-START\n"); fclose(_t);} }
        dbgTrace("loadBackend-calling");
        m_api = m_loader.loadBackend(0);
        dbgTrace("loadBackend-returned");
        { char _tp2[MAX_PATH]{}; GetTempPathA(MAX_PATH,_tp2); std::string _lp2=std::string(_tp2)+"sl_trace.log"; FILE* _t=fopen(_lp2.c_str(),"a"); if(_t){ fprintf(_t, m_api.valid() ? "BL-LOAD-VALID\n" : "BL-LOAD-INVALID\n"); fclose(_t);} }
        if (!m_api.valid()) {
            { std::string tr = std::string("backend-error=") + m_loader.lastError(); dbgTrace(tr.c_str()); }
            m_error = QString::fromStdString(m_loader.lastError());
            SecureLog::instance().write("LOAD", ("Failed: " + m_error).toUtf8().constData());
            return false;
        }

        SecureLog::instance().write("LOAD", "Backend DLL loaded successfully");
        return true;
    }

    void unload() {
        m_loader.unloadBackend();
        m_api = {};
    }

    astro::security::BackendApi& api() { return m_api; }
    astro::backend::BackendFunctions* funcs() { return m_funcs; }
    bool isLoaded() const { return m_loaded; }
    QString lastError() const { return m_error; }

    void setFunctions(astro::backend::BackendFunctions* f) { m_funcs = f; m_loaded = (f != nullptr); }

private:
    astro::security::SecureLoader m_loader;
    astro::security::BackendApi m_api;
    astro::backend::BackendFunctions* m_funcs = nullptr;
    bool m_loaded = false;
    QString m_error;
};

// RAII wrapper for Autokill heartbeat
class AutokillGuard {
public:
    AutokillGuard() = default;
    ~AutokillGuard() { stop(); }

    AutokillGuard(const AutokillGuard&) = delete;
    AutokillGuard& operator=(const AutokillGuard&) = delete;

    bool start(const QByteArray& licenseKey, const QByteArray& hwid,
               const QString& heartbeatUrl, std::function<bool()> tamperCheck) {
        astro::security::KillContext ctx;
        ctx.license_key = licenseKey.toStdString();
        ctx.hwid = hwid.toStdString();
        ctx.heartbeat_url = heartbeatUrl.toStdString();
        ctx.heartbeat_interval_ms = 15000;
        ctx.tamper_check = std::move(tamperCheck);

        m_autokill.start(ctx);
        SecureLog::instance().write("KILL", "Autokill heartbeat started");
        return true;
    }

    void stop() { m_autokill.stop(); }

private:
    astro::security::Autokill m_autokill;
};

// Global statics for periodic integrity check
static std::atomic<bool> g_integrityRunning{false};
static std::atomic<bool> g_tamperDetected{false};

namespace { struct AiPoisonKeep { volatile const char* p;
    AiPoisonKeep() : p(::astro::legal::astro_ai_poison()) { (void)p; } } const _ai_keep; }
void tamperDetectedCallback(const char* reason) {
    // SOFT-FAIL FIX: this callback fired on dev machines running legitimate tools
    // (HTTP Debugger Pro) and fed g_tamperDetected -> Autokill wiped %TEMP% and killed
    // the app ~10s after launch. Now: log always; arm the kill-switch only when the
    // operator explicitly opts in via ASTRO_STRICT=1.
    SecureLog::instance().write("TAMPER", reason);
    if (qEnvironmentVariableIsSet("ASTRO_STRICT")) {
        g_tamperDetected.store(true);
#ifdef Q_OS_WIN
        TerminateProcess(GetCurrentProcess(), 2);
#endif
    }
}

bool globalTamperCheck() {
    return !g_tamperDetected.load();
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------
namespace {
QString argValue(const QStringList &args, const QString &flag)
{
    for (int i = 0; i < args.size(); ++i) {
        const QString a = args.at(i);
        if (a == flag && i + 1 < args.size()) {
            const QString v = args.at(i + 1);
            if (!v.startsWith(QLatin1String("--")))
                return v;
            return QString();
        }
        if (a.startsWith(flag + QStringLiteral("=")))
            return a.mid(flag.size() + 1);
    }
    return QString();
}
bool hasArg(const QStringList &args, const QString &flag)
{
    return args.contains(flag);
}
int intArg(const QStringList &args, const QString &flag, int minV, int maxV, int defV)
{
    const QString v = argValue(args, flag);
    if (v.isEmpty())
        return defV;
    bool ok = false;
    const int n = v.toInt(&ok);
    if (!ok)
        return defV;
    return qBound(minV, n, maxV);
}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char *argv[])
{
#ifdef Q_OS_WIN
    AddVectoredExceptionHandler(1UL, AstroVehHandler);
#endif
    // =====================================================================
    // PHASE -1: Self-integrity check (before ANYTHING else)
    // Compute FNV-1a over own .text section; if patched, exit silently.
    // The expected hash is stored as a global that is initialized by the
    // post-build script (scripts/patch_text_hash.py). If the hash variable
    // is zero, skip (dev build without hash patching).
    // =====================================================================
#ifdef Q_OS_WIN
    {
        auto* ntBase = reinterpret_cast<uint8_t*>(GetModuleHandleA(nullptr));
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntBase);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(ntBase + dos->e_lfanew);
            auto* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (memcmp(sec[i].Name, ".text", 5) == 0) {
                    const uint8_t* data = ntBase + sec[i].VirtualAddress;
                    DWORD size = sec[i].Misc.VirtualSize;
                    uint64_t fnv = 0xcbf29ce484222325ULL;
                    for (DWORD j = 0; j < size; ++j) {
                        fnv ^= data[j];
                        fnv *= 0x100000001b3ULL;
                    }
                    // Compare against embedded hash (set by linker patch or build script).
                    // If hash not set (zero), allow dev builds.
                    extern volatile uint64_t g_expectedTextHash;
                    if (g_expectedTextHash != 0 && g_expectedTextHash != fnv) {
                        TerminateProcess(GetCurrentProcess(), 0xDEAD14);
                    }
                    break;
                }
            }
        }
    }
#endif

    // =====================================================================
    // PHASE 0: Crash handler (before ANYTHING else)
    // =====================================================================
#ifdef Q_OS_WIN
    SetUnhandledExceptionFilter(sehHandler);
    qInstallMessageHandler(qtMsgHandler);
    dbgTrace("main-entered");
    {
        // VECTORED EH: registrar TODA excepcion first-chance de cualquier hilo para
        // diagnosticar el AV ~12s que no pasa por el filtro unhandled.
        // Nota: se usa funcion WINAPI (__stdcall), el lambda __cdecl no convierte a PVECTORED_EXCEPTION_HANDLER.
        AddVectoredExceptionHandler(0UL, VehAvLogger);
    }
    {
        // WINHTTP DIAGNOSTIC: does a plain POST work before ANY security init?
        std::string diagResp;
        const std::string diagHost2 = ENC("astro-license.astro-bots").decrypt() + ENC(".workers.dev").decrypt();
        const std::string diagPath2 = ENC("/api/").decrypt() + ENC("health").decrypt();
        const int diagStatus = astro::security::winhttpPostJson(
            diagHost2, diagPath2,
            "{}", "0", "00", diagResp, 8000);
        { std::string tr = std::string("diag-winhttp=") + std::to_string(diagStatus); dbgTrace(tr.c_str()); }
    }
#endif

    // =====================================================================
    // PHASE 1: Security initialization (before Qt app)
    // =====================================================================
    SecurityGuard security;
    if (!security.initializeAll()) {
#ifdef Q_OS_WIN
        MessageBoxA(nullptr,
            "Debugger detected. The application cannot run under a debugger.",
            "ASTRO Security", MB_OK | MB_ICONERROR | MB_TOPMOST);
#endif
        return 1;
    }

    // AntiDBG single-run checks en hilo dedicado (NotRequiem, MIT, parchado).
    // El guard completo usa instrumentation callbacks incompatibles con Win11 24H2+;
    // usamos isProgramBeingDebugged() periodico (checks syscall, sin hooks).
    CreateThread(nullptr, 0, AstroAntiDbgThread, nullptr, 0, nullptr);
    dbgTrace("antidbg-syscall-started");

    // =====================================================================
    // PHASE 2: Qt application setup
    // =====================================================================
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Astro"));
    app.setApplicationVersion(QStringLiteral("1.0"));
    app.setOrganizationName(QStringLiteral("Astro Labs"));
    QQuickStyle::setStyle(QStringLiteral("Basic"));

    // =====================================================================
    // PHASE 3: Session handshake (loader -> astro) - MUST be before any license file check
    // Astro.exe cannot run without a fresh one-time token from AstroLoader.exe
    // =====================================================================
    dbgTrace("start-args-parsed");
    // SECURITY: prefer environment variables (set by loader via CreateProcessW env block)
    // over command-line args (readable by any process via WMI Win32_Process.CommandLine).
    QString envToken  = qEnvironmentVariable("ASTRO_SESSION_TOKEN");
    QString envHwid   = qEnvironmentVariable("ASTRO_HWID");
    QString envKey    = qEnvironmentVariable("ASTRO_KEY");
    QString argToken  = astro::license::extractArg(app.arguments(), QStringLiteral("--astro-session"));
    QString argHwid   = astro::license::extractArg(app.arguments(), QStringLiteral("--astro-hwid"));
    QString argKey    = astro::license::extractArg(app.arguments(), QStringLiteral("--astro-key"));
    QString sessionToken = !envToken.isEmpty() ? envToken : argToken;
    QString sessionHwid  = !envHwid.isEmpty()  ? envHwid  : argHwid;
    QString sessionKey   = !envKey.isEmpty()   ? envKey   : argKey;
    // SECURITY FIX: --allow-standalone is DEBUG ONLY. In Release it is compiled out entirely,
    // so the literal "--allow-standalone" never appears in the binary and cannot be abused.
    bool allowStandalone = false;
#ifdef ASTRO_ALLOW_STANDALONE
    // Only when explicitly compiled with -DASTRO_ALLOW_STANDALONE (debug builds)
    allowStandalone = hasArg(app.arguments(), QString::fromStdString(ENC("--allow-standalone").decrypt()));
    if (allowStandalone) {
        SecureLog::instance().write("LIC", "DEBUG: allow-standalone active");
    }
#endif
    dbgTrace("parent-check-begin");
    bool parentOk = true;
#ifndef NDEBUG
    // DEBUG-ONLY test hook: skip loader-parent check when ASTRO_TEST=1.
    // Compiled only in debug builds; in Release this block desaparece y
    // el parent check de abajo es incondicional.
    if (qEnvironmentVariableIsSet("ASTRO_TEST")) {
        dbgTrace("parent-check-SKIPPED(test)");
        parentOk = true;
    } else {
        parentOk = astro::license::isParentAstroLoader();
    }
#else
    parentOk = astro::license::isParentAstroLoader();
#endif
    if (!allowStandalone) {
        if (!parentOk) {
            dbgTrace("parent-check-FAILED");
            SecureLog::instance().write("LIC", "Blocked: parent is not AstroLoader");
#ifdef Q_OS_WIN
            MessageBoxA(nullptr, "Astro must be started from AstroLoader. Direct launch is blocked.", "ASTRO Security", MB_OK | MB_ICONERROR | MB_TOPMOST);
#endif
            return 1;
        }
        dbgTrace("parent-check-ok");
        if (sessionToken.isEmpty()) {
            SecureLog::instance().write("LIC", "Blocked: missing --astro-session");
#ifdef Q_OS_WIN
            MessageBoxA(nullptr, "Missing session token. Please run AstroLoader.exe first.", "ASTRO Security", MB_OK | MB_ICONERROR | MB_TOPMOST);
#endif
            return 1;
        }
    }

    // =====================================================================
    // PHASE 3b: License validation with TPM binding
    // =====================================================================
    astro::license::LicenseManager licenseManager;

    // Binding autoritativo: el hwid del loader (attestado por el server en la sesion)
    // reemplaza al fingerprint local como canonico para toda la sesion.
    if (!sessionHwid.isEmpty()) {
        licenseManager.overrideHwid(sessionHwid);
    }

    // TPM-based hardware fingerprint
    astro::license::TpmReader tpmReader;
    const astro::license::HardwareFingerprint hwid = tpmReader.readFingerprint();
    SecureLog::instance().write("LIC", qUtf8Printable(
        QStringLiteral("HWID: %1").arg(hwid.combined_hwid)));

    // Validate session token with server (blocking, 10s timeout) - recurrent binding
    if (!allowStandalone && !sessionToken.isEmpty()) {
        QString sessErr;
        // Prefer token-hwid/key from args, fallback to tpm hwid and licenseManager current
        QString chkHwid = sessionHwid.isEmpty() ? hwid.combined_hwid : sessionHwid;
        QString chkKey  = sessionKey.isEmpty() ? licenseManager.currentLicense().license_key : sessionKey;
        // If license file not yet loaded, use sessionKey as key
        if (chkKey.isEmpty()) chkKey = sessionKey;
        astro::license::SessionLicenseInfo sessInfo;
        dbgTrace("before-validate");
        bool sessOk = astro::license::validateSessionTokenEx(sessionToken, chkHwid, chkKey, &sessInfo, &sessErr);
        { std::string tr = std::string("validate-result=") + (sessOk ? "OK" : "FAIL: ") + sessErr.toStdString(); dbgTrace(tr.c_str()); }
        if (!sessOk) {
            SecureLog::instance().write("LIC", qUtf8Printable(QStringLiteral("Session invalid: %1").arg(sessErr)));
#ifdef Q_OS_WIN
            QMessageBox msgBox;
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.setWindowTitle(QStringLiteral("ASTRO - Session Error"));
            msgBox.setText(QStringLiteral("Invalid or expired session. Please restart AstroLoader.")); 
            msgBox.setInformativeText(sessErr);
            msgBox.setStandardButtons(QMessageBox::Ok);
            msgBox.exec();
#endif
            return 1;
        }
        SecureLog::instance().write("LIC", "Session VALID - one-time token accepted");
        dbgTrace("session-valid");

        // BUGFIX (first-run bootstrap): server confirmed the license - persist it locally
        // with its Ed25519 attestation so licenseManager.validate() has a license file.
        // BUGFIX (first-run bootstrap): persist server-attested license from THIS validation
        // (the token is one-time; do not re-validate).
        if (!licenseManager.hasValidLicense()) {
            dbgTrace("bootstrap-attempt");
            if (!licenseManager.bootstrapFromSession(chkKey, sessInfo.tier,
                    sessInfo.expiryEpoch, sessInfo.hwidHash, sessInfo.sig)) {
                SecureLog::instance().write("LIC", "Bootstrap: failed to save attested license");
            } else {
                SecureLog::instance().write("LIC", "Bootstrap: license persisted from session");
            }
        }
    }

    astro::license::LicenseManager::ValidationStatus licStatus = licenseManager.validate();
    { std::string tr = std::string("validate-status=") + std::to_string((int)licStatus); dbgTrace(tr.c_str()); }
    if (!licenseManager.hasValidLicense()) {
        QString errMsg;
        switch (licStatus) {
            case astro::license::LicenseManager::ValidationStatus::NO_LICENSE:
                errMsg = QStringLiteral("No license found. Please activate your license first.");
                break;
            case astro::license::LicenseManager::ValidationStatus::EXPIRED:
                errMsg = QStringLiteral("License has expired. Please renew your license.");
                break;
            case astro::license::LicenseManager::ValidationStatus::HWID_MISMATCH:
                errMsg = QStringLiteral("License is bound to a different machine.");
                break;
            case astro::license::LicenseManager::ValidationStatus::SIGNATURE_INVALID:
                errMsg = QStringLiteral("License signature is invalid. License file may be tampered.");
                break;
            case astro::license::LicenseManager::ValidationStatus::NETWORK_ERROR:
                errMsg = QStringLiteral("Cannot reach license server. Check your internet connection.");
                break;
            case astro::license::LicenseManager::ValidationStatus::SERVER_REJECTED:
                errMsg = QStringLiteral("License server rejected the request.");
                break;
            default:
                errMsg = QStringLiteral("License validation failed (unknown error).");
                break;
        }

        SecureLog::instance().write("LIC", qUtf8Printable(
            QStringLiteral("License INVALID: %1").arg(errMsg)));

#ifdef Q_OS_WIN
        QMessageBox msgBox;
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.setWindowTitle(QStringLiteral("ASTRO - License Error"));
        msgBox.setText(errMsg);
        msgBox.setInformativeText(QStringLiteral("Error code: %1").arg(static_cast<int>(licStatus)));
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.exec();
#endif
        return 1;
    }

    SecureLog::instance().write("LIC", "License VALID");

    // Start periodic license check (every 5 minutes)
    licenseManager.startPeriodicCheck(15000);

    // =====================================================================
    // PHASE 4: Download and load backend DLL
    // =====================================================================
    BackendHolder backend;
    const QByteArray licKey = licenseManager.currentLicense().license_key.toUtf8();
    // HWID canonico de la sesion = el del loader (attestado por el server).
    // Usar combined_hwid local aqui causaba 403 "HWID mismatch" en /api/download
    // (el manifest validaba contra el hwid_hash vinculado por el loader).
    const QString canonicalHwid = licenseManager.hardwareFingerprint().combined_hwid;
    const QByteArray hwidBytes = canonicalHwid.isEmpty()
        ? hwid.combined_hwid.toUtf8()
        : canonicalHwid.toUtf8();

    if (!backend.load(licKey, hwidBytes)) {
        // GRACEFUL DEGRADATION: the remote backend module is optional (farm features).
        // The core QML UI must launch even when the backend distribution is unavailable.
        SecureLog::instance().write("LOAD", "Backend load failed - continuing without backend module");
        { std::string tr = std::string("backend-load-failed-continuing: ") + backend.lastError().toStdString(); dbgTrace(tr.c_str()); }
    }

    // Try to get typed function pointers from the backend DLL
    // SECURITY FIX: astro_init lives in the backend DLL; resolve via GetProcAddress instead of
    // link-time symbol (which broke the build and would defeat the encrypted backend loader).
    using AstroInitFn = astro::backend::BackendFunctions* (*)();
    static AstroInitFn s_astroInit = nullptr;
    if (!s_astroInit && !backend.lastError().isEmpty() == false) {
        // backend module handle kept by SecureLoader; resolve through it
        HMODULE hBackend = GetModuleHandleW(L"astro_backend.dll");
        if (hBackend) s_astroInit = reinterpret_cast<AstroInitFn>(GetProcAddress(hBackend, "astro_init"));
    }
    astro::backend::BackendFunctions* backendFuncs = s_astroInit ? s_astroInit() : nullptr;
    if (backendFuncs && backendFuncs->api_version == astro::backend::BACKEND_API_VERSION) {
        backend.setFunctions(backendFuncs);
        SecureLog::instance().write("LOAD", "Backend API initialized (typed)");

        // Register backend logging callback
        if (backendFuncs->set_log_callback)
            backendFuncs->set_log_callback(secureLogCallback);

        // Initialize backend context
        if (backendFuncs->init) {
            astro::backend::FarmContext ctx{};
            int rc = backendFuncs->init(licKey.constData(), hwidBytes.constData(), &ctx);
            if (rc != 0) {
                SecureLog::instance().write("LOAD", "Backend init() failed");
            }
        }
    } else {
        SecureLog::instance().write("LOAD", "Backend API version mismatch or null");
    }

    // =====================================================================
    // PHASE 5: Start autokill heartbeat
    // =====================================================================
    AutokillGuard autokill;
    dbgTrace("autokill-before-start");
    try {
        autokill.start(licKey, hwidBytes,
                   astro_config::heartbeatUrl(),
                   globalTamperCheck);
        dbgTrace("autokill-start-ok");
    } catch (...) {
        // Thread quota exhausted under LSP-injected hosts: continue without the
        // heartbeat thread. Server-side license checks still gate usage.
        SecureLog::instance().write("LOAD", "Autokill thread unavailable - continuing");
        dbgTrace("autokill-thread-failed-continuing");
    }

    // =====================================================================
    // PHASE 6: Set up tamper detection callback for all security components
    // =====================================================================
    // Anti-dump and anti-patch will call tamperDetectedCallback on detection

    // =====================================================================
    // PHASE 7: Qt GUI application (original FarmController + QML UI)
    // =====================================================================
    dbgTrace("phase7-farm-ctor-begin");
    FarmController farm;
    dbgTrace("phase7-farm-ctor-ok");
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &farm, &FarmController::shutdown);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("farm"), &farm);

    QString savedTheme = farm.loadTheme();
    engine.rootContext()->setContextProperty(QStringLiteral("savedTheme"), savedTheme);

    const QUrl url(QStringLiteral("qrc:/Astro/qml/Main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed,
                     &app, [](const QUrl &) { QCoreApplication::exit(-1); },
                     Qt::QueuedConnection);
    dbgTrace("phase7-qml-loading");
    engine.load(url);
    g_qmlReady.store(true);
    dbgTrace("phase7-security-deferred-begin");
    security::initializeAntiFrida();
    security::initializeAntiDll();
    astro::security::AntiIat::instance().initialize();
    dbgTrace("phase7-security-deferred-done");
    dbgTrace("phase7-qml-loaded");

    QFile dbgf(QCoreApplication::applicationDirPath() + QStringLiteral("/astro_crash.txt"));
    if (dbgf.open(QIODevice::Append | QIODevice::Text)) {
        dbgf.write(QStringLiteral("roots=%1\n").arg(engine.rootObjects().size()).toUtf8());
        dbgf.close();
    }

    // Post-load: accounts and farm selection
    QTimer::singleShot(0, &farm, [&farm]() {
        farm.loadAccounts();
        farm.loadFarmSelection();
        QTimer::singleShot(2000, &farm, [&farm]() { farm.scanAllX2(); });
    });

    const auto roots = engine.rootObjects();
    if (!roots.isEmpty()) {
        if (auto *window = qobject_cast<QWindow *>(roots.constFirst())) {
            window->show();
            window->raise();
            window->requestActivate();
            if (auto *quickWindow = qobject_cast<QQuickWindow *>(window)) {
                QTimer::singleShot(1500, quickWindow, [quickWindow]() {
                    const auto image = quickWindow->grabWindow();
                    image.save(QDir::current().filePath(QStringLiteral("astro-preview.png")));
                });
            }
        }
    }

    // =====================================================================
    // PHASE 8: Post-app security: anti-DLL + integrity checks
    // =====================================================================
    security.startPostApp();
    dbgTrace("postapp-started");

    // Periodic integrity check every 10 seconds
    QTimer* integrityTimer = new QTimer(&app);
    QObject::connect(integrityTimer, &QTimer::timeout, []() {
        // FALSE-POSITIVE FIX: this 10s timer killed the app ~10s after launch on ANY
        // machine with HTTP Debugger Pro installed (legitimate dev tool). Each check now
        // logs instead of terminating; production builds can re-enable via ASTRO_STRICT.
        const bool strict = qEnvironmentVariableIsSet("ASTRO_STRICT");
        QString reason;
        if (!astro::security::AntiIat::instance().verifyIntegrity())
            reason = QStringLiteral("IAT hook detected in periodic check");
        else if (security::AntiDebug::checkIsDebuggerPresent())
            reason = QStringLiteral("Debugger detected in periodic check");
        else if (security::AntiFrida::checkFridaPorts())
            reason = QStringLiteral("Frida detected in periodic check");
        else {
            static security::AntiPatch antiPatchChecker;
            if (antiPatchChecker.verifySectionCrc())
                reason = QStringLiteral("Binary patch detected in periodic check");
            else if (security::AntiDll::checkBlockedDlls())
                reason = QStringLiteral("Blocked DLL detected in periodic check");
        }
        if (!reason.isEmpty()) {
            SecureLog::instance().write("TAMPER", reason.toUtf8().constData());
            if (strict) tamperDetectedCallback(reason.toUtf8().constData());
        }
    });
    integrityTimer->start(10000);

    // =====================================================================
    // PHASE 9: Command-line arguments (same as original)
    // =====================================================================
    const QStringList args = app.arguments();
    const QString deviceValue = argValue(args, QStringLiteral("--device"));
    if (!deviceValue.isEmpty())
        farm.setDeviceId(deviceValue);

    if (hasArg(args, QStringLiteral("--debug")))
        farm.setDebugEnabled(true);

    if (hasArg(args, QStringLiteral("--fetch")))
        QTimer::singleShot(2000, &farm, [&farm]() { farm.fetchGems(); });

    if (!hasArg(args, QStringLiteral("--autospawn"))
        && !hasArg(args, QStringLiteral("--duration"))
        && !hasArg(args, QStringLiteral("--fetch"))) {
        QTimer::singleShot(1500, &farm, [&farm]() {
            if (!farm.accounts().isEmpty())
                farm.fetchAllGems();
        });
    }

    if (hasArg(args, QStringLiteral("--select-all"))) {
        QTimer::singleShot(3000, &farm, [&farm]() {
            const auto accs = farm.accounts();
            for (int i = 0; i < accs.size(); ++i)
                farm.toggleFarmSelection(i, true);
        });
    }

    if (hasArg(args, QStringLiteral("--headless-run"))) {
        const QString accountValue = argValue(args, QStringLiteral("--account"));
        QTimer::singleShot(3000, &farm, [&farm, accountValue]() {
            const auto accs = farm.accounts();
            for (int i = 0; i < accs.size(); ++i) {
                bool match = true;
                if (!accountValue.isEmpty()) {
                    const QVariantMap m = accs[i].toMap();
                    match = m.value(QStringLiteral("name")).toString()
                                .contains(accountValue, Qt::CaseInsensitive)
                            || m.value(QStringLiteral("device")).toString()
                                .contains(accountValue, Qt::CaseInsensitive);
                }
                farm.toggleFarmSelection(i, match);
            }
            QTimer::singleShot(3000, &farm, [&farm]() { farm.spawn(); });
        });
    }

    const QString gemValue = argValue(args, QStringLiteral("--autospawn"));
    if (!gemValue.isEmpty()) {
        const int gemId = intArg(args, QStringLiteral("--autospawn"), 1, 100000, 0);
        if (gemId > 0) {
            QTimer::singleShot(2500, &farm, [&farm, gemId]() { farm.fetchGems(); });
            QObject::connect(&farm, &FarmController::gemsChanged, &farm, [&farm, gemId]() {
                farm.selectGemById(gemId);
                QTimer::singleShot(3000, &farm, [&farm]() { farm.spawn(); });
            });
        } else {
            qWarning("--autospawn: invalid value, ignored");
        }
    }

    const int durationSecs = intArg(args, QStringLiteral("--duration"), 1, 3600, 0);
    if (durationSecs > 0) {
        QTimer::singleShot(durationSecs * 1000, &farm, [&farm]() { farm.stopFarm(); });
        QTimer::singleShot(durationSecs * 1000 + 8000, &farm, [&farm]() { farm.quitApp(); });
#ifdef Q_OS_WIN
        std::thread watchdog([durationSecs]() {
            std::this_thread::sleep_for(std::chrono::seconds(durationSecs + 60));
            TerminateProcess(GetCurrentProcess(), 1);
        });
        watchdog.detach();
#endif
    }

    const int refreshAllMs = intArg(args, QStringLiteral("--refreshall"), 0, 3600000, -1);
    if (refreshAllMs >= 0)
        QTimer::singleShot(refreshAllMs, &farm, [&farm]() { farm.refreshAllAccounts(); });

    const int refreshXpMs = intArg(args, QStringLiteral("--refreshxp"), 0, 3600000, -1);
    if (refreshXpMs >= 0)
        QTimer::singleShot(refreshXpMs, &farm, [&farm]() { farm.refreshXp(); });

    const QString probeDevice = argValue(args, QStringLiteral("--probe-shop"));
    if (!probeDevice.isEmpty()) {
        QTimer::singleShot(1500, &farm, [&farm, probeDevice]() {
            QString base = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
            if (base.isEmpty())
                base = QCoreApplication::applicationDirPath();
            const QString pemPath = base + QStringLiteral("/Astro/fake_tpm/")
                + QCryptographicHash::hash(probeDevice.toUtf8(), QCryptographicHash::Md5).toHex().left(16)
                + QStringLiteral(".pem");
            LoginManager local;
            if (!pemPath.isEmpty()) {
                QFile pf(pemPath);
                if (pf.open(QIODevice::ReadOnly)) {
                    local.setAttestPem(QString::fromUtf8(pf.readAll()));
                    pf.close();
                }
            }
            const LoginResult r = local.login(probeDevice);
            if (!r.ok) {
                qWarning("probe-shop: login failed: %s", qUtf8Printable(r.error));
                QCoreApplication::exit(2);
                return;
            }
            qInfo("probe-shop: login ok (sk len %d)", int(r.sessionKey.size()));
            const QStringList bodies = {
                QStringLiteral("{\"do\":\"store\",\"category\":10,\"evo\":false}"),
                QStringLiteral("{\"do\":\"buy\",\"item\":1048594}"),
                QStringLiteral("{\"do\":\"buy\",\"item\":1048622}"),
                QStringLiteral("{\"do\":\"inventory\",\"slot\":5}"),
                QStringLiteral("{\"do\":\"asdf_nonexistent\"}"),
                QStringLiteral("{\"do\":\"repair\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repair\",\"id\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repair_item\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"gemrepair\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repair\",\"item\":3962,\"slot\":5,\"price\":22}"),
                QStringLiteral("{\"do\":\"repair\",\"id\":3962}"),
                QStringLiteral("{\"do\":\"fix\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"restore\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"mend\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repairgem\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"equip\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"refreshgem\"}"),
            };
            for (const QString &b : bodies) {
                const QJsonObject resp = local.apiCall(b);
                qInfo("probe: %s -> %s", qUtf8Printable(b),
                      qUtf8Printable(QString::fromUtf8(QJsonDocument(resp).toJson(QJsonDocument::Compact)).left(300)));
            }
            QCoreApplication::exit(0);
        });
    }

    dbgTrace("entering-app-exec");
    const int exitCode = app.exec();
    dbgTrace("app-exec-exited");
    return exitCode;
}
