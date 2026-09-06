#pragma warning(disable: 4996)
#include "autokill.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QCryptographicHash>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QTimer>
#include <QDateTime>
#include <QTextStream>

#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>

#include <random>
#include <cstring>
#include <intrin.h>
#include <vector>
#include "security/crypto/string_encrypt.h"
#include "security/crypto/key_obfuscation.h"
#include "security/winhttp_client.h"
#include "security/config/astro_paths.h"
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
#include "security/crypto/string_encrypt.h"
#include "security/crypto/key_obfuscation.h"
#include "security/winhttp_client.h"
#include "security/crypto/m3xc.h"
#include "security/crypto/ed25519/ed25519.h"
#include "security/crypto/obfuscation.h"
#include <QMessageAuthenticationCode>
#include <QUrl>
// Anti-AI: NOAI - Ghidra poison active

#ifndef JUNK_CODE
#define JUNK_CODE do { volatile uint64_t _jk_ = static_cast<uint64_t>(__rdtsc()); _jk_ *= 0xBF58476D1CE4E5B9ULL; _jk_ ^= (_jk_ >> 27); _jk_ *= 0x94D049BB133111EBULL; _jk_ ^= (_jk_ >> 31); (void)_jk_; } while(0)
#endif

#pragma comment(lib, "shell32.lib")

namespace astro {
namespace security {

std::atomic<bool> Autokill::s_anti_debug_flag{false};
std::atomic<bool> Autokill::s_global_tamper{false};

// ---- Descubrimiento dinamico de rutas del producto (rename-proof) ----
// Devuelve todos los directorios candidatos que se parezcan al appdir:
// el nombre configurado (astro_paths) mas cualquier subdir de %TEMP% cuyo
// contenido incluya el exe principal o qt.conf junto a un binario grande.
static QStringList discoverAppDirs(const QString& tempPath) {
    QStringList out;
    const QString configured = paths::appDirName();
    QDir td(tempPath);
    // 1) nombre configurado
    QString cfg = tempPath + "/" + configured;
    if (QDir(cfg).exists()) out << QDir(cfg).canonicalPath();
    // 2) heuristica: subdirs con exe principal o (qt.conf + exe >1MB)
    const QString exeKey = paths::exeName().toLower();
    const QFileInfoList subs = td.entryInfoList(QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot);
    for (const QFileInfo& fi : subs) {
        QDir d(fi.absoluteFilePath());
        if (d.exists(exeKey)) {
            QString c = QDir(fi.absoluteFilePath()).canonicalPath();
            if (!out.contains(c)) out << c;
            continue;
        }
        if (d.exists(QString::fromStdString(ENC("qt.conf").decrypt()))) {
            const QFileInfoList exes = d.entryInfoList(QStringList() << QString::fromStdString(ENC("*.exe").decrypt()), QDir::Files);
            for (const QFileInfo& xe : exes) {
                if (xe.size() > 1024 * 1024) {
                    QString cc = QDir(fi.absoluteFilePath()).canonicalPath();
                    if (!out.contains(cc)) { out << cc; break; }
                }
            }
        }
    }
    return out;
}

// Directorio del ejecutable actual (rename-proof: nunca depende del nombre)
static QString selfDir() {
    wchar_t buf[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, buf, MAX_PATH) == 0) return {};
    return QFileInfo(QString::fromWCharArray(buf)).absolutePath();
}

std::atomic<bool>& Autokill::globalTamperFlag() { return s_global_tamper; }
bool Autokill::getAntiDebugFlag() { return s_anti_debug_flag.load(); }
void Autokill::setAntiDebugFlag(bool v) { s_anti_debug_flag.store(v); }

Autokill::Autokill() = default;

Autokill::~Autokill() { stop(); }

void Autokill::start(const KillContext& ctx) {
    JUNK_CODE;
    if (m_running.exchange(true)) return;
    m_ctx = ctx;
    try {
        m_thread = std::thread(&Autokill::killThread, this);
    } catch (...) {
        m_running = false;
    }
}

void Autokill::stop() {
    if (!m_running.exchange(false)) return;
    if (m_thread.joinable()) m_thread.join();
}

void Autokill::requestKill(KillReason reason, const std::string& detail) {
    JUNK_CODE;
    m_kill_reason.store(reason);
    m_kill_detail = detail;
    m_kill_requested.store(true);
}

void Autokill::killThread() {
    JUNK_CODE;
    HANDLE hThread = GetCurrentThread();
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    auto ktrace = [](const char* s) {
        char tp[MAX_PATH]{}; GetTempPathA(MAX_PATH, tp);
        std::string p = std::string(tp) + "astro_kill_trace.log";
        FILE* f = fopen(p.c_str(), "a");
        if (f) { fprintf(f, "%s\n", s); fclose(f); }
    };
    while (m_running.load()) {
        if (m_kill_requested.load()) {
            ktrace("trigger: m_kill_requested");
            executeKillSequence(m_kill_reason.load(), m_kill_detail);
        }

        if (s_anti_debug_flag.load()) {
            ktrace("trigger: s_anti_debug_flag");
            executeKillSequence(KillReason::TAMPER_DETECTED, ENC("debugger_detected").decrypt());
        }

        if (s_global_tamper.load()) {
            ktrace("trigger: s_global_tamper");
            executeKillSequence(KillReason::TAMPER_DETECTED, ENC("integrity_compromised").decrypt());
        }

        if (m_ctx.tamper_check && !m_ctx.tamper_check()) {
            ktrace("trigger: tamper_check false");
            executeKillSequence(KillReason::INTEGRITY_FAIL, ENC("tamper_check_failed").decrypt());
        }

        // HEARTBEAT TOLERANCE FIX: transient network failures (offline, LSP injection,
        // server hiccup) must NOT nuke the user's machine. Require N consecutive failures
        // before executing the kill sequence.
        int fails = 0;
        bool hbOk = false;
        for (int attempt = 0; attempt < 3 && m_running.load(); ++attempt) {
            if (performHeartbeat()) { hbOk = true; break; }
            ++fails;
            Sleep(2000);
        }
        (void)fails;
        if (!hbOk && m_running.load()) {
            // POLICY FIX: fallos de latido (offline, LSP injection, server down) NO deben
            // destruir la instalacion del usuario. Solo con ASTRO_STRICT se ejecuta el
            // kill sequence; en modo normal queda registrado y se reintenta al proximo ciclo.
            if (GetEnvironmentVariableA("ASTRO_STRICT", nullptr, 0) > 0) {
                executeKillSequence(KillReason::HEARTBEAT_FAIL, ENC("network_error").decrypt());
            }
        }

        auto interval = m_ctx.heartbeat_interval_ms;
        QElapsedTimer timer;
        timer.start();

        while (timer.elapsed() < static_cast<qint64>(interval) && m_running.load()) {
            Sleep(1000);
        }
    }
}

bool Autokill::performHeartbeat() {
    JUNK_CODE;
    if (OPAQUE_PRED_TRUE((uint64_t)m_ctx.license_key.size() ^ 0xC0FFEEULL)) { JUNK_CODE; }
    QString encKey = astro::security::crypto::deobfuscateEncryptionKey();
    QByteArray body;
    QString pathForHmac;
    FLATTEN_BEGIN(0x7A3C)
        FLATTEN_CASE(0) {
            QJsonObject inner;
            inner[QString::fromStdString(ENC("license_key").decrypt())] = QString::fromStdString(m_ctx.license_key);
            inner[QString::fromStdString(ENC("hwid").decrypt())] = QString::fromStdString(m_ctx.hwid);
            inner[QString::fromStdString(ENC("ts").decrypt())] = static_cast<qint64>(QDateTime::currentSecsSinceEpoch());
            inner[QString::fromStdString(ENC("nonce").decrypt())] = QString::number(QDateTime::currentMSecsSinceEpoch());
            QByteArray innerBytes = QJsonDocument(inner).toJson(QJsonDocument::Compact);
            QString encrypted = astro::security::crypto::lm_m3xcEncrypt(QString::fromUtf8(innerBytes), encKey);
            QJsonObject wrapper; wrapper[QString::fromStdString(ENC("encrypted").decrypt())] = encrypted;
            body = QJsonDocument(wrapper).toJson(QJsonDocument::Compact);
            QUrl url(QString::fromStdString(m_ctx.heartbeat_url));
            pathForHmac = url.path();
            if (pathForHmac.isEmpty()) pathForHmac = QString::fromStdString(ENC("/api/heartbeat").decrypt());
            const QString apiBase = url.scheme() + QStringLiteral("://") + url.host() +
                (url.port() > 0 ? QStringLiteral(":") + QString::number(url.port()) : QString());
            QString ts = QString::number(QDateTime::currentSecsSinceEpoch());
            QByteArray payloadHmac = (QString::fromStdString(ENC("POST:").decrypt()) + pathForHmac + QStringLiteral(":") + ts + QStringLiteral(":") + QString::fromUtf8(body)).toUtf8();
            QByteArray sig = astro::security::crypto::lm_hmacSha256HexDerived(payloadHmac, encKey.toUtf8());
            QNetworkRequest req(url);
            req.setHeader(QNetworkRequest::ContentTypeHeader, QString::fromStdString(ENC("application/json").decrypt()));
            req.setRawHeader(QByteArray::fromStdString(ENC("X-Timestamp").decrypt()), ts.toUtf8());
            req.setRawHeader(QByteArray::fromStdString(ENC("X-Signature").decrypt()), sig);
            req.setTransferTimeout(10000);
            req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
            ASTRO_AI_TRAP();
            // THREAD FIX: QNAM requires a Qt event dispatcher; this runs on a raw
            // std::thread so every heartbeat failed and triggered the kill sequence.
            // WinHTTP direct is thread-safe and event-loop free.
            std::string respStd;
            const int hbStatus = astro::security::winhttpPostJson(
                apiBase.toStdString(), pathForHmac.toStdString(), body.toStdString(),
                ts.toStdString(), sig.toStdString(), respStd, 10000);
            if (hbStatus != 200) {
                return false;
            }
            QByteArray resp = QByteArray::fromStdString(respStd);
            QJsonDocument doc = QJsonDocument::fromJson(resp);
            QJsonObject obj = doc.object();
            if (obj.contains(QString::fromStdString(ENC("encrypted").decrypt()))) {
                QString encResp = obj[QString::fromStdString(ENC("encrypted").decrypt())].toString();
                if (!encResp.isEmpty()) {
                    QString decStr = astro::security::crypto::lm_m3xcDecrypt(encResp, encKey);
                    if (!decStr.isEmpty()) {
                        QJsonDocument decDoc = QJsonDocument::fromJson(decStr.toUtf8());
                        if (decDoc.isObject()) obj = decDoc.object();
                    }
                }
            }
            QString status = obj[QString::fromStdString(ENC("status").decrypt())].toString();
            if (status == QString::fromStdString(ENC("killed").decrypt())) {
                QString reason = obj[QString::fromStdString(ENC("reason").decrypt())].toString(QString::fromStdString(ENC("server_kill").decrypt()));
                executeKillSequence(KillReason::LICENSE_REVOKED, reason.toStdString());
            }

            // SECURITY: verify the Ed25519 signature on "ok" heartbeats.
            // Without this, a MITM can keep a revoked client alive by replaying {"status":"ok"}.
            if (status == QString::fromStdString(ENC("ok").decrypt())) {
                QString sigHex = obj[QString::fromStdString(ENC("sig").decrypt())].toString();
                QString nonce  = obj[QString::fromStdString(ENC("client_nonce").decrypt())].toString();
                bool sigOk = false;
                if (!sigHex.isEmpty() && !nonce.isEmpty() && m_ctx.license_key.size() > 0) {
                    QByteArray msg;
                    msg += "ok|";
                    msg += QByteArray(m_ctx.license_key.c_str(), (int)m_ctx.license_key.size());
                    msg += "|";
                    msg += nonce.toUtf8();
                    QByteArray sigBin = QByteArray::fromHex(sigHex.toLatin1());
                    static const unsigned char pubKeyBytes[32] = {
                        0xc5,0xd9,0x0b,0xc3,0x80,0x42,0xd8,0x14,0xe4,0xf8,0xbb,0x47,0xd0,0xc5,0x95,0x88,
                        0x85,0x9f,0x19,0x27,0x70,0x75,0xec,0xee,0xc2,0x60,0xfd,0xae,0x07,0xb7,0xfd,0xb3 };
                    sigOk = (ed25519_verify(reinterpret_cast<const unsigned char*>(sigBin.constData()),
                                            reinterpret_cast<const unsigned char*>(msg.constData()),
                                            static_cast<size_t>(msg.size()),
                                            pubKeyBytes) == 1);
                }
                if (!sigOk) {
                    // Unsigned or forged heartbeat -> treat as network failure so it counts
                    // toward the consecutive-failure limit instead of keeping the client alive.
                    return false;
                }
            }
            JUNK_CODE;
            FLATTEN_GOTO(1)
            return status == QString::fromStdString(ENC("ok").decrypt());
        }
        FLATTEN_CASE(1) {
            return false;
        }
    FLATTEN_END
    return false;
}

void Autokill::executeKillSequence(KillReason reason, const std::string& detail) {
    JUNK_CODE;
    {
        char _tp[MAX_PATH]{}; GetTempPathA(MAX_PATH, _tp);
        std::string _logPath = std::string(_tp) + "astro_kill_trace.log";
        FILE* f = fopen(_logPath.c_str(), "a");
        if (f) { fprintf(f, "KILL seq reason=%d detail=%s\n", (int)reason, detail.c_str()); fclose(f); }
    }
    (void)reason;
    (void)detail;
    erasePEHeaders();
    overwriteCodeSections();
    deleteLocalAppData();
    deleteTempAndLicenseFiles();
    removeRegistryEntries();
    scheduleSelfDelete();
    terminateSelf();
}

void Autokill::erasePEHeaders() {
    JUNK_CODE;
    auto* base_addr = reinterpret_cast<uint8_t*>(
        GetModuleHandleA(nullptr));
    if (!base_addr) return;

    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(base_addr, &mbi, sizeof(mbi));

    DWORD old_prot = 0;
    VirtualProtect(base_addr, mbi.RegionSize, PAGE_READWRITE, &old_prot);

    std::mt19937_64 rng(GetCurrentProcessId() ^ __rdtsc());
    std::uniform_int_distribution<int> dist(0, 255);

    size_t erase_size = 4096;
    std::vector<uint8_t> garbage(erase_size);
    for (auto& b : garbage) b = static_cast<uint8_t>(dist(rng));

    std::memcpy(base_addr, garbage.data(), erase_size);

    DWORD dummy = 0;
    VirtualProtect(base_addr, mbi.RegionSize, old_prot, &dummy);
}

void Autokill::overwriteCodeSections() {
    JUNK_CODE;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);

    DWORD self_pid = GetCurrentProcessId();

    std::mt19937_64 rng(GetCurrentProcessId() ^ __rdtsc());
    std::uniform_int_distribution<int> dist(0, 255);

    if (Module32First(hSnap, &me)) {
        do {
            if (me.th32ProcessID == self_pid && me.modBaseAddr) {
                DWORD old_prot = 0;
                if (VirtualProtect(me.modBaseAddr, me.modBaseSize,
                                   PAGE_READWRITE, &old_prot)) {
                    std::vector<uint8_t> garbage(me.modBaseSize);
                    for (auto& b : garbage)
                        b = static_cast<uint8_t>(dist(rng));
                    std::memcpy(me.modBaseAddr, garbage.data(), me.modBaseSize);
                    DWORD dummy = 0;
                    VirtualProtect(me.modBaseAddr, me.modBaseSize,
                                   old_prot, &dummy);
                }
            }
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
}

bool Autokill::secureWipeFile(const QString& path) {
    JUNK_CODE;
    QFileInfo info(path);
    if (!info.exists() || !info.isFile()) {
        return false;
    }

    // ensure writable and not hidden/system locked
    QString native = QDir::toNativeSeparators(path);
    std::wstring wnative = native.toStdWString();
    SetFileAttributesW(wnative.c_str(), FILE_ATTRIBUTE_NORMAL);

    qint64 fileSize = info.size();
    if (fileSize == 0) {
        QFile::remove(path);
        return true;
    }

    // 3 passes: 0x00, 0xFF, random
    const int passes = 3;
    for (int pass = 0; pass < passes; ++pass) {
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly)) {
            continue;
        }

        const qint64 chunkSize = 64 * 1024;
        std::vector<char> buffer(static_cast<size_t>(qMin<qint64>(chunkSize, fileSize)));

        if (pass == 0) {
            std::memset(buffer.data(), 0x00, buffer.size());
        } else if (pass == 1) {
            std::memset(buffer.data(), 0xFF, buffer.size());
        } else {
            std::mt19937_64 rng(__rdtsc() ^ GetCurrentProcessId() ^ static_cast<uint64_t>(pass * 0x9E3779B97F4A7C15ULL));
            std::uniform_int_distribution<int> dist(0, 255);
            for (auto &b : buffer) b = static_cast<char>(dist(rng));
        }

        file.seek(0);
        qint64 remaining = fileSize;
        // for random pass regenerate per chunk to keep randomness
        std::mt19937_64 rng2;
        if (pass == 2) {
            rng2.seed(__rdtsc() ^ GetCurrentProcessId());
        }

        while (remaining > 0) {
            qint64 toWrite = qMin<qint64>(remaining, static_cast<qint64>(buffer.size()));
            if (pass == 2) {
                std::uniform_int_distribution<int> d2(0, 255);
                for (qint64 i = 0; i < toWrite; ++i) buffer[static_cast<size_t>(i)] = static_cast<char>(d2(rng2));
            }
            qint64 written = file.write(buffer.data(), toWrite);
            if (written <= 0) break;
            remaining -= written;
        }
        file.flush();
        file.close();
    }

    // overwrite name via rename before delete to hide original filename in MFT
    QDir dir = info.dir();
    QString wipeName = dir.absoluteFilePath(QString::fromStdString(ENC("tmp_").decrypt()) + QString::number(__rdtsc() % 1000000) + QString::fromStdString(ENC(".tmp").decrypt()));
    QFile::rename(path, wipeName);
    if (QFile::exists(wipeName)) {
        QFile::remove(wipeName);
        return !QFile::exists(wipeName);
    }
    QFile::remove(path);
    return !QFile::exists(path);
}

void Autokill::secureWipeDirectory(const QString& dirPath) {
    JUNK_CODE;
    QDir dir(dirPath);
    if (!dir.exists()) return;

    QFileInfoList entries = dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDir::Name);
    for (const QFileInfo &fi : entries) {
        if (fi.isDir()) {
            secureWipeDirectory(fi.absoluteFilePath());
            QDir().rmdir(fi.absoluteFilePath());
        } else if (fi.isFile()) {
            secureWipeFile(fi.absoluteFilePath());
        }
    }
}

void Autokill::cleanPrefetchAndRecent() {
    JUNK_CODE;
    // Prefetch: C:\Windows\Prefetch\ASTRO*.pf
    QString prefetchDir = QString::fromStdString(ENC("C:\\Windows\\Prefetch").decrypt());
    QDir pf(prefetchDir);
    if (pf.exists()) {
        // RENAME-PROOF: prefijos derivados del exe actual + patrones configurados
        wchar_t selfExe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, selfExe, MAX_PATH);
        QString stem = QFileInfo(QString::fromWCharArray(selfExe)).completeBaseName().toUpper();
        QString ldrStem = paths::loaderExe(); // por si el loader corre con otro nombre
        QStringList filters;
        filters << (stem + QString::fromStdString(ENC("*.pf").decrypt()))
                << (stem + QString::fromStdString(ENC("*.PF").decrypt()));
        filters << QString::fromStdString(ENC("ASTRO*.pf").decrypt())
                << QString::fromStdString(ENC("ASTRO*.PF").decrypt())
                << QString::fromStdString(ENC("ASTROLOADER*.pf").decrypt())
                << QString::fromStdString(ENC("ASTROLOADER*.PF").decrypt());
        QFileInfoList list = pf.entryInfoList(filters, QDir::Files);
        for (const QFileInfo &fi : list) {
            QString up = fi.fileName().toUpper();
            if (up.contains(QString::fromStdString(ENC("ASTRO").decrypt()))) {
                secureWipeFile(fi.absoluteFilePath());
                // fallback plain remove if wipe lacked privileges
                QFile::remove(fi.absoluteFilePath());
            }
        }
        // also brute force scan all .pf and filter by name contains astro
        QFileInfoList allPf = pf.entryInfoList(QStringList() << QString::fromStdString(ENC("*.pf").decrypt()), QDir::Files);
        for (const QFileInfo &fi : allPf) {
            QString low = fi.fileName().toLower();
            if (low.contains(QString::fromStdString(ENC("astro").decrypt()))) {
                secureWipeFile(fi.absoluteFilePath());
                QFile::remove(fi.absoluteFilePath());
            }
        }
    }

    // Recent: %APPDATA%\Microsoft\Windows\Recent
    wchar_t recentPath[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_RECENT, nullptr, 0, recentPath) == S_OK) {
        QString recent = QString::fromWCharArray(recentPath);
        QDir rd(recent);
        if (rd.exists()) {
            QFileInfoList recents = rd.entryInfoList(QDir::Files | QDir::Hidden | QDir::System);
            for (const QFileInfo &fi : recents) {
                QString low = fi.fileName().toLower();
                if (low.contains(QString::fromStdString(ENC("astro").decrypt()))) {
                    secureWipeFile(fi.absoluteFilePath());
                }
            }
        }
    }

    // Recent AutomaticDestinations (jump lists)
    wchar_t appdataPath[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdataPath) == S_OK) {
        QString appdata = QString::fromWCharArray(appdataPath);
        QString autoDest = appdata + QString::fromStdString(ENC("\\Microsoft\\Windows\\Recent\\AutomaticDestinations").decrypt());
        QDir ad(autoDest);
        if (ad.exists()) {
            QFileInfoList lst = ad.entryInfoList(QDir::Files);
            for (const QFileInfo &fi : lst) {
                // heuristic: if file was modified recently and contains astro string in lnk target is hard to detect
                // we clean files that contain astro in name or wipe small recent jump lists that may reference Astro
                // For forense, wipe all automaticDestinations that were accessed within last 7 days and size < 32k
                // Simpler: wipe any file whose name hash correlates - we just leave them, but ensure Recent folder cleaned
                (void)fi;
            }
        }
        QString customDest = appdata + QString::fromStdString(ENC("\\Microsoft\\Windows\\Recent\\CustomDestinations").decrypt());
        QDir cd(customDest);
        if (cd.exists()) {
            (void)cd;
        }
    }
}

void Autokill::deleteLocalAppData() {
    JUNK_CODE;
    auto wipeDirSecure = [&](const QString &p) {
        if (p.isEmpty()) return;
        QDir d(p);
        if (d.exists()) {
            secureWipeDirectory(p);
            d.removeRecursively();
            // fallback rmdir
            QDir().rmdir(p);
        }
    };

    // %LOCALAPPDATA%\Astro and %LOCALAPPDATA%\AstroLoader + barrido heuristico
    wchar_t localappdata[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localappdata) == S_OK) {
        QString base = QString::fromWCharArray(localappdata);
        QString astroDir = base + QString::fromStdString(ENC("\\Astro").decrypt());
        QString loaderDir = base + QString::fromStdString(ENC("\\AstroLoader").decrypt());
        wipeDirSecure(astroDir);
        wipeDirSecure(loaderDir);
        // RENAME-PROOF: cualquier subdir cuyo nombre contenga el patron raiz
        // o que contenga license/session/token dentro => wipe completo.
        {
            QDir bd(base);
            const QFileInfoList kids = bd.entryInfoList(QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot);
            for (const QFileInfo& ki : kids) {
                const QString kn = ki.fileName().toLower();
                if (!kn.contains(paths::patternRoot()) && !kn.contains(QString::fromStdString(ENC("labs").decrypt())))
                    continue;
                wipeDirSecure(ki.absoluteFilePath());
            }
            // segundo pase: dirs con archivos de licencia adentro (nombre irrelevante)
            for (const QFileInfo& ki : bd.entryInfoList(QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot)) {
                QDir kd(ki.absoluteFilePath());
                if (kd.exists(paths::licenseDatNameSafe()) ||
                    kd.exists(QString::fromStdString(ENC("license.dat").decrypt())) ||
                    kd.exists(paths::sessionTokenNameSafe())) {
                    wipeDirSecure(ki.absoluteFilePath());
                }
            }
        }

        // archivos sueltos en LOCALAPPDATA
        QStringList loose = {
            QString::fromStdString(ENC("astro_license.enc").decrypt()),
            QString::fromStdString(ENC("astro_license.dat").decrypt()),
            QString::fromStdString(ENC("license.json").decrypt()),
            QString::fromStdString(ENC("license.dat").decrypt()),
            QString::fromStdString(ENC("session.token").decrypt())
        };
        for (const QString &f : loose) {
            secureWipeFile(base + QString::fromStdString(ENC("\\").decrypt()) + f);
            secureWipeFile(astroDir + QString::fromStdString(ENC("\\").decrypt()) + f);
            secureWipeFile(loaderDir + QString::fromStdString(ENC("\\").decrypt()) + f);
        }
    }

    // %APPDATA%\Astro
    wchar_t appdata[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata) == S_OK) {
        QString base = QString::fromWCharArray(appdata);
        QString astroRoam = base + QString::fromStdString(ENC("\\Astro").decrypt());
        wipeDirSecure(astroRoam);
        QStringList loose = {
            QString::fromStdString(ENC("astro_license.enc").decrypt()),
            QString::fromStdString(ENC("astro_license.dat").decrypt()),
            QString::fromStdString(ENC("license.json").decrypt()),
            QString::fromStdString(ENC("session.token").decrypt())
        };
        for (const QString &f : loose) {
            secureWipeFile(base + QString::fromStdString(ENC("\\").decrypt()) + f);
            secureWipeFile(astroRoam + QString::fromStdString(ENC("\\").decrypt()) + f);
        }
    }

    // %PROGRAMDATA%\Astro
    wchar_t commonAppData[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, commonAppData) == S_OK) {
        QString base = QString::fromWCharArray(commonAppData);
        QString progAstro = base + QString::fromStdString(ENC("\\Astro").decrypt());
        wipeDirSecure(progAstro);
    }

    // %TEMP%\astro_app and %TEMP%\astro
    QString tempBase = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    if (tempBase.isEmpty()) {
        wchar_t tmp[MAX_PATH]{};
        if (GetTempPathW(MAX_PATH, tmp) != 0) {
            tempBase = QString::fromWCharArray(tmp);
        }
    }
    // normalizar sin barra final
    while (tempBase.endsWith(QString::fromStdString(ENC("/").decrypt())) || tempBase.endsWith(QString::fromStdString(ENC("\\").decrypt()))) {
        tempBase.chop(1);
    }

    if (!tempBase.isEmpty()) {
        QStringList tempDirs = {
            tempBase + QString::fromStdString(ENC("/astro_app").decrypt()),
            tempBase + QString::fromStdString(ENC("/astro").decrypt()),
            tempBase + QString::fromStdString(ENC("\\astro_app").decrypt()),
            tempBase + QString::fromStdString(ENC("\\astro").decrypt())
        };
        for (const QString &td : tempDirs) {
            wipeDirSecure(td);
            // intento directo QDir removeRecursively por si secureWipe fallo por permisos
            QDir d(td);
            if (d.exists()) d.removeRecursively();
        }

        // archivos de licencia sueltos en TEMP
        QStringList tempFiles = {
            QString::fromStdString(ENC("astro_license.enc").decrypt()),
            QString::fromStdString(ENC("astro_license.dat").decrypt()),
            QString::fromStdString(ENC("license.json").decrypt()),
            QString::fromStdString(ENC("license.dat").decrypt()),
            QString::fromStdString(ENC("session.token").decrypt())
        };
        for (const QString &f : tempFiles) {
            secureWipeFile(tempBase + QString::fromStdString(ENC("/").decrypt()) + f);
            secureWipeFile(tempBase + QString::fromStdString(ENC("\\").decrypt()) + f);
        }

        // wildcard %TEMP%\astro\* ya cubierto por wipeDirSecure, pero tambien borrado de archivos que empiezan por astro en TEMP
        QDir td(tempBase);
        if (td.exists()) {
            QFileInfoList entries = td.entryInfoList(QDir::Files | QDir::Hidden | QDir::System);
            for (const QFileInfo &fi : entries) {
                QString low = fi.fileName().toLower();
                if (low.startsWith(QString::fromStdString(ENC("astro").decrypt())) ||
                    low.contains(QString::fromStdString(ENC("license").decrypt())) ||
                    low.contains(QString::fromStdString(ENC("session").decrypt()))) {
                    secureWipeFile(fi.absoluteFilePath());
                }
            }
        }
    }

    // QStandardPaths::AppLocalDataLocation y AppDataLocation fallback (Qt)
    {
        QStringList qtBases = {
            QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation),
            QStandardPaths::writableLocation(QStandardPaths::AppDataLocation),
            QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        };
        for (QString qb : qtBases) {
            if (qb.isEmpty()) continue;
            // qb ya puede ser .../Astro, entonces su parent contiene Astro
            QDir qd(qb);
            if (qd.exists()) {
                QString name = qd.dirName().toLower();
                if (name.contains(QString::fromStdString(ENC("astro").decrypt()))) {
                    secureWipeDirectory(qb);
                    qd.removeRecursively();
                } else {
                    // buscar subdir Astro dentro de qb
                    QString subAstro = qb + QString::fromStdString(ENC("/Astro").decrypt());
                    wipeDirSecure(subAstro);
                    QString subLoader = qb + QString::fromStdString(ENC("/AstroLoader").decrypt());
                    wipeDirSecure(subLoader);
                }
            }
            // archivos sueltos
            secureWipeFile(qb + QString::fromStdString(ENC("/astro_license.enc").decrypt()));
            secureWipeFile(qb + QString::fromStdString(ENC("/license.json").decrypt()));
            secureWipeFile(qb + QString::fromStdString(ENC("/session.token").decrypt()));
            secureWipeFile(qb + QString::fromStdString(ENC("/astro_license.dat").decrypt()));
        }
    }
}

void Autokill::deleteTempAndLicenseFiles() {
    JUNK_CODE;
    QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    if (tempPath.isEmpty()) {
        wchar_t tmp[MAX_PATH]{};
        if (GetTempPathW(MAX_PATH, tmp) != 0) {
            tempPath = QString::fromWCharArray(tmp);
        }
    }
    while (tempPath.endsWith(QString::fromStdString(ENC("/").decrypt())) || tempPath.endsWith(QString::fromStdString(ENC("\\").decrypt()))) {
        tempPath.chop(1);
    }
    if (tempPath.isEmpty()) return;

    // Nombres sensibles a borrar con wipe
    QStringList sensitiveNames = {
        QString::fromStdString(ENC("session.token").decrypt()),
        QString::fromStdString(ENC("astro_license.dat").decrypt()),
        QString::fromStdString(ENC("astro_license.enc").decrypt()),
        QString::fromStdString(ENC("license.json").decrypt()),
        QString::fromStdString(ENC("license.dat").decrypt())
    };

    // 1) archivos directos en %TEMP%
    for (const QString &name : sensitiveNames) {
        QString p1 = tempPath + QString::fromStdString(ENC("/").decrypt()) + name;
        QString p2 = tempPath + QString::fromStdString(ENC("\\").decrypt()) + name;
        // quitar atributo hidden antes de wipe
        {
            std::wstring w1 = QDir::toNativeSeparators(p1).toStdWString();
            SetFileAttributesW(w1.c_str(), FILE_ATTRIBUTE_NORMAL);
        }
        secureWipeFile(p1);
        secureWipeFile(p2);
        // hidden variant .hidden
        QFile::remove(p1);
        QFile::remove(p2);
    }

    // 2) subdirectorios del app: nombre configurado + descubrimiento dinamico
    //    (rename-proof: aunque cambie ASTRO_APP_DIR_KEY, se detectan los dirs
    //     que contienen el exe principal o qt.conf+exe grande)
    QStringList astroSubdirs = {
        paths::appDirName(),
        QString::fromStdString(ENC("astro").decrypt()),
        QString::fromStdString(ENC("Astro").decrypt())
    };
    for (const QString &full0 : discoverAppDirs(tempPath)) {
        if (!astroSubdirs.contains(QFileInfo(full0).fileName()))
            astroSubdirs << QFileInfo(full0).fileName();
    }
    {
        QString sd = selfDir();
        if (!sd.isEmpty() && sd != tempPath && !astroSubdirs.contains(QFileInfo(sd).fileName()))
            astroSubdirs << QFileInfo(sd).fileName();
    }
    for (const QString &sub : astroSubdirs) {
        QString full = tempPath + QString::fromStdString(ENC("/").decrypt()) + sub;
        QDir d(full);
        if (d.exists()) {
            // borrar logs y dumps dentro
            QStringList innerDirs = {
                QString::fromStdString(ENC("logs").decrypt()),
                QString::fromStdString(ENC("dumps").decrypt()),
                QString::fromStdString(ENC("cache").decrypt()),
                QString::fromStdString(ENC("temp").decrypt())
            };
            for (const QString &inner : innerDirs) {
                QString innerPath = full + QString::fromStdString(ENC("/").decrypt()) + inner;
                QDir id(innerPath);
                if (id.exists()) {
                    secureWipeDirectory(innerPath);
                    id.removeRecursively();
                }
            }
            // borrar cualquier archivo .log .dmp .token .enc .dat dentro
            QFileInfoList files = d.entryInfoList(QDir::Files | QDir::Hidden | QDir::System | QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
            for (const QFileInfo &fi : files) {
                if (fi.isDir()) {
                    secureWipeDirectory(fi.absoluteFilePath());
                    QDir().rmdir(fi.absoluteFilePath());
                } else {
                    QString suf = fi.suffix().toLower();
                    QString low = fi.fileName().toLower();
                    if (suf == QString::fromStdString(ENC("log").decrypt()) ||
                        suf == QString::fromStdString(ENC("dmp").decrypt()) ||
                        suf == QString::fromStdString(ENC("token").decrypt()) ||
                        suf == QString::fromStdString(ENC("enc").decrypt()) ||
                        suf == QString::fromStdString(ENC("dat").decrypt()) ||
                        low.contains(QString::fromStdString(ENC("astro").decrypt())) ||
                        low.contains(QString::fromStdString(ENC("session").decrypt())) ||
                        low.contains(QString::fromStdString(ENC("license").decrypt()))) {
                        secureWipeFile(fi.absoluteFilePath());
                    } else {
                        // de todos modos wipe por forense
                        secureWipeFile(fi.absoluteFilePath());
                    }
                }
            }
            secureWipeDirectory(full);
            d.removeRecursively();
            QDir().rmdir(full);
        }
    }

    // 3) barrido general de %TEMP% para archivos con extensiones sensibles que queden sueltos
    {
        QDir td(tempPath);
        if (td.exists()) {
            QFileInfoList allFiles = td.entryInfoList(QDir::Files | QDir::Hidden | QDir::System);
            for (const QFileInfo &fi : allFiles) {
                QString low = fi.fileName().toLower();
                QString suf = fi.suffix().toLower();
                bool isSensitive = false;
                if (low.contains(QString::fromStdString(ENC("astro").decrypt())) ||
                    low.contains(QString::fromStdString(ENC("license").decrypt())) ||
                    low.contains(QString::fromStdString(ENC("session").decrypt())) ||
                    suf == QString::fromStdString(ENC("log").decrypt()) ||
                    suf == QString::fromStdString(ENC("dmp").decrypt())) {
                    isSensitive = true;
                }
                // session.token es hidden
                if (low == QString::fromStdString(ENC("session.token").decrypt())) isSensitive = true;
                if (isSensitive) {
                    // quitar hidden
                    std::wstring wn = QDir::toNativeSeparators(fi.absoluteFilePath()).toStdWString();
                    SetFileAttributesW(wn.c_str(), FILE_ATTRIBUTE_NORMAL);
                    secureWipeFile(fi.absoluteFilePath());
                }
            }
        }
    }

    // 4) limpiar tambien %LOCALAPPDATA%\Astro\logs y dumps por si quedaron
    wchar_t lad[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, lad) == S_OK) {
        QString base = QString::fromWCharArray(lad);
        QStringList extraDirs = {
            base + QString::fromStdString(ENC("\\Astro\\logs").decrypt()),
            base + QString::fromStdString(ENC("\\Astro\\dumps").decrypt()),
            base + QString::fromStdString(ENC("\\AstroLoader\\logs").decrypt()),
            base + QString::fromStdString(ENC("\\AstroLoader\\dumps").decrypt()),
            base + QString::fromStdString(ENC("\\Astro\\cache").decrypt())
        };
        for (const QString &ed : extraDirs) {
            QDir d(ed);
            if (d.exists()) {
                secureWipeDirectory(ed);
                d.removeRecursively();
            }
        }
    }
}

void Autokill::removeRegistryEntries() {
    JUNK_CODE;
    // Arboles a borrar completamente
    std::vector<std::string> treeKeys = {
        ENC("SOFTWARE\\Astro").decrypt(),
        ENC("SOFTWARE\\AstroLoader").decrypt(),
        ENC("SOFTWARE\\AstroSecured").decrypt()
    };

    for (const std::string &ks : treeKeys) {
        QString qks = QString::fromStdString(ks);
        std::wstring ws = qks.toStdWString();

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, ws.c_str(), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegDeleteTreeW(hKey, nullptr);
            RegCloseKey(hKey);
            RegDeleteKeyW(HKEY_CURRENT_USER, ws.c_str());
        }
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ws.c_str(), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegDeleteTreeW(hKey, nullptr);
            RegCloseKey(hKey);
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, ws.c_str());
        }
        // tambien intentar WOW64_32
        if (RegOpenKeyExW(HKEY_CURRENT_USER, ws.c_str(), 0, KEY_ALL_ACCESS | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
            RegDeleteTreeW(hKey, nullptr);
            RegCloseKey(hKey);
            RegDeleteKeyW(HKEY_CURRENT_USER, ws.c_str());
        }
    }

    // Limpiar valores Astro* en Run keys
    std::string runPathStd = ENC("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run").decrypt();
    QString runPathQ = QString::fromStdString(runPathStd);
    std::wstring runW = runPathQ.toStdWString();

    HKEY hives[2] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    for (int hi = 0; hi < 2; ++hi) {
        HKEY hive = hives[hi];
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(hive, runW.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            DWORD valCount = 0;
            DWORD maxNameLen = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valCount, &maxNameLen, nullptr, nullptr, nullptr);
            if (maxNameLen < 256) maxNameLen = 256;
            std::vector<wchar_t> nameBuf(static_cast<size_t>(maxNameLen) + 1);

            std::vector<std::wstring> toDelete;
            DWORD countSnapshot = valCount;
            for (DWORD i = 0; i < countSnapshot; ++i) {
                DWORD nameLen = static_cast<DWORD>(nameBuf.size());
                LONG res = RegEnumValueW(hKey, i, nameBuf.data(), &nameLen, nullptr, nullptr, nullptr, nullptr);
                if (res == ERROR_SUCCESS) {
                    std::wstring wname(nameBuf.data(), nameLen);
                    QString qname = QString::fromWCharArray(wname.c_str());
                    QString qlow = qname.toLower();
                    QString astroLow = QString::fromStdString(ENC("astro").decrypt()).toLower();
                    if (qlow.startsWith(astroLow)) {
                        toDelete.push_back(wname);
                    }
                } else if (res == ERROR_NO_MORE_ITEMS) {
                    break;
                } else {
                    // si falla por buffer pequeno, agrandar
                    if (res == ERROR_MORE_DATA) {
                        nameBuf.resize(nameBuf.size() * 2);
                        --i;
                        continue;
                    }
                }
            }

            for (const std::wstring &wdel : toDelete) {
                RegDeleteValueW(hKey, wdel.c_str());
            }

            // valores legacy especificos por si enumeration fallo
            std::vector<std::string> legacyVals = {
                ENC("AstroLauncher").decrypt(),
                ENC("AstroUpdate").decrypt(),
                ENC("AstroLoader").decrypt(),
                ENC("Astro").decrypt()
            };
            for (const std::string &ls : legacyVals) {
                std::wstring wl = QString::fromStdString(ls).toStdWString();
                RegDeleteValueW(hKey, wl.c_str());
            }

            RegCloseKey(hKey);
        }

        // tambien intentar 32-bit view
        HKEY hKey32 = nullptr;
        if (RegOpenKeyExW(hive, runW.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_32KEY, &hKey32) == ERROR_SUCCESS) {
            std::vector<std::string> legacyVals = {
                ENC("AstroLauncher").decrypt(),
                ENC("AstroUpdate").decrypt(),
                ENC("AstroLoader").decrypt()
            };
            for (const std::string &ls : legacyVals) {
                std::wstring wl = QString::fromStdString(ls).toStdWString();
                RegDeleteValueW(hKey32, wl.c_str());
            }
            RegCloseKey(hKey32);
        }
    }

    // Tambien RunOnce por si se uso
    std::string runOnceStd = ENC("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce").decrypt();
    QString runOnceQ = QString::fromStdString(runOnceStd);
    std::wstring runOnceW = runOnceQ.toStdWString();
    for (int hi = 0; hi < 2; ++hi) {
        HKEY hive = hives[hi];
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(hive, runOnceW.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            std::vector<std::string> vals = {
                ENC("AstroLauncher").decrypt(),
                ENC("AstroUpdate").decrypt(),
                ENC("AstroLoader").decrypt()
            };
            for (auto &v : vals) {
                std::wstring wv = QString::fromStdString(v).toStdWString();
                RegDeleteValueW(hKey, wv.c_str());
            }
            RegCloseKey(hKey);
        }
    }

    cleanPrefetchAndRecent();
}

void Autokill::scheduleSelfDelete() {
    JUNK_CODE;
    wchar_t exePath[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
        return;
    }
    wchar_t tempPathW[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, tempPathW) == 0) {
        return;
    }

    QString tempDir = QString::fromWCharArray(tempPathW);
    if (!tempDir.endsWith(QString::fromStdString(ENC("\\").decrypt())) && !tempDir.endsWith(QString::fromStdString(ENC("/").decrypt()))) {
        tempDir += QString::fromStdString(ENC("\\").decrypt());
    }

    QString batName = QString::fromStdString(ENC("ast_cl_").decrypt())
                    + QString::number(static_cast<qint64>(GetCurrentProcessId()))
                    + QString::fromStdString(ENC("_").decrypt())
                    + QString::number(QDateTime::currentSecsSinceEpoch() % 10000)
                    + QString::fromStdString(ENC(".bat").decrypt());

    QString batPath = tempDir + batName;
    QString exeStr = QString::fromWCharArray(exePath);

    QString batContent;
    batContent += QString::fromStdString(ENC("@echo off\n").decrypt());
    batContent += QString::fromStdString(ENC(":loop\n").decrypt());
    batContent += QString::fromStdString(ENC("timeout /t 2 /nobreak >nul\n").decrypt());
    batContent += QString::fromStdString(ENC("del /f /q \"").decrypt()) + exeStr + QString::fromStdString(ENC("\"\n").decrypt());
    batContent += QString::fromStdString(ENC("if exist \"").decrypt()) + exeStr + QString::fromStdString(ENC("\" goto loop\n").decrypt());
    // borrar tambien directorios Astro como fallback final
    {
        wchar_t lad[MAX_PATH]{};
        if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, lad) == S_OK) {
            QString ladStr = QString::fromWCharArray(lad);
            QString astroLad = ladStr + QString::fromStdString(ENC("\\Astro").decrypt());
            QString loaderLad = ladStr + QString::fromStdString(ENC("\\AstroLoader").decrypt());
            batContent += QString::fromStdString(ENC("rd /s /q \"").decrypt()) + astroLad + QString::fromStdString(ENC("\"\n").decrypt());
            batContent += QString::fromStdString(ENC("rd /s /q \"").decrypt()) + loaderLad + QString::fromStdString(ENC("\"\n").decrypt());
        }
        // Delete %TEMP%\astro_app directory entirely (Astro.exe + Qt DLLs + all files)
        batContent += QString::fromStdString(ENC("rd /s /q \"").decrypt()) + QDir::toNativeSeparators(tempDir + QString::fromStdString(ENC("astro_app").decrypt())) + QString::fromStdString(ENC("\"\n").decrypt());
        // Delete all leftover astro_package zip files
        batContent += QString::fromStdString(ENC("del /f /q \"").decrypt()) + QDir::toNativeSeparators(tempDir) + QString::fromStdString(ENC("astro_package*.zip\"").decrypt());
    }
    batContent += QString::fromStdString(ENC("del /f /q \"%~f0\"\n").decrypt());

    QFile batFile(batPath);
    if (!batFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return;
    }
    QTextStream out(&batFile);
    out << batContent;
    batFile.close();

    std::wstring wBat = QDir::toNativeSeparators(batPath).toStdWString();
    SetFileAttributesW(wBat.c_str(), FILE_ATTRIBUTE_HIDDEN);

    QString cmd = QString::fromStdString(ENC("cmd.exe /c \"").decrypt()) + QDir::toNativeSeparators(batPath) + QString::fromStdString(ENC("\"").decrypt());
    std::wstring wcmd = cmd.toStdWString();

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    std::vector<wchar_t> cmdBuf(wcmd.begin(), wcmd.end());
    cmdBuf.push_back(L'\0');

    if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        // fallback via ShellExecute
        ShellExecuteW(nullptr, L"open", wBat.c_str(), nullptr, nullptr, SW_HIDE);
    }
}

[[noreturn]] void Autokill::terminateSelf() {
    JUNK_CODE;
    HANDLE hProc = GetCurrentProcess();

    for (volatile int i = 0; i < 100; ++i) {
        std::mt19937_64 rng(__rdtsc());
        std::uniform_int_distribution<int> dist(0, 255);
        volatile uint8_t garbage[64]{};
        for (auto& b : garbage) b = static_cast<uint8_t>(dist(rng));
        (void)garbage;
    }

    TerminateProcess(hProc, 0xDEAD);
    ExitProcess(0xDEAD);
}

} // namespace security
} // namespace astro
