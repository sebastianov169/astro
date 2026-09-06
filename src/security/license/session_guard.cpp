#pragma warning(disable: 4996)
#include <cstdio>
#include <string>
#include "session_guard.h"
#include "security/crypto/m3xc.h"
#include "security/crypto/ed25519/ed25519.h"
#include "security/crypto/string_encrypt.h"
#include "security/crypto/key_obfuscation.h"
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
#include "security/config.h"
#include "security/winhttp_client.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QCoreApplication>
#include <QThread>
#include <atomic>
#include <QTimer>
#include <QDateTime>
#include <QUrl>
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#undef OPAQUE

namespace astro {
namespace license {

QString extractArg(const QStringList& args, const QString& flag){
    for(int i=0;i<args.size();i++){
        if(args[i]==flag && i+1<args.size()){
            QString v=args[i+1];
            if(!v.startsWith("--")) return v;
        }
        if(args[i].startsWith(flag+"=")) return args[i].mid(flag.size()+1);
    }
    return "";
}


static void sgTrace(const char* s) {
#ifdef ASTRO_DEBUG_TRACE
    FILE* f = fopen((std::string(getenv("TEMP")?getenv("TEMP"):".") + "\\astro_sg.log").c_str(), "a");
    if (f) { fprintf(f, "%s\n", s); fclose(f); }
#else
    (void)s;
#endif
}

bool isParentAstroLoader(){
#ifdef Q_OS_WIN
    ASTRO_AI_TRAP();
    DWORD pid = GetCurrentProcessId();
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snap==INVALID_HANDLE_VALUE){ sgTrace("sg: snap-fail"); return false; }
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    if(Process32First(snap, &pe)){
        DWORD myPid=pid;
        do{
            if(pe.th32ProcessID==myPid){ ppid=pe.th32ParentProcessID; break; }
        }while(Process32Next(snap,&pe));
    }
    if(!ppid){ CloseHandle(snap); sgTrace("sg: no-ppid"); return false; }
    // Find parent entry
    QString pname;
    if(Process32First(snap,&pe)){
        do{
            if(pe.th32ProcessID==ppid){ pname = QString::fromWCharArray(pe.szExeFile); break; }
        }while(Process32Next(snap,&pe));
    }
    CloseHandle(snap);
    // Nombres permitidos: AstroLoader.exe clasico o "Astro X.Y.exe" (releases
    // con version en el nombre). El resto del gate (edad del padre, token
    // one-time validado en servidor) sigue intacto.
    QString pl = pname.toLower();
    bool nameOk = (pl.compare(QStringLiteral("astroloader.exe")) == 0) ||
                  (pl.startsWith(QStringLiteral("astro ")) && pl.endsWith(QStringLiteral(".exe")));
    if(!nameOk)
        return false;
    // HARDENING: verify full image path and creation time (anti-PPID spoof)
    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if(!hParent){ sgTrace("sg: open-parent-fail"); return false; }
    bool ok = false;
    do {
        wchar_t imgPath[MAX_PATH]={0};
        DWORD sz = MAX_PATH;
        if(!QueryFullProcessImageNameW(hParent, 0, imgPath, &sz)){ sgTrace("sg: qfpin-fail"); break; }
        sgTrace((std::string("sg: path=") + QString::fromWCharArray(imgPath).toStdString()).c_str());
        sgTrace("sg: after-path-ok");
        QString full = QString::fromWCharArray(imgPath);
        QString fulll = full.toLower();
        bool pathOk = fulll.endsWith(QStringLiteral("astroloader.exe")) ||
                      (fulll.contains(QStringLiteral("\\astro ")) && fulll.endsWith(QStringLiteral(".exe")));
        if(!pathOk) break;
        // Check parent creation time is recent (within 10 minutes) - prevents PID reuse and stale parent
        FILETIME cTime, eTime, kTime, uTime;
        if(!GetProcessTimes(hParent, &cTime, &eTime, &kTime, &uTime)){ sgTrace("sg: getproctimes-fail"); break; }
        sgTrace("sg: proctime-got");
        ULARGE_INTEGER c; c.LowPart=cTime.dwLowDateTime; c.HighPart=cTime.dwHighDateTime;
        FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
        ULARGE_INTEGER now; now.LowPart=nowFt.dwLowDateTime; now.HighPart=nowFt.dwHighDateTime;
        // 10 minutes = 10*60*10^7 = 6000000000  (100ns units)
        const ULONGLONG tenMin = 6000000000ULL;
        if(now.QuadPart < c.QuadPart) break;
        if(now.QuadPart - c.QuadPart > tenMin){ sgTrace("sg: parent-age-exceeds"); break; }
        sgTrace("sg: parent-age-ok");
        // Additional anti-spoof: parent must have a window or be the loader (check via parent's parent not being explorer spoof - optional)
        // Verify token file exists and is recent (loader creates session.token at launch)
        // This ties parent process to current token file age
        wchar_t exePath[MAX_PATH]={0};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t* slash = wcsrchr(exePath, L'\\');
        if(slash) *(slash+1)=L'\0';
        wcscat_s(exePath, L"session.token");
        WIN32_FILE_ATTRIBUTE_DATA fad={0};
        sgTrace((std::string("sg: tokenpath=") + QString::fromWCharArray(exePath).toStdString()).c_str());
        if(GetFileAttributesExW(exePath, GetFileExInfoStandard, &fad)){
            sgTrace("sg: token-file-found");
            // Usar LastWriteTime (no CreationTime): CREATE_ALWAYS/MoveFile preservan ctime
            // (NTFS tunneling) pero el wtime siempre refleja la ultima escritura real.
            ULARGE_INTEGER ftime; ftime.LowPart=fad.ftLastWriteTime.dwLowDateTime; ftime.HighPart=fad.ftLastWriteTime.dwHighDateTime;
            ULONGLONG ageNs = (now.QuadPart >= ftime.QuadPart) ? (now.QuadPart - ftime.QuadPart) : 0;
            sgTrace((std::string("sg: token-age-ns=") + std::to_string(now.QuadPart - ftime.QuadPart)).c_str());
            if(now.QuadPart >= ftime.QuadPart && (now.QuadPart - ftime.QuadPart) <= tenMin){
                ok = true;
                sgTrace("sg: OK");
            } else {
                sgTrace("sg: token-age-exceeds-or-negative");
            }
        } else {
            sgTrace("sg: token-file-MISSING");
            // SECURITY FIX: missing session.token no longer falls back to allow.
            // The loader writes this file right after the server accepts the token; if it is
            // absent or stale, the parent process is not a fresh AstroLoader handshake.
            ok = false;
        }
    } while(false);
    CloseHandle(hParent);
    return ok;
#endif
    return false;
}

bool validateSessionToken(const QString& token, const QString& hwid, const QString& licenseKey, QString* errorOut){
    return validateSessionTokenEx(token, hwid, licenseKey, nullptr, errorOut);
}

bool validateSessionTokenEx(const QString& token, const QString& hwid, const QString& licenseKey,
                            SessionLicenseInfo* infoOut, QString* errorOut){
    if (infoOut) *infoOut = SessionLicenseInfo{};
    if(token.isEmpty() || hwid.isEmpty() || licenseKey.isEmpty()){
        if(errorOut) *errorOut = QString::fromStdString(ENC("Missing token/hwid/key").decrypt());
        return false;
    }
    if(token.length()<32 || token.length()>128) {
        if(errorOut) *errorOut=QString::fromStdString(ENC("Token length invalid").decrypt());
        return false;
    }
    // Build inner JSON and encrypt with m3xc + HMAC
    // SECURITY challenge-response: client_nonce is a random value generated HERE.
    // The server's Ed25519 attestation covers it, so a captured (token,sig) pair from
    // another session cannot be replayed - the signature would not match our nonce.
    QString clientNonce;
    {
        uint8_t raw[16]={0};
        BCRYPT_ALG_HANDLE hAlg=nullptr;
        if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0)==0){
            if(BCryptGenRandom(hAlg, raw, sizeof(raw), 0)==0){
                char hex[3];
                for(int i=0;i<16;++i){ sprintf_s(hex,"%02x",raw[i]); clientNonce+=hex; }
            }
            BCryptCloseAlgorithmProvider(hAlg,0);
        }
        SecureZeroMemory(raw,sizeof(raw));
    }
    if(clientNonce.isEmpty()) clientNonce = QString::number(QDateTime::currentMSecsSinceEpoch());
    QJsonObject inner;
    inner[QString::fromStdString(ENC("license_key").decrypt())]=licenseKey;
    inner[QString::fromStdString(ENC("hwid").decrypt())]=hwid;
    inner[QString::fromStdString(ENC("token").decrypt())]=token;
    inner[QString::fromStdString(ENC("client_nonce").decrypt())]=clientNonce;
    QString innerStr = QString::fromUtf8(QJsonDocument(inner).toJson(QJsonDocument::Compact));
    QString encKey = astro::security::crypto::deobfuscateEncryptionKey();
    sgTrace("sg: encrypting");
    QString encrypted = astro::security::crypto::lm_m3xcEncrypt(innerStr, encKey);
    // SERVER CONTRACT: worker's m3xcDecrypt REQUIRES "b64.tag" (HMAC-SHA256 of the b64
    // with the derived key) - same format the loader sends. Without the tag it throws
    // "Missing HMAC tag" -> HTTP 400 "Invalid encrypted payload".
    const QByteArray tagBytes = astro::security::crypto::lm_hmacSha256HexDerived(encrypted.toUtf8(), encKey.toUtf8());
    encrypted = encrypted + QStringLiteral(".") + QString::fromLatin1(tagBytes);
    sgTrace("sg: encrypted ok");
    QJsonObject body; body[QString::fromStdString(ENC("encrypted").decrypt())]=encrypted;
    QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);
    QString ts = QString::number(QDateTime::currentSecsSinceEpoch());
    QString sigPath = QString::fromStdString(ENC("/api/session/validate").decrypt());
    QString sigPayload = QString::fromStdString(ENC("POST:").decrypt()) + sigPath + QStringLiteral(":") + ts + QStringLiteral(":") + QString::fromUtf8(payload);
    QByteArray sig = astro::security::crypto::lm_hmacSha256HexDerived(sigPayload.toUtf8(), encKey.toUtf8());

    sgTrace((std::string("sg: REQ ts=") + ts.toStdString() + " sig=" + sig.toStdString()).c_str());
    sgTrace("sg: calling-winhttp");
    std::string respStd;
    const int httpStatus = astro::security::winhttpPostJson(
        astro_config::apiBase().toStdString(), sigPath.toStdString(),
        payload.toStdString(), ts.toStdString(), sig.toStdString(), respStd, 10000);
    const QByteArray respData = QByteArray::fromStdString(respStd);
    sgTrace((std::string("sg: winhttp-status=") + std::to_string(httpStatus)).c_str());
    if (httpStatus <= 0) {
        if(errorOut) *errorOut=QString::fromStdString(ENC("Session validation timeout").decrypt());
        return false;
    }
    if (httpStatus != 200) {
        if(errorOut) *errorOut=QString::fromStdString(ENC("Network error: HTTP ").decrypt()) + QString::number(httpStatus);
        return false;
    }
    QJsonDocument doc = QJsonDocument::fromJson(respData);
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
    bool valid = obj[QString::fromStdString(ENC("valid").decrypt())].toBool(false);
    if (!valid) {
        QString st = obj[QString::fromStdString(ENC("status").decrypt())].toString();
        if (st == QString::fromStdString(ENC("ok").decrypt()) || st == QStringLiteral("ok")) valid = true;
        // also check success
        if (obj.contains("success") && obj["success"].toBool(false)) valid = true;
        if (obj.contains(QString::fromStdString(ENC("success").decrypt())) && obj[QString::fromStdString(ENC("success").decrypt())].toBool(false)) valid = true;
    }
    if(!valid){
        QString err = obj[QString::fromStdString(ENC("error").decrypt())].toString(QString::fromStdString(ENC("Session invalid").decrypt()));
        if(errorOut) *errorOut = err;
        return false;
    }
    // SECURITY: verify the server's Ed25519 attestation against OUR challenge nonce.
    // Without this, anyone with the symmetric ENCRYPTION_KEY could forge {"valid":true}.
    // The private key never leaves the Worker, so only the real server can sign.
    {
        QString sigHex  = obj[QString::fromStdString(ENC("sig").decrypt())].toString();
        QString hwidSrv = obj[QString::fromStdString(ENC("hwid_hash").decrypt())].toString();
        QString tierStr = QString::number(obj[QString::fromStdString(ENC("tier").decrypt())].toInt(-1));
        qint64  expEp   = static_cast<qint64>(obj[QString::fromStdString(ENC("expiry_epoch").decrypt())].toDouble(0));
        if (sigHex.isEmpty() || hwidSrv.isEmpty()) {
            sgTrace("sg: attestation-missing");
            if(errorOut) *errorOut = QString::fromStdString(ENC("Server attestation missing").decrypt());
            return false;
        }
        QByteArray msg;
        msg += licenseKey.toUtf8(); msg += '|';
        msg += hwidSrv.toUtf8();    msg += '|';
        msg += tierStr.toUtf8();    msg += '|';
        msg += QByteArray::number(expEp);
        msg += '|'; msg += clientNonce.toUtf8();
        QByteArray sigBin = QByteArray::fromHex(sigHex.toLatin1());
        QByteArray pubKey = QByteArray::fromHex(
            QByteArrayLiteral("c5d90bc38042d814e4f8bb47d0c59588859f19277075eceec260fdae07b7fdb3"));
        bool sigOk = ed25519_verify(reinterpret_cast<const unsigned char*>(sigBin.constData()),
                                    reinterpret_cast<const unsigned char*>(msg.constData()),
                                    static_cast<size_t>(msg.size()),
                                    reinterpret_cast<const unsigned char*>(pubKey.constData())) == 1;
        if (!sigOk) {
            sgTrace("sg: attestation-INVALID");
            // server attestation invalid (logged via sgTrace)
            if(errorOut) *errorOut = QString::fromStdString(ENC("Server attestation invalid").decrypt());
            return false;
        }
        sgTrace("sg: attestation-ok");
    }
    if (infoOut) {
        infoOut->valid       = true;
        infoOut->tier        = obj[QString::fromStdString(ENC("tier").decrypt())].toInt(-1);
        infoOut->expiryEpoch = static_cast<qint64>(obj[QString::fromStdString(ENC("expiry_epoch").decrypt())].toDouble(0));
        infoOut->hwidHash    = obj[QString::fromStdString(ENC("hwid_hash").decrypt())].toString();
        // sig_lic = atestacion SIN nonce (estable, para license.dat bootstrap);
        // fallback a sig si el server viejo no manda sig_lic.
        QString sigLic = obj[QString::fromStdString(ENC("sig_lic").decrypt())].toString();
        infoOut->sig         = sigLic.isEmpty() ? obj[QString::fromStdString(ENC("sig").decrypt())].toString() : sigLic;
        infoOut->clientNonce = clientNonce;
    }
    return true;
}

} // namespace license
} // namespace astro
