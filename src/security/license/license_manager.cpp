#pragma warning(disable: 4996)
#include "license_manager.h"
#include "security/config.h"
#include "security/crypto/string_encrypt.h"
#include "security/crypto/key_obfuscation.h"
#include "security/config/astro_paths.h"
#include "security/crypto/m3xc.h"
#include "security/crypto/ed25519/ed25519.h"
#include "security/crypto/obfuscation.h"

#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QStandardPaths>
#include <QUrl>
#include <QElapsedTimer>
#include <QDateTime>
#include <QtEndian>

#include <bcrypt.h>
#include <windows.h>

#include <array>
#include <cstring>
#include <intrin.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "bcrypt.lib")

namespace astro {
namespace license {

// Canonical license attestation payload - MUST match worker licenseSignature():
// `${license_key}|${hwid_hash}|${tier}|${expiry}`
static QByteArray licenseCanonicalPayload(const astro::license::LicenseData& lic) {
    QByteArray p;
    p += lic.license_key.toUtf8();
    p += '|';
    p += lic.hwid_hash.toUtf8();
    p += '|';
    p += QByteArray::number(static_cast<qlonglong>(lic.tier));
    p += '|';
    p += QByteArray::number(static_cast<qlonglong>(lic.expiry));
    return p;
}


// ---------------------------------------------------------------------------
// Embedded server public key (Ed25519, 32 bytes)
// Replace with actual server public key before production deployment
// ---------------------------------------------------------------------------
const QByteArray LicenseManager::kServerPublicKey =
    QByteArray::fromHex("c5d90bc38042d814e4f8bb47d0c59588859f19277075eceec260fdae07b7fdb3");

// ---------------------------------------------------------------------------
// AES-256-GCM constants
// ---------------------------------------------------------------------------
static constexpr int kAesKeySize    = 32;
static constexpr int kAesIvSize     = 12;
static constexpr int kAesTagSize    = 16;

LicenseManager::LicenseManager(QObject* parent)
    : QObject(parent)
    , m_nam(new QNetworkAccessManager(this))
    , m_refreshTimer(new QTimer(this))
    , m_fileWatcher(new QFileSystemWatcher(this))
{
    m_validationUrl  = astro_config::validateUrl();
    m_activationUrl  = astro_config::activateUrl();

    connect(m_nam, &QNetworkAccessManager::finished,
            this, &LicenseManager::onValidationReply);

    connect(m_refreshTimer, &QTimer::timeout,
            this, &LicenseManager::onPeriodicCheck);

    // (file watcher disabled - see saveLicenseFile note)

    // Read hardware fingerprint once
    TpmReader reader;
    m_hwid = reader.readFingerprint();

    if (!m_hwid.isValid()) {
        qWarning() << "[LicenseManager] Hardware fingerprint incomplete";
    }

    // Watch license file for external changes
    QString licPath = licenseFilePath();
    if (QFile::exists(licPath)) {
        m_fileWatcher->addPath(licPath);
    }

    loadLicenseFile();
}

LicenseManager::~LicenseManager() {
    stopPeriodicCheck();
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------
LicenseManager::ValidationStatus LicenseManager::validate() {
    if (m_license.hwid_hash.isEmpty()) {
        m_status = ValidationStatus::NO_LICENSE;
        m_lastError = QStringLiteral("No license installed");
        emit validationCompleted(m_status);
        return m_status;
    }

    // 1. Check HWID match
    if (m_license.hwid_hash != m_hwid.combined_hwid) {
        m_status = ValidationStatus::HWID_MISMATCH;
        m_lastError = QStringLiteral("License not bound to this hardware");
        emit validationCompleted(m_status);
        return m_status;
    }

    // 2. Check expiry - HARDENED: no offline grace without server-signed token
    // Previously isWithinGrace returned OFFLINE_GRACE as valid local, allowing firewall bypass.
    // Now expired is always EXPIRED locally; grace only via server heartbeat with signed expiry.
    uint64_t now = currentTimestamp();
    if (m_license.isExpired(now)) {
        m_status = ValidationStatus::EXPIRED;
        m_lastError = QStringLiteral("License expired");
        emit validationCompleted(m_status);
        return m_status;
    }

    // 3. Check signature (local static check) - canonical payload matches server
    QByteArray sigPayload = licenseCanonicalPayload(m_license);
    if (!ed25519Verify(sigPayload, m_license.signature, kServerPublicKey)) {
        m_status = ValidationStatus::SIGNATURE_INVALID;
        m_lastError = QStringLiteral("License signature invalid");
        emit validationCompleted(m_status);
        return m_status;
    }

    // All local checks pass — now do online validation
    QJsonObject payload;
    payload["hwid"]     = m_hwid.combined_hwid;
    payload["key"]      = m_license.license_key;
    payload["tier"]     = static_cast<int>(m_license.tier);
    payload["expiry"]   = static_cast<qint64>(m_license.expiry);
    payload["nonce"]    = QString::number(QDateTime::currentMSecsSinceEpoch());

    sendValidationRequest(payload);

    // Return current local status; network callback will update
    m_status = ValidationStatus::VALID;
    m_lastError.clear();
    emit validationCompleted(m_status);
    return m_status;
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------
LicenseManager::ValidationStatus LicenseManager::activate(const QString& licenseKey) {
    if (m_hwid.combined_hwid.isEmpty()) {
        m_status = ValidationStatus::HWID_MISMATCH;
        m_lastError = QStringLiteral("Hardware fingerprint unavailable");
        emit activationCompleted(m_status, m_lastError);
        return m_status;
    }

    QJsonObject payload;
    payload["hwid"]   = m_hwid.combined_hwid;
    payload["key"]    = licenseKey;
    payload["tpm"]    = m_hwid.tpm_manufacturer;
    payload["nonce"]  = QString::number(QDateTime::currentMSecsSinceEpoch());

    sendActivationRequest(payload);

    // Will be updated by onActivationReply
    return m_status;
}

// ---------------------------------------------------------------------------
// Refresh — re-validate and reload from disk
// ---------------------------------------------------------------------------
void LicenseManager::refresh() {
    loadLicenseFile();
    validate();
}

// ---------------------------------------------------------------------------
// Periodic check
// ---------------------------------------------------------------------------
void LicenseManager::startPeriodicCheck(int intervalMs) {
    m_refreshTimer->start(intervalMs);
}

void LicenseManager::stopPeriodicCheck() {
    m_refreshTimer->stop();
}

void LicenseManager::onPeriodicCheck() {
    validate();
}

// ---------------------------------------------------------------------------
// File watcher
// ---------------------------------------------------------------------------
void LicenseManager::onFileChanged(const QString& path) {
    Q_UNUSED(path);
    if (!m_loading) {
        loadLicenseFile();
        validate();
    }
}

// ---------------------------------------------------------------------------
// Network callbacks
// ---------------------------------------------------------------------------
void LicenseManager::onValidationReply(QNetworkReply* reply) {
    JUNK_CODE;
    if (reply->error() != QNetworkReply::NoError) {
        m_status = ValidationStatus::NETWORK_ERROR;
        m_lastError = reply->errorString();
        emit validationCompleted(m_status);
        reply->deleteLater();
        return;
    }

    QByteArray responseData = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(responseData);
    QJsonObject obj = doc.object();
    if (obj.contains(QString::fromStdString(ENC("encrypted").decrypt()))) {
        QString encResp = obj[QString::fromStdString(ENC("encrypted").decrypt())].toString();
        if (!encResp.isEmpty()) {
            QString encKey = astro::security::crypto::deobfuscateEncryptionKey();
            QString decStr = astro::security::crypto::lm_m3xcDecrypt(encResp, encKey);
            if (!decStr.isEmpty()) {
                QJsonDocument decDoc = QJsonDocument::fromJson(decStr.toUtf8());
                if (decDoc.isObject()) obj = decDoc.object();
            }
        }
    }

    bool serverValid = obj["valid"].toBool(false);

    // SECURITY FIX: verify the Ed25519 attestation (sig2) before accepting valid=true.
    // Without this, a MITM with ENCRYPTION_KEY could forge {"valid":true} responses.
    if (serverValid) {
        QString sig2Hex  = obj[QString::fromStdString(ENC("sig2").decrypt())].toString();
        QString hwidSrv  = obj[QString::fromStdString(ENC("hwid_hash").decrypt())].toString();
        int      tierSrv = obj[QString::fromStdString(ENC("tier").decrypt())].toInt(-1);
        qint64   expEpSrv= static_cast<qint64>(obj[QString::fromStdString(ENC("expiry_epoch").decrypt())].toDouble(0));
        if (sig2Hex.isEmpty() || hwidSrv.isEmpty()) {
            m_status = ValidationStatus::SIGNATURE_INVALID;
            m_lastError = QStringLiteral("Server attestation missing");
            emit validationCompleted(m_status);
            reply->deleteLater();
            return;
        }
        if (expEpSrv == 0) expEpSrv = static_cast<qint64>(m_license.expiry); // fallback to stored expiry
        QByteArray msg;
        msg += m_license.license_key.toUtf8(); msg += '|';
        msg += hwidSrv.toUtf8();               msg += '|';
        msg += QByteArray::number(tierSrv);    msg += '|';
        msg += QByteArray::number(expEpSrv);
        QByteArray sigBin2 = QByteArray::fromHex(sig2Hex.toLatin1());
        if (!ed25519Verify(msg, sigBin2, kServerPublicKey)) {
            m_status = ValidationStatus::SIGNATURE_INVALID;
            m_lastError = QStringLiteral("Server license signature invalid");
            emit validationCompleted(m_status);
            deleteLicenseFile();
            reply->deleteLater();
            return;
        }
    }
    QString serverMsg = obj["message"].toString();

    if (serverValid) {
        // Update expiry from server response
        if (obj.contains("new_expiry")) {
            m_license.expiry = static_cast<uint64_t>(obj["new_expiry"].toInteger());
            saveLicenseFile();
        }
        m_status = ValidationStatus::VALID;
        m_lastError.clear();
    } else {
        m_status = ValidationStatus::SERVER_REJECTED;
        m_lastError = serverMsg.isEmpty() ? QStringLiteral("Server rejected license") : serverMsg;

        // If server says HWID mismatch, clear the license
        if (obj["error"].toString() == "hwid_mismatch") {
            deleteLicenseFile();
        }
    }

    emit validationCompleted(m_status);
    reply->deleteLater();
}

void LicenseManager::onActivationReply(QNetworkReply* reply) {
    JUNK_CODE;
    if (reply->error() != QNetworkReply::NoError) {
        m_status = ValidationStatus::NETWORK_ERROR;
        m_lastError = reply->errorString();
        emit activationCompleted(m_status, m_lastError);
        reply->deleteLater();
        return;
    }

    QByteArray responseData = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(responseData);
    QJsonObject obj = doc.object();
    if (obj.contains(QString::fromStdString(ENC("encrypted").decrypt()))) {
        QString encResp = obj[QString::fromStdString(ENC("encrypted").decrypt())].toString();
        if (!encResp.isEmpty()) {
            QString encKey = astro::security::crypto::deobfuscateEncryptionKey();
            QString decStr = astro::security::crypto::lm_m3xcDecrypt(encResp, encKey);
            if (!decStr.isEmpty()) {
                QJsonDocument decDoc = QJsonDocument::fromJson(decStr.toUtf8());
                if (decDoc.isObject()) obj = decDoc.object();
            }
        }
    }

    bool success = obj["success"].toBool(false);
    QString message = obj["message"].toString();

    if (success) {
        // Parse license from response
        QJsonObject licObj = obj["license"].toObject();
        if (licObj.isEmpty()) {
            m_status = ValidationStatus::SERVER_REJECTED;
            m_lastError = QStringLiteral("Server returned empty license");
            emit activationCompleted(m_status, m_lastError);
            reply->deleteLater();
            return;
        }

        LicenseData newLic = LicenseData::fromJson(licObj);
        newLic.hwid_hash = m_hwid.combined_hwid; // Enforce binding

        QByteArray sigHex = licObj["sig"].toString().toUtf8();
        newLic.signature = QByteArray::fromHex(sigHex);

        // Verify signature before accepting - canonical payload matches server
        QByteArray sigPayload = licenseCanonicalPayload(newLic);
        if (!ed25519Verify(sigPayload, newLic.signature, kServerPublicKey)) {
            m_status = ValidationStatus::SIGNATURE_INVALID;
            m_lastError = QStringLiteral("Server license signature invalid");
            emit activationCompleted(m_status, m_lastError);
            reply->deleteLater();
            return;
        }

        m_license = newLic;
        if (saveLicenseFile()) {
            m_status = ValidationStatus::VALID;
            m_lastError.clear();
            emit licenseChanged();
            emit activationCompleted(m_status, QStringLiteral("License activated successfully"));
        } else {
            m_status = ValidationStatus::NETWORK_ERROR;
            m_lastError = QStringLiteral("Failed to save license file");
            emit activationCompleted(m_status, m_lastError);
        }
    } else {
        m_status = ValidationStatus::SERVER_REJECTED;
        m_lastError = message.isEmpty() ? QStringLiteral("Activation failed") : message;
        emit activationCompleted(m_status, m_lastError);
    }

    reply->deleteLater();
}

// ---------------------------------------------------------------------------
// License file I/O
// ---------------------------------------------------------------------------
QString LicenseManager::licenseFilePath() const {
    // Rutas centralizadas en astro_paths.h (rename-proof, cifradas)
    QString localAppData = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QDir dir(localAppData);
    const QString sub = astro::security::paths::dataSubdir();
    if (!dir.exists(sub)) {
        dir.mkpath(sub);
    }
    return dir.absoluteFilePath(sub + "/" + astro::security::paths::licenseDatNameSafe());
}

bool LicenseManager::loadLicenseFile() {
    m_loading = true;

    QString path = licenseFilePath();
    QFile file(path);

    if (!file.exists()) {
        m_loading = false;
        return false;
    }

    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "[LicenseManager] Cannot open license file:" << path;
        m_loading = false;
        return false;
    }

    QByteArray encryptedData = file.readAll();
    file.close();

    QByteArray key = deriveEncryptionKey();
    QByteArray decryptedData = decryptData(encryptedData, key);

    if (decryptedData.isEmpty()) {
        qWarning() << "[LicenseManager] Failed to decrypt license file";
        deleteLicenseFile(); // Remove corrupted file
        m_loading = false;
        return false;
    }

    QJsonDocument doc = QJsonDocument::fromJson(decryptedData);
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "[LicenseManager] Invalid license JSON";
        m_loading = false;
        return false;
    }

    m_license = LicenseData::fromJson(doc.object());

    // Re-attach signature
    QByteArray sigHex = doc.object()["sig"].toString().toUtf8();
    m_license.signature = QByteArray::fromHex(sigHex);

    m_loading = false;
    return true;
}

bool LicenseManager::saveLicenseFile() {
    QJsonObject licObj = m_license.toJson();
    licObj["sig"] = QString::fromLatin1(m_license.signature.toHex());

    QByteArray jsonData = QJsonDocument(licObj).toJson(QJsonDocument::Compact);
    QByteArray key = deriveEncryptionKey();
    QByteArray encryptedData = encryptData(jsonData, key);

    if (encryptedData.isEmpty()) {
        qWarning() << "[LicenseManager] Failed to encrypt license data";
        return false;
    }

    QString path = licenseFilePath();
    QFile file(path);

    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "[LicenseManager] Cannot write license file:" << path;
        return false;
    }

    file.write(encryptedData);
    file.close();

    // WATCHER DISABLED (2026-08-22): QFileSystemWatcher's native thread interacted badly
    // with the /GL+CFG build (stack-cookie fastfail 0xC0000409 right after save) and its
    // failure path deleted freshly-written licenses mid-race. Tamper protection for the
    // license file remains via AES-GCM (tag mismatch = rejected) + Ed25519 signature.
    return true;
}

// ---------------------------------------------------------------------------
// First-run bootstrap: build + persist a server-attested license file
// ---------------------------------------------------------------------------
bool LicenseManager::bootstrapFromSession(const QString& licenseKey, int tier, qint64 expiryEpoch,
                                          const QString& hwidHash, const QString& sigHex) {
    if (licenseKey.isEmpty() || hwidHash.isEmpty() || sigHex.isEmpty()) return false;
    if (sigHex.size() != 128) return false;

    LicenseData lic;
    lic.license_key = licenseKey;
    // Guardar el hwidHash ATTESTED por el server (mismo input de la firma Ed25519).
    // El loader (gatekeeper) es la autoridad del hwid; Astro confia en el attestation.
    lic.hwid_hash   = hwidHash;
    lic.tier        = static_cast<LicenseTier>(tier);
    lic.expiry      = static_cast<uint64_t>(expiryEpoch);
    lic.signature   = QByteArray::fromHex(sigHex.toLatin1());

    // Server attests with the SERVER-side hwid binding. Verify against canonical payload
    // built from the server values (not our local fingerprint) to match its signing input.
    QByteArray canonical;
    canonical += lic.license_key.toUtf8();
    canonical += '|';
    canonical += hwidHash.toUtf8();
    canonical += '|';
    canonical += QByteArray::number(static_cast<qlonglong>(lic.tier));
    canonical += '|';
    canonical += QByteArray::number(expiryEpoch);

    const bool sigOk = ed25519Verify(canonical, lic.signature, kServerPublicKey);
    if (!sigOk) {
        qCritical() << "[LicenseManager] bootstrap signature invalid";
        return false;
    }

    m_license = lic;
    const bool saved = saveLicenseFile();
    return saved;
}

bool LicenseManager::deleteLicenseFile() {
    QString path = licenseFilePath();
    if (QFile::exists(path)) {
        return QFile::remove(path);
    }
    return true;
}

// ---------------------------------------------------------------------------
// AES-256-GCM encryption/decryption
// ---------------------------------------------------------------------------
QByteArray LicenseManager::deriveEncryptionKey() {
    // Derive key from HWID using HKDF-like construction
    QByteArray salt = QByteArray(ENC("astro_license_v1_").decrypt().c_str());
    QByteArray ikm = m_hwid.combined_hwid.toUtf8();

    QByteArray material = salt + ikm;
    QByteArray hash = QCryptographicHash::hash(material, QCryptographicHash::Sha512);

    // Use first 32 bytes as AES-256 key
    return hash.left(kAesKeySize);
}

QByteArray LicenseManager::encryptData(const QByteArray& plaintext, const QByteArray& key) {
    if (key.size() != kAesKeySize) return {};

    // Generate random IV
    QByteArray iv(kAesIvSize, 0);
    BCRYPT_ALG_HANDLE hRng = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);

    if (!BCRYPT_SUCCESS(status)) return {};

    status = BCryptGenRandom(
        hRng,
        reinterpret_cast<PUCHAR>(iv.data()),
        static_cast<ULONG>(iv.size()),
        0
    );
    BCryptCloseAlgorithmProvider(hRng, 0);

    if (!BCRYPT_SUCCESS(status)) return {};

    // Open AES-GCM provider
    BCRYPT_ALG_HANDLE hAes = 0;
    status = BCryptOpenAlgorithmProvider(
        &hAes,
        BCRYPT_AES_ALGORITHM,
        nullptr,
        0
    );
    if (!BCRYPT_SUCCESS(status)) return {};

    status = BCryptSetProperty(
        hAes,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM),
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAes, 0);
        return {};
    }

    BCRYPT_KEY_HANDLE hKey = 0;
    status = BCryptGenerateSymmetricKey(
        hAes,
        &hKey,
        nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(key.constData())),
        static_cast<ULONG>(key.size()),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAes, 0);
        return {};
    }

    // Allocate output buffer
    ULONG cbCipherText = static_cast<ULONG>(plaintext.size());
    QByteArray cipherText(cbCipherText, 0);

    // GCM auth info (additional authenticated data)
    QByteArray authInfo = QByteArray(ENC("astro_license").decrypt().c_str());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aeadInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(aeadInfo);
    aeadInfo.pbNonce   = reinterpret_cast<PUCHAR>(iv.data());
    aeadInfo.cbNonce   = static_cast<ULONG>(iv.size());
    aeadInfo.pbAuthData = reinterpret_cast<PUCHAR>(authInfo.data());
    aeadInfo.cbAuthData = static_cast<ULONG>(authInfo.size());
    aeadInfo.pbTag    = reinterpret_cast<PUCHAR>(cipherText.data() + cbCipherText - kAesTagSize);
    aeadInfo.cbTag    = static_cast<ULONG>(kAesTagSize);

    // Actually, we need IV + ciphertext + tag. Let's restructure:
    // Layout: [IV (12)] [CIPHERTEXT (N)] [TAG (16)]
    QByteArray result;
    result.append(iv);

    // BUFFER FIX: output buffer must hold ciphertext + the 16-byte GCM tag that
    // BCryptEncrypt writes at pbTag. Previously it was sized to plaintext only and
    // BCryptEncrypt overwrote 16 bytes past the allocation (heap corruption,
    // 0xC0000374 crashes on some machines - caught with AddressSanitizer).
    ULONG cbResult = static_cast<ULONG>(plaintext.size()) + kAesTagSize;
    QByteArray outputBuf(cbResult, 0);

    aeadInfo.pbTag = reinterpret_cast<PUCHAR>(outputBuf.data()) + plaintext.size();
    aeadInfo.cbTag = static_cast<ULONG>(kAesTagSize);

    status = BCryptEncrypt(
        hKey,
        reinterpret_cast<PUCHAR>(const_cast<char*>(plaintext.constData())),
        static_cast<ULONG>(plaintext.size()),
        &aeadInfo,
        nullptr, 0,
        reinterpret_cast<PUCHAR>(outputBuf.data()),
        cbResult,
        &cbResult,
        0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);

    if (!BCRYPT_SUCCESS(status)) return {};

    result.append(outputBuf);
    return result;
}

QByteArray LicenseManager::decryptData(const QByteArray& ciphertext, const QByteArray& key) {
    if (key.size() != kAesKeySize) return {};
    if (ciphertext.size() < kAesIvSize + kAesTagSize) return {};

    // Parse layout: [IV (12)] [CIPHERTEXT (N)] [TAG (16)]
    QByteArray iv = ciphertext.left(kAesIvSize);
    QByteArray tag = ciphertext.right(kAesTagSize);
    QByteArray encryptedPayload = ciphertext.mid(kAesIvSize, ciphertext.size() - kAesIvSize - kAesTagSize);

    // Open AES-GCM provider
    BCRYPT_ALG_HANDLE hAes = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return {};

    status = BCryptSetProperty(
        hAes,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM),
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAes, 0);
        return {};
    }

    BCRYPT_KEY_HANDLE hKey = 0;
    status = BCryptGenerateSymmetricKey(
        hAes,
        &hKey,
        nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(key.constData())),
        static_cast<ULONG>(key.size()),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAes, 0);
        return {};
    }

    ULONG cbPlainText = static_cast<ULONG>(encryptedPayload.size());
    QByteArray plainText(cbPlainText, 0);

    QByteArray authInfo = QByteArray(ENC("astro_license").decrypt().c_str());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aeadInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(aeadInfo);
    aeadInfo.pbNonce    = reinterpret_cast<PUCHAR>(iv.data());
    aeadInfo.cbNonce    = static_cast<ULONG>(iv.size());
    aeadInfo.pbAuthData = reinterpret_cast<PUCHAR>(authInfo.data());
    aeadInfo.cbAuthData = static_cast<ULONG>(authInfo.size());
    aeadInfo.pbTag     = reinterpret_cast<PUCHAR>(tag.data());
    aeadInfo.cbTag     = static_cast<ULONG>(kAesTagSize);

    status = BCryptDecrypt(
        hKey,
        reinterpret_cast<PUCHAR>(const_cast<char*>(encryptedPayload.constData())),
        static_cast<ULONG>(encryptedPayload.size()),
        &aeadInfo,
        nullptr, 0,
        reinterpret_cast<PUCHAR>(plainText.data()),
        cbPlainText,
        &cbPlainText,
        0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);

    if (!BCRYPT_SUCCESS(status)) {
        qWarning() << "[LicenseManager] AES-GCM decryption failed:" << status;
        return {};
    }

    return plainText;
}

// ---------------------------------------------------------------------------
// Network requests
// ---------------------------------------------------------------------------
void LicenseManager::sendValidationRequest(const QJsonObject& payload) {
    JUNK_CODE;
    if (OPAQUE_PRED_TRUE((uint64_t)payload.size() ^ 0xC0FFEEULL)) { JUNK_CODE; }
    FLATTEN_BEGIN(0xA11C)
        FLATTEN_CASE(0) {
            QUrl url(m_validationUrl);
            QNetworkRequest request(url);
            request.setHeader(QNetworkRequest::ContentTypeHeader, QString::fromStdString(ENC("application/json").decrypt()));
            ASTRO_AI_TRAP();
            QByteArray inner = QJsonDocument(payload).toJson(QJsonDocument::Compact);
            QString encKey = astro::security::crypto::deobfuscateEncryptionKey();
            QString encrypted = astro::security::crypto::lm_m3xcEncrypt(QString::fromUtf8(inner), encKey);
            QJsonObject wrapper; wrapper[QString::fromStdString(ENC("encrypted").decrypt())] = encrypted;
            QByteArray body = QJsonDocument(wrapper).toJson(QJsonDocument::Compact);
            QString ts = QString::number(QDateTime::currentSecsSinceEpoch());
            QByteArray payloadHmac = (QString::fromStdString(ENC("POST:").decrypt()) + url.path() + QStringLiteral(":") + ts + QStringLiteral(":") + QString::fromUtf8(body)).toUtf8();
            QByteArray sig = astro::security::crypto::lm_hmacSha256HexDerived(payloadHmac, encKey.toUtf8());
            request.setRawHeader(QByteArray::fromStdString(ENC("X-Timestamp").decrypt()), ts.toUtf8());
            request.setRawHeader(QByteArray::fromStdString(ENC("X-Signature").decrypt()), sig);
            request.setTransferTimeout(10000);
            request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
            m_nam->post(request, body);
            JUNK_CODE;
            FLATTEN_GOTO(1)
        }
        FLATTEN_CASE(1) {
        }
    FLATTEN_END
}

void LicenseManager::sendActivationRequest(const QJsonObject& payload) {
    JUNK_CODE;
    if (OPAQUE_PRED_TRUE((uint64_t)payload.size() ^ 0xDEADBEEFULL)) { JUNK_CODE; }
    FLATTEN_BEGIN(0xB22D)
        FLATTEN_CASE(0) {
            QUrl url(m_activationUrl);
            QNetworkRequest request(url);
            request.setHeader(QNetworkRequest::ContentTypeHeader, QString::fromStdString(ENC("application/json").decrypt()));
            ASTRO_AI_TRAP();
            QByteArray inner = QJsonDocument(payload).toJson(QJsonDocument::Compact);
            QString encKey = astro::security::crypto::deobfuscateEncryptionKey();
            QString encrypted = astro::security::crypto::lm_m3xcEncrypt(QString::fromUtf8(inner), encKey);
            QJsonObject wrapper; wrapper[QString::fromStdString(ENC("encrypted").decrypt())] = encrypted;
            QByteArray body = QJsonDocument(wrapper).toJson(QJsonDocument::Compact);
            QString ts = QString::number(QDateTime::currentSecsSinceEpoch());
            QByteArray payloadHmac = (QString::fromStdString(ENC("POST:").decrypt()) + url.path() + QStringLiteral(":") + ts + QStringLiteral(":") + QString::fromUtf8(body)).toUtf8();
            QByteArray sig = astro::security::crypto::lm_hmacSha256HexDerived(payloadHmac, encKey.toUtf8());
            request.setRawHeader(QByteArray::fromStdString(ENC("X-Timestamp").decrypt()), ts.toUtf8());
            request.setRawHeader(QByteArray::fromStdString(ENC("X-Signature").decrypt()), sig);
            request.setTransferTimeout(15000);
            request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
            m_nam->post(request, body);
            JUNK_CODE;
            FLATTEN_GOTO(1)
        }
        FLATTEN_CASE(1) {
        }
    FLATTEN_END
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
QString LicenseManager::serializeLicense(const LicenseData& lic) {
    QJsonObject obj = lic.toJson();
    obj["sig"] = QString::fromLatin1(lic.signature.toHex());
    return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

LicenseData LicenseManager::deserializeLicense(const QByteArray& data) {
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) return {};

    QJsonObject obj = doc.object();
    LicenseData lic = LicenseData::fromJson(obj);
    lic.signature = QByteArray::fromHex(obj["sig"].toString().toUtf8());
    return lic;
}

uint64_t LicenseManager::currentTimestamp() const {
    return static_cast<uint64_t>(QDateTime::currentDateTimeUtc().toSecsSinceEpoch());
}

void LicenseManager::setValidationUrl(const QString& url) {
    m_validationUrl = url;
}

void LicenseManager::setActivationUrl(const QString& url) {
    m_activationUrl = url;
}

// ---------------------------------------------------------------------------
// Ed25519 signature verification (production: use libsodium or Windows CNG)
// This is a stub that accepts all signatures in development mode.
// Replace with real Ed25519 verification before shipping.
// ---------------------------------------------------------------------------
bool LicenseManager::ed25519Verify(const QByteArray& message, const QByteArray& signature, const QByteArray& publicKey) {
    // SECURITY: true Ed25519 verification (orlp public-domain impl). The client embeds ONLY
    // the server public key; licenses are signed with the private key kept as a Worker secret.
    if (signature.size() != 64 || publicKey.size() != 32) return false;
    return ed25519_verify(reinterpret_cast<const unsigned char*>(signature.constData()),
                          reinterpret_cast<const unsigned char*>(message.constData()),
                          static_cast<size_t>(message.size()),
                          reinterpret_cast<const unsigned char*>(publicKey.constData())) == 1;
}

} // namespace license
} // namespace astro
