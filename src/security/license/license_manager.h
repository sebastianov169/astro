#pragma once

#include "license_structure.h"
#include "tpm_reader.h"

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
#include <QByteArray>
#include <QJsonObject>
#include <QFileSystemWatcher>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace astro {
namespace license {

class LicenseManager : public QObject {
    Q_OBJECT

public:
    enum class ValidationStatus {
        VALID,
        EXPIRED,
        HWID_MISMATCH,
        SIGNATURE_INVALID,
        NO_LICENSE,
        NETWORK_ERROR,
        SERVER_REJECTED,
        OFFLINE_GRACE
    };
    Q_ENUM(ValidationStatus)

    explicit LicenseManager(QObject* parent = nullptr);
    ~LicenseManager() override;

    // Core operations
    ValidationStatus validate();
    ValidationStatus activate(const QString& licenseKey);

    // Override del hwid canonico: el loader (gatekeeper) pasa el hwid attestado por
    // el server via --astro-hwid. Ese es el binding autoritativo de la sesion.
    void overrideHwid(const QString& hwidHash) { m_hwid.combined_hwid = hwidHash; }
    void refresh();

    // Accessors
    LicenseData currentLicense() const { return m_license; }
    HardwareFingerprint hardwareFingerprint() const { return m_hwid; }
    bool hasValidLicense() const { return m_status == ValidationStatus::VALID || m_status == ValidationStatus::OFFLINE_GRACE; }
    ValidationStatus lastStatus() const { return m_status; }
    QString lastError() const { return m_lastError; }

    // Server config
    void setValidationUrl(const QString& url);
    void setActivationUrl(const QString& url);

signals:
    void validationCompleted(ValidationStatus status);
    void activationCompleted(ValidationStatus status, const QString& message);
    void licenseChanged();
    void errorOccurred(const QString& error);

public slots:
    void startPeriodicCheck(int intervalMs = 300000); // 5 min default
    void stopPeriodicCheck();

    // BUGFIX (first-run bootstrap): persist a server-attested license locally so
    // validate() passes on the next check. Signature is Ed25519 from the Worker.
    bool bootstrapFromSession(const QString& licenseKey, int tier, qint64 expiryEpoch,
                              const QString& hwidHash, const QString& sigHex);

private slots:
    void onValidationReply(QNetworkReply* reply);
    void onActivationReply(QNetworkReply* reply);
    void onPeriodicCheck();
    void onFileChanged(const QString& path);

private:
    // License file I/O
    bool loadLicenseFile();
    bool saveLicenseFile();
    bool deleteLicenseFile();

    // Cryptographic operations
    QByteArray encryptData(const QByteArray& plaintext, const QByteArray& key);
    QByteArray decryptData(const QByteArray& ciphertext, const QByteArray& key);
    bool verifySignature(const QByteArray& data, const QByteArray& signature, const QByteArray& pubKey);
    QByteArray deriveEncryptionKey();

    // Network
    void sendValidationRequest(const QJsonObject& payload);
    void sendActivationRequest(const QJsonObject& payload);

    // Helpers
    QString licenseFilePath() const;
    QString serializeLicense(const LicenseData& lic);
    LicenseData deserializeLicense(const QByteArray& data);
    uint64_t currentTimestamp() const;

    // Ed25519 signature verification (stub — replace with real implementation)
    bool ed25519Verify(const QByteArray& message, const QByteArray& signature, const QByteArray& publicKey);

    HardwareFingerprint    m_hwid;
    LicenseData            m_license;
    ValidationStatus       m_status = ValidationStatus::NO_LICENSE;
    QString                m_lastError;
    QString                m_validationUrl;
    QString                m_activationUrl;

    QNetworkAccessManager* m_nam = nullptr;
    QTimer*                m_refreshTimer = nullptr;
    QFileSystemWatcher*    m_fileWatcher = nullptr;
    bool                   m_loading = false;

    // Embedded public key for signature verification (Ed25519 32-byte)
    static const QByteArray kServerPublicKey;
};

} // namespace license
} // namespace astro
