#pragma once

#include "hardware_info.h"

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QJsonObject>
#include <QMutex>
#include <QThread>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QElapsedTimer>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace astro {
namespace security {

enum class SecurityEventType {
    DEBUG_ATTEMPT,
    FRIDA_DETECTED,
    DLL_INJECTION,
    LICENSE_CHANGED,
    LICENSE_VALIDATED,
    LICENSE_EXPIRED,
    HWID_MISMATCH,
    TAMPER_DETECTED,
    ANTI_DUMP_TRIGGERED,
    ANTI_PATCH_TRIGGERED,
    SYSTEM_STARTUP,
    SYSTEM_SHUTDOWN,
    API_CALL,
    NETWORK_ERROR,
    CUSTOM
};

struct LogEntry {
    QDateTime timestamp;
    SecurityEventType eventType;
    QString details;
    QString hwid;
    QString ipAddress;
    QString sessionId;
    QJsonObject extraData;
};

class SecureLogger : public QObject {
    Q_OBJECT

public:
    explicit SecureLogger(QObject* parent = nullptr);
    ~SecureLogger() override;

    SecureLogger(const SecureLogger&) = delete;
    SecureLogger& operator=(const SecureLogger&) = delete;

    void initialize();
    void shutdown();

    void logSecurityEvent(SecurityEventType type, const QString& details,
                          const QJsonObject& extra = QJsonObject());
    void logStartup();
    void logShutdown();
    void logSystemInfo();

    void setTelemetryUrl(const QString& url);
    void setMaxLogFileSize(qint64 bytes) { m_maxLogFileSize = bytes; }

    QString sessionId() const { return m_sessionId; }

signals:
    void logWritten(const LogEntry& entry);
    void telemetrySent(bool success);
    void errorOccurred(const QString& error);

private slots:
    void onRotationTimer();
    void onTelemetryReply();

private:
    QString generateSessionId();
    QByteArray deriveDailyKey();
    QByteArray encryptLogEntry(const LogEntry& entry);
    QByteArray hmacSign(const QByteArray& data);
    bool verifyLogIntegrity(const QByteArray& data);
    void writeEncryptedLog(const QByteArray& encryptedData);
    void rotateLogFile();
    void compressOldLogs();
    void sendTelemetry(const QJsonObject& payload);
    QString logFilePath() const;
    QString logDirectory() const;
    void ensureLogDirectory();
    LogEntry createEntry(SecurityEventType type, const QString& details,
                         const QJsonObject& extra = QJsonObject());

    QByteArray aesGcmEncrypt(const QByteArray& plaintext, const QByteArray& key);
    QByteArray aesGcmDecrypt(const QByteArray& ciphertext, const QByteArray& key);

    QString fetchIpAddress();

    QNetworkAccessManager* m_nam = nullptr;
    QTimer* m_rotationTimer = nullptr;
    QTimer* m_telemetryTimer = nullptr;
    QMutex m_logMutex;
    QElapsedTimer m_elapsedTimer;

    QString m_sessionId;
    QString m_ipAddress;
    QString m_telemetryUrl;
    qint64 m_maxLogFileSize = 10 * 1024 * 1024;
    qint64 m_currentLogSize = 0;
    int m_logFileIndex = 0;
    bool m_initialized = false;

    static const QString LOG_DIR_NAME;
    static const QString LOG_FILE_PREFIX;
    static const QString LOG_FILE_EXTENSION;
    static constexpr int ROTATION_CHECK_MS = 60000;
    static constexpr int TELEMETRY_INTERVAL_MS = 300000;
    static constexpr int HMAC_SIZE = 32;
    static constexpr int AES_GCM_IV_SIZE = 12;
    static constexpr int AES_GCM_TAG_SIZE = 16;
};

void initializeSecureLogging();
void shutdownSecureLogging();
SecureLogger* secureLogger();

} // namespace security
} // namespace astro
