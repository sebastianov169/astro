#include "secure_logger.h"
#include "security/config.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QUuid>
#include <QCryptographicHash>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QStandardPaths>
#include <QMutexLocker>
#include <QtEndian>

#include <Windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace astro {
namespace security {

namespace {
    SecureLogger* g_instance = nullptr;
    QMutex g_mutex;

    const QByteArray getEmbedKey() {
        static const QByteArray key = QByteArray::fromHex(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
        return key;
    }
}

const QString SecureLogger::LOG_DIR_NAME = QStringLiteral(QString::fromStdString(ENC("Astro\\logs").decrypt()));
const QString SecureLogger::LOG_FILE_PREFIX = QStringLiteral(QString::fromStdString(ENC("seclog").decrypt()));
const QString SecureLogger::LOG_FILE_EXTENSION = QStringLiteral(QString::fromStdString(ENC(".dat").decrypt()));

SecureLogger::SecureLogger(QObject* parent)
    : QObject(parent)
    , m_nam(new QNetworkAccessManager(this))
    , m_rotationTimer(new QTimer(this))
    , m_telemetryTimer(new QTimer(this))
{
    connect(m_rotationTimer, &QTimer::timeout, this, &SecureLogger::onRotationTimer);
    connect(m_telemetryTimer, &QTimer::timeout, this, [this]() {
        QJsonObject payload;
        payload[ENC("event").decrypt()] = ENC("heartbeat").decrypt();
        payload[ENC("session_id").decrypt()] = m_sessionId;
        payload[ENC("timestamp").decrypt()] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
        payload[ENC("hwid").decrypt()] = HardwareInfo().deviceFingerprint();
        sendTelemetry(payload);
    });
}

SecureLogger::~SecureLogger() {
    shutdown();
}

QString SecureLogger::generateSessionId() {
    QUuid uuid = QUuid::createUuid();
    QByteArray hash = QCryptographicHash::hash(
        uuid.toString().toUtf8() + QDateTime::currentDateTimeUtc().toString(Qt::ISODate).toUtf8(),
        QCryptographicHash::Sha256);
    return hash.left(16).toHex();
}

QString SecureLogger::logDirectory() const {
    QString localAppData = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    if (localAppData.isEmpty()) {
        localAppData = QString::fromLocal8Bit(qgetenv(QString::fromStdString(ENC("LOCALAPPDATA").decrypt())));
    }
    return localAppData + "\\" + LOG_DIR_NAME;
}

QString SecureLogger::logFilePath() const {
    return logDirectory() + "\\" + LOG_FILE_PREFIX +
           QString::number(m_logFileIndex) + LOG_FILE_EXTENSION;
}

void SecureLogger::ensureLogDirectory() {
    QDir dir(logDirectory());
    if (!dir.exists()) {
        dir.mkpath(".");
    }
}

QByteArray SecureLogger::deriveDailyKey() {
    QDate today = QDate::currentDate();
    QByteArray dateBytes = today.toString(QByteArray::fromStdString(ENC("yyyyMMdd").decrypt())).toUtf8();
    QByteArray masterKey = getEmbedKey();

    QByteArray combined = masterKey + dateBytes;
    return QCryptographicHash::hash(combined, QCryptographicHash::Sha256);
}

QByteArray SecureLogger::aesGcmEncrypt(const QByteArray& plaintext, const QByteArray& key) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return QByteArray();

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PVOID)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    BYTE iv[AES_GCM_IV_SIZE]{};
    BCryptGenRandom(hAlg, iv, sizeof(iv), 0);

    DWORD cbPlainText = static_cast<DWORD>(plaintext.size());
    DWORD cbCipherText = cbPlainText;

    BYTE* pOutput = new (std::nothrow) BYTE[cbCipherText + AES_GCM_TAG_SIZE];
    if (!pOutput) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    BCRYPT_AUTH_TAG_INFO authTagInfo{};
    BYTE tag[AES_GCM_TAG_SIZE]{};

    status = BCryptEncrypt(hKey,
        (PUCHAR)plaintext.data(), cbPlainText,
        &authTagInfo, iv, sizeof(iv),
        pOutput, cbCipherText,
        &cbCipherText, 0, iv, sizeof(iv), sizeof(tag));

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        delete[] pOutput;
        return QByteArray();
    }

    memcpy(pOutput + cbCipherText, tag, AES_GCM_TAG_SIZE);

    QByteArray result;
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result.append(reinterpret_cast<const char*>(pOutput), cbCipherText + AES_GCM_TAG_SIZE);

    delete[] pOutput;
    return result;
}

QByteArray SecureLogger::aesGcmDecrypt(const QByteArray& ciphertext, const QByteArray& key) {
    if (ciphertext.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) return QByteArray();

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return QByteArray();

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PVOID)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    const char* data = ciphertext.constData();
    BYTE iv[AES_GCM_IV_SIZE];
    memcpy(iv, data, AES_GCM_IV_SIZE);

    BYTE tag[AES_GCM_TAG_SIZE];
    memcpy(tag, data + ciphertext.size() - AES_GCM_TAG_SIZE, AES_GCM_TAG_SIZE);

    DWORD cbCipherText = static_cast<DWORD>(ciphertext.size() - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE);
    BYTE* pPlainText = new (std::nothrow) BYTE[cbCipherText];
    if (!pPlainText) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    BCRYPT_AUTH_TAG_INFO authTagInfo{};

    status = BCryptDecrypt(hKey,
        (PUCHAR)(data + AES_GCM_IV_SIZE), cbCipherText,
        &authTagInfo, iv, sizeof(iv),
        pPlainText, cbCipherText,
        &cbCipherText, 0, iv, sizeof(iv), sizeof(tag));

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        delete[] pPlainText;
        return QByteArray();
    }

    QByteArray result(reinterpret_cast<const char*>(pPlainText), cbCipherText);
    delete[] pPlainText;
    return result;
}

QByteArray SecureLogger::hmacSign(const QByteArray& data) {
    QByteArray key = deriveDailyKey();

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return QByteArray();

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    BYTE hash[HMAC_SIZE]{};
    DWORD cbHash = HMAC_SIZE;

    status = BCryptHashData(hKey,
        (PUCHAR)data.data(), static_cast<ULONG>(data.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    status = BCryptFinishHash(hKey, hash, cbHash, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return QByteArray();
    return QByteArray(reinterpret_cast<const char*>(hash), HMAC_SIZE);
}

bool SecureLogger::verifyLogIntegrity(const QByteArray& data) {
    if (data.size() < HMAC_SIZE + 1) return false;

    QByteArray payload = data.left(data.size() - HMAC_SIZE);
    QByteArray storedHmac = data.right(HMAC_SIZE);
    QByteArray computedHmac = hmacSign(payload);

    return storedHmac == computedHmac;
}

LogEntry SecureLogger::createEntry(SecurityEventType type, const QString& details,
                                    const QJsonObject& extra) {
    LogEntry entry;
    entry.timestamp = QDateTime::currentDateTimeUtc();
    entry.eventType = type;
    entry.details = details;
    entry.hwid = HardwareInfo().deviceFingerprint();
    entry.ipAddress = m_ipAddress;
    entry.sessionId = m_sessionId;
    entry.extraData = extra;
    return entry;
}

QByteArray SecureLogger::encryptLogEntry(const LogEntry& entry) {
    QJsonObject obj;
    obj[ENC("timestamp").decrypt()] = entry.timestamp.toString(Qt::ISODate);
    obj[ENC("event_type").decrypt()] = static_cast<int>(entry.eventType);
    obj[ENC("details").decrypt()] = entry.details;
    obj[ENC("hwid").decrypt()] = entry.hwid;
    obj["ip"] = entry.ipAddress;
    obj[ENC("session_id").decrypt()] = entry.sessionId;
    if (!entry.extraData.isEmpty()) {
        obj[ENC("extra").decrypt()] = entry.extraData;
    }

    QJsonDocument doc(obj);
    QByteArray plaintext = doc.toJson(QJsonDocument::Compact);

    QByteArray dailyKey = deriveDailyKey();
    QByteArray encrypted = aesGcmEncrypt(plaintext, dailyKey);
    if (encrypted.isEmpty()) return QByteArray();

    QByteArray hmac = hmacSign(encrypted);
    return encrypted + hmac;
}

void SecureLogger::writeEncryptedLog(const QByteArray& encryptedData) {
    QMutexLocker lock(&m_logMutex);

    ensureLogDirectory();
    QFile file(logFilePath());

    qint64 writeSize = encryptedData.size() + sizeof(quint32);

    if (m_currentLogSize + writeSize > m_maxLogFileSize) {
        rotateLogFile();
    }

    if (!file.open(QIODevice::Append | QIODevice::WriteOnly)) {
        emit errorOccurred(file.errorString());
        return;
    }

    quint32 len = static_cast<quint32>(encryptedData.size());
    QByteArray lenBytes(reinterpret_cast<const char*>(&len), sizeof(len));

    file.write(lenBytes);
    file.write(encryptedData);
    file.close();

    m_currentLogSize += writeSize;
}

void SecureLogger::rotateLogFile() {
    QString oldPath = logFilePath();
    if (QFile::exists(oldPath)) {
        QString archivePath = logDirectory() + "\\" + LOG_FILE_PREFIX +
            QString::number(m_logFileIndex) + "_" +
            QDateTime::currentDateTime().toString(ENC("yyyyMMdd_HHmmss").decrypt()) +
            LOG_FILE_EXTENSION + ".gz";

        QFile::rename(oldPath, archivePath);
    }

    m_logFileIndex++;
    m_currentLogSize = 0;
}

void SecureLogger::compressOldLogs() {
    QDir dir(logDirectory());
    QStringList filters;
    filters << ("*_" + QDateTime::currentDateTime().toString(ENC("yyyyMMdd*").decrypt()) + LOG_FILE_EXTENSION + ".gz");
    QFileInfoList files = dir.entryInfoList(filters, QDir::Files);

    for (const auto& file : files) {
        qint64 age = QDateTime::currentDateTime().secsTo(file.lastModified());
        if (age > 7 * 24 * 3600) {
            QFile::remove(file.absoluteFilePath());
        }
    }
}

QString SecureLogger::fetchIpAddress() {
    QNetworkRequest request(QUrl(ENC("https://api.ipify.org?format=json").decrypt()));
    request.setSslConfiguration(QSslConfiguration::defaultConfiguration());

    QNetworkReply* reply = m_nam->get(request);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    QString ip;
    if (reply->error() == QNetworkReply::NoError) {
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        ip = doc.object().value("ip").toString();
    }
    reply->deleteLater();
    return ip;
}

void SecureLogger::sendTelemetry(const QJsonObject& payload) {
    QNetworkRequest request(QUrl(m_telemetryUrl));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QString::fromStdString(ENC("application/json").decrypt()));
    request.setSslConfiguration(QSslConfiguration::defaultConfiguration());

    QJsonDocument doc(payload);
    QNetworkReply* reply = m_nam->post(request, doc.toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        bool success = (reply->error() == QNetworkReply::NoError);
        emit telemetrySent(success);
        reply->deleteLater();
    });
}

void SecureLogger::initialize() {
    if (m_initialized) return;

    m_sessionId = generateSessionId();
    m_ipAddress = fetchIpAddress();

    ensureLogDirectory();

    QFile lastFile(logFilePath());
    if (lastFile.exists()) {
        m_currentLogSize = lastFile.size();
    }

    m_rotationTimer->start(ROTATION_CHECK_MS);
    m_telemetryTimer->start(TELEMETRY_INTERVAL_MS);

    m_initialized = true;

    logSecurityEvent(SecurityEventType::SYSTEM_STARTUP, ENC("Application started").decrypt());

    QJsonObject sysInfo;
    sysInfo[ENC("session_id").decrypt()] = m_sessionId;
    sysInfo["ip"] = m_ipAddress;
    sysInfo[ENC("hwid").decrypt()] = HardwareInfo().deviceFingerprint();
    sysInfo["os"] = QSysInfo::productVersion();
    sysInfo[ENC("build").decrypt()] = QSysInfo::buildVersion();
    sendTelemetry(sysInfo);
}

void SecureLogger::shutdown() {
    if (!m_initialized) return;

    logSecurityEvent(SecurityEventType::SYSTEM_SHUTDOWN, ENC("Application shutting down").decrypt());

    m_rotationTimer->stop();
    m_telemetryTimer->stop();

    m_initialized = false;
}

void SecureLogger::logSecurityEvent(SecurityEventType type, const QString& details,
                                     const QJsonObject& extra) {
    if (!m_initialized) return;

    LogEntry entry = createEntry(type, details, extra);
    QByteArray encrypted = encryptLogEntry(entry);
    if (!encrypted.isEmpty()) {
        writeEncryptedLog(encrypted);
        emit logWritten(entry);
    }
}

void SecureLogger::logStartup() {
    logSecurityEvent(SecurityEventType::SYSTEM_STARTUP, ENC("System initialization complete").decrypt());
}

void SecureLogger::logShutdown() {
    logSecurityEvent(SecurityEventType::SYSTEM_SHUTDOWN, ENC("System shutdown initiated").decrypt());
}

void SecureLogger::logSystemInfo() {
    QJsonObject info;
    HardwareInfo hwInfo;
    SystemFingerprint fp = hwInfo.collect();

    info[ENC("processor").decrypt()] = fp.processorName;
    info[ENC("cores").decrypt()] = static_cast<qint64>(fp.processorCores);
    info["ram"] = static_cast<qint64>(fp.totalRAMBytes);
    info["gpu"] = fp.gpuName;
    info["os"] = fp.osVersion;
    info[ENC("build").decrypt()] = static_cast<qint64>(fp.osBuildNumber);
    info[ENC("disk_serial").decrypt()] = fp.diskSerial;
    info[ENC("bios_serial").decrypt()] = fp.biosSerial;
    info["mac"] = fp.networkMAC;

    logSecurityEvent(SecurityEventType::SYSTEM_STARTUP, ENC("System info collected").decrypt(), info);
}

void SecureLogger::setTelemetryUrl(const QString& url) {
    m_telemetryUrl = url;
}

void SecureLogger::onRotationTimer() {
    rotateLogFile();
    compressOldLogs();
}

void SecureLogger::onTelemetryReply() {
}

void initializeSecureLogging() {
    QMutexLocker lock(&g_mutex);
    if (!g_instance) {
        g_instance = new SecureLogger();
        g_instance->setTelemetryUrl(astro_config::telemetryUrl().toStdString());
        g_instance->initialize();
    }
}

void shutdownSecureLogging() {
    QMutexLocker lock(&g_mutex);
    if (g_instance) {
        g_instance->shutdown();
        delete g_instance;
        g_instance = nullptr;
    }
}

SecureLogger* secureLogger() {
    QMutexLocker lock(&g_mutex);
    return g_instance;
}

} // namespace security
} // namespace astro
