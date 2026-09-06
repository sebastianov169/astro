#include "encrypted_channel.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslCertificate>
#include <QSslCertificateExtension>
#include <QSslConfiguration>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QDateTime>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <WinSock2.h>

#include <cstring>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef BCRYPT_INIT_AUTHENTICATED_CIPHER_MODE_INFO
#define BCRYPT_INIT_AUTHENTICATED_CIPHER_MODE_INFO(_info, _nonce, _nonceLen, _tag, _tagLen) do { \
    memset(&(_info), 0, sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)); \
    (_info).cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO); \
    (_info).dwInfoVersion = 1; \
    (_info).pbNonce = (PUCHAR)(_nonce); \
    (_info).cbNonce = (_nonceLen); \
    (_info).pbTag = (PUCHAR)(_tag); \
    (_info).cbTag = (_tagLen); \
} while(0)
#endif

namespace astro {
namespace security {

static QByteArray deriveSalt(const QByteArray& license_key, const QByteArray& hwid) {
    QByteArray combined;
    combined.append(ENC("astro-salt-v1").decrypt());
    combined.append(license_key);
    combined.append(hwid);
    return QCryptographicHash::hash(combined, QCryptographicHash::Sha256).left(16);
}

EncryptedChannel::EncryptedChannel(const ChannelConfig& cfg)
    : m_cfg(cfg)
{
    std::fill(m_enc_key.begin(), m_enc_key.end(), 0);
    std::fill(m_dec_key.begin(), m_dec_key.end(), 0);
    std::fill(m_enc_salt.begin(), m_enc_salt.end(), 0);
    std::fill(m_dec_salt.begin(), m_dec_salt.end(), 0);
}

EncryptedChannel::~EncryptedChannel() = default;

void EncryptedChannel::setCredentials(const QByteArray& license_key, const QByteArray& hwid) {
    m_license_key = license_key;
    m_hwid = hwid;
    deriveKeys();
}

QByteArray EncryptedChannel::hkdf(const QByteArray& ikm, const QByteArray& salt,
                                   const QByteArray& info, int length) {
    QByteArray prk = QCryptographicHash::hash(salt + ikm, QCryptographicHash::Sha512);
    QByteArray okm;
    QByteArray t;
    int blocks = (length + 63) / 64;
    for (int i = 1; i <= blocks; ++i) {
        QByteArray counter(static_cast<char>(i), 1);
        t = QCryptographicHash::hash(prk + t + info + counter, QCryptographicHash::Sha512);
        okm.append(t);
    }
    return okm.left(length);
}

void EncryptedChannel::deriveKeys() {
    QByteArray ikm;
    ikm.append(m_license_key);
    ikm.append(m_hwid);

    QByteArray ts = QByteArray::number(static_cast<quint64>(
        QDateTime::currentSecsSinceEpoch() / 3600));
    QByteArray salt = deriveSalt(m_license_key, m_hwid);

    QByteArray enc_info = QByteArray(QByteArray::fromStdString(ENC("astro-enc-key-v1").decrypt())) + ts;
    QByteArray dec_info = QByteArray(QByteArray::fromStdString(ENC("astro-dec-key-v1").decrypt())) + ts;
    QByteArray salt_info = QByteArray(QByteArray::fromStdString(ENC("astro-salt-v1").decrypt())) + ts;

    QByteArray enc_key_raw = hkdf(ikm, salt, enc_info, 32);
    QByteArray dec_key_raw = hkdf(ikm, salt, dec_info, 32);
    QByteArray enc_salt_raw = hkdf(ikm, salt, salt_info, 16);
    QByteArray dec_salt_raw = hkdf(ikm, salt, salt_info + QByteArray("dec"), 16);

    std::memcpy(m_enc_key.data(), enc_key_raw.constData(), 32);
    std::memcpy(m_dec_key.data(), dec_key_raw.constData(), 32);
    std::memcpy(m_enc_salt.data(), enc_salt_raw.constData(), 16);
    std::memcpy(m_dec_salt.data(), dec_salt_raw.constData(), 16);
    m_valid = true;
}

QByteArray EncryptedChannel::aesGcmEncrypt(
    const uint8_t key[32], const uint8_t* plaintext, size_t pt_len,
    uint8_t iv_out[16], uint8_t tag_out[16])
{
    QByteArray ct;
    ct.resize(static_cast<int>(pt_len));

    auto* rng = QRandomGenerator::global();
    for (int i = 0; i < 16; ++i)
        iv_out[i] = static_cast<uint8_t>(rng->bounded(256));

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return ct;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ct;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ct;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead{};
    BCRYPT_INIT_AUTHENTICATED_CIPHER_MODE_INFO(aead,
        reinterpret_cast<PUCHAR>(iv_out), 16,
        tag_out, 16);

    DWORD cbResult = 0;
    status = BCryptEncrypt(hKey,
        (PUCHAR)plaintext, static_cast<ULONG>(pt_len),
        &aead, nullptr, 0,
        reinterpret_cast<PUCHAR>(ct.data()), static_cast<ULONG>(pt_len), &cbResult, 0);

    if (!BCRYPT_SUCCESS(status)) {
        ct.clear();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ct;
}

QByteArray EncryptedChannel::aesGcmDecrypt(
    const uint8_t key[32], const uint8_t iv[16], const uint8_t tag[16],
    const uint8_t* ciphertext, size_t ct_len)
{
    QByteArray pt;
    pt.resize(static_cast<int>(ct_len));

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return {};

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead{};
    BCRYPT_INIT_AUTHENTICATED_CIPHER_MODE_INFO(aead,
        const_cast<PUCHAR>(iv), 16,
        const_cast<PUCHAR>(tag), 16);

    DWORD cbResult = 0;
    status = BCryptDecrypt(hKey,
        (PUCHAR)ciphertext, static_cast<ULONG>(ct_len),
        &aead, nullptr, 0,
        (PUCHAR)pt.data(), static_cast<ULONG>(ct_len), &cbResult, 0);

    if (!BCRYPT_SUCCESS(status)) {
        pt.clear();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return pt;
}

QByteArray EncryptedChannel::buildSecurePayload(const QJsonObject& payload) {
    QByteArray plaintext = QJsonDocument(payload).toJson(QJsonDocument::Compact);

    uint8_t iv[kIvLen]{};
    uint8_t tag[kTagLen]{};
    auto ct = aesGcmEncrypt(m_enc_key.data(),
        reinterpret_cast<const uint8_t*>(plaintext.constData()),
        plaintext.size(), iv, tag);

    QJsonObject envelope;
    envelope["iv"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(iv), kIvLen).toBase64());
    envelope["ct"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(ct.data()), ct.size()).toBase64());
    envelope["tag"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(tag), kTagLen).toBase64());
    envelope["seq"] = static_cast<qint64>(m_seq++);
    envelope["ts"] = static_cast<qint64>(
        QDateTime::currentSecsSinceEpoch());

    return QJsonDocument(envelope).toJson(QJsonDocument::Compact);
}

QJsonObject EncryptedChannel::parseSecureResponse(const QByteArray& raw) {
    auto doc = QJsonDocument::fromJson(raw);
    if (!doc.isObject()) return {};
    auto obj = doc.object();

    QByteArray iv = QByteArray::fromBase64(obj["iv"].toString().toUtf8());
    QByteArray ct = QByteArray::fromBase64(obj["ct"].toString().toUtf8());
    QByteArray tag = QByteArray::fromBase64(obj["tag"].toString().toUtf8());

    if (iv.size() != kIvLen || tag.size() != kTagLen) return {};

    QByteArray pt = aesGcmDecrypt(m_dec_key.data(),
        reinterpret_cast<const uint8_t*>(iv.constData()),
        reinterpret_cast<const uint8_t*>(tag.constData()),
        reinterpret_cast<const uint8_t*>(ct.constData()),
        ct.size());

    if (pt.isEmpty()) return {};
    return QJsonDocument::fromJson(pt).object();
}

QJsonObject EncryptedChannel::postEncrypted(const std::string& endpoint,
                                             const QJsonObject& payload) {
    QByteArray body = buildSecurePayload(payload);

    QNetworkRequest req(QUrl(QString::fromStdString(m_cfg.base_url + endpoint)));
    req.setHeader(QNetworkRequest::ContentTypeHeader, QString::fromStdString(ENC("application/octet-stream").decrypt()));
    req.setTransferTimeout(m_cfg.timeout_ms);

    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    if (!m_cfg.pinned_cert_sha256.empty()) {
        QByteArray pin = QByteArray::fromStdString(m_cfg.pinned_cert_sha256);
        QList<QSslCertificate> certs = ssl.peerCertificateChain();
        if (!certs.isEmpty()) {
            QByteArray cert_hash = QCryptographicHash::hash(
                certs.last().toDer(), QCryptographicHash::Sha256).toHex();
            if (cert_hash != pin) {
                return QJsonObject{{QString::fromStdString(ENC("error").decrypt()), QString::fromStdString(ENC("cert_pin_mismatch").decrypt())}};
            }
        }
    }
    req.setSslConfiguration(ssl);

    QNetworkAccessManager nam;
    QNetworkReply* reply = nam.post(req, body);

    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    if (reply->error() != QNetworkReply::NoError) {
        QByteArray errBody = reply->readAll();
        reply->deleteLater();
        return QJsonObject{{QString::fromStdString(ENC("error").decrypt()), reply->errorString()}, {QString::fromStdString(ENC("body").decrypt()), QString::fromUtf8(errBody)}};
    }

    QByteArray resp = reply->readAll();
    reply->deleteLater();
    return parseSecureResponse(resp);
}

QJsonObject EncryptedChannel::postRaw(const std::string& endpoint, const QByteArray& body) {
    QNetworkRequest req(QUrl(QString::fromStdString(m_cfg.base_url + endpoint)));
    req.setHeader(QNetworkRequest::ContentTypeHeader, QString::fromStdString(ENC("application/json").decrypt()));
    req.setTransferTimeout(m_cfg.timeout_ms);

    QNetworkAccessManager nam;
    QNetworkReply* reply = nam.post(req, body);

    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    if (reply->error() != QNetworkReply::NoError) {
        reply->deleteLater();
        return QJsonObject{{QString::fromStdString(ENC("error").decrypt()), reply->errorString()}};
    }

    QByteArray resp = reply->readAll();
    reply->deleteLater();
    return QJsonDocument::fromJson(resp).object();
}

bool EncryptedChannel::verifyServerCert() const {
    if (m_cfg.pinned_cert_sha256.empty()) return true;

    QNetworkRequest req(QUrl(QString::fromStdString(m_cfg.base_url) + QString::fromStdString(ENC("/verify").decrypt())));
    req.setSslConfiguration(QSslConfiguration::defaultConfiguration());

    QNetworkAccessManager nam;
    QNetworkReply* reply = nam.head(req);

    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    bool ok = (reply->error() == QNetworkReply::NoError ||
               reply->error() == QNetworkReply::ProtocolInvalidOperationError);

    if (ok) {
        QSslCertificate cert = reply->sslConfiguration().peerCertificate();
        QByteArray hash = QCryptographicHash::hash(cert.toDer(), QCryptographicHash::Sha256).toHex();
        ok = (hash == QByteArray::fromStdString(m_cfg.pinned_cert_sha256));
    }

    reply->deleteLater();
    return ok;
}

} // namespace security
} // namespace astro
