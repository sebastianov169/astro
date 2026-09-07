// =====================================================================
// SCOPE: m3xc es OFUSCACION DE TRANSPORTE unicamente. No es criptografia estandar.
// Autenticidad de requests -> HMAC-SHA256 (lm_deriveHmacKey).
// Autenticidad de licencias -> Ed25519 (clave publica en ed25519/).
// No usar m3xc para proteger secretos ni como base de confianza.
// =====================================================================
#pragma once
#undef OPAQUE
#include <QString>
#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageAuthenticationCode>
#include <QCryptographicHash>
#include <cstdint>
#include <vector>
#include <cstring>
#include "security/crypto/string_encrypt.h"
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"

namespace astro {
namespace security {
namespace crypto {

// ---------------------------------------------------------------------------
// m3xc - shared port of worker m3xc + HMAC (XTEA 32 rounds + XOR keystream)
// Used by license_manager, session_guard and autokill for encrypted auth
// ---------------------------------------------------------------------------

namespace detail_m3xc {
constexpr uint32_t M3XC_DELTA = 0x9E3779B9u;

inline uint32_t m3xc_readU32BE(const uint8_t* b, int o) {
    return (uint32_t(b[o]) << 24) | (uint32_t(b[o+1]) << 16) | (uint32_t(b[o+2]) << 8) | uint32_t(b[o+3]);
}
inline void m3xc_writeU32BE(uint8_t* b, int o, uint32_t v) {
    b[o] = uint8_t((v >> 24) & 0xff);
    b[o+1] = uint8_t((v >> 16) & 0xff);
    b[o+2] = uint8_t((v >> 8) & 0xff);
    b[o+3] = uint8_t(v & 0xff);
}
inline void m3xc_xteaEnc(uint32_t &v0, uint32_t &v1, const uint32_t k[4]) {
    uint32_t s = 0;
    for (int i = 0; i < 32; ++i) {
        v0 = (v0 + (((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[(s >> 11) & 3])) & 0xffffffffu)) & 0xffffffffu;
        s = (s + M3XC_DELTA) & 0xffffffffu;
        v1 = (v1 + (((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[s & 3])) & 0xffffffffu)) & 0xffffffffu;
    }
}
inline void m3xc_xteaDec(uint32_t &v0, uint32_t &v1, const uint32_t k[4]) {
    uint32_t s = (M3XC_DELTA * 32) & 0xffffffffu;
    for (int i = 0; i < 32; ++i) {
        v1 = (v1 - (((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[s & 3])) & 0xffffffffu)) & 0xffffffffu;
        s = (s - M3XC_DELTA) & 0xffffffffu;
        v0 = (v0 - (((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[(s >> 11) & 3])) & 0xffffffffu)) & 0xffffffffu;
    }
}
inline std::vector<uint8_t> m3xc_deriveKs(const std::vector<uint8_t>& kb, size_t len) {
    std::vector<uint8_t> out(len);
    uint32_t s = 0x12345678u;
    for (size_t i = 0; i < kb.size(); ++i) s = (((s << 5) + s) ^ kb[i]) & 0xffffffffu;
    for (size_t i = 0; i < len; ++i) {
        s = (((s << 13) ^ s) & 0xffffffffu) + uint32_t(i); s &= 0xffffffffu;
        s = ((s >> 17) ^ s) & 0xffffffffu;
        s = (((s << 5) + s + kb[i % kb.size()]) & 0xffffffffu);
        s = (s ^ (uint32_t)(i * 0x9E3779B9u + 0x6A09E667u)) & 0xffffffffu;
        out[i] = uint8_t((s ^ kb[i % kb.size()]) & 0xff);
    }
    return out;
}
} // namespace detail_m3xc

inline QString lm_m3xcEncrypt(const QString& plain, const QString& key) {
    using namespace detail_m3xc;
    QByteArray kb = key.toUtf8();
    if (kb.isEmpty()) return {};
    QByteArray pb = plain.toUtf8();
    int ptLen = pb.size();
    int pad = ptLen == 0 ? 8 : (8 - ptLen % 8);
    if (pad == 0) pad = 8;
    int tot = ptLen + pad;
    std::vector<uint8_t> buf(static_cast<size_t>(tot));
    if (ptLen) memcpy(buf.data(), pb.constData(), size_t(ptLen));
    for (int i = ptLen; i < tot; ++i) buf[size_t(i)] = uint8_t(pad);
    uint32_t sub[4] = {0};
    uint32_t acc = 0x9E3779B9u;
    for (int i = 0; i < kb.size(); ++i) acc = (((acc << 5) + acc) ^ uint8_t(kb[i])) & 0xffffffffu;
    for (int j = 0; j < 4; ++j) {
        acc = ((acc << 13) ^ acc) & 0xffffffffu;
        acc = ((acc >> 17) ^ acc) & 0xffffffffu;
        acc = ((acc << 5) + acc + uint32_t(j * 0x9E3779B9u + 0x6A09E667u)) & 0xffffffffu;
        sub[j] = acc;
    }
    for (int off = 0; off < tot; off += 8) {
        uint32_t v0 = m3xc_readU32BE(buf.data(), off);
        uint32_t v1 = m3xc_readU32BE(buf.data(), off + 4);
        m3xc_xteaEnc(v0, v1, sub);
        m3xc_writeU32BE(buf.data(), off, v0);
        m3xc_writeU32BE(buf.data(), off + 4, v1);
    }
    std::vector<uint8_t> kbv;
    kbv.assign(kb.begin(), kb.end());
    auto ks = m3xc_deriveKs(kbv, size_t(tot));
    for (int i = 0; i < tot; ++i) buf[size_t(i)] ^= ks[size_t(i)];
    QByteArray b(reinterpret_cast<char*>(buf.data()), tot);
    return QString::fromLatin1(b.toBase64());
}

inline QString lm_m3xcDecrypt(const QString& b64, const QString& key) {
    using namespace detail_m3xc;
    QByteArray raw = QByteArray::fromBase64(b64.toLatin1());
    if (raw.isEmpty()) return {};
    int tot = raw.size();
    if (tot % 8 != 0) return {};
    QByteArray kb = key.toUtf8();
    if (kb.isEmpty()) return {};
    std::vector<uint8_t> buf(static_cast<size_t>(tot));
    memcpy(buf.data(), raw.constData(), size_t(tot));
    std::vector<uint8_t> kbv;
    kbv.assign(kb.begin(), kb.end());
    auto ks = m3xc_deriveKs(kbv, size_t(tot));
    for (int i = 0; i < tot; ++i) buf[size_t(i)] ^= ks[size_t(i)];
    uint32_t sub[4] = {0};
    uint32_t acc = 0x9E3779B9u;
    for (int i = 0; i < kb.size(); ++i) acc = (((acc << 5) + acc) ^ uint8_t(kb[i])) & 0xffffffffu;
    for (int j = 0; j < 4; ++j) {
        acc = ((acc << 13) ^ acc) & 0xffffffffu;
        acc = ((acc >> 17) ^ acc) & 0xffffffffu;
        acc = ((acc << 5) + acc + uint32_t(j * 0x9E3779B9u + 0x6A09E667u)) & 0xffffffffu;
        sub[j] = acc;
    }
    for (int off = 0; off < tot; off += 8) {
        uint32_t v0 = m3xc_readU32BE(buf.data(), off);
        uint32_t v1 = m3xc_readU32BE(buf.data(), off + 4);
        m3xc_xteaDec(v0, v1, sub);
        m3xc_writeU32BE(buf.data(), off, v0);
        m3xc_writeU32BE(buf.data(), off + 4, v1);
    }
    if (tot == 0) return {};
    int pad = int(buf[size_t(tot - 1)]);
    if (pad < 1 || pad > 8) return {};
    for (int i = tot - pad; i < tot; ++i) if (int(buf[size_t(i)]) != pad) return {};
    QByteArray out;
    out.resize(tot - pad);
    if (tot - pad > 0) memcpy(out.data(), buf.data(), size_t(tot - pad));
    return QString::fromUtf8(out);
}

inline QByteArray lm_hmacSha256Hex(const QByteArray& data, const QByteArray& key) {
    return QMessageAuthenticationCode::hash(data, key, QCryptographicHash::Sha256).toHex();
}
inline QString lm_hmacSha256HexStr(const QString& key, const QString& msg) {
    return QString::fromLatin1(lm_hmacSha256Hex(msg.toUtf8(), key.toUtf8()));
}
inline QByteArray lm_deriveHmacKey(const QByteArray& masterKey) {
    // HKDF-like: HMAC(master, "astro-hmac-v1") hex -> same as worker deriveHmacKey
    return QMessageAuthenticationCode::hash(QByteArray("astro-hmac-v1"), masterKey, QCryptographicHash::Sha256).toHex();
}
inline QByteArray lm_deriveEncKey(const QByteArray& masterKey) {
    return QMessageAuthenticationCode::hash(QByteArray("astro-enc-v1"), masterKey, QCryptographicHash::Sha256).toHex();
}
inline QByteArray lm_hmacSha256HexDerived(const QByteArray& data, const QByteArray& masterKey) {
    QByteArray hmacKey = lm_deriveHmacKey(masterKey);
    return QMessageAuthenticationCode::hash(data, hmacKey, QCryptographicHash::Sha256).toHex();
}

} // namespace crypto
} // namespace security
} // namespace astro
