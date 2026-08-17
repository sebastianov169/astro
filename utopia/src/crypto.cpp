// crypto.cpp - primitivas criptograficas (replican full_login_and_api.py)
#include "crypto.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include <QRegularExpression>
#include <QUrl>
#include <QRandomGenerator>

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <cmath>
#include <cstring>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

// ================================================================
// base64 / hex / md5
// ================================================================
QString b64Encode(const Bytes &in)
{
    // CON padding '=': el server (HHVM/PHP) NO decodifica base64 sin padding.
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(in.data()),
                                          int(in.size())).toBase64());
}

Bytes b64Decode(const QString &in)
{
    QByteArray raw = in.toLatin1();
    int pad = (4 - (raw.size() % 4)) % 4;
    while (pad-- > 0)
        raw.append('=');
    QByteArray out = QByteArray::fromBase64(raw);
    return Bytes(out.begin(), out.end());
}

QString urlB64EncodeNoPad(const Bytes &in)
{
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(in.data()),
                                          int(in.size())).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString md5Hex(const QString &in)
{
    return QString::fromLatin1(QCryptographicHash::hash(in.toUtf8(), QCryptographicHash::Md5).toHex());
}

// ================================================================
// M2XC
// ================================================================
u32 fmix(u32 x)
{
    x &= M;
    x = ((x ^ (x >> 16)) * 0x45d9f3bu) & M;
    x = ((x ^ (x >> 16)) * 0x45d9f3bu) & M;
    return (x ^ (x >> 16)) & M;
}

std::pair<u32, u32> fmix2(u32 x)
{
    x &= M;
    x = ((x ^ (x >> 16)) * 0x45d9f3bu) & M;
    u32 f2i = ((x ^ (x >> 16)) * 0x45d9f3bu) & M;
    u32 final = (f2i ^ (f2i >> 16)) & M;
    return {f2i, final};
}

u32 ror(u32 x, int r)
{
    x &= M;
    r &= 31;
    return ((x >> r) | (x << (32 - r))) & M;
}

u32 rol(u32 x, int r)
{
    return ror(x, 32 - r);
}

std::array<u32, 4> keystreamXxtea(const Bytes &key, std::array<u32, 4> state,
                                  u32 SUM, int /*counterOffset*/, bool /*passB*/)
{
    u32 w0 = state[0], w1 = state[1], w2 = state[2], w3 = state[3];
    u32 c = 0;
    for (size_t i = 0; i < key.size(); ++i) {
        u32 b = key[i] & 0xFF;
        u32 t = (rol(w3, 3) + b + u32(i) + w0) & M;
        w0 = fmix(t);
        t = (rol((b + u32(i) + w0) & M, 7) ^ w1) & M;
        w1 = fmix(t);
        t = (w2 + rol((b ^ w1) & M, 11) + c) & M;
        w2 = fmix(t);
        t = (rol((b + SUM) & M, 17) ^ w3 ^ w2) & M;
        w3 = fmix(t);
        c = (c + 0x45d9f3bu) & M;
    }
    return {w0, w1, w2, w3};
}

std::array<u32, 4> swfinalizePassA(std::array<u32, 4> s)
{
    u32 w0 = s[0], w1 = s[1], w2 = s[2], w3 = s[3];
    auto f0 = fmix2(w0 ^ 0xa5a5a5a5u);
    auto f1 = fmix2((w1 + 0x3c6ef372u) & M);
    u32 w2f = fmix((((f0.first >> 19) | (f0.second << 13)) & M) ^ w2);
    u32 w3f = fmix((((f1.second << 9) | (f1.first >> 23)) & M) + w3);
    return {f0.second, f1.second, w2f, w3f};
}

std::array<u32, 4> swfinalizePassB(std::array<u32, 4> s)
{
    return swfinalizePassA(s);
}

Bytes transform1(const Bytes &data, std::array<u32, 4> state, u32 H, bool passB)
{
    u32 w0 = state[0], w1 = state[1], w2 = state[2], w3 = state[3];
    Bytes out(data.size());
    for (size_t pos = 0; pos < data.size(); ++pos) {
        u32 p0 = w0, p1 = w1, p2 = w2, p3 = w3;
        u32 val1 = (rol(p1, 5) + p0 + 0x9e3779b9u + u32(pos)) & M;
        auto f0 = fmix2(val1);
        u32 w0n = f0.second;
        u32 val2 = (rol(p2, 7) ^ p1 ^ w0n) & M;
        u32 w1n = fmix(val2);
        u32 val3 = (rol(p3, 11) + p2 + w1n) & M;
        auto f3 = fmix2(val3);
        u32 w2n = f3.second;
        u32 gameTerm = ((f0.first >> 19) | (w0n << 13)) & M;
        u32 val4 = (gameTerm ^ p3 ^ w2n ^ u32(pos)) & M;
        auto fw3 = fmix2(val4);
        u32 w3n = fw3.second;
        u32 termC = ror(w1n, 29);
        u32 termB;
        if (passB)
            termB = ((w2n << 9) | (w2n >> 23)) & M;
        else
            termB = ((f3.first >> 23) | (w2n << 9)) & M;
        u32 termD = ((w3n >> 15) | (w3n << 17)) & M;
        u32 idx = (u32(pos) >> 2) & 3;
        u32 selWord = (idx == 0) ? w0n : (idx == 1) ? w1n : (idx == 2) ? w2n : w3n;
        u32 xorVal = (termD ^ termB ^ termC ^ w0n) & M;
        int shift = (int(pos) & 3) << 3;
        int byteOut = (int((xorVal >> shift) & 0xFF) ^ int(data[pos] & 0xFF));
        byteOut += int((selWord >> shift) & 0xFF);
        byteOut += int(H & 0xFF);
        byteOut += int(pos & 0xFF);
        out[pos] = std::uint8_t(byteOut & 0xFF);
        w0 = w0n; w1 = w1n; w2 = w2n; w3 = w3n;
    }
    return out;
}

Bytes transform2(const Bytes &data, u32 ha, u32 hb, int counterOffset)
{
    int prev = int(hb & 0xFF);
    Bytes out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        int pos = int(i) + counterOffset;
        int shift = (int(i) & 3) << 3;
        u32 haShift = (ha >> shift) & M;
        int val = int(data[i]) ^ int((haShift + u32(prev) + u32(pos)) & 0xFF) ^ prev;
        out[i] = std::uint8_t(val & 0xFF);
        prev = val & 0xFF;
    }
    return out;
}

Bytes inverseTransform1(const Bytes &enc, std::array<u32, 4> state, u32 H, bool passB)
{
    u32 w0 = state[0], w1 = state[1], w2 = state[2], w3 = state[3];
    Bytes out(enc.size());
    for (size_t pos = 0; pos < enc.size(); ++pos) {
        u32 p0 = w0, p1 = w1, p2 = w2, p3 = w3;
        u32 val1 = (rol(p1, 5) + p0 + 0x9e3779b9u + u32(pos)) & M;
        auto f0 = fmix2(val1);
        u32 w0n = f0.second;
        u32 val2 = (rol(p2, 7) ^ p1 ^ w0n) & M;
        u32 w1n = fmix(val2);
        u32 val3 = (rol(p3, 11) + p2 + w1n) & M;
        auto f3 = fmix2(val3);
        u32 w2n = f3.second;
        u32 gameTerm = ((f0.first >> 19) | (w0n << 13)) & M;
        u32 val4 = (gameTerm ^ p3 ^ w2n ^ u32(pos)) & M;
        auto fw3 = fmix2(val4);
        u32 w3n = fw3.second;
        u32 termC = ror(w1n, 29);
        u32 termB;
        if (passB)
            termB = ((w2n << 9) | (w2n >> 23)) & M;
        else
            termB = ((f3.first >> 23) | (w2n << 9)) & M;
        u32 termD = ((w3n >> 15) | (w3n << 17)) & M;
        u32 idx = (u32(pos) >> 2) & 3;
        u32 selWord = (idx == 0) ? w0n : (idx == 1) ? w1n : (idx == 2) ? w2n : w3n;
        u32 xorVal = (termD ^ termB ^ termC ^ w0n) & M;
        int shift = (int(pos) & 3) << 3;
        int byteVal = int(enc[pos] & 0xFF);
        int xorShift = int((xorVal >> shift) & 0xFF);
        int selShift = int((selWord >> shift) & 0xFF);
        int inp = ((byteVal - selShift - int(H & 0xFF) - int(pos & 0xFF)) & 0xFF) ^ xorShift;
        out[pos] = std::uint8_t(inp & 0xFF);
        w0 = w0n; w1 = w1n; w2 = w2n; w3 = w3n;
    }
    return out;
}

Bytes inverseTransform2(const Bytes &enc, u32 ha, u32 hb, int counterOffset)
{
    int prev = int(hb & 0xFF);
    Bytes out(enc.size());
    for (size_t i = 0; i < enc.size(); ++i) {
        int pos = int(i) + counterOffset;
        int shift = (int(i) & 3) << 3;
        u32 haShift = (ha >> shift) & M;
        int mix = int((haShift + u32(prev) + u32(pos)) & 0xFF);
        int encByte = int(enc[i]);
        int val = (encByte ^ mix ^ prev) & 0xFF;
        out[i] = std::uint8_t(val & 0xFF);
        prev = encByte;
    }
    return out;
}

static void appendU32Be(Bytes &out, u32 v)
{
    out.push_back(std::uint8_t((v >> 24) & 0xFF));
    out.push_back(std::uint8_t((v >> 16) & 0xFF));
    out.push_back(std::uint8_t((v >> 8) & 0xFF));
    out.push_back(std::uint8_t(v & 0xFF));
}

static u32 readU32Be(const Bytes &b, size_t off)
{
    return (u32(b[off]) << 24) | (u32(b[off + 1]) << 16) | (u32(b[off + 2]) << 8) | u32(b[off + 3]);
}

Bytes m2xcEncryptFull(const Bytes &data, const Bytes &key, u32 H1, u32 H2)
{
    H1 &= M; H2 &= M;
    int lenData = int(data.size());
    int lenKey = int(key.size());
    std::array<u32, 4> s1 = {
        fmix((u32(lenData) ^ H1 ^ 0x243f6a88u) & M),
        fmix((H2 ^ 0x85a308d3u) & M),
        fmix((u32(lenKey) ^ rol(H1, 7) ^ 0x13198a2eu) & M),
        fmix((rol(H2, 11) ^ 0x3707344u) & M),
    };
    s1 = keystreamXxtea(key, s1, (H1 + H2) & M);
    s1 = swfinalizePassA(s1);
    Bytes round1 = transform1(data, s1, H1, false);
    Bytes round2 = transform2(round1, H1, H2, 0);
    u32 seedA = H1 ^ 0x6a09e667u;
    u32 seedB = H2 ^ 0xbb67ae85u;
    Bytes ks2;
    appendU32Be(ks2, 0x19731f72u);
    appendU32Be(ks2, H1);
    appendU32Be(ks2, H2);
    appendU32Be(ks2, u32(lenData));
    appendU32Be(ks2, u32(round2.size()));
    ks2.insert(ks2.end(), round2.begin(), round2.end());
    std::array<u32, 4> s2 = {
        fmix((u32(ks2.size()) ^ seedA ^ 0x243f6a88u) & M),
        fmix((H2 ^ 0x3ec4a656u) & M),
        fmix((u32(lenKey) ^ rol(seedA, 7) ^ 0x13198a2eu) & M),
        fmix((rol(seedB, 11) ^ 0x3707344u) & M),
    };
    s2 = keystreamXxtea(key, s2, (seedA + seedB) & M, 0, true);
    s2 = swfinalizePassB(s2);
    Bytes round3 = transform1(ks2, s2, seedA, true);
    Bytes round4 = transform2(round3, seedA, seedB, 0);
    u32 H3 = (round4.size() >= 4) ? readU32Be(round4, 0) : 0;
    Bytes blob;
    blob.insert(blob.end(), {'M', '2', 'X', 'C'});
    appendU32Be(blob, H1);
    appendU32Be(blob, H2);
    appendU32Be(blob, H3);
    blob.insert(blob.end(), round2.begin(), round2.end());
    return blob;
}

Bytes m2xcDecryptFull(const Bytes &blob, const Bytes &key)
{
    if (blob.size() < 16 || blob[0] != 'M' || blob[1] != '2' || blob[2] != 'X' || blob[3] != 'C')
        return {};
    u32 H1 = readU32Be(blob, 4);
    u32 H2 = readU32Be(blob, 8);
    Bytes payload(blob.begin() + 16, blob.end());
    int lenData = int(payload.size());
    int lenKey = int(key.size());
    std::array<u32, 4> s1 = {
        fmix((u32(lenData) ^ H1 ^ 0x243f6a88u) & M),
        fmix((H2 ^ 0x85a308d3u) & M),
        fmix((u32(lenKey) ^ rol(H1, 7) ^ 0x13198a2eu) & M),
        fmix((rol(H2, 11) ^ 0x3707344u) & M),
    };
    s1 = keystreamXxtea(key, s1, (H1 + H2) & M);
    s1 = swfinalizePassA(s1);
    Bytes round1 = inverseTransform2(payload, H1, H2, 0);
    Bytes plain = inverseTransform1(round1, s1, H1, false);
    return plain;
}

QString m2xcFmt(const Bytes &blob)
{
    int len = int(blob.size()) - 16;
    QString prefix = QString("%1").arg(len, 8, 10, QLatin1Char('0'));
    return prefix + b64Encode(blob);
}

Bytes parseM2xcBlob(const QString &s)
{
    return b64Decode(s.mid(8));
}

// ================================================================
// AES-CBC (BCrypt)
// ================================================================
static const std::array<std::uint8_t, 16> kIv = {
    0x20, 0x0b, 0x5d, 0x31, 0x79, 0x6f, 0x03, 0x2c,
    0x13, 0x23, 0x3b, 0x65, 0x54, 0x3a, 0x0b, 0x5f,
};

static void requireBcrypt(NTSTATUS status, const char *what)
{
    if (!BCRYPT_SUCCESS(status)) {
        std::ostringstream o;
        o << what << " failed: 0x" << std::hex << u32(status);
        throw std::runtime_error(o.str());
    }
}

Bytes deriveAesKey(const QString &secret)
{
    std::array<int, 16> values{};
    values.fill(11);
    QByteArray e = secret.toUtf8();
    for (int i = 0; i < e.size(); ++i) {
        int slot = i % 16;
        values[slot] += int(std::uint8_t(e.at(slot))) + int(std::uint8_t(e.at(i)));
    }
    Bytes key(16);
    for (int i = 0; i < 16; ++i)
        key[size_t(i)] = std::uint8_t(values[size_t(i)] & 0xFF);
    return key;
}

Bytes deriveCustomAesKey(const QString &secret, int offset)
{
    std::array<int, 16> values{};
    values.fill(11);
    QByteArray e = secret.toUtf8();
    for (int i = 0; i < e.size(); ++i) {
        int slot = i % 16;
        int raw = values[slot] - 100 + offset
            + int(std::uint8_t(e.at(slot))) + int(std::uint8_t(e.at(i)));
        values[slot] = ((raw % 256) + 256) % 256;
    }
    Bytes key(16);
    for (int i = 0; i < 16; ++i)
        key[size_t(i)] = std::uint8_t(values[size_t(i)] & 0xFF);
    return key;
}

Bytes aesCbcCrypt(const Bytes &input, const Bytes &key, bool encrypt)
{
    if (input.empty())
        return {};
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    DWORD result = 0, objectLength = 0;
    requireBcrypt(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0), "OpenAlg(AES)");
    auto close = [&]() {
        if (keyHandle) BCryptDestroyKey(keyHandle);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    };
    requireBcrypt(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
        DWORD(sizeof(BCRYPT_CHAIN_MODE_CBC)), 0), "SetChaining");
    requireBcrypt(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &result, 0), "GetObjLen");
    Bytes keyObject(objectLength);
    requireBcrypt(BCryptGenerateSymmetricKey(alg, &keyHandle, keyObject.data(), DWORD(keyObject.size()),
        const_cast<PUCHAR>(key.data()), DWORD(key.size()), 0), "GenKey");
    Bytes iv(kIv.begin(), kIv.end());
    DWORD outLen = 0;
    NTSTATUS sizeStatus = encrypt
        ? BCryptEncrypt(keyHandle, const_cast<PUCHAR>(input.data()), DWORD(input.size()), nullptr,
            iv.data(), DWORD(iv.size()), nullptr, 0, &outLen, 0)
        : BCryptDecrypt(keyHandle, const_cast<PUCHAR>(input.data()), DWORD(input.size()), nullptr,
            iv.data(), DWORD(iv.size()), nullptr, 0, &outLen, 0);
    requireBcrypt(sizeStatus, encrypt ? "Encrypt(size)" : "Decrypt(size)");
    Bytes output(outLen);
    iv.assign(kIv.begin(), kIv.end());
    NTSTATUS cryptStatus = encrypt
        ? BCryptEncrypt(keyHandle, const_cast<PUCHAR>(input.data()), DWORD(input.size()), nullptr,
            iv.data(), DWORD(iv.size()), output.data(), DWORD(output.size()), &outLen, 0)
        : BCryptDecrypt(keyHandle, const_cast<PUCHAR>(input.data()), DWORD(input.size()), nullptr,
            iv.data(), DWORD(iv.size()), output.data(), DWORD(output.size()), &outLen, 0);
    requireBcrypt(cryptStatus, encrypt ? "Encrypt" : "Decrypt");
    output.resize(outLen);
    close();
    return output;
}

QString aesEncrypt(const QString &payload, const QString &secret, int padTo, bool prefixPaddedLen)
{
    QByteArray raw = payload.toUtf8();
    int pad = (padTo - (raw.size() % padTo)) % padTo;
    Bytes padded(raw.begin(), raw.end());
    padded.insert(padded.end(), size_t(pad), 0);
    Bytes enc = aesCbcCrypt(padded, deriveAesKey(secret), true);
    int logicalLength = (prefixPaddedLen || padTo == 16) ? int(padded.size()) : raw.size();
    QString prefix = QString("%1").arg(logicalLength, 8, 10, QLatin1Char('0'));
    return prefix + b64Encode(enc);
}

QString aesDecryptStr(const QString &payload, const QString &secret)
{
    if (payload.size() <= 8)
        return {};
    Bytes enc = b64Decode(payload.mid(8));
    Bytes dec = aesCbcCrypt(enc, deriveAesKey(secret), false);
    while (!dec.empty() && dec.back() == 0)
        dec.pop_back();
    return QString::fromUtf8(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
}

QString aesEncryptCustom(const QString &payload, const QString &secret, int offset)
{
    QByteArray raw = payload.toUtf8();
    int pad = (16 - (raw.size() % 16)) % 16;
    Bytes padded(raw.begin(), raw.end());
    padded.insert(padded.end(), size_t(pad), 0);
    Bytes enc = aesCbcCrypt(padded, deriveCustomAesKey(secret, offset), true);
    QString prefix = QString("%1").arg(int(padded.size()), 8, 10, QLatin1Char('0'));
    return prefix + b64Encode(enc);
}

// ================================================================
// RSA (BCrypt)
// ================================================================
struct DerTlv {
    std::uint8_t tag = 0;
    Bytes value;
};

static DerTlv readDerTlv(const Bytes &data, size_t &pos)
{
    if (pos + 2 > data.size())
        throw std::runtime_error("bad DER");
    DerTlv tlv;
    tlv.tag = data[pos++];
    std::uint8_t lenByte = data[pos++];
    size_t length = 0;
    if ((lenByte & 0x80u) == 0) {
        length = lenByte;
    } else {
        int count = lenByte & 0x7F;
        if (count <= 0 || count > 4 || pos + size_t(count) > data.size())
            throw std::runtime_error("bad DER length");
        for (int i = 0; i < count; ++i)
            length = (length << 8) | data[pos++];
    }
    if (pos + length > data.size())
        throw std::runtime_error("DER range");
    tlv.value.assign(data.begin() + ptrdiff_t(pos), data.begin() + ptrdiff_t(pos + length));
    pos += length;
    return tlv;
}

static Bytes derReadInt(const Bytes &data, size_t &pos)
{
    DerTlv tlv = readDerTlv(data, pos);
    if (tlv.tag != 0x02)
        throw std::runtime_error("expected DER integer");
    while (tlv.value.size() > 1 && tlv.value.front() == 0)
        tlv.value.erase(tlv.value.begin());
    return tlv.value;
}

static Bytes decodePem(const QString &pem)
{
    QString clean = pem;
    clean.remove(QRegularExpression("-----BEGIN [A-Z ]*-----"));
    clean.remove(QRegularExpression("-----END [A-Z ]*-----"));
    clean.remove(QRegularExpression("\\s"));
    return b64Decode(clean);
}

struct RsaKey {
    Bytes n, e, d, p, q, dp, dq, qinv;
    int bits = 0;
    bool hasPrivate = false;
};

static RsaKey parseRsaPrivateDer(const Bytes &der)
{
    size_t pos = 0;
    DerTlv top = readDerTlv(der, pos);
    if (top.tag != 0x30)
        throw std::runtime_error("not a SEQUENCE");
    size_t inner = 0;
    (void)derReadInt(top.value, inner); // version
    RsaKey key;
    key.n = derReadInt(top.value, inner);
    key.e = derReadInt(top.value, inner);
    key.d = derReadInt(top.value, inner);
    key.p = derReadInt(top.value, inner);
    key.q = derReadInt(top.value, inner);
    key.dp = derReadInt(top.value, inner);
    key.dq = derReadInt(top.value, inner);
    key.qinv = derReadInt(top.value, inner);
    key.bits = int(key.n.size() * 8);
    key.hasPrivate = true;
    return key;
}

static RsaKey parseRsaPublicDer(const Bytes &der)
{
    size_t pos = 0;
    DerTlv top = readDerTlv(der, pos);
    if (top.tag != 0x30 || top.value.empty())
        throw std::runtime_error("bad public");
    size_t inner = 0;
    RsaKey key;
    if (top.value[0] == 0x02) {
        key.n = derReadInt(top.value, inner);
        key.e = derReadInt(top.value, inner);
    } else if (top.value[0] == 0x30) {
        (void)readDerTlv(top.value, inner);
        DerTlv bitString = readDerTlv(top.value, inner);
        if (bitString.tag != 0x03 || bitString.value.size() < 2)
            throw std::runtime_error("bad bitstring");
        Bytes nested(bitString.value.begin() + 1, bitString.value.end());
        return parseRsaPublicDer(nested);
    }
    key.bits = int(key.n.size() * 8);
    return key;
}

static Bytes rsaPublicBlob(const RsaKey &key)
{
    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    header.BitLength = ULONG(key.bits);
    header.cbPublicExp = ULONG(key.e.size());
    header.cbModulus = ULONG(key.n.size());
    Bytes blob(reinterpret_cast<std::uint8_t *>(&header),
               reinterpret_cast<std::uint8_t *>(&header) + sizeof(header));
    blob.insert(blob.end(), key.e.begin(), key.e.end());
    blob.insert(blob.end(), key.n.begin(), key.n.end());
    return blob;
}

static Bytes rsaPrivateBlob(const RsaKey &key)
{
    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = BCRYPT_RSAPRIVATE_MAGIC;
    header.BitLength = ULONG(key.bits);
    header.cbPublicExp = ULONG(key.e.size());
    header.cbModulus = ULONG(key.n.size());
    header.cbPrime1 = ULONG(key.p.size());
    header.cbPrime2 = ULONG(key.q.size());
    Bytes blob(reinterpret_cast<std::uint8_t *>(&header),
               reinterpret_cast<std::uint8_t *>(&header) + sizeof(header));
    blob.insert(blob.end(), key.e.begin(), key.e.end());
    blob.insert(blob.end(), key.n.begin(), key.n.end());
    blob.insert(blob.end(), key.p.begin(), key.p.end());
    blob.insert(blob.end(), key.q.begin(), key.q.end());
    blob.insert(blob.end(), key.dp.begin(), key.dp.end());
    blob.insert(blob.end(), key.dq.begin(), key.dq.end());
    blob.insert(blob.end(), key.qinv.begin(), key.qinv.end());
    return blob;
}

QString rsaEncryptPkcs1Base64(const QString &pem, const QString &plain)
{
    RsaKey key = parseRsaPublicDer(decodePem(pem));
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE kh = nullptr;
    Bytes blob = rsaPublicBlob(key);
    requireBcrypt(BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0), "OpenAlg(RSA)");
    auto close = [&]() {
        if (kh) BCryptDestroyKey(kh);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    };
    requireBcrypt(BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &kh,
        blob.data(), DWORD(blob.size()), 0), "ImportPub");
    QByteArray plainBytes = plain.toUtf8();
    // PKCS1 v1.5 TIPO 2 (encriptacion): 00 02 | PS | 00 | data.
    // El PS debe ser aleatorio y SIN bytes 0x00 (igual que OpenSSL/cryptography).
    // BCryptEncrypt con BCRYPT_PAD_PKCS1 tambien genera PS aleatorio pero puede
    // contener 0x00 -> el server de Mitos.is rechaza ese bloque.
    int k = key.bits / 8;
    int psLen = k - 3 - int(plainBytes.size());
    if (psLen < 8 || int(plainBytes.size()) > k - 11)
        throw std::runtime_error("rsaEncrypt: payload demasiado largo");
    Bytes padded;
    padded.push_back(0x00);
    padded.push_back(0x02);
    while (int(padded.size()) < 2 + psLen) {
        std::uint8_t b = std::uint8_t(QRandomGenerator::global()->bounded(255) + 1);
        if (b != 0)
            padded.push_back(b);
    }
    padded.push_back(0x00);
    padded.insert(padded.end(), plainBytes.begin(), plainBytes.end());
    DWORD outLen = 0;
    requireBcrypt(BCryptEncrypt(kh, padded.data(), DWORD(padded.size()),
        nullptr, nullptr, 0, nullptr, 0, &outLen, BCRYPT_PAD_NONE), "Encrypt(size)");
    Bytes enc(outLen);
    requireBcrypt(BCryptEncrypt(kh, padded.data(), DWORD(padded.size()),
        nullptr, nullptr, 0, enc.data(), DWORD(enc.size()), &outLen, BCRYPT_PAD_NONE), "Encrypt");
    enc.resize(outLen);
    close();
    return b64Encode(enc);
}

Bytes rsaSignPkcs1Sha256(const QString &pem, const QByteArray &msg)
{
    RsaKey key = parseRsaPrivateDer(decodePem(pem));
    // BCrypt requiere prime1 > prime2
    if (key.p < key.q) {
        std::swap(key.p, key.q);
        std::swap(key.dp, key.dq);
    }
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE kh = nullptr;
    Bytes blob = rsaPrivateBlob(key);
    requireBcrypt(BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0), "OpenAlg(RSA sign)");
    auto close = [&]() {
        if (kh) BCryptDestroyKey(kh);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    };
    requireBcrypt(BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPRIVATE_BLOB, &kh,
        blob.data(), DWORD(blob.size()), 0), "ImportPriv");
    QByteArray digest = QCryptographicHash::hash(msg, QCryptographicHash::Sha256);
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    DWORD outLen = 0;
    requireBcrypt(BCryptSignHash(kh, &paddingInfo, reinterpret_cast<PUCHAR>(digest.data()), DWORD(digest.size()),
        nullptr, 0, &outLen, BCRYPT_PAD_PKCS1), "Sign(size)");
    Bytes sig(outLen);
    requireBcrypt(BCryptSignHash(kh, &paddingInfo, reinterpret_cast<PUCHAR>(digest.data()), DWORD(digest.size()),
        sig.data(), DWORD(sig.size()), &outLen, BCRYPT_PAD_PKCS1), "Sign");
    sig.resize(outLen);
    close();
    return sig;
}

Bytes tpmSignPkcs1Sha256(const QByteArray &msg)
{
    // Clave TPM "MitosDeviceKeyV2" (Microsoft Platform Crypto Provider) via NCrypt.
    // Identico al tpm_sign_pkcs1_sha256 del Python (mitosis_client.py).
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenStorageProvider(&prov, L"Microsoft Platform Crypto Provider", 0) != 0)
        throw std::runtime_error("NCryptOpenStorageProvider");
    auto cleanup = [&]() {
        if (key) NCryptFreeObject(key);
        if (prov) NCryptFreeObject(prov);
    };
    if (NCryptOpenKey(prov, &key, L"MitosDeviceKeyV2", 0, 0) != 0) {
        cleanup();
        throw std::runtime_error("NCryptOpenKey MitosDeviceKeyV2");
    }
    QByteArray digest = QCryptographicHash::hash(msg, QCryptographicHash::Sha256);
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    DWORD cb = 0;
    // El Python usa el flag literal 0x2 (la macro NCRYPT_SILENT_FLAG del SDK = 0x40
    // NO funciona en NCryptSignHash con esta clave). Replicar 0x2.
    const DWORD kTpmFlags = 0x2;
    NTSTATUS st = NCryptSignHash(key, &paddingInfo,
                                 reinterpret_cast<PUCHAR>(digest.data()), DWORD(digest.size()),
                                 nullptr, 0, &cb, kTpmFlags);
    if (st != 0) {
        cleanup();
        std::ostringstream o;
        o << "NCryptSignHash size: 0x" << std::hex << std::uint32_t(st);
        throw std::runtime_error(o.str());
    }
    Bytes sig(cb);
    if (NCryptSignHash(key, &paddingInfo,
                       reinterpret_cast<PUCHAR>(digest.data()), DWORD(digest.size()),
                       sig.data(), DWORD(sig.size()), &cb, kTpmFlags) != 0) {
        cleanup();
        throw std::runtime_error("NCryptSignHash");
    }
    sig.resize(cb);
    cleanup();
    return sig;
}

QString tpmBuildMid()
{
    // mid desde la clave PUBLICA del TPM "MitosDeviceKeyV2" (mismo layout
    // rsa1/MID2 que buildMidPem pero sin importar una privada).
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenStorageProvider(&prov, L"Microsoft Platform Crypto Provider", 0) != 0)
        throw std::runtime_error("NCryptOpenStorageProvider(mid)");
    auto cleanup = [&]() {
        if (key) NCryptFreeObject(key);
        if (prov) NCryptFreeObject(prov);
    };
    if (NCryptOpenKey(prov, &key, L"MitosDeviceKeyV2", 0, 0) != 0) {
        cleanup();
        throw std::runtime_error("NCryptOpenKey MitosDeviceKeyV2 (mid)");
    }
    DWORD blobLen = 0;
    if (NCryptExportKey(key, (NCRYPT_KEY_HANDLE)0, BCRYPT_RSAPUBLIC_BLOB, (NCryptBufferDesc*)0,
                        (PUCHAR)0, 0, &blobLen, 0) != 0) {
        cleanup();
        throw std::runtime_error("NCryptExportKey(size)");
    }
    Bytes blob(blobLen);
    if (NCryptExportKey(key, (NCRYPT_KEY_HANDLE)0, BCRYPT_RSAPUBLIC_BLOB, (NCryptBufferDesc*)0,
                        blob.data(), DWORD(blob.size()), &blobLen, 0) != 0) {
        cleanup();
        throw std::runtime_error("NCryptExportKey");
    }
    cleanup();
    blob.resize(blobLen);
    if (blob.size() < sizeof(BCRYPT_RSAKEY_BLOB))
        throw std::runtime_error("RSA blob corto");
    BCRYPT_RSAKEY_BLOB hdr{};
    std::memcpy(&hdr, blob.data(), sizeof(hdr));
    size_t pos = sizeof(BCRYPT_RSAKEY_BLOB);
    Bytes e(blob.begin() + ptrdiff_t(pos), blob.begin() + ptrdiff_t(pos + hdr.cbPublicExp));
    pos += hdr.cbPublicExp;
    Bytes n(blob.begin() + ptrdiff_t(pos), blob.begin() + ptrdiff_t(pos + hdr.cbModulus));

    Bytes rsa1;
    auto appendU32 = [&](u32 v) {
        rsa1.push_back(std::uint8_t(v & 0xFF));
        rsa1.push_back(std::uint8_t((v >> 8) & 0xFF));
        rsa1.push_back(std::uint8_t((v >> 16) & 0xFF));
        rsa1.push_back(std::uint8_t((v >> 24) & 0xFF));
    };
    rsa1.push_back('R'); rsa1.push_back('S'); rsa1.push_back('A'); rsa1.push_back('1');
    appendU32(u32(hdr.BitLength));
    appendU32(u32(e.size()));
    appendU32(u32(n.size()));
    appendU32(0);
    appendU32(0);
    rsa1.insert(rsa1.end(), e.begin(), e.end());
    rsa1.insert(rsa1.end(), n.begin(), n.end());
    Bytes frame;
    frame.push_back('M'); frame.push_back('I'); frame.push_back('D'); frame.push_back('2');
    frame.push_back(1);
    frame.push_back(1);
    frame.push_back(std::uint8_t((rsa1.size() >> 8) & 0xFF));
    frame.push_back(std::uint8_t(rsa1.size() & 0xFF));
    frame.insert(frame.end(), rsa1.begin(), rsa1.end());
    QByteArray shaInput(1, char(1));
    shaInput.append(reinterpret_cast<const char *>(rsa1.data()), int(rsa1.size()));
    QByteArray sha = QCryptographicHash::hash(shaInput, QCryptographicHash::Sha256);
    frame.insert(frame.end(), sha.begin(), sha.end());
    return "M2." + urlB64EncodeNoPad(frame);
}

QString buildMidPem(const QString &pem)
{
    RsaKey priv = parseRsaPrivateDer(decodePem(pem));
    Bytes rsa1;
    auto appendU32 = [&](u32 v) {
        rsa1.push_back(std::uint8_t(v & 0xFF));
        rsa1.push_back(std::uint8_t((v >> 8) & 0xFF));
        rsa1.push_back(std::uint8_t((v >> 16) & 0xFF));
        rsa1.push_back(std::uint8_t((v >> 24) & 0xFF));
    };
    rsa1.push_back('R'); rsa1.push_back('S'); rsa1.push_back('A'); rsa1.push_back('1');
    appendU32(u32(priv.bits));
    appendU32(u32(priv.e.size()));
    appendU32(u32(priv.n.size()));
    appendU32(0);
    appendU32(0);
    rsa1.insert(rsa1.end(), priv.e.begin(), priv.e.end());
    rsa1.insert(rsa1.end(), priv.n.begin(), priv.n.end());
    Bytes frame;
    frame.push_back('M'); frame.push_back('I'); frame.push_back('D'); frame.push_back('2');
    frame.push_back(1);
    frame.push_back(1);
    frame.push_back(std::uint8_t((rsa1.size() >> 8) & 0xFF));
    frame.push_back(std::uint8_t(rsa1.size() & 0xFF));
    frame.insert(frame.end(), rsa1.begin(), rsa1.end());
    QByteArray shaInput(1, char(1));
    shaInput.append(reinterpret_cast<const char *>(rsa1.data()), int(rsa1.size()));
    QByteArray sha = QCryptographicHash::hash(shaInput, QCryptographicHash::Sha256);
    frame.insert(frame.end(), sha.begin(), sha.end());
    return "M2." + urlB64EncodeNoPad(frame);
}

// ================================================================
// Generacion de claves RSA-2048 + export PEM PKCS#1 (para el fake TPM:
// cada device se registra en el EH con su PROPIA clave generada localmente,
// sin depender de la clave TPM real del hardware)
// ================================================================
// El BCRYPT_RSAPRIVATE_BLOB exportado NO incluye d (privateExponent):
// se deriva de p,q,e con aritmetica big-endian minimal.
static Bytes bigTrim(Bytes v)
{
    while (v.size() > 1 && v.front() == 0)
        v.erase(v.begin());
    return v;
}

static int bigCmp(const Bytes &aIn, const Bytes &bIn)
{
    Bytes a = bigTrim(aIn), b = bigTrim(bIn);
    if (a.size() != b.size())
        return a.size() < b.size() ? -1 : 1;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

static Bytes bigAdd(Bytes a, const Bytes &bIn)
{
    a = bigTrim(a);
    Bytes b = bigTrim(bIn);
    while (a.size() < b.size()) a.insert(a.begin(), 0);
    while (b.size() < a.size()) b.insert(b.begin(), 0);
    int carry = 0;
    for (int i = int(a.size()) - 1; i >= 0; --i) {
        int v = int(a[size_t(i)]) + int(b[size_t(i)]) + carry;
        a[size_t(i)] = std::uint8_t(v & 0xFF);
        carry = v >> 8;
    }
    if (carry)
        a.insert(a.begin(), std::uint8_t(carry));
    return bigTrim(a);
}

static Bytes bigSub(Bytes a, const Bytes &bIn)
{
    // requiere a >= b
    a = bigTrim(a);
    Bytes b = bigTrim(bIn);
    while (b.size() < a.size()) b.insert(b.begin(), 0);
    int borrow = 0;
    for (int i = int(a.size()) - 1; i >= 0; --i) {
        int v = int(a[size_t(i)]) - int(b[size_t(i)]) - borrow;
        if (v < 0) { v += 256; borrow = 1; } else { borrow = 0; }
        a[size_t(i)] = std::uint8_t(v);
    }
    return bigTrim(a);
}

static Bytes bigMulSmall(const Bytes &aIn, std::uint32_t k)
{
    if (k == 0)
        return {0};
    Bytes a = bigTrim(aIn);
    Bytes out(a.size(), 0);
    std::uint32_t carry = 0;
    for (int i = int(a.size()) - 1; i >= 0; --i) {
        std::uint32_t v = std::uint32_t(a[size_t(i)]) * k + carry;
        out[size_t(i)] = std::uint8_t(v & 0xFF);
        carry = v >> 8;
    }
    if (carry)
        out.insert(out.begin(), std::uint8_t(carry));
    return bigTrim(out);
}

static Bytes bigMul(const Bytes &aIn, const Bytes &bIn)
{
    Bytes a = bigTrim(aIn), b = bigTrim(bIn);
    if ((a.size() == 1 && a[0] == 0) || (b.size() == 1 && b[0] == 0))
        return {0};
    Bytes out{0};
    for (size_t i = 0; i < b.size(); ++i) {
        Bytes term = bigMulSmall(a, b[size_t(b.size() - 1 - i)]);
        term.insert(term.end(), i, 0);
        out = bigAdd(out, term);
    }
    return bigTrim(out);
}

static Bytes bigSubOne(Bytes v)
{
    v = bigTrim(v);
    if (v.size() == 1 && v[0] == 0)
        return {0};
    for (int i = int(v.size()) - 1; i >= 0; --i) {
        if (v[size_t(i)] != 0) { v[size_t(i)] = std::uint8_t(v[size_t(i)] - 1); break; }
        v[size_t(i)] = 0xFF;
    }
    return bigTrim(v);
}

static std::pair<Bytes, Bytes> bigDivMod(const Bytes &aIn, const Bytes &bIn)
{
    Bytes a = bigTrim(aIn), b = bigTrim(bIn);
    if ((a.size() == 1 && a[0] == 0))
        return {{0}, {0}};
    if (bigCmp(a, b) < 0)
        return {{0}, a};
    Bytes q, r{0};
    for (size_t i = 0; i < a.size(); ++i) {
        r.push_back(a[i]);
        r = bigTrim(r);
        std::uint32_t lo = 0, hi = 256;
        while (lo + 1 < hi) {
            std::uint32_t mid = (lo + hi) / 2;
            if (bigCmp(bigMulSmall(b, mid), r) <= 0)
                lo = mid;
            else
                hi = mid;
        }
        q.push_back(std::uint8_t(lo));
        if (lo != 0)
            r = bigSub(r, bigMulSmall(b, lo));
    }
    return {bigTrim(q), bigTrim(r)};
}

static std::uint32_t bigModSmall(const Bytes &a, std::uint32_t m)
{
    std::uint64_t r = 0;
    for (std::uint8_t b : a)
        r = (r * 256 + b) % m;
    return std::uint32_t(r);
}

// inverso de a mod m con m primo (e=65537): e es primo, phi no divisible por el.
static std::uint32_t modInvSmall(std::uint32_t a, std::uint32_t m)
{
    std::int64_t t = 0, newt = 1;
    std::int64_t r = m, newr = a;
    while (newr != 0) {
        std::int64_t q = r / newr;
        std::int64_t tt = t - q * newt;
        t = newt; newt = tt;
        std::int64_t rr = r - q * newr;
        r = newr; newr = rr;
    }
    if (r != 1)
        return 0;
    if (t < 0)
        t += m;
    return std::uint32_t(t);
}

// d = e^-1 mod phi(p,q) con phi = (p-1)*(q-1). Como e es pequeno (65537),
// se busca el k minimo tal que (k*phi+1) % e == 0 y d = (k*phi+1)/e.
static Bytes derivePrivateExponent(const Bytes &p, const Bytes &q, const Bytes &e)
{
    Bytes phi = bigMul(bigSubOne(p), bigSubOne(q));
    std::uint32_t emod = 0;
    for (std::uint8_t b : e)
        emod = (emod << 8) | b;
    if (emod == 0 || emod % 2 == 0)
        return Bytes();
    std::uint32_t phiMod = bigModSmall(phi, emod);
    std::uint32_t invPhi = modInvSmall(phiMod, emod);
    if (invPhi == 0)
        return Bytes();
    std::uint32_t k = (emod - invPhi) % emod;
    Bytes num = bigAdd(bigMulSmall(phi, k), {1});
    auto dr = bigDivMod(num, e);
    return dr.second.size() == 1 && dr.second[0] == 0 ? dr.first : Bytes();
}

static Bytes derInt(const Bytes &v)
{
    // INTEGER: quita ceros iniciales; si el bit alto esta puesto (o esta vacio)
    // se antepone 0x00 para que el valor sea positivo (DER).
    Bytes val = v;
    while (val.size() > 1 && val.front() == 0)
        val.erase(val.begin());
    if (val.empty() || (val.front() & 0x80))
        val.insert(val.begin(), 0x00);
    Bytes out;
    out.push_back(0x02);
    out.push_back(std::uint8_t(val.size()));
    out.insert(out.end(), val.begin(), val.end());
    return out;
}

static void appendDerLen(Bytes &out, size_t len)
{
    if (len < 0x80) {
        out.push_back(std::uint8_t(len));
    } else {
        Bytes tmp;
        while (len > 0) {
            tmp.insert(tmp.begin(), std::uint8_t(len & 0xFF));
            len >>= 8;
        }
        out.push_back(std::uint8_t(0x80 | tmp.size()));
        out.insert(out.end(), tmp.begin(), tmp.end());
    }
}

static Bytes derSequence(const std::vector<Bytes> &items)
{
    Bytes body;
    for (const auto &it : items)
        body.insert(body.end(), it.begin(), it.end());
    Bytes out;
    out.push_back(0x30);
    appendDerLen(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

bool generateRsaPem2048(QString *pemOut)
{
    if (!pemOut)
        return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    try {
        requireBcrypt(BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0),
                      "OpenAlg(RSA gen)");
        requireBcrypt(BCryptGenerateKeyPair(alg, &key, 2048, 0), "GenerateKeyPair");
        requireBcrypt(BCryptFinalizeKeyPair(key, 0), "FinalizeKeyPair");
        DWORD blobLen = 0;
        requireBcrypt(BCryptExportKey(key, nullptr, BCRYPT_RSAPRIVATE_BLOB, nullptr, 0,
                                      &blobLen, 0), "ExportKey(size)");
        Bytes blob(blobLen);
        requireBcrypt(BCryptExportKey(key, nullptr, BCRYPT_RSAPRIVATE_BLOB, blob.data(),
                                      DWORD(blob.size()), &blobLen, 0), "ExportKey");
        blob.resize(blobLen);

        // BCRYPT_RSAPRIVATE_BLOB: header + e + n + p + q + dp + dq + qinv
        // (mismo layout que rsaPrivateBlob, con cbPrime1/cbPrime2 del header).
        if (blob.size() < sizeof(BCRYPT_RSAKEY_BLOB))
            return false;
        BCRYPT_RSAKEY_BLOB hdr{};
        std::memcpy(&hdr, blob.data(), sizeof(hdr));
        size_t pos = sizeof(BCRYPT_RSAKEY_BLOB);
        auto take = [&](size_t n) -> Bytes {
            Bytes out;
            if (pos + n > blob.size())
                return out;
            out.assign(blob.begin() + ptrdiff_t(pos), blob.begin() + ptrdiff_t(pos + n));
            pos += n;
            return out;
        };
        Bytes e = take(hdr.cbPublicExp);
        Bytes n = take(hdr.cbModulus);
        Bytes p = take(hdr.cbPrime1);
        Bytes q = take(hdr.cbPrime2);
        Bytes dp = take(hdr.cbPrime1);
        Bytes dq = take(hdr.cbPrime2);
        Bytes qinv = take(hdr.cbPrime1);
        if (e.empty() || n.empty() || p.empty() || q.empty()
            || dp.empty() || dq.empty() || qinv.empty())
            return false;

        // PKCS#1: SEQUENCE { version(0), n, e, d, p, q, dp, dq, qinv }.
        Bytes d = derivePrivateExponent(p, q, e);
        std::printf("[crypto] gen: blob=%zu e=%zu n=%zu p=%zu q=%zu d=%zu\n",
                    blob.size(), e.size(), n.size(), p.size(), q.size(), d.size());
        fflush(stdout);
        if (d.empty())
            return false;
        Bytes der = derSequence({ derInt({0}), derInt(n), derInt(e), derInt(d),
                                  derInt(p), derInt(q), derInt(dp), derInt(dq),
                                  derInt(qinv) });
        QString b64 = QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(der.data()),
                                                     int(der.size())).toBase64());
        QString pem = QStringLiteral("-----BEGIN RSA PRIVATE KEY-----\n");
        for (int i = 0; i < b64.size(); i += 64)
            pem += b64.mid(i, 64) + QStringLiteral("\n");
        pem += QStringLiteral("-----END RSA PRIVATE KEY-----\n");

        // round-trip: la PEM generada debe firmar sin lanzar
        (void)rsaSignPkcs1Sha256(pem, QByteArray("roundtrip"));

        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        *pemOut = pem;
        return true;
    } catch (const std::exception &e) {
        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        std::printf("[crypto] generateRsaPem2048 failed: %s\n", e.what()); fflush(stdout);
        return false;
    }
}

// ================================================================
// DTF
// ================================================================
static std::int32_t sar32(std::uint32_t value, int shift)
{
    return std::int32_t(value) >> shift;
}

QString dtfEncrypt(const std::string &payload, const std::string &secret)
{
    int payloadLen = int(payload.size());
    int secretLen = int(secret.size());
    u32 ebx = (u32((payloadLen << 16) ^ secretLen) ^ 0x9e3779b9u);
    u32 r12d = ebx ^ 0xa5f00f5au;
    Bytes out;
    appendU32Be(out, r12d);
    auto appendU16Be = [&](std::uint16_t v) {
        out.push_back(std::uint8_t((v >> 8) & 0xFF));
        out.push_back(std::uint8_t(v & 0xFF));
    };
    appendU16Be(std::uint16_t(((ebx >> 16) ^ u32(payloadLen)) & 0xFFFFu));
    appendU16Be(std::uint16_t((ebx ^ u32(secretLen)) & 0xFFFFu));
    for (int i = 0; i < std::max(payloadLen, secretLen); ++i) {
        ebx ^= (ebx << 13);
        ebx ^= u32(sar32(ebx, 17));
        ebx ^= (ebx << 5);
        std::uint8_t r14d = std::uint8_t(ebx & 0x0Fu);
        std::uint8_t edi = std::uint8_t(u32(sar32(ebx, 4)) & 0x0Fu);
        std::uint8_t pc = i < payloadLen ? std::uint8_t(payload[size_t(i)])
            : std::uint8_t(u32(sar32(ebx, 8)) & 0xFFu);
        std::uint8_t mc = i < secretLen ? std::uint8_t(secret[size_t(i)])
            : std::uint8_t(u32(sar32(ebx, 16)) & 0xFFu);
        std::uint8_t r15d = std::uint8_t((pc + r14d) & 0xFFu);
        std::uint8_t r12v = std::uint8_t((mc + edi) & 0xFFu);
        r15d ^= edi;
        r12v ^= r14d;
        if (ebx & 0x80u) {
            out.push_back(r12v);
            out.push_back(r15d);
        } else {
            out.push_back(r15d);
            out.push_back(r12v);
        }
    }
    return b64Encode(out);
}

QString buildDtf(const QString &sk)
{
    u32 h1 = u32(QRandomGenerator::global()->generate());
    u32 h2 = u32(QRandomGenerator::global()->generate());
    Bytes dataIn("-1457143643", "-1457143643" + 11);
    Bytes raw = m2xcEncryptFull(dataIn,
                                bytesOf(sk), h1, h2);
    QString sf = QString("%1").arg(11, 8, 10, QLatin1Char('0')) + b64Encode(raw);
    while (sf.size() < 64)
        sf += QChar(33 + QRandomGenerator::global()->bounded(94));
    sf = sf.left(44) + '#' + sf.mid(45);
    return dtfEncrypt(sf.toStdString(), sk.toStdString());
}

// ================================================================
// misc
// ================================================================
std::pair<QString, QString> stringDesturple(const QString &token)
{
    QString s1, s2;
    int f = 0;
    double p1 = double(token.size()) / 4.0;
    double p2 = p1;
    for (size_t i = 0; i < size_t(token.size()) / 2; ++i) {
        int pos = (f == 0) ? int((p1 - 0.5) * 2.0 - 1.0) : int((p2 + 0.5) * 2.0 - 1.0);
        if (pos < 0 || size_t(pos + 1) >= size_t(token.size()))
            break;
        QChar a = token.at(pos);
        QChar b = token.at(pos + 1);
        if (f == 0) { s1 += b; s2 += a; }
        else        { s1 += a; s2 += b; }
        f = 1 - f;
        if (f == 1) p1 -= 1.0;
        else        p2 += 1.0;
    }
    return {s1, s2};
}

QString genMagic(size_t length)
{
    // charset identico al del binario/Python: incluye los digitos
    static const char *chars = "abcdefghilmnopqrstuwjkxyzQWERTYUIOPASDFGHJKLZXCVBNM0123456789";
    int n = int(std::strlen(chars));
    QString out;
    for (size_t i = 0; i < length; ++i)
        out += QChar(chars[QRandomGenerator::global()->bounded(n)]);
    return out;
}

QString randomDoubleText()
{
    // rndx exacto del binario: "%.2f" % random.random() = 2 decimales
    // (captured_urls: rndx=0.84, 0.02, 0.21). El server valida el formato.
    double d = double(QRandomGenerator::global()->generate()) / double(0xFFFFFFFFu);
    return QString::number(d, 'f', 2);
}

QString rndx()
{
    return randomDoubleText();
}

QString readDeviceId()
{
    QString path = qEnvironmentVariable("APPDATA") + "/Freakinware/MitosisOG/qw.sol";
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return {};
    QByteArray txt = f.readAll();
    int i = txt.indexOf("y8:deviceIdy");
    if (i < 0)
        return {};
    QByteArray after = txt.mid(i + int(strlen("y8:deviceIdy")));
    int c = after.indexOf(':');
    int n = after.left(c).toInt();
    QByteArray raw = after.mid(c + 1, n);
    return QUrl::fromPercentEncoding(raw);
}
