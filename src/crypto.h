// crypto.h - primitivas criptograficas del login Mitos.is (M2XC, AES, RSA, DTF)
#pragma once

#include <QByteArray>
#include <QString>
#include <QMutex>
#include <array>
#include <cstdint>
#include <string>

// Mutex global del parseo JSON (ver crypto.cpp): serializa
// QJsonDocument::fromJson + QHash internos entre los hilos de trabajo.
extern QMutex g_jsonParseMutex;

// Mutex global del LOGIN COMPLETO (KNOCK/LIM/EH + inventory + loginifneeded):
// Qt 6.10.3 crashea (AV 0xC0000005 en Qt6Core, familia qHashBits/SHA-512,
// RVAs 0x1CE857/0x1CF461/0x1C8A4E, siempre NULL-base r12=0 + [r12+0x7C])
// cuando VARIOS hilos construyen QJsonObject/QVariantMap/hashean a la vez,
// aun con los mutex de parseo y de QCryptographicHash (esas construcciones
// no pasan por ellos). Serializar el login completo elimina la clase de
// race: los logins del pre-spawn/refreshAll/QWS/farm se turnan el mutex.
extern QMutex g_loginMutex;

// Serializa el spawn TCP completo (spawnSession). Ver crypto.cpp.
extern QMutex g_spawnMutex;
extern QMutex g_matchMutex; // 2026-08-10: serializa SOLO la espera del [20]
// Serializa el FLUJO COMPLETO del refreshAll de cuentas SIN farm (login +
// fetchInventory + FarmWorker local con QNAM/connect/disconnect + spawn TCP
// FFA/CTF + settle polls). Verificado 2026-08-08: sin este lock, el flujo
// completo corriendo en paralelo con los 7 farms crasheaba la familia
// 0x1CE857 (QObject ctor/dtor del worker local + QHash internos de
// connect/disconnect contra el controller GUI; SEH con [r13+0x81], rdi=9).
// Los flujos completos quedan serializados entre si; las cuentas CON farm
// (read-only, sin red) no lo tocan.
extern QMutex g_refreshFullMutex;

#include <vector>

using Bytes = std::vector<std::uint8_t>;
using u32 = std::uint32_t;
constexpr u32 M = 0xFFFFFFFFu;

// helper: convierte QString/QByteArray a Bytes de forma segura (evita temporales)
inline Bytes bytesOf(const QString &s)
{
    QByteArray b = s.toUtf8();
    return Bytes(b.begin(), b.end());
}
inline Bytes bytesOf(const QByteArray &b)
{
    return Bytes(b.begin(), b.end());
}

// ---- base64 / hex ----
QString b64Encode(const Bytes &in);
Bytes   b64Decode(const QString &in);
QString urlB64EncodeNoPad(const Bytes &in);
QString md5Hex(const QString &in);

// ---- M2XC ----
u32 fmix(u32 x);
std::pair<u32, u32> fmix2(u32 x);
u32 ror(u32 x, int r);
u32 rol(u32 x, int r);
std::array<u32, 4> keystreamXxtea(const Bytes &key, std::array<u32, 4> state,
                                  u32 SUM, int counterOffset = 0, bool passB = false);
std::array<u32, 4> swfinalizePassA(std::array<u32, 4> s);
std::array<u32, 4> swfinalizePassB(std::array<u32, 4> s);
Bytes transform1(const Bytes &data, std::array<u32, 4> state, u32 H, bool passB = false);
Bytes transform2(const Bytes &data, u32 ha, u32 hb, int counterOffset = 0);
Bytes inverseTransform1(const Bytes &enc, std::array<u32, 4> state, u32 H, bool passB = false);
Bytes inverseTransform2(const Bytes &enc, u32 ha, u32 hb, int counterOffset = 0);
Bytes m2xcEncryptFull(const Bytes &data, const Bytes &key, u32 H1, u32 H2);
Bytes m2xcDecryptFull(const Bytes &blob, const Bytes &key);
QString m2xcFmt(const Bytes &blob);
Bytes parseM2xcBlob(const QString &s);

// ---- AES-CBC (BCrypt) ----
Bytes deriveAesKey(const QString &secret);
Bytes deriveCustomAesKey(const QString &secret, int offset);
Bytes aesCbcCrypt(const Bytes &input, const Bytes &key, bool encrypt);
QString aesEncrypt(const QString &payload, const QString &secret, int padTo = 16, bool prefixPaddedLen = false);
QString aesDecryptStr(const QString &payload, const QString &secret);
QString aesEncryptCustom(const QString &payload, const QString &secret, int offset);

// ---- RSA (BCrypt) ----
QString rsaEncryptPkcs1Base64(const QString &pem, const QString &plain);
Bytes   rsaSignPkcs1Sha256(const QString &pem, const QByteArray &msg);
QString buildMidPem(const QString &pem);

// Genera un par RSA-2048 (BCrypt) y lo exporta como PEM PKCS#1 privado.
// Devuelve false si falla. Requiere BCryptGenerateKeyPair.
bool generateRsaPem2048(QString *pemOut);

// ---- Firma TPM (clave MitosDeviceKeyV2 del equipo, via NCrypt) ----
// El SECURE_PROOF del TCP se firma con la clave TPM REAL del dispositivo,
// no con la PEM embebida (el server valida contra la clave TPM registrada).
Bytes tpmSignPkcs1Sha256(const QByteArray &msg);

// ---- DTF ----
QString dtfEncrypt(const std::string &payload, const std::string &secret);
QString buildDtf(const QString &sk);

// ---- misc ----
std::pair<QString, QString> stringDesturple(const QString &token);
QString genMagic(size_t length = 64);
QString randomDoubleText();
QString rndx();
QString readDeviceId();
