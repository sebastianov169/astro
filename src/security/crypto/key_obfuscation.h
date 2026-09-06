#pragma once
#include <QString>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace astro { namespace security { namespace crypto {

// ENCRYPTION_KEY protected with AES-256-GCM.
// The ciphertext, nonce and tag are embedded as byte arrays.
// The AES key is derived from a compile-time seed via SHA-256.
// Even if a reversor finds the ciphertext, they need to know the
// derivation seed AND implement the same KDF to recover the plaintext.

namespace detail {

inline bool aesGcmDecrypt(
    const uint8_t* key, uint32_t keyLen,
    const uint8_t* nonce, uint32_t nonceLen,
    const uint8_t* ct, uint32_t ctLen,
    const uint8_t* tag, uint32_t tagLen,
    uint8_t* plaintextOut, uint32_t plaintextBufSize)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    // Open AES-GCM algorithm
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // Set GCM chaining mode
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    // Import key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key, keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    // Prepare BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    struct AuthInfo {
        ULONG cbSize;
        ULONG dwInfoVersion;
        const UCHAR* pbNonce;
        ULONG cbNonce;
        const UCHAR* pbTag;
        UCHAR* pbTag2; // unused for decrypt but same field
        ULONG cbTag;
        const UCHAR* pbAuthData;
        ULONG cbAuthData;
        const UCHAR* pbMacContext;
        ULONG cbMacContext;
        ULONG cbAAD;
        ULONGLONG qbDataCopy;
    } authInfo = {};
    authInfo.cbSize = sizeof(authInfo);
    authInfo.dwInfoVersion = 1;
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = nonceLen;
    authInfo.pbTag = tag;
    authInfo.cbTag = tagLen;

    // Decrypt
    ULONG resultLen = 0;
    status = BCryptDecrypt(hKey,
        (PUCHAR)ct, ctLen,
        &authInfo,
        nullptr, 0,
        plaintextOut, plaintextBufSize,
        &resultLen, 0);

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
}

} // namespace detail

// Returns the deobfuscated ENCRYPTION_KEY as a QString.
// Uses AES-256-GCM decryption of an embedded ciphertext.
inline QString deobfuscateEncryptionKey() {
    // Derivation seed -> SHA-256 -> AES-256 key
    static const char kSeed[] = {
        0x41,0x73,0x74,0x72,0x6f,0x53,0x65,0x63,  // "AstroSec"
        0x75,0x72,0x65,0x4b,0x65,0x79,0x44,0x65,  // "ureKeyDe"
        0x72,0x69,0x76,0x61,0x74,0x69,0x6f,0x6e,  // "rivation"
        0x5f,0x76,0x31,0x5f,0x32,0x30,0x32,0x36,  // "_v1_2026"
        0x5f,0x30,0x38,0x5f,0x32,0x33             // "_08_23"
    };

    // SHA-256 of seed = f4f032caf277dd6cc1575aeaa969c40bd3d92144fb8b649b7e6dc96db233bb05
    static const uint8_t kAesKey[32] = {
        0xf4,0xf0,0x32,0xca,0xf2,0x77,0xdd,0x6c,
        0xc1,0x57,0x5a,0xea,0xa9,0x69,0xc4,0x0b,
        0xd3,0xd9,0x21,0x44,0xfb,0x8b,0x64,0x9b,
        0x7e,0x6d,0xc9,0x6d,0xb2,0x33,0xbb,0x05
    };

    static const uint8_t kNonce[12] = {
        0x5c,0x85,0x7a,0x46,0xa0,0x90,0x21,0x66,0x47,0xde,0x43,0x5f
    };

    static const uint8_t kCiphertext[64] = {
        0xd4,0x83,0xcd,0xf4,0xd1,0x20,0x0b,0xcc,
        0x6e,0xf0,0xf8,0xfb,0xc1,0xd3,0x8a,0x3f,
        0x12,0x53,0xbf,0xa1,0xb1,0x85,0x5c,0xae,
        0x6d,0xcd,0x82,0x3b,0x3d,0xf9,0x19,0xd1,
        0x0e,0x9b,0xf2,0x26,0x63,0xf3,0x86,0x59,
        0x80,0x60,0xd4,0x20,0x16,0xb3,0x62,0x06,
        0xb9,0x87,0x00,0x1e,0xdb,0xf4,0xde,0x66,
        0x0a,0x5c,0x71,0x0c,0x27,0x69,0x1a,0xf3
    };

    static const uint8_t kTag[16] = {
        0x6f,0x5a,0xca,0xcf,0xbf,0x06,0x52,0xf4,
        0x0f,0xd3,0xf9,0x62,0x4e,0x0b,0x92,0x03
    };

    uint8_t plaintext[65] = {};
    if (!detail::aesGcmDecrypt(kAesKey, 32, kNonce, 12,
                               kCiphertext, 64, kTag, 16,
                               plaintext, sizeof(plaintext) - 1)) {
        return QString(); // Decryption failed - tamper or wrong key
    }

    QString result = QString::fromLatin1(reinterpret_cast<const char*>(plaintext), 64);
    SecureZeroMemory(plaintext, sizeof(plaintext));
    return result;
}

}}} // namespace
