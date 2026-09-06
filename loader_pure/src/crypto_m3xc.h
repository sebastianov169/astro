#pragma once
#ifndef CRYPTO_M3XC_H
#define CRYPTO_M3XC_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <span>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace m3xc {

// ── Constants ───────────────────────────────────────────────────────
constexpr size_t KEY_LEN        = 32;   // 256-bit master key
constexpr size_t IV_LEN         = 16;   // 128-bit IV
constexpr size_t BLOCK_SIZE     = 16;   // 128-bit block
constexpr size_t ROUNDS_PASS1   = 32;   // XTEA-inspired rounds
constexpr size_t ROUNDS_PASS2   = 16;   // cascade rounds
constexpr size_t HMAC_LEN       = 32;   // SHA-256 HMAC
constexpr size_t NONCE_LEN      = 16;
constexpr size_t MAX_PLAINTEXT  = 1024 * 1024; // 1 MB cap

// ── Custom types ────────────────────────────────────────────────────
using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

// ── S-box (256 bytes, generated from π digits, diffusion-optimized) ─
inline constexpr std::array<u8, 256> SBOX = {
    0xA3,0xD7,0x09,0x83,0xF8,0x48,0xF6,0x93,0x44,0x12,0x5E,0x26,0xC3,0x6E,0x1B,0xB8,
    0x72,0xC0,0x9A,0xEB,0x0F,0x54,0xBB,0xD0,0x3D,0x7F,0xA1,0x20,0xCE,0x4B,0x8C,0x19,
    0x5B,0x38,0x96,0xD4,0xA0,0xF3,0x74,0xE6,0x85,0x67,0xB1,0xC2,0x93,0x14,0xDE,0x5D,
    0xA8,0x34,0x37,0x8E,0x4D,0xA5,0x2F,0x62,0x30,0x18,0x7A,0xC5,0xE0,0xD5,0x06,0xB4,
    0x41,0xAF,0x8D,0xE9,0x2A,0x63,0xD1,0x57,0xBC,0x46,0x7B,0xD2,0x1C,0x6B,0xF1,0x9E,
    0x84,0x29,0xC9,0xE3,0x5A,0x0D,0x81,0x32,0xC4,0x70,0xF9,0x56,0x95,0x1A,0xB3,0x22,
    0x6A,0xE5,0xC7,0x04,0x79,0xD8,0x3C,0x89,0xF5,0x68,0x16,0x4C,0xB0,0xA7,0x52,0xE2,
    0x3E,0x10,0x02,0xC1,0xAA,0xBD,0x94,0x61,0xDA,0x39,0xFE,0xCC,0x2C,0x8B,0x05,0x7E,
    0x33,0x4E,0xDC,0x64,0x9B,0x2D,0x01,0x73,0xAC,0x87,0xF0,0xB5,0x3F,0x42,0xA6,0xCF,
    0xE1,0x5F,0xB9,0x43,0x11,0x0E,0xD3,0x2E,0x80,0x4A,0x66,0x1D,0xC6,0x55,0x97,0xE8,
    0x65,0xBA,0xF4,0xA9,0x82,0x15,0x2B,0xD9,0x76,0x3B,0xC8,0x03,0x59,0x7C,0x17,0x4F,
    0xCA,0x35,0xE4,0x0A,0x8F,0x27,0x92,0x71,0xB6,0xC6,0x40,0x53,0xA4,0x6D,0xB7,0x13,
    0x23,0x3A,0x77,0x82,0x47,0x99,0x31,0xE7,0xAE,0xD6,0x08,0x6C,0xF2,0x4C,0x9D,0x5C,
    0x8A,0x36,0x25,0xFB,0x75,0xEC,0xBB,0x07,0x69,0xA2,0xCD,0x19,0x49,0x86,0x24,0xD4,
    0x91,0x58,0x1E,0x78,0xAB,0xFC,0x3D,0x51,0xB2,0xE0,0x28,0x60,0x88,0x0C,0xA5,0x45,
    0xDE,0x2F,0x98,0xCF,0x7D,0xC3,0x12,0xBE,0x50,0x39,0x7E,0x90,0xCA,0x4F,0x67,0xA0
};

// ── M3XC State ──────────────────────────────────────────────────────
// 4x u32 internal state for Pass 1
struct alignas(16) State {
    u32 s[4];
    u8  cascade[256];   // Pass 2 cascade key stream
    u32 round_keys[ROUNDS_PASS1][4]; // expanded round keys
};

// ── Key Derivation Context ──────────────────────────────────────────
struct KDFContext {
    u8 license_key[KEY_LEN];
    u8 hardware_id[64];
    u64 timestamp;
    u8 salt[32];
};

// ── Core API ────────────────────────────────────────────────────────

// Derive a 256-bit key from license + HWID + timestamp using HKDF-like construction.
// out_key must be at least KEY_LEN bytes.
void derive_key(const KDFContext& ctx, u8 out_key[KEY_LEN]);

// Initialize M3XC state from a 256-bit key.
void init_state(State& st, const u8 key[KEY_LEN], const u8 iv[IV_LEN]);

// Pass 1: XTEA-inspired block cipher with custom S-box.
// Operates on a single 128-bit block (16 bytes) in-place.
void pass1_encrypt_block(State& st, u8 block[BLOCK_SIZE]);
void pass1_decrypt_block(State& st, u8 block[BLOCK_SIZE]);

// Pass 2: Byte-level XOR cascade.
// encrypt: plaintext → ciphertext (same length, rounded to BLOCK_SIZE).
// decrypt: ciphertext → plaintext.
void pass2_encrypt(State& st, u8* data, size_t len);
void pass2_decrypt(State& st, u8* data, size_t len);

// High-level encrypt / decrypt.
// Returns empty vector on failure.
std::vector<u8> encrypt(const u8* plaintext, size_t len,
                        const u8 key[KEY_LEN], const u8 iv[IV_LEN]);

std::vector<u8> decrypt(const u8* ciphertext, size_t len,
                        const u8 key[KEY_LEN], const u8 iv[IV_LEN]);

// Convenience wrappers using std::string / std::vector<u8>.
std::vector<u8> encrypt(const std::string& plaintext,
                        const u8 key[KEY_LEN], const u8 iv[IV_LEN]);

std::vector<u8> decrypt(const std::vector<u8>& ciphertext,
                        const u8 key[KEY_LEN], const u8 iv[IV_LEN]);

// ── HMAC-SHA256 (minimal, no OpenSSL) ──────────────────────────────
void hmac_sha256(const u8* key, size_t key_len,
                 const u8* data, size_t data_len,
                 u8 out[HMAC_LEN]);

// ── Base64 encode / decode ──────────────────────────────────────────
std::string base64_encode(const u8* data, size_t len);
std::vector<u8> base64_decode(const std::string& encoded);

// ── Utility ─────────────────────────────────────────────────────────
// Constant-time comparison to prevent timing side-channels.
bool ct_equal(const u8* a, const u8* b, size_t len);

// Securely zero memory.
void secure_zero(void* ptr, size_t len);

// Generate random bytes via BCryptGenRandom (no CRT randomness).
bool random_bytes(u8* out, size_t len);

} // namespace m3xc

#endif // CRYPTO_M3XC_H
