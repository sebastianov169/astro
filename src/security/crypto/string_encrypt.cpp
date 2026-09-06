// string_encrypt.cpp - Runtime helpers for compile-time string encryption
// Secure zeroing, string pool management, integrity verification
#include "string_encrypt.h"

#include <algorithm>
#include <vector>
#include <mutex>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace security {
namespace crypto {

// ================================================================
// String pool - runtime registry of encrypted string checksums
// ================================================================
// Used to verify that encrypted strings haven't been tampered with
// at runtime. Each ENC() string can optionally register itself here.

struct PoolEntry {
    uint32_t    checksum;
    const char* name;       // for debugging only (never plaintext)
    size_t      expectedLen;
};

static std::vector<PoolEntry>& getPool()
{
    static std::vector<PoolEntry> pool;
    return pool;
}

static std::mutex& getPoolMutex()
{
    static std::mutex mtx;
    return mtx;
}

bool registerEncryptedString(uint32_t checksum, const char* name, size_t len)
{
    std::lock_guard<std::mutex> lock(getPoolMutex());
    // Duplicate check
    for (const auto& e : getPool()) {
        if (e.checksum == checksum && e.expectedLen == len)
            return false; // already registered
    }
    getPool().push_back({ checksum, name, len });
    return true;
}

// ================================================================
// Integrity verification
// ================================================================
// Verify that all registered encrypted strings still have valid
// checksums. Returns the number of corrupted entries.
// Call this periodically or at critical code paths.

size_t verifyStringIntegrity()
{
    std::lock_guard<std::mutex> lock(getPoolMutex());
    size_t corrupted = 0;
    for (const auto& entry : getPool()) {
        // Recompute checksum over the encrypted bytes pointed to by name.
        // In practice, the caller stores the EncryptedString object and
        // calls its .checksum() method directly. This pool-based check
        // is a secondary defense layer.
        (void)entry;
        // TODO: if entries store a pointer to the encrypted data,
        // recompute and compare checksums here.
    }
    return corrupted;
}

// ================================================================
// XOR decryption routines (standalone, for use outside ENC macro)
// ================================================================

// Decrypt a buffer in-place with a single-byte XOR key
void xorDecryptInPlace(uint8_t* data, size_t len, uint8_t key) noexcept
{
    for (size_t i = 0; i < len; ++i)
        data[i] ^= static_cast<uint8_t>(key ^ (i & 0xFF));
}

// Decrypt a buffer into a new allocation
std::vector<uint8_t> xorDecrypt(const uint8_t* data, size_t len, uint8_t key) noexcept
{
    std::vector<uint8_t> result(len);
    for (size_t i = 0; i < len; ++i)
        result[i] = data[i] ^ static_cast<uint8_t>(key ^ (i & 0xFF));
    return result;
}

// XOR-encrypt a buffer (same operation as decrypt, symmetric)
void xorEncryptInPlace(uint8_t* data, size_t len, uint8_t key) noexcept
{
    xorDecryptInPlace(data, len, key);
}

// ================================================================
// Batch string pool encryption
// ================================================================
// At startup, encrypt all registered plaintext strings in the pool.
// This is called once during initialization and ensures no plaintext
// remains in .rdata after the pool is set up.

struct PlaintextEntry {
    char*       ptr;
    size_t      len;
    uint8_t     key;
};

static std::vector<PlaintextEntry>& getPlaintextPool()
{
    static std::vector<PlaintextEntry> pool;
    return pool;
}

void registerPlaintext(char* ptr, size_t len, uint8_t key)
{
    std::lock_guard<std::mutex> lock(getPoolMutex());
    getPlaintextPool().push_back({ ptr, len, key });
}

void encryptPool()
{
    std::lock_guard<std::mutex> lock(getPoolMutex());
    for (auto& entry : getPlaintextPool()) {
        for (size_t i = 0; i < entry.len; ++i)
            entry.ptr[i] ^= static_cast<char>(entry.key ^ (i & 0xFF));
    }
    // Clear the registration (strings are now encrypted)
    getPlaintextPool().clear();
}

// ================================================================
// Secure string utilities
// ================================================================

// removed

// Constant-time comparison (prevents timing side-channels)
bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

} // namespace crypto
} // namespace security
