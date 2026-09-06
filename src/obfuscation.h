#pragma once
// Shim for legacy #include "obfuscation.h" -> forwards to secured location
#include "security/crypto/string_encrypt.h"
#include "security/crypto/obfuscation.h"

// OBFUSCATE(str) -> const char* : decrypts compile-time XOR string into a static buffer.
// Compatible with loader-style call sites: QString::fromUtf8(OBFUSCATE("...")), std::string(OBFUSCATE("...")).
#define OBFUSCATE(str) ([]() -> const char* {         static const std::string _s = ::security::crypto::EncryptedString<sizeof(str), ::security::crypto::deriveKey(__COUNTER__, __LINE__)>(str).decrypt();         return _s.c_str();     }())

#ifndef OPAQUE_PRED_TRUE
#define OPAQUE_PRED_TRUE(x) ((((unsigned long long)(x) * (unsigned long long)(x) + (unsigned long long)(x)) & 1ULL) == 0)
#endif
