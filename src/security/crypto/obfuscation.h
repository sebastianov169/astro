// obfuscation.h - Code obfuscation helpers for anti-analysis
// Compile-time random keys, control flow flattening, virtual branches,
// encrypted lambdas. All C++17, MSVC x64 compatible.
#pragma once

#include <cstdint>
#include <utility>
#include <intrin.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace security {
namespace obfuscation {

// ================================================================
// Compile-time random number generator (xorshift32)
// ================================================================
// Seeded from __TIME__ so each build produces different constants.
// Used to generate XOR keys, switch seeds, and branch masks at compile time.
struct XorShift32 {
    uint32_t state;

    constexpr XorShift32(uint32_t seed) noexcept : state(seed ? seed : 1) {}

    constexpr uint32_t next() noexcept
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }

    constexpr uint8_t nextByte() noexcept
    {
        return static_cast<uint8_t>(next() & 0xFF);
    }

    constexpr uint32_t range(uint32_t lo, uint32_t hi) noexcept
    {
        return lo + (next() % (hi - lo + 1));
    }
};

// File-scope RNG seeded from __TIME__ (mutable for runtime use in macros)
inline XorShift32 g_rng(
    static_cast<uint32_t>((__TIME__[0] - '0') * 10 + (__TIME__[1] - '0')) * 3600u +
    static_cast<uint32_t>((__TIME__[3] - '0') * 10 + (__TIME__[4] - '0')) * 60u +
    static_cast<uint32_t>((__TIME__[6] - '0') * 10 + (__TIME__[7] - '0')) +
    __LINE__ * 7u
);

// ================================================================
// OBFUSCATE(str) - Compile-time encrypted string
// ================================================================
// Drops into any context expecting a std::string or QString.
// Re-exports security::crypto::ENC under a shorter alias.

} // namespace obfuscation
} // namespace security

#include "string_encrypt.h"

namespace security {
namespace obfuscation {

#define OBFUSCATE(str)     ::security::crypto::ENC(str)
#define OBFUSCATE_S(str)   ::security::crypto::ENC_S(str)
#ifdef ASTRO_QT
#define OBFUSCATE_Q(str)   ::security::crypto::ENC_Q(str)
#endif

// ================================================================
// Control flow flattening
// ================================================================


#define FLATTEN_BEGIN(seed)                                              \
    {                                                                    \
        (void)(seed); /* el estado SIEMPRE arranca en el primer case (0):  \
                         si arrancara en el seed caeria a default y la      \
                         funcion retornaria vacia sin ejecutar nada */     \
        int __fl_state = 0;                                              \
        bool __fl_done = false;                                          \
        while (!__fl_done) {                                             \
            switch (__fl_state) {

#define FLATTEN_CASE(n)                                                  \
            case n:

#define FLATTEN_GOTO(n)                                                  \
                __fl_state = static_cast<int>(n);                        \
                break;

#define FLATTEN_END                                                      \
            default:                                                     \
                __fl_done = true;                                        \
                break;                                                   \
            }                                                            \
        }                                                                \
    }

/* HIKARI: cffobf ya aplana el control flow; el dispatcher manual while+switch
   duplicado dentro de cffobf genera loops infinitos (hang verificado en
   fetchManifest). Neutralizar FLATTEN bajo build Hikari. */
#ifdef ASTRO_HIKARI_BUILD
#undef FLATTEN_BEGIN
#define FLATTEN_BEGIN(seed) { {
#undef FLATTEN_CASE
#define FLATTEN_CASE(n)
#undef FLATTEN_GOTO
#define FLATTEN_GOTO(n)
#undef FLATTEN_END
#define FLATTEN_END } }
#endif

#define FLATTEN_BEGIN_NOARG                                              \
    {                                                                    \
        int __fl_state = static_cast<int>(__LINE__ ^ 0xDEADBEEF);        \
        bool __fl_done = false;                                          \
        while (!__fl_done) {                                             \
            switch (__fl_state) {

#define FLATTEN_END_NOARG FLATTEN_END

// ================================================================
// VIRTUAL_BRANCH - opaque predicate branching
// ================================================================
#define _VB_MASK(var)                                                    \
    (reinterpret_cast<uintptr_t>(&var) >> 3) & 1

#define VIRTUAL_BRANCH(cond)                                            \
    {                                                                    \
        volatile uintptr_t __vb_anchor = reinterpret_cast<uintptr_t>(&__vb_anchor); \
        if (static_cast<bool>(cond) ^ (_VB_MASK(__vb_anchor))) {

#define VIRTUAL_ELSE                                                     \
        } else {

#define VIRTUAL_END                                                      \
        }                                                                \
    }

// ================================================================
// ENCRYPTED_LAMBDA - XOR-wrapped lambda execution
// ================================================================
#define ENCRYPTED_LAMBDA(body)                                           \
    [__el_key = static_cast<uint32_t>(                                   \
          __COUNTER__ * 2654435761u ^ 0xDEADBEEFu)]() mutable {         \
        volatile uint32_t __el_state = __el_key;                         \
        __el_state ^= 0xDEADBEEFu;                                      \
        auto __el_body = [&]() { body };                                 \
        auto __el_result = __el_body();                                  \
        __el_state ^= 0xDEADBEEFu;                                      \
        return __el_result;                                              \
    }

#define ENCRYPTED_LAMBDA_VOID(body)                                      \
    [__el_key = static_cast<uint32_t>(                                   \
          __COUNTER__ * 2654435761u ^ 0xDEADBEEFu)]() mutable {         \
        volatile uint32_t __el_state = __el_key;                         \
        __el_state ^= 0xDEADBEEFu;                                      \
        body;                                                            \
        __el_state ^= 0xDEADBEEFu;                                      \
    }

// ================================================================
// Computed dispatch
// ================================================================
#define DISPATCH_BEGIN(name, max_states)                                 \
    {                                                                    \
        static const int _dp_##name##_table[] = {                        \
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15      \
        };                                                               \
        int _dp_##name##_state = 0;                                      \
        bool _dp_##name##_done = false;                                  \
        goto _dp_##name##_dispatch;                                      \
        while (!_dp_##name##_done) {                                     \
        _dp_##name##_dispatch:                                           \
        switch (_dp_##name##_table[_dp_##name##_state]) {

#define DISPATCH_CASE(n)                                                 \
            case n: {

#define DISPATCH_GOTO(name, n)                                           \
                _dp_##name##_state = (n);                                \
                break;

#define DISPATCH_END                                                     \
            default:                                                     \
                _dp_##name##_done = true;                                \
                break;                                                   \
            }                                                            \
        }                                                                \
    }

// ================================================================
// Opaque constant
// ================================================================
template<uint32_t Encrypted, uint8_t Key>
struct OpaqueConstant {
    static constexpr uint32_t value = Encrypted;

    static uint32_t decrypt() noexcept
    {
        uint32_t v = Encrypted;
        auto* p = reinterpret_cast<uint8_t*>(&v);
        for (int i = 0; i < 4; ++i)
            p[i] ^= static_cast<uint8_t>(Key ^ i);
        return v;
    }
};

#ifdef OPAQUE
#undef OPAQUE
#endif
#define OPAQUE(val)                                                      \
    ::security::obfuscation::OpaqueConstant<                             \
        static_cast<uint32_t>(val) ^ (static_cast<uint32_t>(__COUNTER__) * 0x01000193u), \
        ::security::obfuscation::g_rng.nextByte()                        \
    >::decrypt()

// ================================================================
// Junk / Opaque predicates (compatible with backend/loader obsuf)
// ================================================================
#ifndef JUNK_CODE
#define JUNK_CODE \
    do { \
        volatile uint64_t _jk_ = static_cast<uint64_t>(__rdtsc()); \
        _jk_ *= 0xBF58476D1CE4E5B9ULL; \
        _jk_ ^= (_jk_ >> 27); \
        _jk_ *= 0x94D049BB133111EBULL; \
        _jk_ ^= (_jk_ >> 31); \
        (void)_jk_; \
    } while (0)
#endif

#ifndef JUNK_LOOP
#define JUNK_LOOP(n) \
    for (volatile int _jl_ = 0; _jl_ < (n); ++_jl_) { \
        volatile uint64_t _jm_ = uint64_t(_jl_) * 0xDEADBEEFCAFEBABEULL; \
        _jm_ = (_jm_ << 13) | (_jm_ >> 51); \
        (void)_jm_; \
    }
#endif

#ifndef OPAQUE_PRED_TRUE
#ifdef OPAQUE
#undef OPAQUE
#endif
#define OPAQUE_PRED_TRUE(x) ((((uint64_t)(x) * (uint64_t)(x) + (uint64_t)(x)) & 1ULL) == 0)
#endif
#ifndef OPAQUE_PRED_FALSE
#ifdef OPAQUE
#undef OPAQUE
#endif
#define OPAQUE_PRED_FALSE(x) ((x) != 0 && ((x) ^ (x)) != 0)
#endif

} // namespace obfuscation
} // namespace security
