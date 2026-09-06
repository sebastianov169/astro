#pragma once
#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <cstdint>
#include <array>
#include <type_traits>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace obf {

namespace detail {

constexpr uint64_t mix_seed(uint64_t a, uint64_t b) noexcept {
    a ^= b + 0x9E3779B97F4A7C15ULL + (a << 6) + (a >> 2);
    return a;
}

template <size_t N, uint64_t Key, uint64_t Seed>
struct XorString {
    char data[N]{};
    std::array<uint8_t,16> key_{};
    constexpr std::array<uint8_t,16> makeKey() noexcept {
        std::array<uint8_t,16> k{};
        uint64_t h = Key ^ Seed;
        for(size_t i=0;i<16;i++){
            h = mix_seed(h, i*0x9E3779B97F4A7C15ULL);
            k[i] = uint8_t((h >> ((i%8)*8)) & 0xFF) ^ uint8_t((Seed >> (i*4)) & 0xFF);
        }
        return k;
    }
    constexpr XorString(const char (&str)[N]) noexcept : key_(makeKey()) {
        for (size_t i = 0; i < N; ++i) {
            uint8_t ks = uint8_t(key_[i%16] ^ uint8_t(i & 0xFF) ^ uint8_t((i>>8)&0xFF));
            ks = uint8_t((ks << (i%3)) | (ks >> (8-(i%3))));
            data[i] = static_cast<char>(str[i] ^ static_cast<char>(ks));
        }
    }
    __declspec(noinline) const char* decrypt() const noexcept {
        static char buf[N]{};
        static bool done = false;
        if (!done) {
            for (size_t i = 0; i < N; ++i) {
                uint8_t ks = uint8_t(key_[i%16] ^ uint8_t(i & 0xFF) ^ uint8_t((i>>8)&0xFF));
                ks = uint8_t((ks << (i%3)) | (ks >> (8-(i%3))));
                buf[i] = static_cast<char>(data[i] ^ static_cast<char>(ks));
            }
            done = true;
        }
        return buf;
    }
    // RAII secure clear for decrypted buffer
    struct SecureClear {
        ~SecureClear(){ volatile char* p=(volatile char*)XorString::decrypt(); for(size_t i=0;i<N;i++) p[i]=0; }
    };
};

} // namespace detail

#define OBFUSCATE(str)     ([]() -> const char* {         constexpr static auto ct = ::obf::detail::XorString<             sizeof(str),             static_cast<uint64_t>(__LINE__) * 0xA0761D6478BD642FULL,             static_cast<uint64_t>(__COUNTER__) * 0x6C62272E07BB0142ULL         >(str);         return ct.decrypt();     }())

#define FLATTEN_BEGIN     {         int _obf_state_ = static_cast<int>(             (__LINE__ ^ 0xDEADBEEF) & 0x7FFFFFFF);         bool _obf_running_ = true;         while (_obf_running_) {             switch (_obf_state_) {

#define FLATTEN_END             default: _obf_running_ = false; break;             }         }     }

#define CASE(n)         case n: [[fallthrough]]

#define CASE_START(n)         case n:

#define CONTINUE(x)             _obf_state_ = (x); break

#define BREAK_FLAT             _obf_state_ = -1; break

#define JUNK_CODE     do {         volatile uint64_t _jk_ =             static_cast<uint64_t>(__rdtsc());         _jk_ *= 0xBF58476D1CE4E5B9ULL;         _jk_ ^= (_jk_ >> 27);         _jk_ *= 0x94D049BB133111EBULL;         _jk_ ^= (_jk_ >> 31);         (void)_jk_;     } while (0)

#define JUNK_LOOP(n)     for (volatile int _jl_ = 0; _jl_ < (n); ++_jl_) {         volatile uint64_t _jm_ = _jl_ * 0xDEADBEEFCAFEBABEULL;         _jm_ = (_jm_ << 13) | (_jm_ >> 51);         (void)_jm_;     }

#define OPAQUE_PRED_TRUE(x)     ((((uint64_t)(x) * (uint64_t)(x) + (uint64_t)(x)) & 1ULL) == 0)

#define OPAQUE_PRED_DIV7(x)     (((uint64_t)(x) * (uint64_t)(x) * (uint64_t)(x) - (uint64_t)(x)) % 7ULL == 0)

#define OPAQUE_PRED_FALSE(x)     ((x) != 0 && ((x) ^ (x)) != 0)

#define SPAGHETTI_BEGIN     {         int _sp_state_ = static_cast<int>(__rdtsc() & 0xFF);         goto SPAG_LABEL_##__LINE__;

#define SPAGHETTI_END         goto SPAG_EXIT_##__LINE__;         SPAG_EXIT_##__LINE__:;     }

#define SPAG_GOTO(n)     do {         _sp_state_ = (n);         goto SPAG_LABEL_##__LINE__;     } while(0)

#define SPAG_LABEL     SPAG_LABEL_##__LINE__:     switch (_sp_state_)

struct ObfString {
    char* buf;
    size_t len;
    size_t cap;
    ObfString(char* b, size_t c) : buf(b), len(0), cap(c) {}
    void push(char c) {
        if (len < cap) buf[len++] = c;
    }
    void push_obfuscated(char c, uint8_t key) {
        push(static_cast<char>(c ^ key));
    }
    const char* c_str() const {
        const_cast<char*>(buf)[len] = '\0';
        return buf;
    }
    ~ObfString(){ volatile char* p=(volatile char*)buf; for(size_t i=0;i<len;i++) p[i]=0; }
};

} // namespace obf

#include <intrin.h>

#endif // OBFUSCATION_H
