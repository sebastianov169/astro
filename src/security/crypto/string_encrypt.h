#pragma once
// string_encrypt.h - original restored + minimal 16B strengthening (keeps API)
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#ifdef ASTRO_QT
#include <QByteArray>
#include <QString>
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
namespace security {
namespace crypto {
constexpr uint8_t deriveKey(uint32_t counter, uint32_t line) noexcept
{
    constexpr uint32_t TIME_SEED =
        static_cast<uint32_t>((__TIME__[0] - '0') * 10 + (__TIME__[1] - '0')) * 3600u +
        static_cast<uint32_t>((__TIME__[3] - '0') * 10 + (__TIME__[4] - '0')) * 60u +
        static_cast<uint32_t>((__TIME__[6] - '0') * 10 + (__TIME__[7] - '0'));
    uint32_t h = counter * 2654435761u;
    h ^= line * 2246822519u;
    h ^= TIME_SEED;
    h ^= h >> 13;
    h *= 0x5bd1e995u;
    h ^= h >> 15;
    return static_cast<uint8_t>((h ^ (h >> 8)) & 0xFF);
}
inline void secureZero(volatile char* ptr, size_t n) noexcept
{
    for (size_t i = 0; i < n; ++i) ptr[i]=0;
}
inline void secureZero(void* ptr, size_t n) noexcept { secureZero(static_cast<volatile char*>(ptr), n); }
void secureClearString(std::string& str) noexcept;
#ifdef ASTRO_QT
void secureClearByteArray(QByteArray& arr) noexcept;
#endif
struct SecureStringClear{ std::string& ref; explicit SecureStringClear(std::string& s):ref(s){} ~SecureStringClear(){ secureClearString(ref);} };
inline bool isDebuggerPresent() noexcept { return ::IsDebuggerPresent()!=FALSE; }
template<size_t N, uint8_t Key>
class EncryptedString {
    std::array<char, N> data_{};
    // 16B expansion helper
    static constexpr std::array<uint8_t,16> expandKey() noexcept{
        std::array<uint8_t,16> k{};
        uint32_t h = uint32_t(Key)*2654435761u ^ uint32_t(N)*2246822519u;
        for(int i=0;i<16;i++){ h = (h*0x9E3779B9u) ^ uint32_t(i*0x85EBCA6Bu); h=(h<<13)|(h>>19); k[i]=uint8_t(h & 0xFF); }
        return k;
    }
public:
    constexpr EncryptedString(const char (&str)[N]) noexcept : data_{}
    {
        auto k16 = expandKey();
        for (size_t i = 0; i < N; ++i){
            uint8_t ks = uint8_t(k16[i%16] ^ uint8_t(i & 0xFF));
            data_[i] = str[i] ^ static_cast<char>(ks ^ Key);
        }
    }
    std::string decrypt() const
    {
        if (isDebuggerPresent()) return {};
        auto k16 = expandKey();
        std::string result(N-1,'\0');
        for (size_t i=0;i<N-1;++i){
            uint8_t ks = uint8_t(k16[i%16] ^ uint8_t(i & 0xFF));
            result[i]= data_[i] ^ static_cast<char>(ks ^ Key);
        }
        return result;
    }
#ifdef ASTRO_QT
    QString decryptQt() const { QByteArray utf8(decrypt().c_str(), static_cast<int>(N-1)); QString out=QString::fromUtf8(utf8); volatile char* p=const_cast<volatile char*>(utf8.data()); for(int i=0;i<utf8.size();++i) p[i]=0; return out; }
#endif
    std::string operator()() const { return decrypt(); }
    const std::array<char,N>& encrypted() const noexcept {return data_;}
    static constexpr size_t size() noexcept {return N;}
    static constexpr uint8_t key() noexcept {return Key;}
    constexpr uint32_t checksum() const noexcept { uint32_t crc=0x811c9dc5u; for(size_t i=0;i<N;++i){crc ^= uint32_t(uint8_t(data_[i])); crc*=0x01000193u;} return crc; }
};
#define _SEC_ENC_IMPL(str, key_val) ([]() -> const ::security::crypto::EncryptedString<sizeof(str), key_val>& { constexpr static auto _e = ::security::crypto::EncryptedString<sizeof(str), key_val>(str); return _e; }())
#define ENC(str) _SEC_ENC_IMPL(str, ::security::crypto::deriveKey(__COUNTER__, __LINE__))
#define ENC_S(str) ENC(str).decrypt()
#ifdef ASTRO_QT
#define ENC_Q(str) ENC(str).decryptQt()
#endif
void xorDecryptInPlace(uint8_t* data, size_t len, uint8_t key) noexcept;
std::vector<uint8_t> xorDecrypt(const uint8_t* data, size_t len, uint8_t key) noexcept;
void xorEncryptInPlace(uint8_t* data, size_t len, uint8_t key) noexcept;
bool registerEncryptedString(uint32_t checksum, const char* name, size_t len);
size_t verifyStringIntegrity();
void registerPlaintext(char* ptr, size_t len, uint8_t key);
void encryptPool();
bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept;
} // namespace crypto
} // namespace security
