#pragma once
#ifndef ENCRYPTED_SECTIONS_H
#define ENCRYPTED_SECTIONS_H
#include <Windows.h>
#include <intrin.h>
#include <cstdint>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace enc_sec {

static uint64_t g_hw_key = 0;

static inline uint64_t derive_hw_key() {
    uint64_t key = 0;
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    key ^= (uint64_t)cpuInfo[0] << 32;
    key ^= (uint64_t)cpuInfo[1];
    __cpuid(cpuInfo, 1);
    key ^= (uint64_t)cpuInfo[2] << 16;
    key ^= (uint64_t)cpuInfo[3] << 48;
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    key ^= ms.ullTotalPhys;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    key ^= (uint64_t)si.dwNumberOfProcessors * 0x9E3779B97F4A7C15ULL;
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    key ^= cnt.QuadPart;
    key ^= freq.QuadPart << 7;
    key = (key << 13) | (key >> 51);
    key ^= 0xDEADBEEFCAFEBABEULL;
    key = (key << 17) | (key >> 47);
    key ^= 0x123456789ABCDEF0ULL;
    return key;
}

static inline uint64_t get_hw_key() {
    if (g_hw_key == 0) {
        g_hw_key = derive_hw_key();
    }
    return g_hw_key;
}

static inline void encrypt_data(uint8_t* data, size_t size, uint64_t key) {
    uint8_t* p = data;
    uint8_t* end = data + size;
    while (p < end) {
        uint64_t chunk = 0;
        size_t remaining = (size_t)(end - p);
        size_t chunk_size = remaining < 8 ? remaining : 8;
        for (size_t i = 0; i < chunk_size; i++) {
            chunk |= (uint64_t)p[i] << (i * 8);
        }
        chunk ^= key;
        chunk = (chunk << 11) | (chunk >> 53);
        chunk ^= key * 0x9E3779B97F4A7C15ULL;
        for (size_t i = 0; i < chunk_size; i++) {
            p[i] = (uint8_t)(chunk >> (i * 8));
        }
        p += chunk_size;
        key = (key << 7) | (key >> 57);
        key ^= chunk;
    }
}

static inline void decrypt_data(uint8_t* data, size_t size, uint64_t key) {
    uint8_t* p = data;
    uint8_t* end = data + size;
    while (p < end) {
        uint64_t chunk = 0;
        size_t remaining = (size_t)(end - p);
        size_t chunk_size = remaining < 8 ? remaining : 8;
        for (size_t i = 0; i < chunk_size; i++) {
            chunk |= (uint64_t)p[i] << (i * 8);
        }
        chunk ^= key * 0x9E3779B97F4A7C15ULL;
        chunk = (chunk >> 11) | (chunk << 53);
        chunk ^= key;
        for (size_t i = 0; i < chunk_size; i++) {
            p[i] = (uint8_t)(chunk >> (i * 8));
        }
        p += chunk_size;
        key = (key << 7) | (key >> 57);
        key ^= chunk;
    }
}

struct EncryptedFunction {
    void* address;
    size_t size;
    uint64_t key;
    bool encrypted;
};

template<typename T>
class EncryptedFunc {
public:
    __declspec(noinline) EncryptedFunc(T func, size_t size)
        : m_func(func), m_size(size), m_key(get_hw_key()), m_encrypted(false) {}

    __declspec(noinline) ~EncryptedFunc() {
        if (m_encrypted) {
            decrypt();
        }
    }

    __declspec(noinline) T get() {
        if (m_encrypted) {
            decrypt();
        }
        return m_func;
    }

    __declspec(noinline) void encrypt() {
        if (!m_encrypted && m_func && m_size > 0) {
            encrypt_data((uint8_t*)m_func, m_size, m_key);
            m_encrypted = true;
        }
    }

    __declspec(noinline) void decrypt() {
        if (m_encrypted && m_func && m_size > 0) {
            decrypt_data((uint8_t*)m_func, m_size, m_key);
            m_encrypted = false;
        }
    }

private:
    T m_func;
    size_t m_size;
    uint64_t m_key;
    bool m_encrypted;
};

}

#define ENCRYPTED_FUNC_BEGIN(func_name) \
    __declspec(noinline) void func_name##_encrypted_impl()

#define ENCRYPTED_FUNC_END(func_name) \
    static enc_sec::EncryptedFunc<void(*)()> g_enc_##func_name( \
        func_name##_encrypted_impl, 0)

#define ENCRYPTED_SECTION(name) \
    __pragma(section(name, read, write)) \
    __declspec(allocate(name))

#define ENCRYPT_AT_STARTUP(func) \
    static bool g_enc_init_##func = false; \
    if (!g_enc_init_##func) { \
        g_enc_init_##func = true; \
    }

#define DECRYPT_AT_RUNTIME(func) \
    static bool g_dec_init_##func = false; \
    if (!g_dec_init_##func) { \
        g_dec_init_##func = true; \
    }

#endif
