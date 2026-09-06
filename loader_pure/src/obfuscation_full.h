#pragma once
#ifndef OBFUSCATION_FULL_H
#define OBFUSCATION_FULL_H
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <Windows.h>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace obf_full {

struct ObfUnicodeStr { uint16_t Length; uint16_t MaximumLength; wchar_t* Buffer; };
struct ObfListEntry { ObfListEntry* Flink; ObfListEntry* Blink; };
struct ObfPebLdr {
    uint32_t Length; uint8_t Initialized; uint8_t _p[3]; void* SsHandle;
    ObfListEntry InLoadOrderModuleList; ObfListEntry InMemoryOrderModuleList;
    ObfListEntry InInitializationOrderModuleList;
};
struct ObfLdrEntry {
    ObfListEntry InLoadOrderLinks; ObfListEntry InMemoryOrderLinks;
    ObfListEntry InInitializationOrderLinks; void* DllBase; void* EntryPoint;
    uint32_t SizeOfImage; ObfUnicodeStr FullDllName; ObfUnicodeStr BaseDllName;
};
struct ObfPeb {
    uint8_t R0[2]; uint8_t BeingDebugged; uint8_t R1[1]; void* R2[2]; ObfPebLdr* Ldr;
};

constexpr uint32_t fnv1a(const char* s) noexcept {
    uint32_t h = 0x811C9DC5u;
    for (; *s; ++s) { h ^= static_cast<uint8_t>(*s); h *= 0x01000193u; }
    return h;
}

namespace h {
    constexpr uint32_t M_k32 = fnv1a(OBFUSCATE("kernel32.dll"));
    constexpr uint32_t M_u32 = fnv1a(OBFUSCATE("user32.dll"));
    constexpr uint32_t M_g32 = fnv1a(OBFUSCATE("gdi32.dll"));
    constexpr uint32_t M_s32 = fnv1a(OBFUSCATE("shell32.dll"));
    constexpr uint32_t M_c32 = fnv1a(OBFUSCATE("comctl32.dll"));
    constexpr uint32_t M_a32 = fnv1a(OBFUSCATE("advapi32.dll"));
    constexpr uint32_t M_bc  = fnv1a(OBFUSCATE("bcrypt.dll"));
    constexpr uint32_t M_wh  = fnv1a(OBFUSCATE("winhttp.dll"));
    constexpr uint32_t M_w2  = fnv1a(OBFUSCATE("ws2_32.dll"));
    constexpr uint32_t M_nt  = fnv1a(OBFUSCATE("ntdll.dll"));
    constexpr uint32_t M_wi  = fnv1a(OBFUSCATE("wininet.dll"));
    constexpr uint32_t F_GetProcAddress       = fnv1a(OBFUSCATE("GetProcAddress"));
    constexpr uint32_t F_GetModuleHandleA     = fnv1a(OBFUSCATE("GetModuleHandleA"));
    constexpr uint32_t F_LoadLibraryW         = fnv1a(OBFUSCATE("LoadLibraryW"));
    constexpr uint32_t F_FreeLibrary          = fnv1a(OBFUSCATE("FreeLibrary"));
    constexpr uint32_t F_GetTempPathW         = fnv1a(OBFUSCATE("GetTempPathW"));
    constexpr uint32_t F_CreateFileW          = fnv1a(OBFUSCATE("CreateFileW"));
    constexpr uint32_t F_ReadFile             = fnv1a(OBFUSCATE("ReadFile"));
    constexpr uint32_t F_WriteFile            = fnv1a(OBFUSCATE("WriteFile"));
    constexpr uint32_t F_CloseHandle          = fnv1a(OBFUSCATE("CloseHandle"));
    constexpr uint32_t F_GetFileAttributesW   = fnv1a(OBFUSCATE("GetFileAttributesW"));
    constexpr uint32_t F_FindFirstFileW       = fnv1a(OBFUSCATE("FindFirstFileW"));
    constexpr uint32_t F_FindNextFileW        = fnv1a(OBFUSCATE("FindNextFileW"));
    constexpr uint32_t F_FindClose            = fnv1a(OBFUSCATE("FindClose"));
    constexpr uint32_t F_DeleteFileW          = fnv1a(OBFUSCATE("DeleteFileW"));
    constexpr uint32_t F_RemoveDirectoryW     = fnv1a(OBFUSCATE("RemoveDirectoryW"));
    constexpr uint32_t F_CreateDirectoryW     = fnv1a(OBFUSCATE("CreateDirectoryW"));
    constexpr uint32_t F_CreateProcessW       = fnv1a(OBFUSCATE("CreateProcessW"));
    constexpr uint32_t F_WaitForSingleObject  = fnv1a(OBFUSCATE("WaitForSingleObject"));
    constexpr uint32_t F_GetCurrentProcess    = fnv1a(OBFUSCATE("GetCurrentProcess"));
    constexpr uint32_t F_TerminateProcess     = fnv1a(OBFUSCATE("TerminateProcess"));
    constexpr uint32_t F_CreateThread         = fnv1a(OBFUSCATE("CreateThread"));
    constexpr uint32_t F_GetSystemMetrics     = fnv1a(OBFUSCATE("GetSystemMetrics"));
    constexpr uint32_t F_MultiByteToWideChar  = fnv1a(OBFUSCATE("MultiByteToWideChar"));
    constexpr uint32_t F_SetWindowTextA       = fnv1a(OBFUSCATE("SetWindowTextA"));
    constexpr uint32_t F_SetWindowTextW       = fnv1a(OBFUSCATE("SetWindowTextW"));
    constexpr uint32_t F_GetWindowTextW       = fnv1a(OBFUSCATE("GetWindowTextW"));
    constexpr uint32_t F_SendMessageW         = fnv1a(OBFUSCATE("SendMessageW"));
    constexpr uint32_t F_CreateWindowExW      = fnv1a(OBFUSCATE("CreateWindowExW"));
    constexpr uint32_t F_CreateWindowW        = fnv1a(OBFUSCATE("CreateWindowW"));
    constexpr uint32_t F_RegisterClassExW     = fnv1a(OBFUSCATE("RegisterClassExW"));
    constexpr uint32_t F_ShowWindow           = fnv1a(OBFUSCATE("ShowWindow"));
    constexpr uint32_t F_UpdateWindow         = fnv1a(OBFUSCATE("UpdateWindow"));
    constexpr uint32_t F_GetMessageW          = fnv1a(OBFUSCATE("GetMessageW"));
    constexpr uint32_t F_TranslateMessage     = fnv1a(OBFUSCATE("TranslateMessage"));
    constexpr uint32_t F_DispatchMessageW     = fnv1a(OBFUSCATE("DispatchMessageW"));
    constexpr uint32_t F_PostQuitMessage      = fnv1a(OBFUSCATE("PostQuitMessage"));
    constexpr uint32_t F_DefWindowProcW       = fnv1a(OBFUSCATE("DefWindowProcW"));
    constexpr uint32_t F_LoadCursorW          = fnv1a(OBFUSCATE("LoadCursorW"));
    constexpr uint32_t F_LoadIconW            = fnv1a(OBFUSCATE("LoadIconW"));
    constexpr uint32_t F_GetClientRect        = fnv1a(OBFUSCATE("GetClientRect"));
    constexpr uint32_t F_EnableWindow         = fnv1a(OBFUSCATE("EnableWindow"));
    constexpr uint32_t F_SetBkMode            = fnv1a(OBFUSCATE("SetBkMode"));
    constexpr uint32_t F_SetTextColor         = fnv1a(OBFUSCATE("SetTextColor"));
    constexpr uint32_t F_SetBkColor           = fnv1a(OBFUSCATE("SetBkColor"));
    constexpr uint32_t F_DrawTextW            = fnv1a(OBFUSCATE("DrawTextW"));
    constexpr uint32_t F_CreateFontW          = fnv1a(OBFUSCATE("CreateFontW"));
    constexpr uint32_t F_CreateSolidBrush     = fnv1a(OBFUSCATE("CreateSolidBrush"));
    constexpr uint32_t F_FillRect             = fnv1a(OBFUSCATE("FillRect"));
    constexpr uint32_t F_CreateRoundRectRgn   = fnv1a(OBFUSCATE("CreateRoundRectRgn"));
    constexpr uint32_t F_FillRgn              = fnv1a(OBFUSCATE("FillRgn"));
    constexpr uint32_t F_DeleteObject         = fnv1a(OBFUSCATE("DeleteObject"));
    constexpr uint32_t F_CreatePen            = fnv1a(OBFUSCATE("CreatePen"));
    constexpr uint32_t F_SelectObject         = fnv1a(OBFUSCATE("SelectObject"));
    constexpr uint32_t F_MoveToEx             = fnv1a(OBFUSCATE("MoveToEx"));
    constexpr uint32_t F_LineTo               = fnv1a(OBFUSCATE("LineTo"));
    constexpr uint32_t F_RoundRect            = fnv1a(OBFUSCATE("RoundRect"));
    constexpr uint32_t F_ShellExecuteW        = fnv1a(OBFUSCATE("ShellExecuteW"));
    constexpr uint32_t F_InitCommonControlsEx = fnv1a(OBFUSCATE("InitCommonControlsEx"));
    constexpr uint32_t F_RegOpenKeyExW        = fnv1a(OBFUSCATE("RegOpenKeyExW"));
    constexpr uint32_t F_RegQueryValueExW     = fnv1a(OBFUSCATE("RegQueryValueExW"));
    constexpr uint32_t F_RegCloseKey          = fnv1a(OBFUSCATE("RegCloseKey"));
    constexpr uint32_t F_BCryptOpenAlgorithmProvider  = fnv1a(OBFUSCATE("BCryptOpenAlgorithmProvider"));
    constexpr uint32_t F_BCryptCreateHash             = fnv1a(OBFUSCATE("BCryptCreateHash"));
    constexpr uint32_t F_BCryptHashData               = fnv1a(OBFUSCATE("BCryptHashData"));
    constexpr uint32_t F_BCryptFinishHash             = fnv1a(OBFUSCATE("BCryptFinishHash"));
    constexpr uint32_t F_BCryptDestroyHash            = fnv1a(OBFUSCATE("BCryptDestroyHash"));
    constexpr uint32_t F_BCryptCloseAlgorithmProvider = fnv1a(OBFUSCATE("BCryptCloseAlgorithmProvider"));
    constexpr uint32_t F_BCryptGenRandom             = fnv1a(OBFUSCATE("BCryptGenRandom"));
    constexpr uint32_t F_WinHttpOpen          = fnv1a(OBFUSCATE("WinHttpOpen"));
    constexpr uint32_t F_WinHttpCloseHandle   = fnv1a(OBFUSCATE("WinHttpCloseHandle"));
    constexpr uint32_t F_WinHttpConnect       = fnv1a(OBFUSCATE("WinHttpConnect"));
    constexpr uint32_t F_WinHttpOpenRequest   = fnv1a(OBFUSCATE("WinHttpOpenRequest"));
    constexpr uint32_t F_WinHttpSendRequest   = fnv1a(OBFUSCATE("WinHttpSendRequest"));
    constexpr uint32_t F_WinHttpReceiveResponse = fnv1a(OBFUSCATE("WinHttpReceiveResponse"));
    constexpr uint32_t F_WinHttpQueryHeaders  = fnv1a(OBFUSCATE("WinHttpQueryHeaders"));
    constexpr uint32_t F_WinHttpReadData      = fnv1a(OBFUSCATE("WinHttpReadData"));
    constexpr uint32_t F_NtQueryInformationProcess = fnv1a(OBFUSCATE("NtQueryInformationProcess"));
    constexpr uint32_t F_InternetOpenA        = fnv1a(OBFUSCATE("InternetOpenA"));
    constexpr uint32_t F_InternetCloseHandle  = fnv1a(OBFUSCATE("InternetCloseHandle"));
    constexpr uint32_t F_InternetConnectA     = fnv1a(OBFUSCATE("InternetConnectA"));
    constexpr uint32_t F_HttpOpenRequestA     = fnv1a(OBFUSCATE("HttpOpenRequestA"));
    constexpr uint32_t F_HttpSendRequestA     = fnv1a(OBFUSCATE("HttpSendRequestA"));
    constexpr uint32_t F_InternetReadFile     = fnv1a(OBFUSCATE("InternetReadFile"));
    constexpr uint32_t F_HttpQueryInfoA       = fnv1a(OBFUSCATE("HttpQueryInfoA"));
    constexpr uint32_t F_InternetCrackUrlA    = fnv1a(OBFUSCATE("InternetCrackUrlA"));
    constexpr uint32_t F_InternetQueryOptionA = fnv1a(OBFUSCATE("InternetQueryOptionA"));
}

inline ObfPeb* get_peb() noexcept {
#ifdef _WIN64
    return reinterpret_cast<ObfPeb*>(__readgsqword(0x60));
#else
    return reinterpret_cast<ObfPeb*>(__readfsdword(0x30));
#endif
}
inline uint32_t hash_w_ci(const wchar_t* s, uint32_t bl) noexcept {
    uint32_t hv = 0x811C9DC5u; uint32_t n = bl / 2;
    for (uint32_t i = 0; i < n; ++i) { wchar_t c = s[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        hv ^= static_cast<uint8_t>(c & 0xFF); hv *= 0x01000193u; } return hv;
}
inline void* find_module(uint32_t mh) noexcept {
    ObfPeb* p = get_peb(); if (!p||!p->Ldr) return nullptr;
    ObfListEntry* hd = &p->Ldr->InMemoryOrderModuleList; ObfListEntry* c = hd->Flink;
    while (c != hd) {
        ObfLdrEntry* e = reinterpret_cast<ObfLdrEntry*>(
            reinterpret_cast<uint8_t*>(c) - offsetof(ObfLdrEntry, InMemoryOrderLinks));
        if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0)
            if (hash_w_ci(e->BaseDllName.Buffer, e->BaseDllName.Length) == mh)
                return e->DllBase;
        c = c->Flink;
    } return nullptr;
}
inline void* find_export(void* base, uint32_t fh) noexcept {
    if (!base) return nullptr;
    uint8_t* b = static_cast<uint8_t*>(base);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(b);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    auto* ed = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ed->Size == 0) return nullptr;
    auto* d = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(b + ed->VirtualAddress);
    uint32_t* nm = reinterpret_cast<uint32_t*>(b + d->AddressOfNames);
    uint16_t* or = reinterpret_cast<uint16_t*>(b + d->AddressOfNameOrdinals);
    uint32_t* fc = reinterpret_cast<uint32_t*>(b + d->AddressOfFunctions);
    for (uint32_t i = 0; i < d->NumberOfNames; ++i) {
        const char* n = reinterpret_cast<const char*>(b + nm[i]);
        uint32_t hv = 0x811C9DC5u;
        for (const char* p = n; *p; ++p) { hv ^= static_cast<uint8_t>(*p); hv *= 0x01000193u; }
        if (hv == fh) return b + fc[or[i]];
    } return nullptr;
}
inline void* resolve_api(uint32_t mh, uint32_t fh) noexcept {
    return find_export(find_module(mh), fh);
}
template<typename T>
inline T resolve(uint32_t mh, uint32_t fh) noexcept {
    return reinterpret_cast<T>(resolve_api(mh, fh));
}

namespace cx {
constexpr uint64_t mix(uint64_t a, uint64_t b) noexcept {
    a ^= b + 0x9E3779B97F4A7C15ULL + (a << 6) + (a >> 2); return a;
}
template<size_t N, uint64_t K, uint64_t S> struct XorN {
    char d[N]{};
    constexpr XorN(const char (&s)[N]) noexcept {
        for (size_t i = 0; i < N; ++i) { uint64_t k = mix(K, mix(S, i));
            d[i] = static_cast<char>(s[i] ^ static_cast<char>(k & 0xFF)); }
    }
    __declspec(noinline) const char* dec() const noexcept {
        static char buf[N]{}; static volatile bool done = false;
        if (!done) { for (size_t i = 0; i < N; ++i) { uint64_t k = mix(K, mix(S, i));
            buf[i] = static_cast<char>(d[i] ^ static_cast<char>(k & 0xFF)); } done = true; }
        return buf;
    }
};
template<size_t N, uint64_t K, uint64_t S> struct XorW {
    wchar_t d[N]{};
    constexpr XorW(const wchar_t (&s)[N]) noexcept {
        for (size_t i = 0; i < N; ++i) { uint64_t k = mix(K, mix(S, i));
            d[i] = static_cast<wchar_t>(s[i] ^ static_cast<wchar_t>(k & 0xFFFF)); }
    }
    __declspec(noinline) const wchar_t* dec() const noexcept {
        static wchar_t buf[N]{}; static volatile bool done = false;
        if (!done) { for (size_t i = 0; i < N; ++i) { uint64_t k = mix(K, mix(S, i));
            buf[i] = static_cast<wchar_t>(d[i] ^ static_cast<wchar_t>(k & 0xFFFF)); } done = true; }
        return buf;
    }
};
}
}

#define ENCRYPT_STR(s) ([]() -> const char* { \
    constexpr static auto _x_ = ::obf_full::cx::XorN<sizeof(s), \
        static_cast<uint64_t>(__LINE__)*0xA0761D6478BD642FULL^0x3C9B5F2E1A0D7468ULL, \
        static_cast<uint64_t>(__COUNTER__)*0x6C62272E07BB0142ULL^0x85B9A4D36E72F015ULL>(s); \
    return _x_.dec(); }())
#define DECRYPT_STR(var, s) const char* var = ENCRYPT_STR(s)
#define WENCRYPT_STR(s) ([]() -> const wchar_t* { \
    constexpr static auto _xw_ = ::obf_full::cx::XorW<sizeof(s)/sizeof(wchar_t), \
        static_cast<uint64_t>(__LINE__)*0xA0761D6478BD642FULL^0x7F3E1A5D9C2B8046ULL, \
        static_cast<uint64_t>(__COUNTER__)*0x6C62272E07BB0142ULL^0xA3D64E18B59C720FULL>(s); \
    return _xw_.dec(); }())

#define FLATTEN_BEGIN { volatile int _fls_ = static_cast<int>(__rdtsc()&0x7FFFFFFF); \
    volatile bool _flr_ = true; while(_flr_) { switch(_fls_) {
#define FL(n) case n:
#define FL_GOTO(n) _fls_ = static_cast<int>(n); break;
#define FL_GOTO_RND _fls_ = static_cast<int>((__rdtsc()>>17)^ \
    (static_cast<uint32_t>(_fls_)*0x9E3779B9u)); break;
#define FL_EXIT _fls_ = -1; break;
#define FLATTEN_END default: _flr_ = false; break; } } }

#define JUNK() do { volatile uint64_t _jk_ = static_cast<uint64_t>(__rdtsc()); \
    _jk_ = (_jk_*0xBF58476D1CE4E5B9ULL)^(_jk_>>27); _jk_ *= 0x94D049BB133111EBULL; \
    _jk_ ^= (_jk_>>31); (void)_jk_; } while(0)
#define JUNK_LOOP(n) for (volatile int _jl_=0;_jl_<(n);++_jl_) { \
    volatile uint64_t _jm_=static_cast<uint64_t>(_jl_)*0xDEADBEEFCAFEBABEULL; \
    _jm_=(_jm_<<13)|(_jm_>>51); _jm_^=0x9E3779B97F4A7C15ULL; (void)_jm_; }
#define JUNK_BLOCK do { volatile uint64_t _a_=__rdtsc(); \
    volatile uint64_t _b_=_a_^0x9E3779B97F4A7C15ULL; \
    volatile uint64_t _c_=(_b_<<13)|(_b_>>51); volatile uint64_t _d_=_c_*_a_; \
    _d_^=(_d_>>7); _a_=_d_+_c_; (void)_a_;(void)_b_;(void)_c_;(void)_d_; } while(0)

#define OPAQUE_TRUE(x) ((((uint64_t)(x)*(uint64_t)(x)+(uint64_t)(x))&1ULL)==0)
#define OPAQUE_DIV7(x) (((uint64_t)(x)*(uint64_t)(x)*(uint64_t)(x)-(uint64_t)(x))%7ULL==0)
#define OPAQUE_FALSE(x) ((x)!=0&&((x)^(x))!=0)
#define OPAQUE_GE1(x) (((x)|1)>=1)

#define SPAGHETTI_BEGIN { volatile int _sp_=static_cast<int>(__rdtsc()&0xFF); goto _sp_entry_;
#define SPAGHETTI_END goto _sp_done_; _sp_done_:; }
#define SPAG_LABEL(n) _sp_case_##n##_: if(true)
#define SPAG_SET(n) _sp_=(n); goto _sp_entry_;
#define SPAG_DISPATCH _sp_entry_: switch(_sp_)

#define ANTI_DISASM do { volatile int _ad_=static_cast<int>(__rdtsc()); \
    if(_ad_&1){__nop();__nop();__nop();__nop();__nop();__nop();__nop();__nop();} \
    else{__nop();__nop();__nop();__nop();} __nop();__nop();__nop(); } while(0)
#define ANTI_DISASM_IND do { static void(*_adt_)()[]={ \
    []{__nop();},[]{__nop();},[]{__nop();},[]{__nop();},[]{__nop();} }; \
    volatile uint32_t _adi_=static_cast<uint32_t>(__rdtsc())%5; _adt_[_adi_](); } while(0)

#define RESOLVE_FUNC_OBF(ret,nm,cc,mod,fn,...) \
    static ret (cc* nm)(__VA_ARGS__)=nullptr; \
    if(!nm){ ANTI_DISASM; \
    nm=::obf_full::resolve<ret(cc*)(__VA_ARGS__)>(::obf_full::h::mod,::obf_full::h::fn); JUNK(); }

static volatile uint64_t g_obf_sink = 0;
inline void obf_sink(uint64_t v) noexcept {
    g_obf_sink ^= v; g_obf_sink = (g_obf_sink<<13)|(g_obf_sink>>51);
}

constexpr uint64_t MUTATION_SEED = static_cast<uint64_t>(__LINE__) * 0xA0761D6478BD642FULL ^
    static_cast<uint64_t>(__COUNTER__) * 0x6C62272E07BB0142ULL ^ 0xDEADBEEFCAFEBABEULL;

#define VM_PROTECT(func_name) \
    { static void* _vm_compiled_##func_name = nullptr; \
    static bool _vm_init_##func_name = false; \
    if (!_vm_init_##func_name) { \
        _vm_init_##func_name = true; \
        _vm_compiled_##func_name = ::vm::vm_compile_function( \
            (void*)&func_name, 64, ::vm::vm_get_build_key()); \
    } }

#define ENCRYPTED_FUNC \
    __declspec(noinline) __attribute__((section(OBFUSCATE(".enc$M"))))

#define ANTI_VM_CHECK \
    do { volatile int _avm_=static_cast<int>(__rdtsc()); \
    if(_avm_&1){ \
        int _ci_[4]={0}; __cpuid(_ci_,1); \
        volatile bool _hv_=(_ci_[2]&(1<<31))!=0; \
        if(_hv_){ volatile int _d_=0; for(volatile int _i_=0;_i_<1000000;_i_++) \
            _d_+=_i_*3; TerminateProcess(GetCurrentProcess(),0); } \
    } } while(0)

#define ANTI_SANDBOX_CHECK \
    do { volatile int _asc_=static_cast<int>(__rdtsc()); \
    if(_asc_&3){ \
        DWORD _tc_=GetTickCount(); \
        if(_tc_<(1000*60*10)){ \
            volatile int _d_=0; for(volatile int _i_=0;_i_<1000000;_i_++) \
                _d_+=_i_*3; TerminateProcess(GetCurrentProcess(),0); \
        } \
    } } while(0)

#define VM_DISPATCH_LOOP() \
    { volatile int _vdl_=static_cast<int>(__rdtsc()&0x7FFFFFFF); \
    volatile bool _vdr_=true; while(_vdr_) { \
        switch(_vdl_&0xFF) { \
        case 0x00: _vdr_=false; break; \
        default: _vdl_=(static_cast<int>((__rdtsc()>>17)^ \
            (static_cast<uint32_t>(_vdl_)*0x9E3779B9u))&0x7FFFFFFF); break; \
        } } }

#endif
