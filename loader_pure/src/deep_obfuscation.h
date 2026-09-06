#pragma once
// ============================================================
// deep_obfuscation.h - Runtime API resolution + self-integrity
// (2026-08-21) Adds: hashed dynamic import resolution, .text CRC
// self-check, and stack-built strings for the most sensitive
// constants. Static analysis sees no plaintext, no direct imports.
// ============================================================
#include <windows.h>
#include <string>
#include "obfuscation.h"

namespace deep {

// --- Compile-time FNV-1a hash for API names ---
constexpr DWORD hashA(const char* s, DWORD h = 0x811C9DC5) {
    return s[0] == '\0' ? h : hashA(s + 1, (h ^ static_cast<unsigned char>(s[0])) * 0x01000193u);
}
constexpr DWORD hashW(const wchar_t* s, DWORD h = 0x811C9DC5) {
    return s[0] == L'\0' ? h : hashW(s + 1, (h ^ static_cast<unsigned char>(s[0])) * 0x01000193u);
}

// --- PEB-walk module lookup by hashed name ---
inline HMODULE findModuleHash(DWORD wanted) {
#if defined(_M_X64)
    const auto peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
#else
    const auto peb = reinterpret_cast<const unsigned char*>(__readfsdword(0x30));
#endif
    const auto ldr = reinterpret_cast<const unsigned char*>(*reinterpret_cast<void**>(const_cast<unsigned char*>(peb) + 0x18));
    const auto head = reinterpret_cast<const unsigned char*>(*reinterpret_cast<void**>(const_cast<unsigned char*>(ldr) + 0x20));
    auto cur = reinterpret_cast<const unsigned char*>(*reinterpret_cast<void* const*>(head));
    while (cur != head) {
        const auto entry = cur - 0x10;                       // LDR_DATA_TABLE_ENTRY.BaseDllName
        const auto us = reinterpret_cast<const UNICODE_STRING*>(entry + 0x58);
        if (us->Buffer && us->Length) {
            DWORD h = 0x811C9DC5;
            for (USHORT i = 0; i < us->Length / sizeof(wchar_t); ++i) {
                wchar_t ch = us->Buffer[i];
                if (ch >= L'A' && ch <= L'Z') ch += 32;
                h = (h ^ static_cast<unsigned char>(ch)) * 0x01000193u;
            }
            if (h == wanted) return reinterpret_cast<HMODULE>(*reinterpret_cast<void* const*>(entry + 0x30));
        }
        cur = reinterpret_cast<const unsigned char*>(*reinterpret_cast<void* const*>(cur));
    }
    return nullptr;
}

// --- Export table walk by hashed name ---
inline void* findExportHash(HMODULE mod, DWORD wanted) {
    if (!mod) return nullptr;
    const auto base = reinterpret_cast<const unsigned char*>(mod);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return nullptr;
    const auto exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + expRva);
    const auto names = reinterpret_cast<const DWORD*>(base + exp->AddressOfNames);
    const auto ords  = reinterpret_cast<const WORD*>(base + exp->AddressOfNameOrdinals);
    const auto funcs = reinterpret_cast<const DWORD*>(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const auto name = reinterpret_cast<const char*>(base + names[i]);
        // case-insensitive FNV over ASCII
        DWORD h = 0x811C9DC5;
        for (const char* p = name; *p; ++p) {
            char ch = *p; if (ch >= 'A' && ch <= 'Z') ch += 32;
            h = (h ^ static_cast<unsigned char>(ch)) * 0x01000193u;
        }
        if (h == wanted) return reinterpret_cast<void*>(const_cast<unsigned char*>(base) + funcs[ords[i]]);
    }
    return nullptr;
}

// --- Generic resolver: module hash + api hash ---
template <typename Fn>
inline Fn resolve(DWORD modHash, DWORD fnHash) {
    return reinterpret_cast<Fn>(findExportHash(findModuleHash(modHash), fnHash));
}

// --- Self integrity: checksum of .text section, computed at startup ---
inline DWORD g_textChecksum = 0;

inline bool computeTextChecksum() {
    const auto base = reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD sum = 0;
            const auto start = base + sec[i].VirtualAddress;
            const size_t len = sec[i].Misc.VirtualSize;
            for (size_t off = 0; off < len; off += 4) {
                DWORD v;
                __try { v = *reinterpret_cast<const volatile DWORD*>(start + off); }
                __except (EXCEPTION_EXECUTE_HANDLER) { break; }
                sum = ((sum << 7) | (sum >> 25)) ^ v;
            }
            g_textChecksum = sum;
            return true;
        }
    }
    return false;
}

inline bool textIntact() {
    DWORD before = g_textChecksum;
    computeTextChecksum();
    return before == g_textChecksum && before != 0;
}

} // namespace deep

// Hashed aliases for the APIs the loader resolves dynamically.
// Usage example:
//   auto pShellExecute = deep::resolve<decltype(&ShellExecuteW)>(
//        deep::hashW(L"shell32.dll"), deep::hashA("ShellExecuteW"));
