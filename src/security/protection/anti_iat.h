#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <windows.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"

namespace astro { namespace security {

// IAT Protection: snapshots critical IAT entries at startup and periodically
// verifies they haven't been redirected to foreign modules or inline-hooked.

struct IatEntry {
    const char* func_name;
    void* original_addr;
    HMODULE original_module;
};

class AntiIat {
public:
    static AntiIat& instance() {
        static AntiIat inst;
        return inst;
    }

    bool initialize();
    bool verifyIntegrity();
    size_t entryCount() const { return m_entries.size(); }

private:
    AntiIat() = default;

    std::vector<IatEntry> m_entries;
    bool m_initialized = false;

    static bool addressInModule(void* addr, HMODULE hmod);
    static bool isInlineHooked(void* funcAddr);
};

}} // namespace
