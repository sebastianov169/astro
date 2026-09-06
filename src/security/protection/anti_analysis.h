#pragma once
#ifndef ASTRO_ANTI_ANALYSIS_H
#define ASTRO_ANTI_ANALYSIS_H

#include <cstdint>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <intrin.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"

namespace security {

enum AstroDetection : uint32_t {
    ASTRO_DETECT_NONE             = 0,
    ASTRO_DETECT_DEBUGGER         = 1 << 0,
    ASTRO_DETECT_REMOTE_DEBUGGER  = 1 << 1,
    ASTRO_DETECT_DEBUG_PORT       = 1 << 2,
    ASTRO_DETECT_PEB_DEBUG        = 1 << 3,
    ASTRO_DETECT_NT_GLOBAL_FLAG   = 1 << 4,
    ASTRO_DETECT_HW_BREAKPOINTS   = 1 << 5,
    ASTRO_DETECT_TIMING           = 1 << 6,
    ASTRO_DETECT_TOOL_MODULE      = 1 << 7,
    ASTRO_DETECT_FRIDA_THREAD     = 1 << 8,
    ASTRO_DETECT_FRIDA_PORT       = 1 << 9,
    ASTRO_DETECT_MODULE_INTEGRITY = 1 << 10,
    ASTRO_DETECT_SCYLLAHIDE       = 1 << 11,
    ASTRO_DETECT_ALL              = 0x0FFF,
};

uint32_t astro_run_all_checks(bool autokill = false);

bool astro_check_is_debugger_present();
bool astro_check_remote_debugger_present();
bool astro_check_debug_port();
bool astro_check_peb_being_debugged();
bool astro_check_nt_global_flag();
bool astro_check_hw_breakpoints();
bool astro_check_timing();
bool astro_check_tool_modules();
bool astro_check_frida_threads();
bool astro_check_frida_ports();
bool astro_check_frida_pipes();
bool astro_check_module_integrity();
bool astro_check_scyllahide();
uint64_t astro_compute_text_hash();
bool astro_verify_text_hash(uint64_t expected);

}

#endif
