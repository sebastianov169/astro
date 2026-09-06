#pragma once
#ifndef ANTI_ANALYSIS_H
#define ANTI_ANALYSIS_H

#include <cstdint>
#include <string>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace antidebug {

// Detection result bitmask
enum Detection : uint32_t {
    DETECT_NONE              = 0,
    DETECT_DEBUGGER          = 1 << 0,
    DETECT_REMOTE_DEBUGGER   = 1 << 1,
    DETECT_DEBUG_PORT        = 1 << 2,
    DETECT_PEB_DEBUG         = 1 << 3,
    DETECT_NT_GLOBAL_FLAG    = 1 << 4,
    DETECT_HW_BREAKPOINTS    = 1 << 5,
    DETECT_TIMING            = 1 << 6,
    DETECT_TOOL_MODULE       = 1 << 7,
    DETECT_FRIDA_THREAD      = 1 << 8,
    DETECT_FRIDA_PORT        = 1 << 9,
    DETECT_MODULE_INTEGRITY  = 1 << 10,
    DETECT_SCYLLAHIDE        = 1 << 11,
    DETECT_ALL               = 0x0FFF,
};

// Run all checks.  Returns bitmask of detections.
// If autokill is true and any detection is found, terminates the process.
uint32_t run_all_checks(bool autokill = false);

// Individual checks (can be called separately)
bool check_is_debugger_present();
bool check_remote_debugger_present();
bool check_debug_port();
bool check_peb_being_debugged();
bool check_nt_global_flag();
bool check_hw_breakpoints();
bool check_timing();
bool check_tool_modules();
bool check_frida_threads();
bool check_frida_ports();
bool check_module_integrity();
bool check_scyllahide();

// Module integrity: hash the .text section of the main module.
// Call once at startup, then verify periodically.
uint64_t compute_text_hash();
bool verify_text_hash(uint64_t expected);

} // namespace antidebug

#endif // ANTI_ANALYSIS_H
