#pragma once
#ifndef ANTI_VM_H
#define ANTI_VM_H
#include <Windows.h>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace anti_vm {

enum class VMType {
    NONE,
    VMWARE,
    VIRTUALBOX,
    HYPERV,
    QEMU,
    SANDBOXIE,
    CUCKOO,
    ANALYSIS_TOOL
};

struct VMDetectionResult {
    VMType type;
    bool detected;
    DWORD detection_method;
};

bool initialize();
VMDetectionResult run_all_checks();
void terminate_if_vm();

}

#endif
