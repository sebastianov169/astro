#pragma once
#include <string>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace tpm {
    // Get hardware fingerprint (SHA-256 of motherboard + volume serial)
    std::string getHardwareId();
}
