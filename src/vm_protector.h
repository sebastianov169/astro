#pragma once
#include <cstdint>
// Stub vm_protector - real VMProtect would be linked externally; stub allows syntax check
#define VM_PROTECT(x) 
#define VM_BEGIN
#define VM_END
namespace vm {
    inline uint64_t vm_get_build_key() { return 0xA5A5A5A5ULL; }
    inline uint64_t vm_get_pad() { return 0x5A5A5A5AULL; }
    inline uint32_t vm_get_key32() { return 0xDEADBEEF; }
}
