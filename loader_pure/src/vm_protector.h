#pragma once
#ifndef VM_PROTECTOR_H
#define VM_PROTECTOR_H
#include <cstdint>
#include <cstddef>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace vm {

enum class Opcode : uint8_t {
    OP_PUSH_IMM = 0x01,
    OP_PUSH_REG = 0x02,
    OP_POP      = 0x03,
    OP_ADD      = 0x04,
    OP_SUB      = 0x05,
    OP_MUL      = 0x06,
    OP_XOR      = 0x07,
    OP_MOV      = 0x08,
    OP_JMP      = 0x09,
    OP_JZ       = 0x0A,
    OP_JNZ      = 0x0B,
    OP_CALL     = 0x0C,
    OP_RET      = 0x0D,
    OP_NOP      = 0x0E,
    OP_ENCRYPT  = 0x0F,
    OP_DECRYPT  = 0x10,
    OP_AND      = 0x11,
    OP_OR       = 0x12,
    OP_SHL      = 0x13,
    OP_SHR      = 0x14,
    OP_NOT      = 0x15,
    OP_NEG      = 0x16,
    OP_CMP      = 0x17,
    OP_LOAD     = 0x18,
    OP_STORE    = 0x19,
    OP_SYSCALL  = 0x1A,
    OP_HALT     = 0xFF,
};

struct VMContext {
    uint64_t regs[16];
    uint64_t stack[256];
    uint32_t sp;
    uint32_t pc;
    uint8_t* bytecode;
    uint32_t bytecode_size;
    bool running;
};

using VMHandler = void(*)(VMContext&);

struct VMHandlerEntry {
    VMHandler handler;
    uint32_t complexity_score;
};

VMContext* vm_create(const uint8_t* bytecode, uint32_t size);
void vm_destroy(VMContext* ctx);
int vm_execute(VMContext* ctx);
void vm_init_handlers();

void* vm_compile_function(void* original_func, size_t func_size, uint64_t build_key);
void vm_free_compiled(void* compiled);

uint64_t vm_get_build_key();

}

#define VM_PROTECT(func_name) \
    static void* _vm_compiled_##func_name = nullptr; \
    static bool _vm_init_##func_name = false; \
    if (!_vm_init_##func_name) { \
        _vm_init_##func_name = true; \
    }

#define VM_DISPATCH() vm::vm_execute(ctx)

#endif
