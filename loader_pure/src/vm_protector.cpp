#include "vm_protector.h"
#include <Windows.h>
#include <intrin.h>
#include <cstdlib>
#include <cstring>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace vm {

static VMHandlerEntry g_handlers[256];
static bool g_handlers_init = false;

static uint64_t g_build_key = 0;

static uint64_t derive_build_key() {
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    uint64_t t = cnt.QuadPart;
    uint64_t f = freq.QuadPart;
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    uint64_t mem = ms.ullTotalPhys;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint64_t proc = si.dwNumberOfProcessors;
    return (t ^ (f << 17) ^ (mem >> 3) ^ (proc * 0x9E3779B97F4A7C15ULL)) & 0xFFFFFFFFFFFFFFFFULL;
}

uint64_t vm_get_build_key() {
    if (g_build_key == 0) {
        g_build_key = derive_build_key();
    }
    return g_build_key;
}

static inline uint64_t vm_mix(uint64_t a, uint64_t b) noexcept {
    a ^= b + 0x9E3779B97F4A7C15ULL + (a << 6) + (a >> 2);
    return a;
}

static inline uint64_t vm_rotl(uint64_t v, int n) noexcept {
    return (v << n) | (v >> (64 - n));
}

static inline bool vm_check_zf(VMContext* ctx) {
    return ctx->regs[0] == 0;
}

static void vm_push_imm(VMContext& c) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= (uint64_t)c.bytecode[c.pc + i] << (i * 8);
    }
    c.pc += 8;
    if (c.sp < 256) {
        c.stack[c.sp++] = val;
    }
}

static void vm_push_reg(VMContext& c) {
    uint8_t reg = c.bytecode[c.pc++];
    if (c.sp < 256 && reg < 16) {
        c.stack[c.sp++] = c.regs[reg];
    }
}

static void vm_pop(VMContext& c) {
    uint8_t reg = c.bytecode[c.pc++];
    if (c.sp > 0 && reg < 16) {
        c.regs[reg] = c.stack[--c.sp];
    }
}

static void vm_add(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        uint64_t a = c.stack[--c.sp];
        c.stack[c.sp++] = a + b;
    }
}

static void vm_sub(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        uint64_t a = c.stack[--c.sp];
        c.stack[c.sp++] = a - b;
    }
}

static void vm_mul(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        uint64_t a = c.stack[--c.sp];
        c.stack[c.sp++] = a * b;
    }
}

static void vm_xor(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        uint64_t a = c.stack[--c.sp];
        c.stack[c.sp++] = a ^ b;
    }
}

static void vm_mov(VMContext& c) {
    uint8_t dst = c.bytecode[c.pc++];
    uint8_t src = c.bytecode[c.pc++];
    if (dst < 16 && src < 16) {
        c.regs[dst] = c.regs[src];
    }
}

static void vm_jmp(VMContext& c) {
    uint32_t offset = 0;
    for (int i = 0; i < 4; i++) {
        offset |= (uint32_t)c.bytecode[c.pc + i] << (i * 8);
    }
    c.pc = offset;
}

static void vm_jz(VMContext& c) {
    uint32_t offset = 0;
    for (int i = 0; i < 4; i++) {
        offset |= (uint32_t)c.bytecode[c.pc + i] << (i * 8);
    }
    c.pc += 4;
    if (c.sp > 0 && c.stack[c.sp - 1] == 0) {
        c.pc = offset;
    }
}

static void vm_jnz(VMContext& c) {
    uint32_t offset = 0;
    for (int i = 0; i < 4; i++) {
        offset |= (uint32_t)c.bytecode[c.pc + i] << (i * 8);
    }
    c.pc += 4;
    if (c.sp > 0 && c.stack[c.sp - 1] != 0) {
        c.pc = offset;
    }
}

static void vm_call(VMContext& c) {
    uint32_t offset = 0;
    for (int i = 0; i < 4; i++) {
        offset |= (uint32_t)c.bytecode[c.pc + i] << (i * 8);
    }
    c.pc += 4;
    if (c.sp < 256) {
        c.stack[c.sp++] = c.pc;
    }
    c.pc = offset;
}

static void vm_ret(VMContext& c) {
    if (c.sp > 0) {
        c.pc = (uint32_t)c.stack[--c.sp];
    }
}

static void vm_nop(VMContext& c) {
    (void)c;
}

static void vm_encrypt(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t key = c.stack[--c.sp];
        uint64_t val = c.stack[--c.sp];
        uint64_t result = val;
        for (int i = 0; i < 4; i++) {
            result ^= key + vm_rotl(vm_mix(result, key), 13);
            key = vm_rotl(key, 7);
        }
        c.stack[c.sp++] = result;
    }
}

static void vm_decrypt(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t key = c.stack[--c.sp];
        uint64_t val = c.stack[--c.sp];
        uint64_t result = val;
        for (int i = 0; i < 4; i++) {
            key = vm_rotl(key, 57);
            result ^= key + vm_rotl(vm_mix(result, key), 13);
        }
        c.stack[c.sp++] = result;
    }
}

static void vm_and(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        c.stack[c.sp - 1] &= b;
    }
}

static void vm_or(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        c.stack[c.sp - 1] |= b;
    }
}

static void vm_shl(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        c.stack[c.sp - 1] <<= (b & 63);
    }
}

static void vm_shr(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        c.stack[c.sp - 1] >>= (b & 63);
    }
}

static void vm_not(VMContext& c) {
    if (c.sp > 0) {
        c.stack[c.sp - 1] = ~c.stack[c.sp - 1];
    }
}

static void vm_neg(VMContext& c) {
    if (c.sp > 0) {
        c.stack[c.sp - 1] = -(int64_t)c.stack[c.sp - 1];
    }
}

static void vm_cmp(VMContext& c) {
    if (c.sp >= 2) {
        uint64_t b = c.stack[--c.sp];
        uint64_t a = c.stack[c.sp - 1];
        c.stack[c.sp - 1] = (a == b) ? 0 : ((a > b) ? 1 : (uint64_t)-1);
    }
}

static void vm_load(VMContext& c) {
    uint8_t reg = c.bytecode[c.pc++];
    if (c.sp > 0 && reg < 16) {
        uint64_t addr = c.stack[--c.sp];
        c.regs[reg] = *(uint64_t*)addr;
    }
}

static void vm_store(VMContext& c) {
    uint8_t reg = c.bytecode[c.pc++];
    if (c.sp > 0 && reg < 16) {
        uint64_t addr = c.stack[--c.sp];
        *(uint64_t*)addr = c.regs[reg];
    }
}

static void vm_halt(VMContext& c) {
    c.running = false;
}

static void vm_unknown(VMContext& c) {
    c.running = false;
}

void vm_init_handlers() {
    if (g_handlers_init) return;
    for (int i = 0; i < 256; i++) {
        g_handlers[i].handler = vm_unknown;
        g_handlers[i].complexity_score = 0;
    }

    g_handlers[(int)Opcode::OP_PUSH_IMM] = { vm_push_imm, 3 };
    g_handlers[(int)Opcode::OP_PUSH_REG] = { vm_push_reg, 2 };
    g_handlers[(int)Opcode::OP_POP]      = { vm_pop, 2 };
    g_handlers[(int)Opcode::OP_ADD]      = { vm_add, 1 };
    g_handlers[(int)Opcode::OP_SUB]      = { vm_sub, 1 };
    g_handlers[(int)Opcode::OP_MUL]      = { vm_mul, 1 };
    g_handlers[(int)Opcode::OP_XOR]      = { vm_xor, 1 };
    g_handlers[(int)Opcode::OP_MOV]      = { vm_mov, 1 };
    g_handlers[(int)Opcode::OP_JMP]      = { vm_jmp, 3 };
    g_handlers[(int)Opcode::OP_JZ]       = { vm_jz, 3 };
    g_handlers[(int)Opcode::OP_JNZ]      = { vm_jnz, 3 };
    g_handlers[(int)Opcode::OP_CALL]     = { vm_call, 3 };
    g_handlers[(int)Opcode::OP_RET]      = { vm_ret, 2 };
    g_handlers[(int)Opcode::OP_NOP]      = { vm_nop, 0 };
    g_handlers[(int)Opcode::OP_ENCRYPT]  = { vm_encrypt, 4 };
    g_handlers[(int)Opcode::OP_DECRYPT]  = { vm_decrypt, 4 };
    g_handlers[(int)Opcode::OP_AND]      = { vm_and, 1 };
    g_handlers[(int)Opcode::OP_OR]       = { vm_or, 1 };
    g_handlers[(int)Opcode::OP_SHL]      = { vm_shl, 1 };
    g_handlers[(int)Opcode::OP_SHR]      = { vm_shr, 1 };
    g_handlers[(int)Opcode::OP_NOT]      = { vm_not, 1 };
    g_handlers[(int)Opcode::OP_NEG]      = { vm_neg, 1 };
    g_handlers[(int)Opcode::OP_CMP]      = { vm_cmp, 1 };
    g_handlers[(int)Opcode::OP_LOAD]     = { vm_load, 3 };
    g_handlers[(int)Opcode::OP_STORE]    = { vm_store, 3 };
    g_handlers[(int)Opcode::OP_HALT]     = { vm_halt, 0 };

    g_handlers_init = true;
}

VMContext* vm_create(const uint8_t* bytecode, uint32_t size) {
    VMContext* ctx = (VMContext*)VirtualAlloc(NULL, sizeof(VMContext),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ctx) return nullptr;
    ZeroMemory(ctx, sizeof(VMContext));
    ctx->bytecode = (uint8_t*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ctx->bytecode) {
        VirtualFree(ctx, 0, MEM_RELEASE);
        return nullptr;
    }
    CopyMemory(ctx->bytecode, bytecode, size);
    ctx->bytecode_size = size;
    ctx->running = true;
    return ctx;
}

void vm_destroy(VMContext* ctx) {
    if (ctx) {
        if (ctx->bytecode) {
            SecureZeroMemory(ctx->bytecode, ctx->bytecode_size);
            VirtualFree(ctx->bytecode, 0, MEM_RELEASE);
        }
        SecureZeroMemory(ctx, sizeof(VMContext));
        VirtualFree(ctx, 0, MEM_RELEASE);
    }
}

int vm_execute(VMContext* ctx) {
    if (!ctx || !ctx->bytecode) return -1;
    vm_init_handlers();
    volatile int iterations = 0;
    while (ctx->running) {
        if (ctx->pc >= ctx->bytecode_size) break;
        uint8_t op = ctx->bytecode[ctx->pc++];
        VMHandler handler = g_handlers[op].handler;
        if (handler == vm_unknown) break;
        handler(*ctx);
        iterations++;
        if (iterations > 10000000) break;
    }
    return iterations;
}

void* vm_compile_function(void* original_func, size_t func_size, uint64_t build_key) {
    if (!original_func || func_size == 0) return nullptr;
    uint32_t total_size = (uint32_t)(func_size * 2 + 256);
    uint8_t* bytecode = (uint8_t*)VirtualAlloc(NULL, total_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!bytecode) return nullptr;
    uint32_t pos = 0;
    uint8_t* src = (uint8_t*)original_func;
    for (size_t i = 0; i < func_size; i += 8) {
        uint64_t chunk = 0;
        for (size_t j = 0; j < 8 && (i + j) < func_size; j++) {
            chunk |= (uint64_t)src[i + j] << (j * 8);
        }
        uint64_t encrypted = chunk ^ (build_key + i);
        bytecode[pos++] = (uint8_t)Opcode::OP_PUSH_IMM;
        for (int k = 0; k < 8; k++) {
            bytecode[pos++] = (uint8_t)(encrypted >> (k * 8));
        }
        bytecode[pos++] = (uint8_t)Opcode::OP_PUSH_IMM;
        uint64_t key_part = build_key ^ (i * 0x9E3779B97F4A7C15ULL);
        for (int k = 0; k < 8; k++) {
            bytecode[pos++] = (uint8_t)(key_part >> (k * 8));
        }
        bytecode[pos++] = (uint8_t)Opcode::OP_XOR;
        bytecode[pos++] = (uint8_t)Opcode::OP_NOP;
    }
    bytecode[pos++] = (uint8_t)Opcode::OP_HALT;
    return bytecode;
}

void vm_free_compiled(void* compiled) {
    if (compiled) {
        VirtualFree(compiled, 0, MEM_RELEASE);
    }
}

}
