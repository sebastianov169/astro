#pragma once

#include <cstdint>
#include <cstring>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace astro {
namespace backend {

enum class FarmStatus : int {
    STOPPED = 0,
    RUNNING = 1,
    PAUSED  = 2,
    STATUS_ERROR = -1  // renamed: ERROR collides with winerror.h macro
};

struct InventoryItem {
    int id;
    int slot;
    int gem_type;
    int durability;
    int max_durability;
    char name[128];
};

struct FarmContext {
    void* internal;
};

struct BackendFunctions {
    uint32_t api_version;

    int  (*init)(const char* license_key, const char* hwid, FarmContext* ctx);
    void (*shutdown)(FarmContext* ctx);

    int  (*start_farm)(FarmContext* ctx, int gem_id);
    void (*stop_farm)(FarmContext* ctx);
    FarmStatus (*farm_status)(FarmContext* ctx);

    int  (*login)(FarmContext* ctx, const char* device_id, char* session_key_out, int key_buf_len);
    int  (*get_inventory)(FarmContext* ctx, int slot, InventoryItem* item_out);
    int  (*get_gem_info)(FarmContext* ctx, int* gem_id_out, int* gem_count_out);

    int  (*buy_item)(FarmContext* ctx, int item_id);
    int  (*equip_item)(FarmContext* ctx, int item_id, int slot);
    int  (*repair_item)(FarmContext* ctx, int item_id, int slot);

    int  (*api_call)(FarmContext* ctx, const char* json_body, char* response_out, int response_buf_len);

    void (*set_log_callback)(void (*callback)(const char* level, const char* message));
    void (*set_progress_callback)(void (*callback)(int percent, const char* status));
};

inline constexpr uint32_t BACKEND_API_VERSION = 1;

} // namespace backend
} // namespace astro

extern "C" {
    astro::backend::BackendFunctions* astro_init();
    void astro_shutdown();
}
