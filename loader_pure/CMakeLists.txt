cmake_minimum_required(VERSION 3.21)
project(AstroLoader VERSION 1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(AstroLoader WIN32
    src/main.cpp
    src/http_client.cpp
    src/tpm_reader.cpp
    src/anti_analysis.cpp
    src/anti_dll.cpp
    src/worker_crypto.cpp
    src/hw_collect.cpp
)

# AntiDBG (NotRequiem, MIT): syscall-based anti-debugging library
set(ANTIDBG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../antidbg")
add_library(antidebug_loader STATIC IMPORTED)
set_target_properties(antidebug_loader PROPERTIES IMPORTED_LOCATION "${ANTIDBG_DIR}/build_md/Release/antidebug.lib")

target_include_directories(AstroLoader PRIVATE src)
target_link_libraries(AstroLoader PRIVATE
    winhttp crypt32 ncrypt bcrypt ws2_32 psapi
    comctl32 shell32 ole32 oleaut32 shlwapi
    antidebug_loader
)
target_compile_definitions(AstroLoader PRIVATE NOMINMAX UNICODE _UNICODE)
# Ofuscacion deshabilitada temporalmente para build con espacio en path - se incluye manual en cpp si se necesita
# target_compile_options(AstroLoader PRIVATE /FI"${CMAKE_CURRENT_SOURCE_DIR}/src/obfuscation_map.h")

# ---- Release hardening & obfuscation (2026-08-21) ----
target_compile_options(AstroLoader PRIVATE
    $<$<CONFIG:Release>:/GL>          # Whole program optimization
    $<$<CONFIG:Release>:/GS>          # Buffer security check
    $<$<CONFIG:Release>:/sdl>         # Security development lifecycle checks
    $<$<CONFIG:Release>:/guard:cf>    # Control Flow Guard
    $<$<CONFIG:Release>:/Gy>          # Function-level linking
    $<$<CONFIG:Release>:/Zc:threadSafeInit-> # avoid static-init order issues
)
target_link_options(AstroLoader PRIVATE
    $<$<CONFIG:Release>:/LTCG>
    $<$<CONFIG:Release>:/INCREMENTAL:NO>
    $<$<CONFIG:Release>:/OPT:REF,ICF>   # Eliminate unreferenced funcs/data + COMDAT folding
    $<$<CONFIG:Release>:/GUARD:CF>
)
