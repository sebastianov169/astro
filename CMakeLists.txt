cmake_minimum_required(VERSION 3.21)

project(Astro VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Quick QuickControls2 Network Widgets)
qt_standard_project_setup()

# Ed25519 (orlp public-domain) for license attestation verification
file(GLOB ED25519_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/security/crypto/ed25519/*.cpp")

# Port hardening-v92: v92 intacto (farm/crypto/login/tcp + Main.qml 3 paginas).
# src/main.cpp se preserva en disco pero el entry es src/main_secured.cpp
# para evitar main() duplicado. Sin Utopia.
add_executable(Astro
    ${ED25519_SOURCES}
    src/main_secured.cpp
    src/farm_controller.h
    src/farm_controller.cpp
    src/crypto.h
    src/crypto.cpp
    src/login.h
    src/login.cpp
    src/tcp_farm.h
    src/tcp_farm.cpp
    src/security/license/license_structure.h
    src/security/license/tpm_reader.h
    src/security/license/tpm_reader.cpp
    src/security/license/license_manager.h
    src/security/license/license_manager.cpp
    src/security/winhttp_client.h
    src/security/winhttp_client.cpp
    src/security/protection/anti_debug.h
    src/security/protection/anti_debug.cpp
    src/security/protection/anti_vm.h
    src/security/protection/anti_vm.cpp
    src/security/protection/anti_sandbox.h
    src/security/protection/anti_sandbox.cpp
    src/security/protection/anti_frida.h
    src/security/protection/anti_frida.cpp
    src/security/protection/anti_dll.h
    src/security/protection/anti_dll.cpp
    src/security/protection/anti_dump.h
    src/security/protection/anti_dump.cpp
    src/security/protection/anti_patch.h
    src/security/protection/anti_patch.cpp
    src/security/protection/anti_iat.h
    src/security/protection/anti_iat.cpp
    src/security/protection/anti_analysis.h
    src/security/protection/anti_analysis.cpp
    src/security/loader/backend_api.h
    src/security/loader/encrypted_channel.h
    src/security/loader/encrypted_channel.cpp
    src/security/loader/secure_loader.h
    src/security/loader/secure_loader.cpp
    src/security/loader/autokill.h
    src/security/loader/autokill.cpp
    src/security/license/session_guard.h
    src/security/license/session_guard.cpp
    src/security/crypto/string_encrypt.h
    src/security/crypto/string_encrypt.cpp
    src/security/crypto/obfuscation.h
    src/security/crypto/m3xc.h
)

qt_add_qml_module(Astro
    URI Astro
    VERSION 1.0
    QML_FILES
        qml/Main.qml
    RESOURCES
        assets/gems-sprite.png
        assets/gems/01-black-01.png
        assets/gems/01-black-02.png
        assets/gems/01-black-03.png
        assets/gems/01-black-04.png
        assets/gems/01-black-05.png
        assets/gems/02-blue-01.png
        assets/gems/02-blue-02.png
        assets/gems/02-blue-03.png
        assets/gems/02-blue-04.png
        assets/gems/02-blue-05.png
        assets/gems/03-brown-01.png
        assets/gems/03-brown-02.png
        assets/gems/03-brown-03.png
        assets/gems/03-brown-04.png
        assets/gems/03-brown-05.png
        assets/gems/04-cyan-01.png
        assets/gems/04-cyan-02.png
        assets/gems/04-cyan-03.png
        assets/gems/04-cyan-04.png
        assets/gems/04-cyan-05.png
        assets/gems/05-green-01.png
        assets/gems/05-green-02.png
        assets/gems/05-green-03.png
        assets/gems/05-green-04.png
        assets/gems/05-green-05.png
        assets/gems/06-orange-01.png
        assets/gems/06-orange-02.png
        assets/gems/06-orange-03.png
        assets/gems/06-orange-04.png
        assets/gems/06-orange-05.png
        assets/gems/07-pink-01.png
        assets/gems/07-pink-02.png
        assets/gems/07-pink-03.png
        assets/gems/07-pink-04.png
        assets/gems/07-pink-05.png
        assets/gems/08-purple-01.png
        assets/gems/08-purple-02.png
        assets/gems/08-purple-03.png
        assets/gems/08-purple-04.png
        assets/gems/08-purple-05.png
        assets/gems/09-red-01.png
        assets/gems/09-red-02.png
        assets/gems/09-red-03.png
        assets/gems/09-red-04.png
        assets/gems/09-red-05.png
        assets/gems/10-white-01.png
        assets/gems/10-white-02.png
        assets/gems/10-white-03.png
        assets/gems/10-white-04.png
        assets/gems/10-white-05.png
        assets/gems/11-yellow-01.png
        assets/gems/11-yellow-02.png
        assets/gems/11-yellow-03.png
        assets/gems/11-yellow-04.png
        assets/gems/11-yellow-05.png
        assets/gems/12-forest-01.png
        assets/gems/12-forest-02.png
        assets/gems/12-forest-03.png
        assets/gems/12-forest-04.png
        assets/gems/12-forest-05.png
        assets/gems/13-gold-01.png
        assets/gems/13-gold-02.png
        assets/gems/13-gold-03.png
        assets/gems/13-gold-04.png
        assets/gems/13-gold-05.png
        assets/gems/14-gray-01.png
        assets/gems/14-gray-02.png
        assets/gems/14-gray-03.png
        assets/gems/14-gray-04.png
        assets/gems/14-gray-05.png
        assets/gems/15-indigo-01.png
        assets/gems/15-indigo-02.png
        assets/gems/15-indigo-03.png
        assets/gems/15-indigo-04.png
        assets/gems/15-indigo-05.png
        assets/gems/16-magenta-01.png
        assets/gems/16-magenta-02.png
        assets/gems/16-magenta-03.png
        assets/gems/16-magenta-04.png
        assets/gems/16-magenta-05.png
        assets/gems/17-maroon-01.png
        assets/gems/17-maroon-02.png
        assets/gems/17-maroon-03.png
        assets/gems/17-maroon-04.png
        assets/gems/17-maroon-05.png
        assets/gems/18-rainbow-01.png
        assets/gems/18-rainbow-02.png
        assets/gems/18-rainbow-03.png
        assets/gems/18-rainbow-04.png
        assets/gems/18-rainbow-05.png
        assets/gems/19-silver-01.png
        assets/gems/19-silver-02.png
        assets/gems/19-silver-03.png
        assets/gems/19-silver-04.png
        assets/gems/19-silver-05.png
        assets/gems/20-teal-01.png
        assets/gems/20-teal-02.png
        assets/gems/20-teal-03.png
        assets/gems/20-teal-04.png
        assets/gems/20-teal-05.png
        assets/visuals/trap-hero.png
        assets/visuals/trap-lounge.png
        assets/visuals/trap-mono.png
)

set_target_properties(Astro PROPERTIES
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# AntiDBG (NotRequiem, MIT): opcional. En v92-clean no se exige el .lib para configurar.
# Si existe se enlaza, si no el build sigue con el resto del esquema.
set(ANTIDBG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../antidbg")
if(NOT EXISTS "${ANTIDBG_DIR}/build_md/Release/antidebug.lib")
    set(ANTIDBG_DIR "C:/Users/ren/Desktop/og mito/antidbg")
endif()
# ASTRO_NO_ANTIDBG=ON fuerza compilar sin el .lib externo (Hikari/1429: el .lib
# trae /GL de otro compiler y rompe el link LNK1257). Resto del esquema intacto.
if(DEFINED ASTRO_NO_ANTIDBG AND ASTRO_NO_ANTIDBG)
    set(ANTIDBG_DIR "C:/nonexistent-antidbg-disabled")
    add_compile_definitions(ASTRO_NO_ANTIDBG=1)
endif()
if(EXISTS "${ANTIDBG_DIR}/build_md/Release/antidebug.lib")
    add_library(antidebug STATIC IMPORTED)
    set_target_properties(antidebug PROPERTIES IMPORTED_LOCATION "${ANTIDBG_DIR}/build_md/Release/antidebug.lib")
    target_include_directories(Astro PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${ANTIDBG_DIR}/antidebug
    )
    target_link_libraries(Astro PRIVATE antidebug)
else()
    target_include_directories(Astro PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    message(STATUS "antidebug.lib no encontrado, se compila sin AntiDBG externo")
endif()

target_link_libraries(Astro PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Network
    Qt6::Widgets
    bcrypt
    crypt32
    ncrypt
    ntdll
    psapi
    ws2_32
    iphlpapi
    ole32
    oleaut32
    wlanapi
)

if(WIN32)
    target_compile_definitions(Astro PRIVATE NOMINMAX UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    # Ofuscacion total: renombrado de simbolos (funciones, variables, atributos) en todo el build
    if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        target_compile_options(Astro PRIVATE "/FI${CMAKE_CURRENT_SOURCE_DIR}/src/security/obfuscation_map.h")
    else()
        # clang-cl (Hikari): -FI con path separado evita el quoting roto de Ninja
        target_compile_options(Astro PRIVATE "/FI" "${CMAKE_CURRENT_SOURCE_DIR}/src/security/obfuscation_map.h")
    endif()

    # ---- Hikari LLVM: ofuscacion por-archivo (solo codigo propio; moc/Qt sin tocar) ----
    if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set(HIKARI_FLAGS "-mllvm;-enable-cffobf;-mllvm;-enable-bcfobf;-mllvm;-enable-subobf;-mllvm;-enable-splitobf")
        foreach(_src
            src/main.cpp
            src/login.cpp
            src/security/logging/hardware_info.cpp
            src/security/logging/secure_logger.cpp
            src/security/license/license_manager.cpp
            src/security/license/tpm_reader.cpp
            src/security/winhttp_client.cpp
            src/security/protection/anti_debug.cpp
            src/security/protection/anti_vm.cpp
            src/security/protection/anti_sandbox.cpp
            src/security/protection/anti_frida.cpp
            src/security/protection/anti_patch.cpp
            src/security/protection/anti_iat.cpp
            src/security/protection/anti_dump.cpp
            src/security/protection/anti_dll.cpp
            src/security/protection/anti_analysis.cpp
            src/security/loader/secure_loader.cpp
            src/security/loader/autokill.cpp
            src/security/loader/encrypted_channel.cpp
            src/security/license/session_guard.cpp
            src/security/crypto/string_encrypt.cpp
            src/security/crypto/ed25519/sha512.cpp
            src/security/crypto/ed25519/verify.cpp
            src/security/crypto/ed25519/fe.cpp
            src/security/crypto/ed25519/ge.cpp
            src/security/crypto/ed25519/sc.cpp
            src/security/crypto/ed25519/add_scalar.cpp)
            if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_src}")
                set_source_files_properties("${_src}" PROPERTIES COMPILE_OPTIONS "${HIKARI_FLAGS}")
            endif()
        endforeach()
        # TU grandes (farm_controller/main_secured/tcp_farm): clang15-Hikari los
        # tumba con pases full (ICE). Precedente tcp_farm: solo cff, resto intacto.
        set(HIKARI_TCP "-mllvm;-enable-cffobf")
        foreach(_big src/tcp_farm.cpp src/farm_controller.cpp src/main_secured.cpp)
            if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_big}")
                set_source_files_properties(${_big} PROPERTIES COMPILE_OPTIONS "${HIKARI_TCP}")
            endif()
        endforeach()
        set(HIKARI_LIGHT "-mllvm;-enable-cffobf;-mllvm;-enable-subobf")
        foreach(_src2 src/crypto.cpp)
            if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_src2}")
                set_source_files_properties("${_src2}" PROPERTIES COMPILE_OPTIONS "${HIKARI_LIGHT}")
            endif()
        endforeach()
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS Astro
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# SECURITY: private RSA key is NO LONGER shipped with the client.
# The previous copy_if_different exposed the server private key in astro_package.zip.
# If you need local development, symlink manually and never include in release.
# add_custom_command(TARGET Astro POST_BUILD ... embedded_rsa_private_14.pem) REMOVED

# ---- Release hardening & obfuscation (2026-08-21) ----
target_compile_options(Astro PRIVATE
    $<$<CONFIG:Release>:/GL>
    $<$<CONFIG:Release>:/GS>
    $<$<CONFIG:Release>:/sdl>
    $<$<CONFIG:Release>:/guard:cf>
    $<$<CONFIG:Release>:/Gy>
)
target_link_options(Astro PRIVATE
    $<$<CONFIG:Release>:/INCREMENTAL:NO>
    $<$<CONFIG:Release>:/OPT:REF,ICF>
    $<$<CONFIG:Release>:/GUARD:CF>
)
