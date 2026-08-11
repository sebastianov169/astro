cmake_minimum_required(VERSION 3.21)

project(Astro VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Quick QuickControls2 Network)

qt_add_executable(Astro
    src/main.cpp
    src/farm_controller.h
    src/farm_controller.cpp
    src/crypto.h
    src/crypto.cpp
    src/login.h
    src/login.cpp
    src/tcp_farm.h
    src/tcp_farm.cpp
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

target_link_libraries(Astro PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Network
    bcrypt
    crypt32
    ncrypt
)

if(WIN32)
    target_compile_definitions(Astro PRIVATE NOMINMAX UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
endif()

include(GNUInstallDirs)
install(TARGETS Astro
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# copia la clave privada RSA del backend junto al ejecutable
add_custom_command(TARGET Astro POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/embedded_rsa_private_14.pem"
        "$<TARGET_FILE_DIR:Astro>/embedded_rsa_private_14.pem"
)
