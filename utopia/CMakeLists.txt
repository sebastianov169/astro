cmake_minimum_required(VERSION 3.21)

project(UtopiaDashboard VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Quick QuickControls2 Network Concurrent)

# The lab and shop images are runtime resources referenced from QML. Keep the
# lists generated from the asset folders so adding a new potion also packages
# its sprite in the application.
file(GLOB POTION_SPRITES CONFIGURE_DEPENDS
    RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    assets/potions/sprites/*.png
    assets/potions/lab_sprites/*.png
)

qt_add_executable(UtopiaDashboard
    src/main.cpp
    src/loginbridge.cpp
    src/login.cpp
    src/crypto.cpp
)

qt_add_qml_module(UtopiaDashboard
    URI Utopia
    VERSION 1.0
    QML_FILES
        qml/Main.qml
    RESOURCES
        assets/potions/catalog-01.png
        assets/potions/catalog-02.png
        assets/potions/catalog-03.png
        assets/potions/catalog-04.png
        assets/potions/catalog-05.png
        assets/visuals/rapper-close.png
        assets/visuals/rapper-cross.png
        assets/visuals/mixtape.png
        ${POTION_SPRITES}
)

set_target_properties(UtopiaDashboard PROPERTIES
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE FALSE
)

target_link_libraries(UtopiaDashboard PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Network
    Qt6::Concurrent
)

if(MINGW)
    target_link_libraries(UtopiaDashboard PRIVATE bcrypt crypt32 ncrypt comdlg32)
endif()

include(GNUInstallDirs)
install(TARGETS UtopiaDashboard
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
