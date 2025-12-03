# Use PkgConfig to find xkbcommon if standard CMake find fails, 
# but usually find_package works if the FindXkbcommon.cmake module is present.
find_package(Xkbcommon REQUIRED)

set(autotype_WAYLAND_SOURCES AutoTypeWayland.cpp)

add_library(keepassxc-autotype-wayland MODULE ${autotype_WAYLAND_SOURCES})

# CHANGED: Qt5:: -> Qt6::
target_link_libraries(keepassxc-autotype-wayland 
    keepassxc_gui 
    Qt6::Core 
    Qt6::Widgets 
    Qt6::DBus 
    ${Xkbcommon_LIBRARIES}
)

install(TARGETS keepassxc-autotype-wayland
        BUNDLE DESTINATION . COMPONENT Runtime
        LIBRARY DESTINATION ${PLUGIN_INSTALL_DIR} COMPONENT Runtime)