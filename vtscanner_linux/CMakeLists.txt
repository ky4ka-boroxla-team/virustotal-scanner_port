cmake_minimum_required(VERSION 3.10)
project(VirusTotalScannerLinux)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(X11 REQUIRED)
find_package(OpenGL REQUIRED)

set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui)

add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

target_include_directories(imgui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

add_executable(vt_scanner_linux
    src/main_linux.cpp
    src/app.cpp
    src/config.cpp
    src/lang.cpp
    src/sha256.cpp
    src/http_client_linux.cpp
)

target_include_directories(vt_scanner_linux PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/json
)

target_link_libraries(vt_scanner_linux
    imgui
    ${OPENSSL_LIBRARIES}
    ${X11_LIBRARIES}
    ${OPENGL_LIBRARIES}
    pthread
    dl
)