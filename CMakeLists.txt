cmake_minimum_required(VERSION 3.16)
project(VirusTotalScannerPro LANGUAGES CXX)

if (NOT WIN32)
    message(FATAL_ERROR "This project targets Windows only (Dear ImGui DX11/Win32 backend, WinHTTP).")
endif()

if(MSVC)
    string(REPLACE "/Zi" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "/Zi" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    string(REPLACE "/Zi" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
    string(REPLACE "/Zi" "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
    
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG:NONE")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /DEBUG:NONE")

    set(CompilerFlags CMAKE_CXX_FLAGS_RELEASE CMAKE_C_FLAGS_RELEASE)
    foreach(flag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${flag} "${${flag}}")
    endforeach()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)
set(JSON_DIR  ${CMAKE_SOURCE_DIR}/third_party/json)

add_executable(VirusTotalScannerPro WIN32
    src/main.cpp
    src/app.cpp
    src/config.cpp
    src/http_client.cpp
    src/lang.cpp
    src/sha256.cpp

    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(VirusTotalScannerPro PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${JSON_DIR}
    src
)

target_compile_definitions(VirusTotalScannerPro PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

if(MSVC)
    target_compile_options(VirusTotalScannerPro PRIVATE /O2 /DNDEBUG)
endif()

target_link_libraries(VirusTotalScannerPro PRIVATE
    d3d11.lib
    d3dcompiler.lib
    dwmapi.lib
    winhttp.lib
    comdlg32.lib
    shell32.lib
)
