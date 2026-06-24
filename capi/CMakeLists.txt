cmake_minimum_required(VERSION 3.20)
project(cleitonq-capi
    VERSION 0.2.0
    DESCRIPTION "CleitonQ C API — post-quantum authentication for autonomous systems"
    LANGUAGES C
)

# ── Find Cargo ────────────────────────────────────────────────────────────────

find_program(CARGO_EXECUTABLE cargo
    REQUIRED
    DOC "Rust cargo package manager (https://rustup.rs)"
)

# ── Build configuration ───────────────────────────────────────────────────────

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(_CLQ_CARGO_FLAGS "")
    set(_CLQ_CARGO_PROFILE "debug")
else()
    set(_CLQ_CARGO_FLAGS "--release")
    set(_CLQ_CARGO_PROFILE "release")
endif()

set(_CLQ_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")

# ── Static library output path ───────────────────────────────────────────────

if(WIN32)
    set(_CLQ_LIB "${_CLQ_TARGET_DIR}/${_CLQ_CARGO_PROFILE}/cleitonq_capi.lib")
elseif(APPLE)
    set(_CLQ_LIB "${_CLQ_TARGET_DIR}/${_CLQ_CARGO_PROFILE}/libcleitonq_capi.a")
else()
    set(_CLQ_LIB "${_CLQ_TARGET_DIR}/${_CLQ_CARGO_PROFILE}/libcleitonq_capi.a")
endif()

# ── Cargo build command ────────────────────────────────────────────────────────

add_custom_command(
    OUTPUT "${_CLQ_LIB}"
    COMMAND ${CARGO_EXECUTABLE} build
            ${_CLQ_CARGO_FLAGS}
            --target-dir "${_CLQ_TARGET_DIR}"
            --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Building CleitonQ C API (cargo ${_CLQ_CARGO_PROFILE})..."
    VERBATIM
)

add_custom_target(cleitonq_capi_cargo ALL DEPENDS "${_CLQ_LIB}")

# ── Imported static target ─────────────────────────────────────────────────────

add_library(CleitonQ::capi STATIC IMPORTED GLOBAL)
add_dependencies(CleitonQ::capi cleitonq_capi_cargo)
set_target_properties(CleitonQ::capi PROPERTIES
    IMPORTED_LOCATION "${_CLQ_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# Rust static libs require platform system libraries
if(UNIX AND NOT APPLE)
    set_target_properties(CleitonQ::capi PROPERTIES
        INTERFACE_LINK_LIBRARIES "dl;pthread;m"
    )
elseif(APPLE)
    set_target_properties(CleitonQ::capi PROPERTIES
        INTERFACE_LINK_LIBRARIES "-framework Security;-framework CoreFoundation"
    )
elseif(WIN32)
    set_target_properties(CleitonQ::capi PROPERTIES
        INTERFACE_LINK_LIBRARIES "Bcrypt;ws2_32;Userenv;ntdll"
    )
endif()

# ── Examples ──────────────────────────────────────────────────────────────────

option(CLEITONQ_BUILD_EXAMPLES "Build C API usage examples" ON)
if(CLEITONQ_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ── Install ───────────────────────────────────────────────────────────────────

include(GNUInstallDirs)

install(FILES include/cleitonq.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(FILES "${_CLQ_LIB}"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

# ── CMake package config (find_package support) ───────────────────────────────

include(CMakePackageConfigHelpers)

configure_package_config_file(
    cmake/CleitonQConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/CleitonQConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CleitonQ"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/CleitonQConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/CleitonQConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/CleitonQConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CleitonQ"
)

# ── Summary ───────────────────────────────────────────────────────────────────

message(STATUS "CleitonQ C API v${PROJECT_VERSION}")
message(STATUS "  Cargo:   ${CARGO_EXECUTABLE}")
message(STATUS "  Profile: ${_CLQ_CARGO_PROFILE}")
message(STATUS "  Output:  ${_CLQ_LIB}")
message(STATUS "  Include: ${CMAKE_CURRENT_SOURCE_DIR}/include")
