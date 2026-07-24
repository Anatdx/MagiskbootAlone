cmake_minimum_required(VERSION 3.20)

project(magiskboot_alone LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Crypto: mbedTLS only (SHA1/SHA256 + AVB verify/sign). No OpenSSL, no picosha2.
# LZ4: prefer the vendored Magisk-compatible source on every platform so
# standalone and embedded builds use the same implementation.
set(LZ4_VENDORED "${CMAKE_CURRENT_SOURCE_DIR}/external/lz4")
if(EXISTS "${LZ4_VENDORED}/lz4.c")
  set(LZ4_LIB_DIR "${LZ4_VENDORED}")
  message(STATUS "magiskboot: using vendored LZ4 (external/lz4)")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
  include(FetchContent)
  FetchContent_Declare(
    magisk_lz4
    GIT_REPOSITORY https://github.com/topjohnwu/Magisk.git
    GIT_TAG master
    GIT_SHALLOW TRUE
  )
  FetchContent_GetProperties(magisk_lz4)
  if(NOT magisk_lz4_POPULATED)
    FetchContent_Populate(magisk_lz4)
  endif()
  set(LZ4_LIB_DIR "${magisk_lz4_SOURCE_DIR}/native/src/external/lz4/lib")
  message(STATUS "magiskboot: using LZ4 from Magisk (git clone)")
else()
  include(FetchContent)
  FetchContent_Declare(
    lz4
    GIT_REPOSITORY https://github.com/lz4/lz4.git
    GIT_TAG v1.10.0
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(lz4)
  set(LZ4_LIB_DIR ${lz4_SOURCE_DIR}/lib)
  message(STATUS "magiskboot: using LZ4 from FetchContent (upstream)")
endif()

# Host (Linux/macOS/Windows): find zlib and optional OpenSSL.
# Android (NDK): use NDK sysroot zlib; OpenSSL typically OFF unless you provide a prebuilt.
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  # NDK provides zlib in the sysroot (libz)
  set(ZLIB_FOUND 1)
  find_library(LZMA_LIB lzma)
else()
  find_package(ZLIB REQUIRED)
  find_library(LZMA_LIB lzma)
endif()
include(CheckIncludeFile)
check_include_file("lzma.h" HAVE_LZMA_H)

set(MAGISKBOOT_USE_FETCHED_LZMA OFF)
if(NOT (LZMA_LIB AND HAVE_LZMA_H))
  include(FetchContent)
  # Build only liblzma from upstream xz, disable all command-line tools and NLS.
  set(XZ_TOOL_XZ OFF CACHE BOOL "" FORCE)
  set(XZ_TOOL_XZDEC OFF CACHE BOOL "" FORCE)
  set(XZ_TOOL_LZMADEC OFF CACHE BOOL "" FORCE)
  set(XZ_TOOL_LZMAINFO OFF CACHE BOOL "" FORCE)
  set(XZ_NLS OFF CACHE BOOL "" FORCE)
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    magisk_xz
    GIT_REPOSITORY https://github.com/tukaani-project/xz.git
    GIT_TAG v5.6.4
    GIT_SHALLOW TRUE
  )
  FetchContent_GetProperties(magisk_xz)
  if(NOT magisk_xz_POPULATED)
    if(POLICY CMP0169)
      cmake_policy(PUSH)
      cmake_policy(SET CMP0169 OLD)
    endif()
    FetchContent_Populate(magisk_xz)
    if(POLICY CMP0169)
      cmake_policy(POP)
    endif()
  endif()
  add_subdirectory(
    ${magisk_xz_SOURCE_DIR}
    ${magisk_xz_BINARY_DIR}
    EXCLUDE_FROM_ALL
  )
  if(TARGET liblzma)
    set(MAGISKBOOT_USE_FETCHED_LZMA ON)
  endif()
endif()

# mbedTLS: SHA1/SHA256 + X.509/RSA/ECDSA for AVB verify & sign
include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  mbedtls
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
  GIT_TAG v3.6.2
  GIT_SHALLOW TRUE
  GIT_SUBMODULES "framework"
)
FetchContent_MakeAvailable(mbedtls)
message(STATUS "magiskboot: using mbedTLS for SHA and AVB")

set(MAGISKBOOT_CORE_SOURCES
  src/base_host.cpp
  src/boot_ramdisk.cpp
  src/bootimg.cpp
  src/boot_crypto.cpp
  src/cpio.cpp
  ${LZ4_LIB_DIR}/lz4.c
  ${LZ4_LIB_DIR}/lz4frame.c
  ${LZ4_LIB_DIR}/lz4hc.c
  ${LZ4_LIB_DIR}/xxhash.c
)

add_library(magiskboot_core STATIC ${MAGISKBOOT_CORE_SOURCES})
target_include_directories(magiskboot_core PUBLIC
  src
)
target_include_directories(magiskboot_core PRIVATE
  ${LZ4_LIB_DIR}
)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  target_link_libraries(magiskboot_core PUBLIC z)
  # LZ4: no override — match Magisk (use lz4.c defaults: method 1 on GCC/Clang)
else()
  target_link_libraries(magiskboot_core PUBLIC ZLIB::ZLIB)
endif()

if(LZMA_LIB AND HAVE_LZMA_H)
  target_link_libraries(magiskboot_core PUBLIC ${LZMA_LIB})
  target_compile_definitions(magiskboot_core PRIVATE USE_LIBLZMA=1)
  message(STATUS "magiskboot: XZ support enabled via system liblzma")
elseif(MAGISKBOOT_USE_FETCHED_LZMA)
  target_link_libraries(magiskboot_core PUBLIC liblzma)
  target_include_directories(magiskboot_core PRIVATE "${magisk_xz_SOURCE_DIR}/src/liblzma/api")
  target_compile_definitions(magiskboot_core PRIVATE USE_LIBLZMA=1)
  message(STATUS "magiskboot: XZ support enabled via vendored xz/liblzma")
else()
  message(WARNING "magiskboot: liblzma not found; XZ support disabled")
endif()

target_link_libraries(magiskboot_core PUBLIC mbedx509 mbedcrypto)
target_compile_definitions(magiskboot_core PRIVATE USE_MBEDTLS=1)
target_include_directories(magiskboot_core PRIVATE ${mbedtls_SOURCE_DIR}/include)

add_executable(magiskboot src/magiskboot_main.cpp)
target_compile_definitions(magiskboot PRIVATE MAGISKBOOT_STANDALONE=1)
target_link_libraries(magiskboot PRIVATE magiskboot_core)

option(MAGISKBOOT_BUILD_TESTS "Build MagiskbootAlone unit tests" ON)
if(MAGISKBOOT_BUILD_TESTS)
  enable_testing()
  add_executable(cpio_document_test tests/cpio_document_test.cpp)
  target_link_libraries(cpio_document_test PRIVATE magiskboot_core)
  add_test(NAME cpio_document_test COMMAND cpio_document_test)
endif()

