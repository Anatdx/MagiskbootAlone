cmake_minimum_required(VERSION 3.20)

project(magiskboot_alone LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(MAGISKBOOT_USE_OPENSSL "Use OpenSSL for SHA1/SHA256" ON)

include(FetchContent)
FetchContent_Declare(
  lz4
  GIT_REPOSITORY https://github.com/lz4/lz4.git
  GIT_TAG v1.10.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(lz4)

# Host (Linux/macOS/Windows): find zlib and optional OpenSSL.
# Android (NDK): use NDK sysroot zlib; OpenSSL typically OFF unless you provide a prebuilt.
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  # NDK provides zlib in the sysroot (libz)
  set(ZLIB_FOUND 1)
else()
  find_package(ZLIB REQUIRED)
endif()

if(MAGISKBOOT_USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
endif()

add_executable(magiskboot
  src/base_host.cpp
  src/bootimg.cpp
  src/boot_crypto.cpp
  src/cpio.cpp
  src/magiskboot_main.cpp
  ${lz4_SOURCE_DIR}/lib/lz4.c
  ${lz4_SOURCE_DIR}/lib/lz4frame.c
  ${lz4_SOURCE_DIR}/lib/lz4hc.c
  ${lz4_SOURCE_DIR}/lib/xxhash.c
)

target_compile_definitions(magiskboot PRIVATE MAGISKBOOT_STANDALONE=1)
target_include_directories(magiskboot PRIVATE
  src
  ${lz4_SOURCE_DIR}/lib
)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  target_link_libraries(magiskboot PRIVATE z)
else()
  target_link_libraries(magiskboot PRIVATE ZLIB::ZLIB)
endif()

if(MAGISKBOOT_USE_OPENSSL)
  target_link_libraries(magiskboot PRIVATE OpenSSL::Crypto)
  target_compile_definitions(magiskboot PRIVATE USE_OPENSSL_SHA=1)
endif()

