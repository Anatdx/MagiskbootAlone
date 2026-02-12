#!/usr/bin/env bash
# Build magiskboot for Android (device) using NDK.
# Requires ANDROID_NDK or ANDROID_HOME/NDK to be set.
#
# Usage:
#   ./build_android.sh [abi]
#   ABI: arm64-v8a (default) | armeabi-v7a | x86 | x86_64

set -e

if [[ -n "${ANDROID_NDK}" ]]; then
  NDK="${ANDROID_NDK}"
elif [[ -n "${ANDROID_HOME}" ]] && [[ -d "${ANDROID_HOME}/ndk" ]]; then
  # Use latest installed NDK
  NDK=$(find "${ANDROID_HOME}/ndk" -maxdepth 1 -type d -name "[0-9]*" | sort -V | tail -n1)
  if [[ -z "${NDK}" ]]; then
    echo "No NDK found under ANDROID_HOME/ndk. Set ANDROID_NDK or install NDK." >&2
    exit 1
  fi
else
  echo "Set ANDROID_NDK or ANDROID_HOME (with ndk installed)." >&2
  exit 1
fi

ABI="${1:-arm64-v8a}"
TOOLCHAIN="${NDK}/build/cmake/android.toolchain.cmake"
BUILD_DIR="build_android_${ABI}"

echo "NDK=${NDK}"
echo "ABI=${ABI}"

cmake -S . -B "${BUILD_DIR}" \
  -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" \
  -DANDROID_ABI="${ABI}" \
  -DANDROID_PLATFORM=android-21 \
  -DMAGISKBOOT_USE_OPENSSL=OFF

cmake --build "${BUILD_DIR}"

echo "Output: ${BUILD_DIR}/magiskboot"
