#pragma once

#include <string>

// Standalone replacement for Rust/cxx Utf8CStr
using Utf8CStr = std::string;

// Internal magiskboot APIs (used by bootimg.cpp wrappers).
// Full implementation: copy parsing/repack logic from Magisk native/src/boot/bootimg.cpp.
int unpack(Utf8CStr image, bool skip_decomp, bool hdr);
void repack(Utf8CStr src_img, Utf8CStr out_img, bool skip_comp);
int split_image_dtb(Utf8CStr filename, bool skip_decomp);
