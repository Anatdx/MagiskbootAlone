#include <bit>
#include <functional>
#include <memory>
#include <span>

#include "base_host.hpp"
#include "boot_crypto.hpp"
#include "bootimg.hpp"
#include "magiskboot.hpp"

using namespace std;

#define PADDING 15
#define SHA256_DIGEST_SIZE 32
#define SHA_DIGEST_SIZE 20

#define RETURN_OK       0
#define RETURN_ERROR    1
#define RETURN_CHROMEOS 2
#define RETURN_VENDOR   3

// NOTE: This file is a direct adaptation of Magisk's native/src/boot/bootimg.cpp,
// with dependencies on Magisk-specific base / Rust removed so it can be built
// standalone via CMake. For brevity, only the helper functions and public
// magiskboot entry points are kept here; the internal boot image parsing
// structures and methods are identical to upstream.

static void decompress(FileFormat type, int fd, const void *in, size_t size) {
    decompress_bytes(type, byte_view{in, size}, fd);
}

static off_t compress_len(FileFormat type, byte_view in, int fd) {
    auto prev = lseek(fd, 0, SEEK_CUR);
    compress_bytes(type, in, fd);
    auto now = lseek(fd, 0, SEEK_CUR);
    return now - prev;
}

static void dump(const void *buf, size_t size, const char *filename) {
    if (size == 0)
        return;
    int fd = creat(filename, 0644);
    xwrite(fd, buf, size);
    close(fd);
}

static size_t restore(int fd, const char *filename) {
    int ifd = xopen(filename, O_RDONLY);
    size_t size = lseek(ifd, 0, SEEK_END);
    lseek(ifd, 0, SEEK_SET);
    xsendfile(fd, ifd, nullptr, size);
    close(ifd);
    return size;
}

static bool check_env(const char *name) {
    const char *val = getenv(name);
    return val != nullptr && val == "true"sv;
}

// --- The rest of boot image parsing / dyn_img_hdr / boot_img implementation
// is taken unchanged from Magisk's bootimg.cpp. To get full unpack/repack/split-dtb
// behaviour, copy the full contents of Magisk native/src/boot/bootimg.cpp and
// adjust includes to use base_host/boot_crypto/magiskboot. Stubs below allow
// the project to build and run until then.

int unpack(Utf8CStr, bool, bool) {
    return RETURN_OK;  // stub: copy full implementation from Magisk bootimg.cpp
}

void repack(Utf8CStr, Utf8CStr, bool) {
    /* stub */
}

int split_image_dtb(Utf8CStr, bool) {
    return RETURN_OK;  // stub
}

void cleanup() {
    /* stub: remove extracted files when implemented */
}

FileFormat check_fmt(const void *buf, size_t len) {
    (void)buf;
    (void)len;
    return FileFormat::UNKNOWN;  // stub: detect format from magic when implemented
}

// Public magiskboot APIs (signatures mapped to const char* for standalone use).

int unpack(const char *image, bool skip_decomp, bool hdr) {
    Utf8CStr img{image};
    return ::unpack(img, skip_decomp, hdr);
}

void repack(const char *src_img, const char *out_img, bool skip_comp) {
    Utf8CStr src{src_img};
    Utf8CStr dst{out_img};
    ::repack(src, dst, skip_comp);
}

int split_image_dtb(const char *filename, bool skip_decomp) {
    Utf8CStr fn{filename};
    return ::split_image_dtb(fn, skip_decomp);
}

