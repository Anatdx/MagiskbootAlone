#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <sys/sendfile.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// Minimal host-side base utilities adapted from Magisk `base.hpp`,
// but without any Rust or Android-specific dependencies.

// Logging helpers – route everything to stderr.
inline void LOGD(const char *fmt, ...) {
#ifdef NDEBUG
    (void)fmt;
#else
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
#endif
}

inline void LOGI(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

inline void LOGW(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

inline void LOGE(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#define PLOGE(fmt, args...) \
    LOGE(fmt " failed with %d: %s\n", ##args, errno, std::strerror(errno))

extern "C" {

// xwraps – thin error-logging wrappers around POSIX APIs.

inline FILE *xfopen(const char *pathname, const char *mode) {
    FILE *fp = std::fopen(pathname, mode);
    if (!fp) PLOGE("fopen %s", pathname ? pathname : "(null)");
    return fp;
}

inline int xopen(const char *pathname, int flags, mode_t mode = 0) {
    int fd = ::open(pathname, flags, mode);
    if (fd < 0) PLOGE("open %s", pathname ? pathname : "(null)");
    return fd;
}

inline ssize_t xwrite(int fd, const void *buf, size_t count) {
    ssize_t n = ::write(fd, buf, count);
    if (n < 0) PLOGE("write");
    return n;
}

inline ssize_t xsendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
#if defined(__linux__)
    off_t off = offset ? *offset : 0;
    ssize_t n = ::sendfile(out_fd, in_fd, &off, count);
    if (n < 0) PLOGE("sendfile");
    if (offset) *offset = off;
    return n;
#else
    /* Portable fallback: copy via read/write (macOS/BSD have different sendfile API) */
    char buf[65536];
    ssize_t total = 0;
    if (offset && *offset) ::lseek(in_fd, *offset, SEEK_SET);
    while (count > 0) {
        size_t to_read = count < sizeof(buf) ? count : sizeof(buf);
        ssize_t r = ::read(in_fd, buf, to_read);
        if (r <= 0) break;
        ssize_t w = ::write(out_fd, buf, static_cast<size_t>(r));
        if (w != r) break;
        total += w;
        count -= static_cast<size_t>(w);
        if (offset) *offset += w;
        if (static_cast<size_t>(r) < to_read) break;
    }
    return total;
#endif
}

inline int xmkdir(const char *pathname, mode_t mode) {
    int r = ::mkdir(pathname, mode);
    if (r < 0 && errno != EEXIST) PLOGE("mkdir %s", pathname ? pathname : "(null)");
    return r;
}

inline int xmkdirs(const char *pathname, mode_t mode) {
    // Simple recursive mkdir -p implementation.
    std::string path(pathname);
    if (path.empty()) return -1;
    if (path.back() == '/') path.pop_back();

    for (std::size_t i = 1; i < path.size(); ++i) {
        if (path[i] == '/') {
            std::string sub = path.substr(0, i);
            if (::mkdir(sub.c_str(), mode) < 0 && errno != EEXIST) {
                PLOGE("mkdir %s", sub.c_str());
                return -1;
            }
        }
    }
    if (::mkdir(path.c_str(), mode) < 0 && errno != EEXIST) {
        PLOGE("mkdir %s", path.c_str());
        return -1;
    }
    return 0;
}

} // extern "C"

// byte_view / byte_data – simplified versions (no Rust interop).
struct byte_view {
    byte_view() : ptr(nullptr), sz(0) {}
    byte_view(const void *buf, std::size_t sz) : ptr(static_cast<const std::uint8_t *>(buf)), sz(sz) {}

    const std::uint8_t *data() const { return ptr; }
    std::size_t size() const { return sz; }

private:
    const std::uint8_t *ptr;
    std::size_t sz;
};

struct byte_data {
    byte_data() : ptr(nullptr), sz(0) {}
    byte_data(void *buf, std::size_t sz) : ptr(static_cast<std::uint8_t *>(buf)), sz(sz) {}

    std::uint8_t *data() const { return ptr; }
    std::size_t size() const { return sz; }

private:
    std::uint8_t *ptr;
    std::size_t sz;
};

// mmap-backed read-only mapping.
struct mmap_data : public byte_data {
    mmap_data() = default;
    explicit mmap_data(const char *name, bool rw = false);
    mmap_data(int fd, std::size_t sz, bool rw = false);
    ~mmap_data();

private:
    void *addr = nullptr;
    std::size_t len = 0;
};

// RAII fd wrapper.
struct owned_fd {
    owned_fd() : fd(-1) {}
    explicit owned_fd(int fd) : fd(fd) {}
    ~owned_fd() { if (fd >= 0) ::close(fd); }

    operator int() const { return fd; }
    int release() { int old = fd; fd = -1; return old; }

private:
    int fd;
};

