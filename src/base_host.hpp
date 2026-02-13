#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <type_traits>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <sys/sendfile.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

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

inline int xopenat(int dirfd, const char *pathname, int flags, mode_t mode = 0) {
#ifdef __ANDROID__
    int fd = ::openat(dirfd, pathname, flags, mode);
#else
    int fd = ::openat(dirfd, pathname, flags, static_cast<mode_t>(mode));
#endif
    if (fd < 0) PLOGE("openat %s", pathname ? pathname : "(null)");
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

// write_zero: write `size` zero bytes to fd
inline void write_zero(int fd, std::size_t size) {
    std::vector<char> buf(65536, 0);
    while (size > 0) {
        std::size_t n = size < buf.size() ? size : buf.size();
        if (xwrite(fd, buf.data(), n) != static_cast<ssize_t>(n))
            return;
        size -= n;
    }
}

// ssprintf: like snprintf but returns bytes written
inline int ssprintf(char *dest, std::size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(dest, size, fmt, ap);
    va_end(ap);
    return n < 0 ? 0 : (n >= static_cast<int>(size) ? static_cast<int>(size) - 1 : n);
}

// strscpy: truncating copy, returns bytes written
inline std::size_t strscpy(char *dest, const char *src, std::size_t size) {
    if (size == 0) return 0;
    std::size_t i = 0;
    while (i < size - 1 && src[i]) {
        dest[i] = src[i];
        ++i;
    }
    dest[i] = '\0';
    return i;
}

// parse_prop_file: read key=value lines, call fn(key, value) for each.
// value.data() is null-terminated (points into line buffer).
template <typename Functor>
inline void parse_prop_file(const char *file, Functor &&fn) {
    FILE *fp = std::fopen(file, "r");
    if (!fp) return;
    char line[4096];
    while (std::fgets(line, sizeof(line), fp)) {
        char *eq = std::strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        std::size_t len = std::strlen(val);
        if (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '\r'))
            val[--len] = '\0';
        if (!fn(std::string_view(key), std::string_view(val))) break;
    }
    std::fclose(fp);
}

// rm_rf: recursively remove path
bool rm_rf(const char *path);

template <typename T>
static inline T align_to(T v, int a) {
    static_assert(std::is_integral_v<T>);
    return (v + a - 1) / a * a;
}

template <typename T>
static inline T align_padding(T v, int a) {
    return align_to(v, a) - v;
}

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
    mmap_data(int dirfd, const char *name, bool rw = false);
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

