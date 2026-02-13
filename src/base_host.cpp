#include "base_host.hpp"

#include <dirent.h>

bool rm_rf(const char *path) {
    if (!path || !*path) return false;
    struct stat st{};
    if (lstat(path, &st) < 0) return (errno == ENOENT);
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d) return false;
        struct dirent *ent;
        while ((ent = readdir(d)) != nullptr) {
            if (ent->d_name[0] == '.' && (ent->d_name[1] == '\0' ||
                (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
                continue;
            std::string sub(path);
            sub += '/';
            sub += ent->d_name;
            if (!rm_rf(sub.c_str())) {
                closedir(d);
                return false;
            }
        }
        closedir(d);
        return rmdir(path) == 0;
    }
    return unlink(path) == 0;
}

mmap_data::mmap_data(const char *name, bool rw) {
    int flags = rw ? O_RDWR : O_RDONLY;
    int fd = ::open(name, flags);
    if (fd < 0) {
        PLOGE("open %s", name ? name : "(null)");
        return;
    }
    struct stat st{};
    if (fstat(fd, &st) < 0) {
        PLOGE("fstat %s", name ? name : "(null)");
        ::close(fd);
        return;
    }
    len = static_cast<std::size_t>(st.st_size);
    int prot = rw ? (PROT_READ | PROT_WRITE) : PROT_READ;
    addr = ::mmap(nullptr, len, prot, MAP_SHARED, fd, 0);
    ::close(fd);
    if (addr == MAP_FAILED) {
        PLOGE("mmap %s", name ? name : "(null)");
        addr = nullptr;
        len = 0;
        return;
    }
    *static_cast<byte_data *>(this) = byte_data(addr, len);
}

mmap_data::mmap_data(int dirfd, const char *name, bool rw) {
    int flags = rw ? O_RDWR : O_RDONLY;
    int fd = xopenat(dirfd, name, flags);
    if (fd < 0) return;
    struct stat st{};
    if (fstat(fd, &st) < 0) {
        ::close(fd);
        return;
    }
    len = static_cast<std::size_t>(st.st_size);
    int prot = rw ? (PROT_READ | PROT_WRITE) : PROT_READ;
    addr = ::mmap(nullptr, len, prot, MAP_SHARED, fd, 0);
    ::close(fd);
    if (addr == MAP_FAILED) {
        addr = nullptr;
        len = 0;
        return;
    }
    *static_cast<byte_data *>(this) = byte_data(addr, len);
}

mmap_data::mmap_data(int fd, std::size_t sz, bool rw) {
    len = sz;
    int prot = rw ? (PROT_READ | PROT_WRITE) : PROT_READ;
    addr = ::mmap(nullptr, len, prot, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        PLOGE("mmap fd=%d", fd);
        addr = nullptr;
        len = 0;
        return;
    }
    *static_cast<byte_data *>(this) = byte_data(addr, len);
}

mmap_data::~mmap_data() {
    if (addr && len) {
        ::munmap(addr, len);
    }
}

