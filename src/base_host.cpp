#include "base_host.hpp"

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

