#include "cpio.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#include "base_host.hpp"

namespace {

struct NewcHeader {
    std::array<char, 6> magic;
    std::array<char, 8> ino;
    std::array<char, 8> mode;
    std::array<char, 8> uid;
    std::array<char, 8> gid;
    std::array<char, 8> nlink;
    std::array<char, 8> mtime;
    std::array<char, 8> filesize;
    std::array<char, 8> devmajor;
    std::array<char, 8> devminor;
    std::array<char, 8> rdevmajor;
    std::array<char, 8> rdevminor;
    std::array<char, 8> namesize;
    std::array<char, 8> check;
};

static_assert(sizeof(NewcHeader) == 110, "invalid newc header size");

constexpr const char* kTrailer = "TRAILER!!!";

std::uint32_t parse_hex8(const char* s) {
    std::array<char, 9> buf = {};
    std::memcpy(buf.data(), s, 8);
    char* end = nullptr;
    unsigned long v = std::strtoul(buf.data(), &end, 16);
    if (end == buf.data()) {
        return 0;
    }
    return static_cast<std::uint32_t>(v);
}

std::uint32_t align4(std::uint32_t v) {
    return (v + 3U) & ~3U;
}

bool write_all(int fd, const void* data, std::size_t len) {
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::size_t done = 0;
    while (done < len) {
        const ssize_t n = ::write(fd, p + done, len - done);
        if (n <= 0) {
            return false;
        }
        done += static_cast<std::size_t>(n);
    }
    return true;
}

void format_hex8(char* out, std::uint32_t v) {
    std::array<char, 9> tmp = {};
    const int ret = std::snprintf(tmp.data(), tmp.size(), "%08x", v);
    if (ret >= 0 && static_cast<std::size_t>(ret) >= 8) {
        std::memcpy(out, tmp.data(), 8);
    }
}

bool write_entry(int fd, std::string_view entry_name, std::uint32_t ino, const CpioEntry& entry) {
    NewcHeader h{};
    std::memcpy(h.magic.data(), "070701", 6);
    format_hex8(h.ino.data(), ino);
    format_hex8(h.mode.data(), entry.mode);
    format_hex8(h.uid.data(), entry.uid);
    format_hex8(h.gid.data(), entry.gid);
    format_hex8(h.nlink.data(), (entry.mode & S_IFMT) == S_IFDIR ? 2U : 1U);
    format_hex8(h.mtime.data(), 0);
    format_hex8(h.filesize.data(), static_cast<std::uint32_t>(entry.data.size()));
    format_hex8(h.devmajor.data(), 0);
    format_hex8(h.devminor.data(), 0);
    format_hex8(h.rdevmajor.data(), entry.rdev_major);
    format_hex8(h.rdevminor.data(), entry.rdev_minor);
    format_hex8(h.namesize.data(), static_cast<std::uint32_t>(entry_name.size() + 1));
    format_hex8(h.check.data(), 0);

    if (!write_all(fd, &h, sizeof(h))) {
        return false;
    }
    if (!write_all(fd, entry_name.data(), entry_name.size()) || !write_all(fd, "\0", 1)) {
        return false;
    }
    /* Pad so next header is at align_4(sizeof(NewcHeader) + namesize), matching load(). */
    const std::uint32_t namesize = static_cast<std::uint32_t>(entry_name.size() + 1);
    const std::uint32_t pos_after_name = sizeof(NewcHeader) + namesize;
    const std::uint32_t next_aligned = (pos_after_name + 3) & ~3U;
    const std::uint32_t name_pad_len = next_aligned - pos_after_name;
    if (name_pad_len != 0) {
        const std::array<std::uint8_t, 3> zeros = {0, 0, 0};
        if (!write_all(fd, zeros.data(), name_pad_len)) {
            return false;
        }
    }
    if (!entry.data.empty() && !write_all(fd, entry.data.data(), entry.data.size())) {
        return false;
    }
    const std::uint32_t data_pad =
        align4(static_cast<std::uint32_t>(entry.data.size())) - static_cast<std::uint32_t>(entry.data.size());
    if (data_pad != 0) {
        const std::array<std::uint8_t, 3> zeros = {0, 0, 0};
        if (!write_all(fd, zeros.data(), data_pad)) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> split_ws(const std::string& s) {
    std::istringstream iss(s);
    std::vector<std::string> out;
    std::string token;
    while (iss >> token) {
        out.push_back(token);
    }
    return out;
}

}  // namespace

std::string CpioArchive::normalize_path(const std::string& path) {
    std::vector<std::string> segs;
    std::string current;
    for (char c : path) {
        if (c == '/') {
            if (!current.empty() && current != ".") {
                segs.push_back(current);
            }
            current.clear();
            continue;
        }
        current.push_back(c);
    }
    if (!current.empty() && current != ".") {
        segs.push_back(current);
    }
    std::string out;
    for (std::size_t i = 0; i < segs.size(); ++i) {
        if (i != 0) {
            out.push_back('/');
        }
        out += segs[i];
    }
    return out;
}

bool CpioArchive::load(const std::string& path) {
    entries_.clear();
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        if (errno == ENOENT) {
            return true;
        }
        PLOGE("stat %s", path.c_str());
        return false;
    }
    if (st.st_size == 0) {
        return true;
    }

    mmap_data data(path.c_str(), false);
    if (data.data() == nullptr || data.size() == 0) {
        PLOGE("mmap %s", path.c_str());
        return false;
    }

    const auto* p = data.data();
    std::size_t off = 0;
    const std::size_t total = data.size();

    static constexpr std::array<char, 7> kNewcMagic = {"070701"};

    /* Match Magisk native/src/boot/cpio.rs load_from_data() exactly */
    while (off + sizeof(NewcHeader) <= total) {
        const auto* h = reinterpret_cast<const NewcHeader*>(p + off);
        if (std::memcmp(h->magic.data(), kNewcMagic.data(), 6) != 0) {
            /* Only at start: skip leading garbage (some images have padding before first header). Match Rust behavior: search all. */
            bool found = false;
            if (off == 0 && total >= 6) {
                const std::size_t search_limit = total - 6;
                for (std::size_t i = 0; i <= search_limit; ++i) {
                    if (std::memcmp(p + i, kNewcMagic.data(), 6) == 0) {
                        off = i;
                        found = true;
                        break; /* retry with off at first 070701 */
                    }
                }
            }
            if (found) {
                continue;
            }
            LOGE("Invalid cpio magic at offset %zu\n", off);
            return false;
        }

        off += sizeof(NewcHeader);
        const std::uint32_t namesize = parse_hex8(h->namesize.data());
        if (namesize == 0 || off + namesize > total) {
            LOGE("Invalid cpio namesize\n");
            return false;
        }
        std::string name(reinterpret_cast<const char*>(p + off), namesize > 0 ? namesize - 1 : 0);
        /* newc: pathname is namesize bytes, then NUL padding to 4-byte boundary (pos = align_4(pos)). */
        off += static_cast<std::size_t>(namesize);
        off = (off + 3) & ~static_cast<std::size_t>(3);

        if (name == "." || name == "..") {
            continue;
        }
        if (name == kTrailer) {
            /* Magisk: data[pos..].find(b"070701") => pos += x or break */
            const std::size_t search_max = total >= 6 ? total - 6 : 0;
            bool found = false;
            for (std::size_t i = off; i <= search_max; ++i) {
                if (std::memcmp(p + i, kNewcMagic.data(), 6) == 0) {
                    off = i;
                    found = true;
                    break;
                }
            }
            if (!found) {
                break;
            }
            continue;
        }

        const std::uint32_t mode = parse_hex8(h->mode.data());
        const std::uint32_t uid = parse_hex8(h->uid.data());
        const std::uint32_t gid = parse_hex8(h->gid.data());
        const std::uint32_t filesize = parse_hex8(h->filesize.data());
        const std::uint32_t rdev_major = parse_hex8(h->rdevmajor.data());
        const std::uint32_t rdev_minor = parse_hex8(h->rdevminor.data());
        if (off + filesize > total) {
            LOGE("Invalid cpio filesize\n");
            return false;
        }
        CpioEntry entry;
        entry.mode = mode;
        entry.uid = uid;
        entry.gid = gid;
        entry.rdev_major = rdev_major;
        entry.rdev_minor = rdev_minor;
        entry.data.assign(p + off, p + off + filesize);
        entries_[normalize_path(name)] = std::move(entry);
        off += static_cast<std::size_t>(filesize);
        off = (off + 3) & ~static_cast<std::size_t>(3); /* align_4(pos) like Magisk */
    }

    return true;
}

bool CpioArchive::dump(const std::string& path) const {
    int fd = xopen(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        return false;
    }
    owned_fd owned(fd);

    std::uint32_t ino = 1;
    for (const auto& [name, entry] : entries_) {
        if (!write_entry(fd, name, ino++, entry)) {
            PLOGE("write cpio entry");
            return false;
        }
    }

    CpioEntry trailer;
    trailer.mode = S_IFREG;
    if (!write_entry(fd, kTrailer, ino, trailer)) {
        PLOGE("write cpio trailer");
        return false;
    }
    return true;
}

bool CpioArchive::exists(const std::string& path) const {
    return entries_.find(normalize_path(path)) != entries_.end();
}

int CpioArchive::test() const {
    if (exists("init.magisk.rc") || exists(".backup/.magisk") || exists("overlay.d/sbin/magisk32.xz") ||
        exists("overlay.d/sbin/magisk64.xz")) {
        return 1;
    }
    if (exists("sbin/launch_daemonsu.sh") || exists("init.xposed.rc")) {
        return 2;
    }
    return 0;
}

bool CpioArchive::add(std::uint32_t mode, std::string_view cpio_path, const std::string& src_file) {
    std::ifstream ifs(src_file, std::ios::binary);
    if (!ifs) {
        PLOGE("open source file %s", src_file.c_str());
        return false;
    }
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    CpioEntry entry;
    entry.mode = (mode & 07777U) | S_IFREG;
    entry.uid = 0;
    entry.gid = 0;
    entry.data = std::move(data);
    entries_[normalize_path(std::string(cpio_path))] = std::move(entry);
    return true;
}

bool CpioArchive::mkdir(std::uint32_t mode, const std::string& path) {
    CpioEntry entry;
    entry.mode = (mode & 07777U) | S_IFDIR;
    entry.uid = 0;
    entry.gid = 0;
    entry.data.clear();
    entries_[normalize_path(path)] = std::move(entry);
    return true;
}

bool CpioArchive::rm(const std::string& path) {
    return entries_.erase(normalize_path(path)) > 0;
}

bool CpioArchive::mv(const std::string& from, const std::string& to) {
    const auto from_norm = normalize_path(from);
    const auto to_norm = normalize_path(to);
    auto it = entries_.find(from_norm);
    if (it == entries_.end()) {
        return false;
    }
    entries_[to_norm] = std::move(it->second);
    entries_.erase(it);
    return true;
}

int cpio_commands(const std::string& file, const std::vector<std::string>& cmds) {
    CpioArchive archive;
    if (!archive.load(file)) {
        return 1;
    }
    bool dirty = false;

    for (const auto& raw : cmds) {
        auto tokens = split_ws(raw);
        if (tokens.empty()) {
            continue;
        }
        const auto& op = tokens[0];
        if (op == "test") {
            return archive.test();
        }
        if (op == "exists") {
            if (tokens.size() != 2) {
                LOGE("cpio exists: expected 1 arg\n");
                return 1;
            }
            return archive.exists(tokens[1]) ? 0 : 1;
        }
        if (op == "add") {
            if (tokens.size() != 4) {
                LOGE("cpio add: expected 3 args\n");
                return 1;
            }
            char* end = nullptr;
            unsigned long mode = std::strtoul(tokens[1].c_str(), &end, 8);
            if (end == tokens[1].c_str() || !archive.add(static_cast<std::uint32_t>(mode), tokens[2], tokens[3])) {
                return 1;
            }
            dirty = true;
            continue;
        }
        if (op == "mkdir") {
            if (tokens.size() != 3) {
                LOGE("cpio mkdir: expected 2 args\n");
                return 1;
            }
            char* end = nullptr;
            unsigned long mode = std::strtoul(tokens[1].c_str(), &end, 8);
            if (end == tokens[1].c_str() ||
                !archive.mkdir(static_cast<std::uint32_t>(mode), tokens[2])) {
                return 1;
            }
            dirty = true;
            continue;
        }
        if (op == "rm") {
            if (tokens.size() != 2) {
                LOGE("cpio rm: expected 1 arg\n");
                return 1;
            }
            archive.rm(tokens[1]);
            dirty = true;
            continue;
        }
        if (op == "mv") {
            if (tokens.size() != 3) {
                LOGE("cpio mv: expected 2 args\n");
                return 1;
            }
            if (!archive.mv(tokens[1], tokens[2])) {
                return 1;
            }
            dirty = true;
            continue;
        }
        LOGE("Unsupported cpio command: %s\n", op.c_str());
        return 1;
    }

    if (dirty) {
        return archive.dump(file) ? 0 : 1;
    }
    return 0;
}
