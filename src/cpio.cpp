#include "cpio.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <fstream>
#include <functional>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#include "base_host.hpp"
#include "boot_crypto.hpp"

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

std::size_t remove_patterns_from_buf(
    std::vector<std::uint8_t>& buf,
    const std::function<std::size_t(const std::uint8_t*, std::size_t)>& matcher) {
    std::size_t write = 0;
    std::size_t read = 0;
    const std::size_t len = buf.size();
    while (read < len) {
        const std::size_t matched = matcher(buf.data() + read, len - read);
        if (matched > 0) {
            read += matched;
            continue;
        }
        buf[write++] = buf[read++];
    }
    if (write < len) {
        std::fill(buf.begin() + static_cast<std::ptrdiff_t>(write), buf.end(), 0);
    }
    return write;
}

std::size_t match_csv_pattern(const std::uint8_t* data, std::size_t len,
                              const std::initializer_list<const char*>& patterns) {
    if (len == 0) {
        return 0;
    }
    std::size_t consumed = 0;
    if (data[0] == ',') {
        consumed = 1;
        if (consumed >= len) {
            return 0;
        }
    }
    for (const char* pat : patterns) {
        const std::size_t p_len = std::strlen(pat);
        if (consumed + p_len > len) {
            continue;
        }
        if (std::memcmp(data + consumed, pat, p_len) != 0) {
            continue;
        }
        consumed += p_len;
        if (consumed < len && data[consumed] == '=') {
            while (consumed < len) {
                const std::uint8_t c = data[consumed];
                if (c == ' ' || c == '\n' || c == '\0') {
                    break;
                }
                consumed++;
            }
        }
        return consumed;
    }
    return 0;
}

bool should_patch_fstab_entry(const std::string& name, const CpioEntry& entry) {
    if ((entry.mode & S_IFMT) != S_IFREG) {
        return false;
    }
    if (name.rfind(".backup", 0) == 0 || name.rfind("twrp", 0) == 0 || name.rfind("recovery", 0) == 0) {
        return false;
    }
    return name.rfind("fstab", 0) == 0;
}

bool ends_with(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool transcode_xz(const std::vector<std::uint8_t>& input, std::vector<std::uint8_t>& output,
                  bool compress) {
#ifdef USE_LIBLZMA
    std::array<char, 64> temp_template{};
    std::snprintf(temp_template.data(), temp_template.size(), "/tmp/magiskboot-cpio-XXXXXX");
    const int temp_fd = mkstemp(temp_template.data());
    if (temp_fd < 0) {
        PLOGE("mkstemp");
        return false;
    }
    owned_fd owned(temp_fd);
    const std::string temp_path(temp_template.data());
    bool ok = false;
    try {
        const std::uint8_t* ptr = input.empty() ? nullptr : input.data();
        if (compress) {
            compress_bytes(FileFormat::XZ, byte_view{ptr, input.size()}, temp_fd);
        } else {
            decompress_bytes(FileFormat::XZ, byte_view{ptr, input.size()}, temp_fd);
        }
        if (lseek(temp_fd, 0, SEEK_SET) < 0) {
            PLOGE("lseek");
            ::unlink(temp_path.c_str());
            return false;
        }
        output.clear();
        std::array<std::uint8_t, 64 * 1024> buf{};
        while (true) {
            const ssize_t n = ::read(temp_fd, buf.data(), buf.size());
            if (n < 0) {
                PLOGE("read");
                ::unlink(temp_path.c_str());
                return false;
            }
            if (n == 0) {
                break;
            }
            output.insert(output.end(), buf.begin(), buf.begin() + n);
        }
        ok = true;
    } catch (const std::exception& e) {
        LOGW("XZ transcode failed: %s\n", e.what());
        ok = false;
    }
    ::unlink(temp_path.c_str());
    return ok;
#else
    (void)input;
    (void)output;
    (void)compress;
    return false;
#endif
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

    /* Reject LZ4 legacy ramdisk (unpack with --skip-decomp). Otherwise we might find "070701"
     * by chance in the stream and parse garbage as cpio → huge memory/cache and hang. */
    static constexpr unsigned char kLz4LegacyMagic[] = {0x02, 0x21, 0x4c, 0x18};
    if (total >= 4 && std::memcmp(p, kLz4LegacyMagic, 4) == 0) {
        LOGE("Input is LZ4 compressed ramdisk, not cpio; decompress ramdisk first\n");
        return false;
    }

    static constexpr std::array<char, 7> kNewcMagic = {"070701"};

    /* Match Magisk native/src/boot/cpio.rs load_from_data() exactly */
    while (off + sizeof(NewcHeader) <= total) {
        const auto* h = reinterpret_cast<const NewcHeader*>(p + off);
        if (std::memcmp(h->magic.data(), kNewcMagic.data(), 6) != 0) {
            /* Only at start: skip leading padding (some images have a few bytes before first header).
             * Search only the first 512 bytes. If we searched the whole file, non-cpio data (e.g. LZ4
             * ramdisk when unpack used --skip-decomp) would often contain "070701" by chance; we would
             * then parse garbage as cpio entries (huge namesize/filesize), causing huge memory and
             * disk use and apparent hang. Limiting to 512 bytes gives a clean "Invalid cpio magic"
             * failure for non-cpio input while still allowing real cpio with leading padding. */
            constexpr std::size_t kInitialSearchLimit = 512;
            bool found = false;
            if (off == 0 && total >= 6) {
                const std::size_t search_limit =
                    (total - 6 <= kInitialSearchLimit) ? (total - 6) : kInitialSearchLimit;
                for (std::size_t i = 0; i <= search_limit; ++i) {
                    if (std::memcmp(p + i, kNewcMagic.data(), 6) == 0) {
                        off = i;
                        found = true;
                        break;
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
    if (exists("init.magisk.rc") || exists("overlay/init.magisk.rc") || exists(".backup/.magisk") ||
        exists("overlay.d/sbin/magisk32.xz") ||
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

bool CpioArchive::rm(const std::string& path, bool recursive) {
    const auto norm = normalize_path(path);
    bool removed = entries_.erase(norm) > 0;
    if (!recursive) {
        return removed;
    }
    const auto prefix = norm + "/";
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->first.rfind(prefix, 0) == 0) {
            it = entries_.erase(it);
            removed = true;
        } else {
            ++it;
        }
    }
    return removed;
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

bool CpioArchive::ln(const std::string& src, const std::string& dst) {
    CpioEntry entry;
    entry.mode = S_IFLNK;
    entry.uid = 0;
    entry.gid = 0;
    entry.rdev_major = 0;
    entry.rdev_minor = 0;
    const auto src_norm = normalize_path(src);
    entry.data.assign(src_norm.begin(), src_norm.end());
    entries_[normalize_path(dst)] = std::move(entry);
    return true;
}

void CpioArchive::ls(const std::string& path, bool recursive) const {
    const auto base = normalize_path(path);
    for (const auto& [name, entry] : entries_) {
        if (!base.empty()) {
            if (name == base) {
                // include exact match
            } else if (name.rfind(base + "/", 0) != 0) {
                continue;
            } else if (!recursive && name.find('/', base.size() + 1) != std::string::npos) {
                continue;
            }
        } else if (!recursive && name.find('/') != std::string::npos) {
            continue;
        }
        std::printf("%o\t%s\n", entry.mode, name.c_str());
    }
}

bool CpioArchive::extract_entry(const std::string& normalized_path, const std::string& out) const {
    auto it = entries_.find(normalized_path);
    if (it == entries_.end()) {
        LOGE("No such file: %s\n", normalized_path.c_str());
        return false;
    }

    const auto& entry = it->second;
    const std::uint32_t file_type = entry.mode & S_IFMT;
    const mode_t perm = static_cast<mode_t>(entry.mode & 07777U);

    std::string parent;
    const auto slash = out.find_last_of('/');
    if (slash != std::string::npos) {
        parent = out.substr(0, slash);
    }
    if (!parent.empty() && xmkdirs(parent.c_str(), 0755) != 0) {
        return false;
    }

    if (file_type == S_IFDIR) {
        if (xmkdirs(out.c_str(), perm == 0 ? 0755 : perm) != 0) {
            return false;
        }
        return true;
    }

    ::unlink(out.c_str());

    if (file_type == S_IFREG) {
        const mode_t create_mode = perm == 0 ? 0644 : perm;
        const int fd = xopen(out.c_str(), O_CREAT | O_TRUNC | O_WRONLY, create_mode);
        if (fd < 0) {
            return false;
        }
        owned_fd owned(fd);
        if (!entry.data.empty() &&
            xwrite(fd, entry.data.data(), entry.data.size()) != static_cast<ssize_t>(entry.data.size())) {
            return false;
        }
        return true;
    }

    if (file_type == S_IFLNK) {
        std::string target(entry.data.begin(), entry.data.end());
        if (::symlink(target.c_str(), out.c_str()) != 0) {
            PLOGE("symlink %s", out.c_str());
            return false;
        }
        return true;
    }

    if (file_type == S_IFBLK || file_type == S_IFCHR) {
        const mode_t node_mode = static_cast<mode_t>(entry.mode);
        const dev_t dev = makedev(entry.rdev_major, entry.rdev_minor);
        if (::mknod(out.c_str(), node_mode, dev) != 0) {
            PLOGE("mknod %s", out.c_str());
            return false;
        }
        return true;
    }

    LOGE("Unsupported entry type for %s\n", normalized_path.c_str());
    return false;
}

bool CpioArchive::extract(const std::string& path, const std::string& out) const {
    return extract_entry(normalize_path(path), out);
}

bool CpioArchive::extract_all() const {
    for (const auto& [name, _] : entries_) {
        if (name == "." || name == "..") {
            continue;
        }
        if (!extract_entry(name, name)) {
            return false;
        }
    }
    return true;
}

bool CpioArchive::patch(bool keep_verity, bool keep_force_encrypt) {
    auto patch_verity_matcher = [](const std::uint8_t* data, std::size_t len) -> std::size_t {
        return match_csv_pattern(data, len, {"verifyatboot", "verify", "avb_keys", "avb", "support_scfs",
                                             "fsverity"});
    };
    auto patch_encrypt_matcher = [](const std::uint8_t* data, std::size_t len) -> std::size_t {
        return match_csv_pattern(data, len, {"forceencrypt", "forcefdeorfbe", "fileencryption"});
    };

    for (auto& [name, entry] : entries_) {
        if (!should_patch_fstab_entry(name, entry)) {
            continue;
        }
        if (!keep_verity) {
            const std::size_t new_len = remove_patterns_from_buf(entry.data, patch_verity_matcher);
            entry.data.resize(new_len);
        }
        if (!keep_force_encrypt) {
            const std::size_t new_len = remove_patterns_from_buf(entry.data, patch_encrypt_matcher);
            entry.data.resize(new_len);
        }
    }

    if (!keep_verity) {
        // Mirror Magisk's behavior: drop verity key in ramdisk when patching verity.
        rm("verity_key");
    }
    return true;
}

bool CpioArchive::backup(const std::string& origin, bool skip_compress) {
    CpioArchive orig_archive;
    if (!orig_archive.load(origin)) {
        return false;
    }

    orig_archive.rm(".backup", true);
    rm(".backup", true);

    std::string rm_list;
    std::map<std::string, CpioEntry> backups;

    for (const auto& [name, orig_entry] : orig_archive.entries_) {
        const auto it = entries_.find(name);
        if (it == entries_.end() || it->second.data != orig_entry.data || it->second.mode != orig_entry.mode) {
            const std::string backup_name = std::string(".backup/") + name;
            if (!skip_compress) {
                std::vector<std::uint8_t> compressed;
                if (transcode_xz(orig_entry.data, compressed, true)) {
                    CpioEntry compressed_entry = orig_entry;
                    compressed_entry.data = std::move(compressed);
                    backups[backup_name + ".xz"] = std::move(compressed_entry);
                    continue;
                }
            }
            backups[backup_name] = orig_entry;
        }
    }

    for (const auto& [name, _] : entries_) {
        if (orig_archive.entries_.find(name) == orig_archive.entries_.end()) {
            rm_list += name;
            rm_list.push_back('\0');
        }
    }

    CpioEntry backup_dir;
    backup_dir.mode = S_IFDIR;
    backups[".backup"] = backup_dir;

    CpioEntry magisk_marker;
    magisk_marker.mode = S_IFREG;
    backups[".backup/.magisk"] = magisk_marker;

    if (!rm_list.empty()) {
        CpioEntry rmlist_entry;
        rmlist_entry.mode = S_IFREG;
        rmlist_entry.data.assign(rm_list.begin(), rm_list.end());
        backups[".backup/.rmlist"] = std::move(rmlist_entry);
    }

    entries_.insert(backups.begin(), backups.end());
    return true;
}

bool CpioArchive::restore() {
    std::vector<std::string> backup_keys;
    for (const auto& [name, _] : entries_) {
        if (name.rfind(".backup/", 0) == 0 || name == ".backup") {
            backup_keys.push_back(name);
        }
    }

    std::vector<std::string> rm_targets;
    const auto rm_it = entries_.find(".backup/.rmlist");
    if (rm_it != entries_.end()) {
        const auto& data = rm_it->second.data;
        std::string current;
        for (const auto ch : data) {
            if (ch == 0) {
                if (!current.empty()) {
                    rm_targets.push_back(current);
                    current.clear();
                }
            } else {
                current.push_back(static_cast<char>(ch));
            }
        }
        if (!current.empty()) {
            rm_targets.push_back(current);
        }
    }

    for (const auto& target : rm_targets) {
        rm(target, false);
    }

    std::map<std::string, CpioEntry> restore_entries;
    for (const auto& key : backup_keys) {
        if (key == ".backup" || key == ".backup/.magisk" || key == ".backup/.rmlist") {
            continue;
        }
        const auto it = entries_.find(key);
        if (it == entries_.end()) {
            continue;
        }
        std::string target = key.substr(std::string(".backup/").size());
        CpioEntry restored = it->second;
        if (ends_with(target, ".xz")) {
            const std::string plain_target = target.substr(0, target.size() - 3);
            std::vector<std::uint8_t> decompressed;
            if (transcode_xz(restored.data, decompressed, false)) {
                restored.data = std::move(decompressed);
                target = plain_target;
            } else {
                LOGE("Cannot decompress backup entry %s\n", key.c_str());
                return false;
            }
        }
        restore_entries[target] = std::move(restored);
    }

    rm(".backup", true);
    for (auto& [target, entry] : restore_entries) {
        entries_[target] = std::move(entry);
    }
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
            if (tokens.size() != 2 && tokens.size() != 3) {
                LOGE("cpio rm: expected ENTRY or -r ENTRY\n");
                return 1;
            }
            const bool recursive = (tokens.size() == 3 && tokens[1] == "-r");
            const std::string target = recursive ? tokens[2] : tokens[1];
            archive.rm(target, recursive);
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
        if (op == "ln") {
            if (tokens.size() != 3) {
                LOGE("cpio ln: expected 2 args\n");
                return 1;
            }
            if (!archive.ln(tokens[1], tokens[2])) {
                return 1;
            }
            dirty = true;
            continue;
        }
        if (op == "ls") {
            bool recursive = false;
            std::string path = "/";
            if (tokens.size() == 2) {
                if (tokens[1] == "-r") {
                    recursive = true;
                } else {
                    path = tokens[1];
                }
            } else if (tokens.size() == 3) {
                if (tokens[1] != "-r") {
                    LOGE("cpio ls: expected [-r] [path]\n");
                    return 1;
                }
                recursive = true;
                path = tokens[2];
            } else if (tokens.size() > 3) {
                LOGE("cpio ls: expected [-r] [path]\n");
                return 1;
            }
            archive.ls(path, recursive);
            return 0;
        }
        if (op == "extract") {
            if (tokens.size() == 1) {
                return archive.extract_all() ? 0 : 1;
            }
            if (tokens.size() == 3) {
                return archive.extract(tokens[1], tokens[2]) ? 0 : 1;
            }
            LOGE("cpio extract: expected no args or <entry> <out>\n");
            return 1;
        }
        if (op == "patch") {
            if (tokens.size() != 1) {
                LOGE("cpio patch: expected no args\n");
                return 1;
            }
            const bool keep_verity = std::getenv("KEEPVERITY") != nullptr;
            const bool keep_force_encrypt = std::getenv("KEEPFORCEENCRYPT") != nullptr;
            if (!archive.patch(keep_verity, keep_force_encrypt)) {
                return 1;
            }
            dirty = true;
            continue;
        }
        if (op == "backup") {
            if (tokens.size() != 2 && tokens.size() != 3) {
                LOGE("cpio backup: expected ORIG [-n]\n");
                return 1;
            }
            const bool skip_compress = (tokens.size() == 3 && tokens[2] == "-n");
            if (tokens.size() == 3 && !skip_compress) {
                LOGE("cpio backup: only -n is supported as optional third arg\n");
                return 1;
            }
            if (!archive.backup(tokens[1], skip_compress)) {
                return 1;
            }
            dirty = true;
            continue;
        }
        if (op == "restore") {
            if (tokens.size() != 1) {
                LOGE("cpio restore: expected no args\n");
                return 1;
            }
            if (!archive.restore()) {
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
