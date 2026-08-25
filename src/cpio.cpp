#include "cpio.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#if defined(__linux__) || defined(__ANDROID__)
#include <sys/sysmacros.h>  /* makedev */
#endif
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

void format_hex8(char* out, std::uint32_t v) {
    std::array<char, 9> tmp = {};
    const int ret = std::snprintf(tmp.data(), tmp.size(), "%08x", v);
    if (ret >= 0 && static_cast<std::size_t>(ret) >= 8) {
        std::memcpy(out, tmp.data(), 8);
    }
}

bool write_entry(
    const CpioDataSink& sink,
    std::string_view entry_name,
    const CpioEntry& entry) {
    if (entry_name.size() >= std::numeric_limits<std::uint32_t>::max() ||
        entry.data.size() > std::numeric_limits<std::uint32_t>::max()) {
        LOGE("cpio entry is too large to encode: %.*s\n",
             static_cast<int>(entry_name.size()), entry_name.data());
        return false;
    }

    NewcHeader h{};
    std::memcpy(h.magic.data(), "070701", 6);
    format_hex8(h.ino.data(), entry.ino);
    format_hex8(h.mode.data(), entry.mode);
    format_hex8(h.uid.data(), entry.uid);
    format_hex8(h.gid.data(), entry.gid);
    format_hex8(h.nlink.data(), entry.nlink);
    format_hex8(h.mtime.data(), entry.mtime);
    format_hex8(h.filesize.data(), static_cast<std::uint32_t>(entry.data.size()));
    format_hex8(h.devmajor.data(), entry.dev_major);
    format_hex8(h.devminor.data(), entry.dev_minor);
    format_hex8(h.rdevmajor.data(), entry.rdev_major);
    format_hex8(h.rdevminor.data(), entry.rdev_minor);
    format_hex8(h.namesize.data(), static_cast<std::uint32_t>(entry_name.size() + 1));
    format_hex8(h.check.data(), entry.check);

    if (!sink(reinterpret_cast<const std::uint8_t*>(&h), sizeof(h))) {
        return false;
    }
    if (!sink(
            reinterpret_cast<const std::uint8_t*>(entry_name.data()),
            entry_name.size()) ||
        !sink(reinterpret_cast<const std::uint8_t*>("\0"), 1)) {
        return false;
    }
    /* Pad so next header is at align_4(sizeof(NewcHeader) + namesize), matching load(). */
    const std::uint32_t namesize = static_cast<std::uint32_t>(entry_name.size() + 1);
    const std::uint32_t pos_after_name = sizeof(NewcHeader) + namesize;
    const std::uint32_t next_aligned = (pos_after_name + 3) & ~3U;
    const std::uint32_t name_pad_len = next_aligned - pos_after_name;
    if (name_pad_len != 0) {
        const std::array<std::uint8_t, 3> zeros = {0, 0, 0};
        if (!sink(zeros.data(), name_pad_len)) {
            return false;
        }
    }
    if (!entry.data.empty() &&
        !sink(entry.data.data(), entry.data.size())) {
        return false;
    }
    const std::uint32_t data_pad =
        align4(static_cast<std::uint32_t>(entry.data.size())) - static_cast<std::uint32_t>(entry.data.size());
    if (data_pad != 0) {
        const std::array<std::uint8_t, 3> zeros = {0, 0, 0};
        if (!sink(zeros.data(), data_pad)) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> split_ws(const std::string& text) {
    constexpr std::string_view kWhitespace = " \t\r\n\f\v";
    std::vector<std::string> out;
    for (std::size_t begin = 0; begin < text.size();) {
        begin = text.find_first_not_of(kWhitespace, begin);
        if (begin == std::string::npos)
            break;
        std::size_t end = text.find_first_of(kWhitespace, begin);
        if (end == std::string::npos)
            end = text.size();
        out.emplace_back(text, begin, end - begin);
        begin = end;
    }
    return out;
}

template <typename Matcher>
std::size_t remove_patterns_from_buf(std::vector<std::uint8_t>& buf, const Matcher& matcher) {
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

bool read_source(
    const CpioDataSource& source,
    std::size_t max_bytes,
    std::vector<std::uint8_t>& output) {
    if (!source) {
        return false;
    }
    std::vector<std::uint8_t> result;
    std::array<std::uint8_t, 64U * 1024U> buffer{};
    while (true) {
        const ssize_t count = source(buffer.data(), buffer.size());
        if (count < 0 || static_cast<std::size_t>(count) > buffer.size()) {
            return false;
        }
        if (count == 0) {
            break;
        }
        const auto chunk_size = static_cast<std::size_t>(count);
        if (result.size() > max_bytes || chunk_size > max_bytes - result.size()) {
            return false;
        }
        result.insert(result.end(), buffer.begin(), buffer.begin() + count);
    }
    output = std::move(result);
    return true;
}

bool is_valid_child_name(std::string_view name) {
    return !name.empty() && name != "." && name != ".." &&
           name.find('/') == std::string_view::npos &&
           name.find('\0') == std::string_view::npos;
}

bool has_unsafe_path_segment(std::string_view path) {
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end =
            separator == std::string_view::npos ? path.size() : separator;
        if (path.substr(start, end - start) == "..") {
            return true;
        }
        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1;
    }
    return path.find('\0') != std::string_view::npos;
}

}  // namespace

std::string CpioArchive::normalize_path(const std::string& path) {
    std::vector<std::string> segs;
    std::string current;
    for (char c : path) {
        if (c == '\0') {
            return {};
        }
        if (c == '/') {
            if (current == "..") {
                return {};
            }
            if (!current.empty() && current != ".") {
                segs.push_back(current);
            }
            current.clear();
            continue;
        }
        current.push_back(c);
    }
    if (current == "..") {
        return {};
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
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        if (errno == ENOENT) {
            return load(nullptr, 0);
        }
        PLOGE("stat %s", path.c_str());
        return false;
    }
    if (st.st_size == 0) {
        return load(nullptr, 0);
    }

    mmap_data data(path.c_str(), false);
    if (data.data() == nullptr || data.size() == 0) {
        PLOGE("mmap %s", path.c_str());
        return false;
    }
    return load(data.data(), data.size());
}

bool CpioArchive::load(const std::uint8_t* data, std::size_t size) {
    CpioArchive replacement;
    if (!replacement.parse(data, size)) {
        return false;
    }
    *this = std::move(replacement);
    return true;
}

bool CpioArchive::load_fd(int fd, std::size_t max_bytes) {
    if (fd < 0) {
        errno = EBADF;
        return false;
    }

    std::vector<std::uint8_t> bytes;
    std::array<std::uint8_t, 64U * 1024U> buffer{};
    while (true) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            PLOGE("read cpio stream");
            return false;
        }
        if (count == 0) {
            break;
        }
        const auto chunk_size = static_cast<std::size_t>(count);
        if (bytes.size() > max_bytes || chunk_size > max_bytes - bytes.size()) {
            LOGE("cpio stream exceeds configured limit of %zu bytes\n", max_bytes);
            return false;
        }
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
    }
    return load(bytes.data(), bytes.size());
}

bool CpioArchive::parse(const std::uint8_t* data, std::size_t size) {
    entries_.clear();
    next_node_id_ = 1;
    next_order_ = 1;
    next_inode_ = 1;
    if (size == 0) {
        return true;
    }
    if (data == nullptr) {
        return false;
    }

    const auto* p = data;
    std::size_t off = 0;
    const std::size_t total = size;
    if (total < sizeof(NewcHeader)) {
        LOGE("Input is too small to contain a cpio archive\n");
        return false;
    }
    bool saw_trailer = false;

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
        if (namesize == 0 || namesize > kCpioMaxPathSize ||
            namesize > total - off) {
            LOGE("Invalid cpio namesize\n");
            return false;
        }
        if (p[off + namesize - 1] != '\0') {
            LOGE("Invalid cpio entry name terminator\n");
            return false;
        }
        std::string name(reinterpret_cast<const char*>(p + off), namesize > 0 ? namesize - 1 : 0);
        /* newc: pathname is namesize bytes, then NUL padding to 4-byte boundary (pos = align_4(pos)). */
        off += static_cast<std::size_t>(namesize);
        off = (off + 3) & ~static_cast<std::size_t>(3);
        if (off > total) {
            LOGE("Invalid cpio name padding\n");
            return false;
        }
        const std::uint32_t filesize = parse_hex8(h->filesize.data());
        if (filesize > total - off) {
            LOGE("Invalid cpio filesize\n");
            return false;
        }

        if (name == "." || name == "..") {
            saw_trailer = false;
            off += static_cast<std::size_t>(filesize);
            off = (off + 3) & ~static_cast<std::size_t>(3);
            if (off > total) {
                LOGE("Invalid cpio data padding\n");
                return false;
            }
            continue;
        }
        if (name == kTrailer) {
            saw_trailer = true;
            off += static_cast<std::size_t>(filesize);
            off = (off + 3) & ~static_cast<std::size_t>(3);
            if (off > total) {
                LOGE("Invalid cpio trailer padding\n");
                return false;
            }
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
        saw_trailer = false;
        CpioEntry entry;
        entry.id = next_node_id_++;
        entry.order = next_order_++;
        entry.ino = parse_hex8(h->ino.data());
        entry.mode = parse_hex8(h->mode.data());
        entry.uid = parse_hex8(h->uid.data());
        entry.gid = parse_hex8(h->gid.data());
        entry.nlink = parse_hex8(h->nlink.data());
        entry.mtime = parse_hex8(h->mtime.data());
        entry.dev_major = parse_hex8(h->devmajor.data());
        entry.dev_minor = parse_hex8(h->devminor.data());
        entry.rdev_major = parse_hex8(h->rdevmajor.data());
        entry.rdev_minor = parse_hex8(h->rdevminor.data());
        entry.check = parse_hex8(h->check.data());
        entry.data.assign(p + off, p + off + filesize);
        if (entry.ino != std::numeric_limits<std::uint32_t>::max()) {
            next_inode_ = std::max(next_inode_, entry.ino + 1);
        }
        const std::string normalized = normalize_path(name);
        if (normalized.empty()) {
            LOGE("Invalid empty cpio entry path\n");
            return false;
        }
        ensure_parent_directories(normalized);
        if (entries_.size() >= kCpioMaxEntryCount) {
            LOGE("cpio archive contains too many entries\n");
            return false;
        }
        const auto existing = entries_.find(normalized);
        if (existing != entries_.end() && existing->second.synthetic) {
            entry.id = existing->second.id;
        }
        entries_[normalized] = std::move(entry);
        off += static_cast<std::size_t>(filesize);
        off = (off + 3) & ~static_cast<std::size_t>(3); /* align_4(pos) like Magisk */
        if (off > total) {
            LOGE("Invalid cpio data padding\n");
            return false;
        }
    }

    if (!saw_trailer) {
        LOGE("cpio archive is missing its trailer\n");
        return false;
    }
    return true;
}

bool CpioArchive::dump(const std::string& path) const {
    mode_t mode = 0644;
    struct stat existing {};
    if (::stat(path.c_str(), &existing) == 0) {
        mode = existing.st_mode & 07777;
    }

    std::string temporary_template = path + ".tmp.XXXXXX";
    std::vector<char> temporary_path(
        temporary_template.begin(), temporary_template.end());
    temporary_path.push_back('\0');
    const int fd = ::mkstemp(temporary_path.data());
    if (fd < 0) {
        PLOGE("mkstemp %s", temporary_template.c_str());
        return false;
    }
    bool success = ::fchmod(fd, mode) == 0 && dump_fd(fd) && ::fsync(fd) == 0;
    if (::close(fd) != 0) {
        success = false;
    }
    if (success && ::rename(temporary_path.data(), path.c_str()) == 0) {
        return true;
    }
    if (success) {
        PLOGE("rename %s", path.c_str());
    }
    ::unlink(temporary_path.data());
    return false;
}

bool CpioArchive::dump_fd(int fd) const {
    if (fd < 0) {
        errno = EBADF;
        return false;
    }

    return dump([fd](const std::uint8_t* data, std::size_t size) {
        std::size_t offset = 0;
        while (offset < size) {
            const ssize_t count = ::write(fd, data + offset, size - offset);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                return false;
            }
            offset += static_cast<std::size_t>(count);
        }
        return true;
    });
}

bool CpioArchive::dump(const CpioDataSink& sink) const {
    if (!sink) {
        return false;
    }

    std::vector<std::pair<std::string_view, const CpioEntry*>> ordered;
    ordered.reserve(entries_.size());
    for (const auto& [name, entry] : entries_) {
        if (!entry.synthetic) {
            ordered.emplace_back(name, &entry);
        }
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second->order < rhs.second->order;
    });

    for (const auto& [name, entry] : ordered) {
        if (!write_entry(sink, name, *entry)) {
            LOGE("Failed to stream cpio entry\n");
            return false;
        }
    }

    CpioEntry trailer;
    trailer.ino = next_inode_;
    trailer.mode = S_IFREG;
    trailer.nlink = 1;
    if (!write_entry(sink, kTrailer, trailer)) {
        LOGE("Failed to stream cpio trailer\n");
        return false;
    }
    return true;
}

bool CpioArchive::dump(
    std::vector<std::uint8_t>& output,
    std::size_t max_bytes) const {
    std::vector<std::uint8_t> replacement;
    const bool success = dump(
        [&](const std::uint8_t* data, std::size_t size) {
            if (replacement.size() > max_bytes ||
                size > max_bytes - replacement.size()) {
                return false;
            }
            replacement.insert(replacement.end(), data, data + size);
            return true;
        });
    if (!success) {
        return false;
    }
    output = std::move(replacement);
    return true;
}

std::optional<std::string> CpioArchive::path_by_id(CpioNodeId id) const {
    if (id == kCpioRootNodeId) {
        return std::string{};
    }
    for (const auto& [path, entry] : entries_) {
        if (entry.id == id) {
            return path;
        }
    }
    return std::nullopt;
}

CpioEntry* CpioArchive::entry_by_id(CpioNodeId id) {
    if (id == kCpioRootNodeId) {
        return nullptr;
    }
    for (auto& [_, entry] : entries_) {
        if (entry.id == id) {
            return &entry;
        }
    }
    return nullptr;
}

const CpioEntry* CpioArchive::entry_by_id(CpioNodeId id) const {
    if (id == kCpioRootNodeId) {
        return nullptr;
    }
    for (const auto& [_, entry] : entries_) {
        if (entry.id == id) {
            return &entry;
        }
    }
    return nullptr;
}

const CpioEntry* CpioArchive::content_entry(const CpioEntry& entry) const {
    if (entry.nlink <= 1) {
        return &entry;
    }
    for (const auto& [_, candidate] : entries_) {
        if (candidate.ino == entry.ino &&
            candidate.dev_major == entry.dev_major &&
            candidate.dev_minor == entry.dev_minor &&
            !candidate.data.empty()) {
            return &candidate;
        }
    }
    return &entry;
}

CpioEntry* CpioArchive::content_entry(CpioEntry& entry) {
    return const_cast<CpioEntry*>(
        static_cast<const CpioArchive*>(this)->content_entry(entry));
}

std::optional<CpioNodeId> CpioArchive::find(std::string_view path) const {
    if (has_unsafe_path_segment(path)) {
        return std::nullopt;
    }
    const std::string normalized = normalize_path(std::string(path));
    if (normalized.empty()) {
        return kCpioRootNodeId;
    }
    const auto it = entries_.find(normalized);
    if (it == entries_.end()) {
        return std::nullopt;
    }
    return it->second.id;
}

CpioNodeInfo CpioArchive::node_info(
    const std::string& path,
    const CpioEntry& entry) const {
    CpioNodeInfo info;
    info.id = entry.id;
    info.path = path;
    info.synthetic = entry.synthetic;
    const auto separator = path.rfind('/');
    const std::string parent_path =
        separator == std::string::npos ? std::string{} : path.substr(0, separator);
    info.name = separator == std::string::npos ? path : path.substr(separator + 1);
    info.parent_id = find(parent_path).value_or(kCpioRootNodeId);
    info.ino = entry.ino;
    info.mode = entry.mode;
    info.uid = entry.uid;
    info.gid = entry.gid;
    info.nlink = entry.nlink;
    info.mtime = entry.mtime;
    info.dev_major = entry.dev_major;
    info.dev_minor = entry.dev_minor;
    info.rdev_major = entry.rdev_major;
    info.rdev_minor = entry.rdev_minor;
    const CpioEntry* content = content_entry(entry);
    info.size = content->data.size();
    if ((entry.mode & S_IFMT) == S_IFLNK) {
        info.link_target = std::string(content->data.begin(), content->data.end());
    }
    return info;
}

std::optional<CpioNodeInfo> CpioArchive::stat(CpioNodeId id) const {
    if (id == kCpioRootNodeId) {
        CpioNodeInfo root;
        root.id = kCpioRootNodeId;
        root.parent_id = kCpioRootNodeId;
        root.mode = S_IFDIR | 0755U;
        root.nlink = 2;
        return root;
    }
    const auto path = path_by_id(id);
    if (!path) {
        return std::nullopt;
    }
    const auto it = entries_.find(*path);
    if (it == entries_.end()) {
        return std::nullopt;
    }
    return node_info(*path, it->second);
}

std::vector<CpioNodeInfo> CpioArchive::list(CpioNodeId directory_id) const {
    const auto directory_path = path_by_id(directory_id);
    if (!directory_path) {
        return {};
    }
    if (directory_id != kCpioRootNodeId) {
        const CpioEntry* directory = entry_by_id(directory_id);
        if (directory == nullptr || (directory->mode & S_IFMT) != S_IFDIR) {
            return {};
        }
    }

    std::vector<CpioNodeInfo> result;
    for (const auto& [path, entry] : entries_) {
        const auto separator = path.rfind('/');
        const std::string parent_path =
            separator == std::string::npos ? std::string{} : path.substr(0, separator);
        if (parent_path == *directory_path) {
            result.push_back(node_info(path, entry));
        }
    }
    std::sort(result.begin(), result.end(), [this](const auto& lhs, const auto& rhs) {
        const CpioEntry* lhs_entry = entry_by_id(lhs.id);
        const CpioEntry* rhs_entry = entry_by_id(rhs.id);
        return lhs_entry != nullptr && rhs_entry != nullptr &&
               lhs_entry->order < rhs_entry->order;
    });
    return result;
}

bool CpioArchive::read_content(CpioNodeId id, const CpioDataSink& sink) const {
    return read_content(
        id,
        0,
        std::numeric_limits<std::uint64_t>::max(),
        sink);
}

bool CpioArchive::read_content(
    CpioNodeId id,
    std::uint64_t requested_offset,
    std::uint64_t requested_length,
    const CpioDataSink& sink) const {
    const CpioEntry* entry = entry_by_id(id);
    if (entry == nullptr || !sink) {
        return false;
    }
    return read_entry_content(*entry, requested_offset, requested_length, sink);
}

bool CpioArchive::read_content(
    std::string_view path,
    std::uint64_t requested_offset,
    std::uint64_t requested_length,
    const CpioDataSink& sink) const {
    if (!sink || has_unsafe_path_segment(path)) {
        return false;
    }
    const auto it = entries_.find(normalize_path(std::string(path)));
    if (it == entries_.end()) {
        return false;
    }
    return read_entry_content(it->second, requested_offset, requested_length, sink);
}

bool CpioArchive::read_entry_content(
    const CpioEntry& entry,
    std::uint64_t requested_offset,
    std::uint64_t requested_length,
    const CpioDataSink& sink) const {
    const auto& data = content_entry(entry)->data;
    if (requested_offset > data.size()) {
        return false;
    }
    const std::size_t begin = static_cast<std::size_t>(requested_offset);
    const std::uint64_t available = data.size() - begin;
    const std::size_t length = static_cast<std::size_t>(
        std::min(requested_length, available));
    constexpr std::size_t kChunkSize = 64U * 1024U;
    std::size_t offset = 0;
    while (offset < length) {
        const std::size_t count = std::min(kChunkSize, length - offset);
        if (!sink(data.data() + begin + offset, count)) {
            return false;
        }
        offset += count;
    }
    return true;
}

bool CpioArchive::replace_content(
    CpioNodeId id,
    const CpioDataSource& source,
    std::size_t max_bytes) {
    CpioEntry* entry = entry_by_id(id);
    if (entry == nullptr || (entry->mode & S_IFMT) == S_IFDIR) {
        return false;
    }
    std::vector<std::uint8_t> replacement;
    if (!read_source(source, max_bytes, replacement)) {
        return false;
    }
    CpioEntry* owner = content_entry(*entry);
    if (entry->nlink > 1) {
        for (auto& [_, candidate] : entries_) {
            if (&candidate != owner &&
                candidate.ino == entry->ino &&
                candidate.dev_major == entry->dev_major &&
                candidate.dev_minor == entry->dev_minor) {
                candidate.data.clear();
            }
        }
    }
    owner->data = std::move(replacement);
    owner->check = 0;
    return true;
}

bool CpioArchive::update_metadata(CpioNodeId id, const CpioMetadataPatch& patch) {
    CpioEntry* entry = entry_by_id(id);
    if (entry == nullptr) {
        return false;
    }
    if (patch.permissions) {
        if ((*patch.permissions & ~07777U) != 0) {
            return false;
        }
    }
    materialize(*entry);
    if (patch.permissions) {
        entry->mode = (entry->mode & S_IFMT) | *patch.permissions;
    }
    if (patch.uid) {
        entry->uid = *patch.uid;
    }
    if (patch.gid) {
        entry->gid = *patch.gid;
    }
    if (patch.mtime) {
        entry->mtime = *patch.mtime;
    }
    return true;
}

std::optional<std::string> CpioArchive::child_path(
    CpioNodeId parent_id,
    std::string_view name) const {
    if (!is_valid_child_name(name)) {
        return std::nullopt;
    }
    const auto parent_path = path_by_id(parent_id);
    if (!parent_path) {
        return std::nullopt;
    }
    if (parent_id != kCpioRootNodeId) {
        const CpioEntry* parent = entry_by_id(parent_id);
        if (parent == nullptr || (parent->mode & S_IFMT) != S_IFDIR) {
            return std::nullopt;
        }
    }
    return parent_path->empty() ? std::string(name) : *parent_path + "/" + std::string(name);
}

CpioEntry CpioArchive::make_entry(std::uint32_t mode) {
    CpioEntry entry;
    entry.id = next_node_id_++;
    entry.order = next_order_++;
    entry.ino = next_inode_;
    if (next_inode_ != std::numeric_limits<std::uint32_t>::max()) {
        ++next_inode_;
    }
    entry.mode = mode;
    entry.nlink = (mode & S_IFMT) == S_IFDIR ? 2U : 1U;
    return entry;
}

void CpioArchive::ensure_parent_directories(const std::string& path) {
    std::size_t separator = path.find('/');
    while (separator != std::string::npos) {
        const std::string parent_path = path.substr(0, separator);
        if (!parent_path.empty() && entries_.find(parent_path) == entries_.end()) {
            CpioEntry parent;
            parent.id = next_node_id_++;
            parent.order = next_order_++;
            parent.synthetic = true;
            parent.mode = S_IFDIR | 0755U;
            parent.nlink = 2;
            entries_.emplace(parent_path, std::move(parent));
        }
        separator = path.find('/', separator + 1);
    }
}

void CpioArchive::materialize(CpioEntry& entry) {
    if (!entry.synthetic) {
        return;
    }
    entry.synthetic = false;
    entry.ino = next_inode_;
    if (next_inode_ != std::numeric_limits<std::uint32_t>::max()) {
        ++next_inode_;
    }
}

bool CpioArchive::create_file(
    CpioNodeId parent_id,
    std::string_view name,
    std::uint32_t permissions,
    std::uint32_t uid,
    std::uint32_t gid,
    const CpioDataSource& source,
    CpioNodeId* created_id,
    std::size_t max_bytes) {
    if ((permissions & ~07777U) != 0) {
        return false;
    }
    const auto path = child_path(parent_id, name);
    if (!path || entries_.find(*path) != entries_.end() ||
        entries_.size() >= kCpioMaxEntryCount) {
        return false;
    }
    std::vector<std::uint8_t> content;
    if (!read_source(source, max_bytes, content)) {
        return false;
    }
    CpioEntry entry = make_entry(S_IFREG | permissions);
    entry.uid = uid;
    entry.gid = gid;
    entry.data = std::move(content);
    const CpioNodeId id = entry.id;
    entries_.emplace(*path, std::move(entry));
    if (created_id != nullptr) {
        *created_id = id;
    }
    return true;
}

bool CpioArchive::create_directory(
    CpioNodeId parent_id,
    std::string_view name,
    std::uint32_t permissions,
    std::uint32_t uid,
    std::uint32_t gid,
    CpioNodeId* created_id) {
    if ((permissions & ~07777U) != 0) {
        return false;
    }
    const auto path = child_path(parent_id, name);
    if (!path) {
        return false;
    }
    const auto existing = entries_.find(*path);
    if (existing != entries_.end()) {
        if (!existing->second.synthetic) {
            return false;
        }
        CpioEntry& entry = existing->second;
        materialize(entry);
        entry.mode = S_IFDIR | permissions;
        entry.uid = uid;
        entry.gid = gid;
        if (created_id != nullptr) {
            *created_id = entry.id;
        }
        return true;
    }
    if (entries_.size() >= kCpioMaxEntryCount) {
        return false;
    }
    CpioEntry entry = make_entry(S_IFDIR | permissions);
    entry.uid = uid;
    entry.gid = gid;
    const CpioNodeId id = entry.id;
    entries_.emplace(*path, std::move(entry));
    if (created_id != nullptr) {
        *created_id = id;
    }
    return true;
}

bool CpioArchive::create_symbolic_link(
    CpioNodeId parent_id,
    std::string_view name,
    std::string_view target,
    std::uint32_t uid,
    std::uint32_t gid,
    CpioNodeId* created_id) {
    if (target.find('\0') != std::string_view::npos) {
        return false;
    }
    const auto path = child_path(parent_id, name);
    if (!path || entries_.find(*path) != entries_.end() ||
        entries_.size() >= kCpioMaxEntryCount) {
        return false;
    }
    CpioEntry entry = make_entry(S_IFLNK | 0777U);
    entry.uid = uid;
    entry.gid = gid;
    entry.data.assign(target.begin(), target.end());
    const CpioNodeId id = entry.id;
    entries_.emplace(*path, std::move(entry));
    if (created_id != nullptr) {
        *created_id = id;
    }
    return true;
}

void CpioArchive::refresh_hard_link_count(
    std::uint32_t ino,
    std::uint32_t dev_major,
    std::uint32_t dev_minor) {
    std::uint32_t count = 0;
    for (const auto& [_, entry] : entries_) {
        if (entry.ino == ino &&
            entry.dev_major == dev_major &&
            entry.dev_minor == dev_minor &&
            (entry.mode & S_IFMT) != S_IFDIR) {
            ++count;
        }
    }
    for (auto& [_, entry] : entries_) {
        if (entry.ino == ino &&
            entry.dev_major == dev_major &&
            entry.dev_minor == dev_minor &&
            (entry.mode & S_IFMT) != S_IFDIR) {
            entry.nlink = std::max(1U, count);
        }
    }
}

bool CpioArchive::create_hard_link(
    CpioNodeId parent_id,
    std::string_view name,
    CpioNodeId target_id,
    CpioNodeId* created_id) {
    const auto path = child_path(parent_id, name);
    CpioEntry* target = entry_by_id(target_id);
    if (!path || entries_.find(*path) != entries_.end() || target == nullptr ||
        entries_.size() >= kCpioMaxEntryCount ||
        (target->mode & S_IFMT) == S_IFDIR) {
        return false;
    }
    CpioEntry entry = *target;
    entry.id = next_node_id_++;
    entry.order = next_order_++;
    entry.data.clear();
    const CpioNodeId id = entry.id;
    const std::uint32_t ino = entry.ino;
    const std::uint32_t dev_major = entry.dev_major;
    const std::uint32_t dev_minor = entry.dev_minor;
    entries_.emplace(*path, std::move(entry));
    refresh_hard_link_count(ino, dev_major, dev_minor);
    if (created_id != nullptr) {
        *created_id = id;
    }
    return true;
}

bool CpioArchive::copy(
    CpioNodeId id,
    CpioNodeId destination_id,
    std::string_view new_name,
    CpioNodeId* created_id) {
    const auto source_path = path_by_id(id);
    const auto destination_path = child_path(destination_id, new_name);
    if (!source_path || source_path->empty() || !destination_path ||
        entries_.find(*destination_path) != entries_.end()) {
        return false;
    }
    const std::string source_prefix = *source_path + "/";
    if (destination_path->rfind(source_prefix, 0) == 0) {
        return false;
    }

    std::vector<std::string> source_paths;
    for (const auto& [path, _] : entries_) {
        if (path == *source_path || path.rfind(source_prefix, 0) == 0) {
            source_paths.push_back(path);
        }
    }
    if (source_paths.empty()) {
        return false;
    }
    if (source_paths.size() > kCpioMaxEntryCount - entries_.size()) {
        return false;
    }
    std::sort(source_paths.begin(), source_paths.end(), [this](const auto& lhs, const auto& rhs) {
        return entries_.at(lhs).order < entries_.at(rhs).order;
    });

    using LinkKey = std::tuple<std::uint32_t, std::uint32_t, std::uint32_t>;
    std::map<LinkKey, std::size_t> selected_link_counts;
    for (const auto& path : source_paths) {
        const CpioEntry& entry = entries_.at(path);
        if (entry.nlink > 1 && (entry.mode & S_IFMT) != S_IFDIR) {
            ++selected_link_counts[{entry.ino, entry.dev_major, entry.dev_minor}];
        }
    }

    std::vector<std::pair<std::string, CpioEntry>> copies;
    copies.reserve(source_paths.size());
    std::map<LinkKey, std::uint32_t> copied_inodes;
    std::map<LinkKey, std::size_t> copied_link_owner;
    std::map<LinkKey, std::vector<std::uint8_t>> copied_link_content;

    for (const auto& old_path : source_paths) {
        const CpioEntry& original = entries_.at(old_path);
        const std::string suffix = old_path.substr(source_path->size());
        const std::string new_path = *destination_path + suffix;
        if (entries_.find(new_path) != entries_.end()) {
            return false;
        }

        CpioEntry copy = original;
        CpioEntry identity = make_entry(copy.mode);
        copy.id = identity.id;
        copy.order = identity.order;
        const bool is_directory = (copy.mode & S_IFMT) == S_IFDIR;
        const LinkKey key{copy.ino, copy.dev_major, copy.dev_minor};
        const auto count_it = selected_link_counts.find(key);
        const std::size_t selected_count =
            count_it == selected_link_counts.end() ? 0 : count_it->second;

        if (!is_directory && selected_count > 1) {
            const auto inode_it = copied_inodes.find(key);
            if (inode_it == copied_inodes.end()) {
                copied_inodes.emplace(key, identity.ino);
                copy.ino = identity.ino;
                copied_link_content.emplace(key, content_entry(original)->data);
            } else {
                copy.ino = inode_it->second;
            }
            copy.nlink = static_cast<std::uint32_t>(selected_count);
            copy.data.clear();
            copied_link_owner[key] = copies.size();
        } else {
            copy.ino = identity.ino;
            copy.nlink = is_directory ? 2U : 1U;
            if (!is_directory) {
                copy.data = content_entry(original)->data;
            }
        }
        copies.emplace_back(new_path, std::move(copy));
    }

    for (const auto& [key, owner_index] : copied_link_owner) {
        copies[owner_index].second.data = std::move(copied_link_content[key]);
    }

    const CpioNodeId root_copy_id = copies.front().second.id;
    for (auto& [path, entry] : copies) {
        entries_.emplace(std::move(path), std::move(entry));
    }
    if (created_id != nullptr) {
        *created_id = root_copy_id;
    }
    return true;
}

bool CpioArchive::remove(CpioNodeId id, bool recursive) {
    const auto path = path_by_id(id);
    CpioEntry* entry = entry_by_id(id);
    if (!path || path->empty() || entry == nullptr) {
        return false;
    }
    const std::string prefix = *path + "/";
    const bool has_children = std::any_of(entries_.begin(), entries_.end(), [&](const auto& item) {
        return item.first.rfind(prefix, 0) == 0;
    });
    if (has_children && !recursive) {
        return false;
    }
    using LinkKey = std::tuple<std::uint32_t, std::uint32_t, std::uint32_t>;
    std::set<LinkKey> affected_links;
    std::map<LinkKey, std::vector<std::uint8_t>> affected_content;
    for (const auto& [candidate_path, candidate] : entries_) {
        if (candidate_path != *path &&
            (!recursive || candidate_path.rfind(prefix, 0) != 0)) {
            continue;
        }
        if (candidate.nlink > 1 && (candidate.mode & S_IFMT) != S_IFDIR) {
            const LinkKey key{
                candidate.ino, candidate.dev_major, candidate.dev_minor};
            affected_links.insert(key);
            affected_content.emplace(key, content_entry(candidate)->data);
        }
    }
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->first == *path || (recursive && it->first.rfind(prefix, 0) == 0)) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    for (const auto& key : affected_links) {
        const auto [ino, dev_major, dev_minor] = key;
        CpioEntry* surviving_entry = nullptr;
        bool has_content = false;
        for (auto& [_, candidate] : entries_) {
            if (candidate.ino == ino &&
                candidate.dev_major == dev_major &&
                candidate.dev_minor == dev_minor &&
                (candidate.mode & S_IFMT) != S_IFDIR) {
                if (surviving_entry == nullptr) {
                    surviving_entry = &candidate;
                }
                has_content = has_content || !candidate.data.empty();
            }
        }
        if (surviving_entry != nullptr && !has_content) {
            surviving_entry->data = std::move(affected_content[key]);
        }
        refresh_hard_link_count(ino, dev_major, dev_minor);
    }
    return true;
}

bool CpioArchive::move(
    CpioNodeId id,
    CpioNodeId destination_id,
    std::string_view new_name) {
    const auto source_path = path_by_id(id);
    const auto destination_path = child_path(destination_id, new_name);
    if (!source_path || source_path->empty() || !destination_path) {
        return false;
    }
    if (*source_path == *destination_path) {
        return true;
    }
    const std::string source_prefix = *source_path + "/";
    if (destination_path->rfind(source_prefix, 0) == 0) {
        return false;
    }

    std::set<std::string> moving_paths;
    for (const auto& [path, _] : entries_) {
        if (path == *source_path || path.rfind(source_prefix, 0) == 0) {
            moving_paths.insert(path);
        }
    }
    if (moving_paths.empty()) {
        return false;
    }

    std::vector<std::pair<std::string, CpioEntry>> moved;
    moved.reserve(moving_paths.size());
    for (const auto& old_path : moving_paths) {
        const std::string suffix = old_path.substr(source_path->size());
        const std::string new_path = *destination_path + suffix;
        const auto collision = entries_.find(new_path);
        if (collision != entries_.end() && moving_paths.find(new_path) == moving_paths.end()) {
            return false;
        }
        moved.emplace_back(new_path, entries_.at(old_path));
    }
    for (const auto& old_path : moving_paths) {
        entries_.erase(old_path);
    }
    for (auto& [new_path, entry] : moved) {
        entries_.emplace(std::move(new_path), std::move(entry));
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
    const int fd = open(src_file.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PLOGE("open source file %s", src_file.c_str());
        return false;
    }
    struct stat status{};
    if (fstat(fd, &status) != 0 || status.st_size < 0 ||
        static_cast<std::uintmax_t>(status.st_size) >
            static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
        close(fd);
        return false;
    }

    // st_size is a sizing hint, not the read length. Every caller in the boot
    // patch feeds this a regular file, but magiskboot is also reachable as a
    // multi-call applet, and procfs/sysfs/fifo sources report st_size 0 while
    // still having content. The ifstream slurp this replaced read those
    // correctly, so keep reading to EOF and only use the hint to size the buffer.
    constexpr std::size_t kReadChunk = 64U * 1024U;
    std::vector<std::uint8_t> data;
    if (S_ISREG(status.st_mode) && status.st_size > 0) {
        data.resize(static_cast<std::size_t>(status.st_size));
    }
    std::size_t filled = 0;
    for (;;) {
        if (filled == data.size()) {
            data.resize(data.empty() ? kReadChunk : data.size() * 2U);
        }
        const ssize_t count = read(fd, data.data() + filled, data.size() - filled);
        if (count > 0) {
            filled += static_cast<std::size_t>(count);
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        close(fd);
        PLOGE("read source file %s", src_file.c_str());
        return false;
    }
    close(fd);
    data.resize(filled);
    data.shrink_to_fit();

    const std::string path = normalize_path(std::string(cpio_path));
    if (path.empty()) {
        return false;
    }
    CpioEntry entry = make_entry((mode & 07777U) | S_IFREG);
    entry.uid = 0;
    entry.gid = 0;
    entry.data = std::move(data);
    const auto existing = entries_.find(path);
    if (existing != entries_.end()) {
        entry.id = existing->second.id;
        entry.order = existing->second.order;
        entry.ino = existing->second.ino;
    }
    entries_[path] = std::move(entry);
    return true;
}

bool CpioArchive::mkdir(std::uint32_t mode, const std::string& path) {
    const std::string normalized = normalize_path(path);
    if (normalized.empty()) {
        return false;
    }
    CpioEntry entry = make_entry((mode & 07777U) | S_IFDIR);
    entry.uid = 0;
    entry.gid = 0;
    entry.data.clear();
    const auto existing = entries_.find(normalized);
    if (existing != entries_.end()) {
        entry.id = existing->second.id;
        entry.order = existing->second.order;
        entry.ino = existing->second.ino;
    }
    entries_[normalized] = std::move(entry);
    return true;
}

bool CpioArchive::rm(const std::string& path, bool recursive) {
    const auto id = find(path);
    return id && *id != kCpioRootNodeId && remove(*id, recursive);
}

bool CpioArchive::mv(const std::string& from, const std::string& to) {
    const auto from_norm = normalize_path(from);
    const auto to_norm = normalize_path(to);
    const auto source_id = find(from_norm);
    if (!source_id || *source_id == kCpioRootNodeId || to_norm.empty()) {
        return false;
    }
    const auto separator = to_norm.rfind('/');
    const std::string parent_path =
        separator == std::string::npos ? std::string{} : to_norm.substr(0, separator);
    const std::string name =
        separator == std::string::npos ? to_norm : to_norm.substr(separator + 1);
    const auto parent_id = find(parent_path);
    return parent_id && move(*source_id, *parent_id, name);
}

bool CpioArchive::ln(const std::string& src, const std::string& dst) {
    const std::string destination = normalize_path(dst);
    if (destination.empty()) {
        return false;
    }
    const auto separator = destination.rfind('/');
    const std::string parent_path =
        separator == std::string::npos ? std::string{} : destination.substr(0, separator);
    const std::string name =
        separator == std::string::npos ? destination : destination.substr(separator + 1);
    const auto parent_id = find(parent_path);
    return parent_id &&
           create_symbolic_link(*parent_id, name, src, 0, 0);
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
    const auto prepare_backup_entry = [this](CpioEntry entry) {
        CpioEntry identity = make_entry(entry.mode);
        entry.id = identity.id;
        entry.order = identity.order;
        entry.ino = identity.ino;
        entry.nlink = (entry.mode & S_IFMT) == S_IFDIR ? 2U : 1U;
        return entry;
    };

    for (const auto& [name, orig_entry] : orig_archive.entries_) {
        if (orig_entry.synthetic) {
            continue;
        }
        const auto it = entries_.find(name);
        if (it == entries_.end() || it->second.data != orig_entry.data || it->second.mode != orig_entry.mode) {
            const std::string backup_name = std::string(".backup/") + name;
            if (!skip_compress) {
                std::vector<std::uint8_t> compressed;
                if (transcode_xz(orig_entry.data, compressed, true)) {
                    CpioEntry compressed_entry = orig_entry;
                    compressed_entry.data = std::move(compressed);
                    backups[backup_name + ".xz"] =
                        prepare_backup_entry(std::move(compressed_entry));
                    continue;
                }
            }
            backups[backup_name] = prepare_backup_entry(orig_entry);
        }
    }

    for (const auto& [name, entry] : entries_) {
        if (entry.synthetic) {
            continue;
        }
        if (orig_archive.entries_.find(name) == orig_archive.entries_.end()) {
            rm_list += name;
            rm_list.push_back('\0');
        }
    }

    CpioEntry backup_dir = make_entry(S_IFDIR | 0755U);
    backups[".backup"] = backup_dir;

    CpioEntry magisk_marker = make_entry(S_IFREG | 0644U);
    backups[".backup/.magisk"] = magisk_marker;

    if (!rm_list.empty()) {
        CpioEntry rmlist_entry = make_entry(S_IFREG | 0644U);
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
        const auto existing = entries_.find(target);
        if (existing != entries_.end()) {
            entry.id = existing->second.id;
            entry.order = existing->second.order;
        } else {
            CpioEntry identity = make_entry(entry.mode);
            entry.id = identity.id;
            entry.order = identity.order;
        }
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
