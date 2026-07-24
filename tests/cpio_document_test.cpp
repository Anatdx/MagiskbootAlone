#include "cpio.hpp"
#include "boot_ramdisk.hpp"
#include "boot_crypto.hpp"
#include "bootimg.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

static_assert(sizeof(NewcHeader) == 110);

void format_hex8(char* output, std::uint32_t value) {
    std::array<char, 9> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%08x", value);
    std::memcpy(output, buffer.data(), 8);
}

void pad4(std::vector<std::uint8_t>& output) {
    while ((output.size() & 3U) != 0) {
        output.push_back(0);
    }
}

void pad_to(
    std::vector<std::uint8_t>& output,
    std::size_t alignment) {
    while ((output.size() % alignment) != 0) {
        output.push_back(0);
    }
}

void append_entry(std::vector<std::uint8_t>& output, std::string_view name, std::uint32_t ino,
                  std::uint32_t mode, std::uint32_t uid, std::uint32_t gid, std::uint32_t nlink,
                  std::uint32_t mtime, std::uint32_t dev_major, std::uint32_t dev_minor,
                  std::uint32_t rdev_major, std::uint32_t rdev_minor, std::string_view data = {}) {
    NewcHeader header{};
    std::memcpy(header.magic.data(), "070701", 6);
    format_hex8(header.ino.data(), ino);
    format_hex8(header.mode.data(), mode);
    format_hex8(header.uid.data(), uid);
    format_hex8(header.gid.data(), gid);
    format_hex8(header.nlink.data(), nlink);
    format_hex8(header.mtime.data(), mtime);
    format_hex8(header.filesize.data(), static_cast<std::uint32_t>(data.size()));
    format_hex8(header.devmajor.data(), dev_major);
    format_hex8(header.devminor.data(), dev_minor);
    format_hex8(header.rdevmajor.data(), rdev_major);
    format_hex8(header.rdevminor.data(), rdev_minor);
    format_hex8(header.namesize.data(), static_cast<std::uint32_t>(name.size() + 1));

    const auto* header_bytes = reinterpret_cast<const std::uint8_t*>(&header);
    output.insert(output.end(), header_bytes, header_bytes + sizeof(header));
    output.insert(output.end(), name.begin(), name.end());
    output.push_back(0);
    pad4(output);
    output.insert(output.end(), data.begin(), data.end());
    pad4(output);
}

std::vector<std::uint8_t> make_archive() {
    std::vector<std::uint8_t> archive;
    append_entry(archive, "system", 10, S_IFDIR | 0755U, 1000, 1000, 2, 111, 8, 1, 0, 0);
    append_entry(archive, "system/bin", 11, S_IFDIR | 0755U, 0, 2000, 2, 222, 8, 1, 0, 0);
    append_entry(archive, "system/bin/tool", 42, S_IFREG | 0750U, 0, 2000, 2, 333, 8, 1, 0, 0,
                 "payload");
    append_entry(archive, "system/bin/tool2", 42, S_IFREG | 0750U, 0, 2000, 2, 333, 8, 1, 0, 0);
    append_entry(archive, "dev/console", 50, S_IFCHR | 0600U, 0, 0, 1, 444, 8, 1, 5, 1);
    append_entry(archive, "TRAILER!!!", 51, S_IFREG, 0, 0, 1, 0, 0, 0, 0, 0);
    return archive;
}

bool check(bool condition, const char* expression, int line) {
    if (!condition) {
        std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    }
    return condition;
}

#define CHECK(expression)                                                   \
    do {                                                                    \
        if (!check(static_cast<bool>(expression), #expression, __LINE__)) { \
            return false;                                                   \
        }                                                                   \
    } while (false)

CpioDataSource source_from(std::string value) {
    return [value = std::move(value), offset = std::size_t{0}](
               std::uint8_t* output, std::size_t capacity) mutable -> ssize_t {
        const std::size_t count = std::min(capacity, value.size() - offset);
        if (count == 0) {
            return 0;
        }
        std::memcpy(output, value.data() + offset, count);
        offset += count;
        return static_cast<ssize_t>(count);
    };
}

bool write_file(
    const char* path,
    const std::vector<std::uint8_t>& bytes) {
    const int fd = ::open(
        path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t count =
            ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (count <= 0) {
            ::close(fd);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    return ::close(fd) == 0;
}

std::string read_all(const CpioArchive& archive, CpioNodeId id, bool& success) {
    std::string result;
    success = archive.read_content(id, [&](const std::uint8_t* data, std::size_t size) {
        result.append(reinterpret_cast<const char*>(data), size);
        return true;
    });
    return result;
}

std::string read_range(
    const CpioArchive& archive,
    CpioNodeId id,
    std::uint64_t offset,
    std::uint64_t length,
    bool& success) {
    std::string result;
    success = archive.read_content(
        id,
        offset,
        length,
        [&](const std::uint8_t* data, std::size_t size) {
            result.append(reinterpret_cast<const char*>(data), size);
            return true;
        });
    return result;
}

bool document_round_trip_test() {
    const auto bytes = make_archive();
    CpioDocument document;
    CHECK(document.load(bytes.data(), bytes.size()));

    const auto bin_id = document.find("system/bin");
    const auto tool_id = document.find("system/bin/tool");
    const auto tool2_id = document.find("system/bin/tool2");
    const auto dev_id = document.find("dev");
    const auto console_id = document.find("dev/console");
    CHECK(bin_id);
    CHECK(tool_id);
    CHECK(tool2_id);
    CHECK(dev_id);
    CHECK(console_id);

    const auto tool = document.stat(*tool_id);
    const auto console = document.stat(*console_id);
    CHECK(tool);
    CHECK(console);
    CHECK(tool->ino == 42);
    CHECK(tool->nlink == 2);
    CHECK(tool->mtime == 333);
    CHECK(tool->uid == 0);
    CHECK(tool->gid == 2000);
    CHECK(console->rdev_major == 5);
    CHECK(console->rdev_minor == 1);
    CHECK(document.stat(*dev_id)->synthetic);
    const auto root_entries = document.list(kCpioRootNodeId);
    CHECK(std::any_of(root_entries.begin(), root_entries.end(),
                      [&](const auto& entry) { return entry.id == *dev_id; }));
    const std::array<std::uint8_t, 8> invalid_archive{0x42, 0x41, 0x44, 0x43,
                                                      0x50, 0x49, 0x4f, 0x00};
    CHECK(!document.load(invalid_archive.data(), invalid_archive.size()));
    CHECK(document.find("system/bin/tool") == tool_id);

    bool read_ok = false;
    CHECK(read_all(document, *tool2_id, read_ok) == "payload");
    CHECK(read_ok);
    CHECK(read_range(document, *tool2_id, 1, 4, read_ok) == "aylo");
    CHECK(read_ok);
    CHECK(read_range(document, *tool2_id, 7, 10, read_ok).empty());
    CHECK(read_ok);
    CHECK(read_range(document, *tool2_id, 8, 1, read_ok).empty());
    CHECK(!read_ok);
    CHECK(document.replace_content(*tool2_id, source_from("replacement")));
    CHECK(read_all(document, *tool_id, read_ok) == "replacement");
    CHECK(read_ok);

    CHECK(document.move(*bin_id, kCpioRootNodeId, "sbin"));
    CHECK(!document.find("system/bin"));
    CHECK(document.find("sbin") == bin_id);
    CHECK(document.find("sbin/tool") == tool_id);
    CHECK(document.find("sbin/tool2") == tool2_id);

    CpioNodeId symlink_id = kCpioRootNodeId;
    CHECK(document.create_symbolic_link(kCpioRootNodeId, "init", "/system/bin/init", 0, 0,
                                        &symlink_id));
    const auto symlink = document.stat(symlink_id);
    CHECK(symlink);
    CHECK(symlink->link_target == "/system/bin/init");

    CpioNodeId hardlink_id = kCpioRootNodeId;
    CHECK(document.create_hard_link(kCpioRootNodeId, "tool-copy", *tool_id, &hardlink_id));
    CHECK(document.stat(*tool_id)->nlink == 3);
    CHECK(document.stat(*tool2_id)->nlink == 3);
    CHECK(document.stat(hardlink_id)->nlink == 3);
    CHECK(read_all(document, hardlink_id, read_ok) == "replacement");
    CHECK(read_ok);

    CpioNodeId copied_sbin_id = kCpioRootNodeId;
    CHECK(document.copy(*bin_id, kCpioRootNodeId, "sbin-copy", &copied_sbin_id));
    const auto copied_tool = document.find("sbin-copy/tool");
    const auto copied_tool2 = document.find("sbin-copy/tool2");
    CHECK(copied_sbin_id != *bin_id);
    CHECK(copied_tool);
    CHECK(copied_tool2);
    CHECK(*copied_tool != *tool_id);
    CHECK(document.stat(*copied_tool)->ino == document.stat(*copied_tool2)->ino);
    CHECK(document.stat(*copied_tool)->ino != 42);
    CHECK(document.stat(*copied_tool)->nlink == 2);
    CHECK(read_all(document, *copied_tool2, read_ok) == "replacement");
    CHECK(read_ok);

    std::vector<std::uint8_t> streamed_archive;
    CHECK(document.dump(streamed_archive));
    CpioDocument streamed_reload;
    CHECK(streamed_reload.load(
        streamed_archive.data(), streamed_archive.size()));
    CHECK(streamed_reload.find("sbin/tool") != std::nullopt);
    const std::vector<std::uint8_t> unchanged_output = {1, 2, 3};
    streamed_archive = unchanged_output;
    CHECK(!document.dump(streamed_archive, 16));
    CHECK(streamed_archive == unchanged_output);

    std::array<char, 64> temporary_path{};
    std::snprintf(temporary_path.data(), temporary_path.size(), "/tmp/cpio-document-test-XXXXXX");
    const int temporary_fd = mkstemp(temporary_path.data());
    CHECK(temporary_fd >= 0);
    ::close(temporary_fd);
    CHECK(document.dump(temporary_path.data()));
    CHECK(cpio_commands(
              temporary_path.data(),
              {"exists sbin/tool"}) == 0);

    CpioDocument reloaded;
    const bool loaded = reloaded.load(temporary_path.data());
    ::unlink(temporary_path.data());
    CHECK(loaded);

    const auto reloaded_tool = reloaded.find("sbin/tool");
    const auto reloaded_tool2 = reloaded.find("sbin/tool2");
    const auto reloaded_hardlink = reloaded.find("tool-copy");
    const auto reloaded_dev = reloaded.find("dev");
    CHECK(reloaded_tool);
    CHECK(reloaded_tool2);
    CHECK(reloaded_hardlink);
    CHECK(reloaded_dev);
    CHECK(reloaded.stat(*reloaded_tool)->ino == 42);
    CHECK(reloaded.stat(*reloaded_tool)->nlink == 3);
    CHECK(reloaded.stat(*reloaded_tool)->mtime == 333);
    CHECK(reloaded.stat(*reloaded_tool2)->ino == 42);
    CHECK(reloaded.stat(*reloaded_hardlink)->ino == 42);
    CHECK(reloaded.stat(*reloaded_dev)->synthetic);
    CHECK(read_all(reloaded, *reloaded_tool2, read_ok) == "replacement");
    CHECK(read_ok);
    return true;
}

bool recursive_remove_updates_hard_links_test() {
    const auto bytes = make_archive();
    CpioDocument document;
    CHECK(document.load(bytes.data(), bytes.size()));
    const auto bin_id = document.find("system/bin");
    const auto tool_id = document.find("system/bin/tool");
    CHECK(bin_id);
    CHECK(tool_id);

    CpioNodeId surviving_link = kCpioRootNodeId;
    CHECK(document.create_hard_link(kCpioRootNodeId, "survivor", *tool_id, &surviving_link));
    CHECK(document.stat(surviving_link)->nlink == 3);
    CHECK(document.remove(*bin_id, true));
    CHECK(!document.find("system/bin/tool"));
    CHECK(document.stat(surviving_link)->nlink == 1);
    bool read_ok = false;
    CHECK(read_all(document, surviving_link, read_ok) == "payload");
    CHECK(read_ok);
    return true;
}

bool compression_memory_stream_test() {
    const auto input = make_archive();
    const std::array<FileFormat, 4> formats = {
        FileFormat::GZIP,
        FileFormat::LZ4,
        FileFormat::LZ4_LEGACY,
        FileFormat::XZ,
    };
    for (const FileFormat format : formats) {
        std::vector<std::uint8_t> compressed;
        CHECK(compress_bytes(
            format,
            byte_view(input.data(), input.size()),
            compressed,
            kCpioDefaultMaxContentSize));
        CHECK(!compressed.empty());

        std::vector<std::uint8_t> decompressed;
        CHECK(decompress_bytes(
            format,
            byte_view(compressed.data(), compressed.size()),
            decompressed,
            kCpioDefaultMaxContentSize));
        CHECK(decompressed == input);

        const std::vector<std::uint8_t> unchanged = {9, 8, 7};
        decompressed = unchanged;
        CHECK(!decompress_bytes(
            format,
            byte_view(compressed.data(), compressed.size()),
            decompressed,
            16));
        CHECK(decompressed == unchanged);

        compressed.resize(compressed.size() / 2);
        decompressed = unchanged;
        CHECK(!decompress_bytes(
            format,
            byte_view(compressed.data(), compressed.size()),
            decompressed,
            kCpioDefaultMaxContentSize));
        CHECK(decompressed == unchanged);
    }
    return true;
}

bool boot_ramdisk_document_test() {
    const auto cpio = make_archive();
    std::vector<std::uint8_t> packed_ramdisk;
    CHECK(compress_bytes(
        FileFormat::LZ4_LEGACY,
        byte_view(cpio.data(), cpio.size()),
        packed_ramdisk,
        kCpioDefaultMaxContentSize));

    boot_img_hdr_v4 header{};
    std::memcpy(
        header.magic.data(), BOOT_MAGIC, BOOT_MAGIC_SIZE);
    header.ramdisk_size =
        static_cast<std::uint32_t>(packed_ramdisk.size());
    header.header_size = sizeof(header);
    header.header_version = 4;

    constexpr std::size_t kPageSize = 4096;
    std::vector<std::uint8_t> source(kPageSize, 0);
    std::memcpy(source.data(), &header, sizeof(header));
    source.insert(
        source.end(), packed_ramdisk.begin(), packed_ramdisk.end());
    pad_to(source, kPageSize);

    std::array<char, 64> source_path{};
    std::array<char, 64> output_path{};
    std::snprintf(
        source_path.data(),
        source_path.size(),
        "/tmp/boot-ramdisk-source-XXXXXX");
    std::snprintf(
        output_path.data(),
        output_path.size(),
        "/tmp/boot-ramdisk-output-XXXXXX");
    const int source_fd = ::mkstemp(source_path.data());
    const int output_fd = ::mkstemp(output_path.data());
    CHECK(source_fd >= 0);
    CHECK(output_fd >= 0);
    ::close(source_fd);
    ::close(output_fd);
    CHECK(write_file(source_path.data(), source));

    BootRamdiskDocument document;
    CHECK(document.load(source_path.data()));
    CHECK(document.info().header_version == 4);
    CHECK(document.info().compression == FileFormat::LZ4_LEGACY);
    CHECK(!document.info().has_kernel);
    CHECK(!document.info().has_avb_footer);
    const auto tool_id = document.ramdisk().find("system/bin/tool");
    CHECK(tool_id);
    CHECK(document.ramdisk().replace_content(
        *tool_id, source_from("boot-edit")));
    CHECK(!document.load("/definitely/missing/boot.img"));
    CHECK(document.loaded());
    CHECK(document.ramdisk().find("system/bin/tool") == tool_id);
    CHECK(write_file(
        output_path.data(), std::vector<std::uint8_t>(128, 0)));
    CHECK(!document.load(output_path.data()));
    CHECK(document.loaded());
    CHECK(document.dump(output_path.data()));

    BootRamdiskDocument reloaded;
    CHECK(reloaded.load(output_path.data()));
    const auto reloaded_tool =
        reloaded.ramdisk().find("system/bin/tool");
    CHECK(reloaded_tool);
    bool read_ok = false;
    CHECK(read_all(
              reloaded.ramdisk(), *reloaded_tool, read_ok) ==
          "boot-edit");
    CHECK(read_ok);

    ::unlink(source_path.data());
    ::unlink(output_path.data());
    return true;
}

}  // namespace

int main() {
    return document_round_trip_test() &&
                   recursive_remove_updates_hard_links_test() &&
                   compression_memory_stream_test() &&
                   boot_ramdisk_document_test()
               ? 0
               : 1;
}
