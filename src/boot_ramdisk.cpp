#include "boot_ramdisk.hpp"

#include "bootimg.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace {

constexpr std::size_t kMaximumRamdiskSize = kCpioDefaultMaxContentSize;
constexpr std::uint32_t kAvbAlignment = 4096;
constexpr std::uint64_t kModernBootPageSize = 4096;

bool read_exact_at(int fd, void* output, std::size_t size, off_t offset) {
    auto* bytes = static_cast<std::uint8_t*>(output);
    std::size_t completed = 0;
    while (completed < size) {
        const ssize_t count = ::pread(fd, bytes + completed, size - completed,
                                      offset + static_cast<off_t>(completed));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        completed += static_cast<std::size_t>(count);
    }
    return true;
}

bool add_aligned_block(std::uint64_t& offset, std::uint64_t block_size, std::uint64_t image_size) {
    if (offset > image_size || block_size > image_size - offset) {
        return false;
    }
    const std::uint64_t end = offset + block_size;
    if (end > std::numeric_limits<std::uint64_t>::max() - (kModernBootPageSize - 1U)) {
        return false;
    }
    offset = ((end + kModernBootPageSize - 1U) / kModernBootPageSize) * kModernBootPageSize;
    return true;
}

bool validate_modern_boot_header(const std::string& path, std::uint64_t image_size) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    boot_img_hdr_v4 header{};
    const bool read_success = read_exact_at(fd, &header, sizeof(header), 0);
    const bool close_success = ::close(fd) == 0;
    if (!read_success || !close_success ||
        std::memcmp(header.magic.data(), BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0 ||
        (header.header_version != 3 && header.header_version != 4) ||
        header.header_size < sizeof(boot_img_hdr_v3) || header.header_size > kModernBootPageSize ||
        image_size < kModernBootPageSize) {
        return false;
    }

    std::uint64_t offset = kModernBootPageSize;
    return add_aligned_block(offset, header.kernel_size, image_size) &&
           add_aligned_block(offset, header.ramdisk_size, image_size) &&
           add_aligned_block(offset, header.header_version == 4 ? header.signature_size : 0,
                             image_size);
}

bool is_supported_compression(FileFormat format) {
    switch (format) {
    case FileFormat::GZIP:
    case FileFormat::ZOPFLI:
    case FileFormat::XZ:
    case FileFormat::LZ4:
    case FileFormat::LZ4_LEGACY:
    case FileFormat::LZ4_LG:
        return true;
    default:
        return false;
    }
}

bool has_unsupported_layout(const boot_img& image) {
    return image.hdr->is_vendor() || image.hdr->vendor_ramdisk_table_size() != 0 ||
           image.payload.data() != image.map.data() || image.flags[MTK_KERNEL] ||
           image.flags[MTK_RAMDISK] || image.flags[CHROMEOS_FLAG] || image.flags[DHTB_FLAG] ||
           image.flags[BLOB_FLAG] || image.flags[NOOKHD_FLAG] || image.flags[ACCLAIM_FLAG] ||
           image.flags[AMONET_FLAG] || image.flags[SEANDROID_FLAG] || image.flags[LG_BUMP_FLAG] ||
           image.flags[AVB1_SIGNED_FLAG] || image.flags[ZIMAGE_KERNEL] ||
           image.kernel_dtb.size() != 0;
}

bool append_bytes(std::vector<std::uint8_t>& output, const void* data, std::size_t size,
                  std::size_t max_output_size) {
    if (output.size() > max_output_size || size > max_output_size - output.size()) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    if (bytes == nullptr) {
        return false;
    }
    output.insert(output.end(), bytes, bytes + size);
    return true;
}

bool align_output(std::vector<std::uint8_t>& output, std::size_t alignment,
                  std::size_t max_output_size) {
    if (alignment == 0) {
        return false;
    }
    const std::size_t remainder = output.size() % alignment;
    const std::size_t padding = remainder == 0 ? 0 : alignment - remainder;
    if (output.size() > max_output_size || padding > max_output_size - output.size()) {
        return false;
    }
    output.resize(output.size() + padding, 0);
    return true;
}

bool write_all(int fd, const std::uint8_t* data, std::size_t size) {
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
}

}  // namespace

class BootRamdiskDocument::Impl {
public:
    std::unique_ptr<boot_img> image;
    CpioDocument ramdisk;
    BootRamdiskInfo info;
    mutable std::string error;

    void fail(std::string message) const { error = std::move(message); }

    bool build(std::vector<std::uint8_t>& output, std::size_t max_output_size) const {
        if (!image) {
            fail("no boot image is loaded");
            return false;
        }
        if (image->map.size() > max_output_size) {
            fail("source boot image exceeds the configured output limit");
            return false;
        }

        std::vector<std::uint8_t> raw_ramdisk;
        if (!ramdisk.dump(raw_ramdisk, kMaximumRamdiskSize)) {
            fail("failed to serialize ramdisk CPIO");
            return false;
        }

        std::vector<std::uint8_t> packed_ramdisk;
        if (is_supported_compression(info.compression)) {
            if (!compress_bytes(info.compression, byte_view(raw_ramdisk.data(), raw_ramdisk.size()),
                                packed_ramdisk, kMaximumRamdiskSize)) {
                fail("failed to restore ramdisk compression");
                return false;
            }
        } else if (info.compression == FileFormat::UNKNOWN) {
            packed_ramdisk = std::move(raw_ramdisk);
        } else {
            fail("unsupported ramdisk compression");
            return false;
        }

        if (packed_ramdisk.size() > std::numeric_limits<std::uint32_t>::max()) {
            fail("packed ramdisk is too large for the boot header");
            return false;
        }

        const boot_img& source = *image;
        const std::size_t page_size = source.hdr->page_size();
        const std::size_t header_space = source.hdr->hdr_space();
        if (page_size == 0 || header_space > source.map.size() ||
            source.hdr->kernel_size() > source.map.size() ||
            source.hdr->signature_size() > source.map.size()) {
            fail("invalid boot image block sizes");
            return false;
        }

        std::vector<std::uint8_t> rebuilt;
        rebuilt.reserve(std::min(source.map.size(), max_output_size));
        if (!append_bytes(rebuilt, source.payload.data(), header_space, max_output_size) ||
            !append_bytes(rebuilt, source.kernel, source.hdr->kernel_size(), max_output_size) ||
            !align_output(rebuilt, page_size, max_output_size) ||
            !append_bytes(rebuilt, packed_ramdisk.data(), packed_ramdisk.size(), max_output_size) ||
            !align_output(rebuilt, page_size, max_output_size) ||
            !append_bytes(rebuilt, source.signature, source.hdr->signature_size(),
                          max_output_size) ||
            !align_output(rebuilt, page_size, max_output_size)) {
            fail("rebuilt boot image exceeds the configured size limit");
            return false;
        }

        const std::size_t aosp_image_size = rebuilt.size();
        auto header = std::unique_ptr<dyn_img_hdr>(source.hdr->clone());
        header->set_ramdisk_size(static_cast<std::uint32_t>(packed_ramdisk.size()));
        header->set_header_size(static_cast<std::uint32_t>(header->hdr_size()));
        if (header->hdr_size() > rebuilt.size()) {
            fail("boot header does not fit its header block");
            return false;
        }
        std::memcpy(rebuilt.data(), header->raw_hdr(), header->hdr_size());

        if (source.flags[AVB_FLAG]) {
            const std::uint64_t vbmeta_size = __builtin_bswap64(source.avb_footer->vbmeta_size);
            if (vbmeta_size > std::numeric_limits<std::size_t>::max() ||
                !align_output(rebuilt, kAvbAlignment, max_output_size)) {
                fail("invalid AVB metadata size");
                return false;
            }
            const std::size_t vbmeta_offset = rebuilt.size();
            if (!append_bytes(rebuilt, source.vbmeta, static_cast<std::size_t>(vbmeta_size),
                              max_output_size) ||
                source.map.size() < sizeof(AvbFooter) ||
                rebuilt.size() > source.map.size() - sizeof(AvbFooter)) {
                fail("rebuilt image no longer fits before the AVB footer");
                return false;
            }
            rebuilt.resize(source.map.size(), 0);
            AvbFooter footer{};
            std::memcpy(&footer, source.avb_footer, sizeof(footer));
            footer.original_image_size = __builtin_bswap64(aosp_image_size);
            footer.vbmeta_offset = __builtin_bswap64(vbmeta_offset);
            std::memcpy(rebuilt.data() + rebuilt.size() - sizeof(footer), &footer, sizeof(footer));
        } else if (rebuilt.size() < source.map.size()) {
            rebuilt.resize(source.map.size(), 0);
        }

        error.clear();
        output = std::move(rebuilt);
        return true;
    }
};

BootRamdiskDocument::BootRamdiskDocument() : impl_(std::make_unique<Impl>()) {}

BootRamdiskDocument::~BootRamdiskDocument() = default;

BootRamdiskDocument::BootRamdiskDocument(BootRamdiskDocument&&) noexcept = default;

BootRamdiskDocument& BootRamdiskDocument::operator=(BootRamdiskDocument&&) noexcept = default;

bool BootRamdiskDocument::load(const std::string& image_path) {
    struct stat image_stat{};
    if (::stat(image_path.c_str(), &image_stat) != 0 || image_stat.st_size <= 0 ||
        static_cast<std::uint64_t>(image_stat.st_size) > kBootImageDefaultMaxSize ||
        !validate_modern_boot_header(image_path, static_cast<std::uint64_t>(image_stat.st_size))) {
        impl_->fail("boot image is missing, empty, or too large");
        return false;
    }

    std::unique_ptr<boot_img> candidate;
    try {
        candidate = std::make_unique<boot_img>(image_path.c_str());
    } catch (const std::exception& error) {
        impl_->fail(error.what());
        return false;
    }

    const std::uint32_t header_version = candidate->hdr->header_version();
    if ((header_version != 3 && header_version != 4) || has_unsupported_layout(*candidate)) {
        impl_->fail("only standard AOSP boot/init_boot v3-v4 images are supported");
        return false;
    }
    if (candidate->hdr->ramdisk_size() == 0 || candidate->ramdisk == nullptr) {
        impl_->fail("boot image does not contain a ramdisk");
        return false;
    }

    const std::size_t packed_size = candidate->hdr->ramdisk_size();
    std::vector<std::uint8_t> raw_ramdisk;
    if (is_supported_compression(candidate->r_fmt)) {
        if (!decompress_bytes(candidate->r_fmt, byte_view(candidate->ramdisk, packed_size),
                              raw_ramdisk, kMaximumRamdiskSize)) {
            impl_->fail("failed to decompress boot ramdisk");
            return false;
        }
    } else if (candidate->r_fmt == FileFormat::UNKNOWN) {
        raw_ramdisk.assign(candidate->ramdisk, candidate->ramdisk + packed_size);
    } else {
        impl_->fail("unsupported boot ramdisk compression");
        return false;
    }

    CpioDocument document;
    if (!document.load(raw_ramdisk.data(), raw_ramdisk.size())) {
        impl_->fail("boot ramdisk is not a valid newc CPIO archive");
        return false;
    }

    BootRamdiskInfo loaded_info;
    loaded_info.header_version = header_version;
    loaded_info.source_image_size = candidate->map.size();
    loaded_info.packed_ramdisk_size = packed_size;
    loaded_info.compression = candidate->r_fmt;
    loaded_info.has_kernel = candidate->hdr->kernel_size() != 0;
    loaded_info.has_avb_footer = candidate->flags[AVB_FLAG];

    impl_->image = std::move(candidate);
    impl_->ramdisk = std::move(document);
    impl_->info = loaded_info;
    impl_->error.clear();
    return true;
}

bool BootRamdiskDocument::loaded() const noexcept {
    return impl_->image != nullptr;
}

CpioDocument& BootRamdiskDocument::ramdisk() {
    if (!loaded()) {
        throw std::logic_error("no boot image is loaded");
    }
    return impl_->ramdisk;
}

const CpioDocument& BootRamdiskDocument::ramdisk() const {
    if (!loaded()) {
        throw std::logic_error("no boot image is loaded");
    }
    return impl_->ramdisk;
}

const BootRamdiskInfo& BootRamdiskDocument::info() const {
    if (!loaded()) {
        throw std::logic_error("no boot image is loaded");
    }
    return impl_->info;
}

const std::string& BootRamdiskDocument::last_error() const noexcept {
    return impl_->error;
}

bool BootRamdiskDocument::dump(std::vector<std::uint8_t>& output,
                               std::size_t max_output_size) const {
    return impl_->build(output, max_output_size);
}

bool BootRamdiskDocument::dump(const BootByteSink& sink, std::size_t max_output_size) const {
    if (!sink) {
        impl_->fail("output sink is not set");
        return false;
    }
    std::vector<std::uint8_t> output;
    if (!impl_->build(output, max_output_size)) {
        return false;
    }
    if (!sink(output.data(), output.size())) {
        impl_->fail("output sink rejected the rebuilt boot image");
        return false;
    }
    impl_->error.clear();
    return true;
}

bool BootRamdiskDocument::dump(const std::string& output_path, std::size_t max_output_size) const {
    std::vector<std::uint8_t> output;
    if (!impl_->build(output, max_output_size)) {
        return false;
    }

    mode_t mode = 0644;
    struct stat existing{};
    if (::stat(output_path.c_str(), &existing) == 0) {
        mode = existing.st_mode & 07777;
    }
    std::string temporary_template = output_path + ".tmp.XXXXXX";
    std::vector<char> temporary_path(temporary_template.begin(), temporary_template.end());
    temporary_path.push_back('\0');
    const int fd = ::mkstemp(temporary_path.data());
    if (fd < 0) {
        impl_->fail("failed to create temporary output image");
        return false;
    }
    bool success =
        ::fchmod(fd, mode) == 0 && write_all(fd, output.data(), output.size()) && ::fsync(fd) == 0;
    if (::close(fd) != 0) {
        success = false;
    }
    if (success && ::rename(temporary_path.data(), output_path.c_str()) == 0) {
        impl_->error.clear();
        return true;
    }
    ::unlink(temporary_path.data());
    impl_->fail("failed to atomically replace output image");
    return false;
}
