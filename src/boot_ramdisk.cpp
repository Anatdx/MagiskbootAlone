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
constexpr std::uint64_t kStandardBootPageSize = 4096;

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

bool add_aligned_block(std::uint64_t& offset, std::uint64_t block_size, std::uint64_t alignment,
                       std::uint64_t image_size) {
    if (alignment == 0) {
        return false;
    }
    if (offset > image_size || block_size > image_size - offset) {
        return false;
    }
    const std::uint64_t end = offset + block_size;
    if (end > std::numeric_limits<std::uint64_t>::max() - (alignment - 1U)) {
        return false;
    }
    offset = ((end + alignment - 1U) / alignment) * alignment;
    return true;
}

bool validate_modern_boot_header(const std::string& path, std::uint64_t image_size) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    std::array<std::uint8_t, BOOT_MAGIC_SIZE> magic{};
    if (!read_exact_at(fd, magic.data(), magic.size(), 0)) {
        ::close(fd);
        return false;
    }

    bool valid = false;
    if (std::memcmp(magic.data(), BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0) {
        boot_img_hdr_v4 header{};
        if (read_exact_at(fd, &header, sizeof(header), 0) &&
            (header.header_version == 3 || header.header_version == 4) &&
            header.header_size >= sizeof(boot_img_hdr_v3) &&
            header.header_size <= kStandardBootPageSize &&
            image_size >= kStandardBootPageSize) {
            std::uint64_t offset = kStandardBootPageSize;
            valid =
                add_aligned_block(offset, header.kernel_size, kStandardBootPageSize, image_size) &&
                add_aligned_block(offset, header.ramdisk_size, kStandardBootPageSize, image_size) &&
                add_aligned_block(offset,
                                  header.header_version == 4 ? header.signature_size : 0,
                                  kStandardBootPageSize, image_size);
        }
    } else if (std::memcmp(magic.data(), VENDOR_BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0) {
        boot_img_hdr_vnd_v4 header{};
        if (read_exact_at(fd, &header, sizeof(header), 0) &&
            (header.header_version == 3 || header.header_version == 4) &&
            header.page_size != 0 && header.page_size <= 64U * 1024U &&
            header.header_size >= sizeof(boot_img_hdr_vnd_v3) &&
            header.header_size <= header.page_size) {
            const std::uint64_t page_size = header.page_size;
            std::uint64_t offset = 0;
            valid = add_aligned_block(offset, header.header_size, page_size, image_size) &&
                    add_aligned_block(offset, header.ramdisk_size, page_size, image_size) &&
                    add_aligned_block(offset, header.dtb_size, page_size, image_size);
            if (valid && header.header_version == 4) {
                valid = add_aligned_block(offset, header.vendor_ramdisk_table_size, page_size,
                                          image_size) &&
                        add_aligned_block(offset, header.bootconfig_size, page_size, image_size);
            }
        }
    }
    const bool close_success = ::close(fd) == 0;
    return valid && close_success;
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
    return image.payload.data() != image.map.data() || image.flags[MTK_KERNEL] ||
           image.flags[MTK_RAMDISK] || image.flags[CHROMEOS_FLAG] || image.flags[DHTB_FLAG] ||
           image.flags[BLOB_FLAG] || image.flags[NOOKHD_FLAG] || image.flags[ACCLAIM_FLAG] ||
           image.flags[AMONET_FLAG] || image.flags[SEANDROID_FLAG] || image.flags[LG_BUMP_FLAG] ||
           image.flags[AVB1_SIGNED_FLAG] || image.flags[ZIMAGE_KERNEL] ||
           image.kernel_dtb.size() != 0;
}

std::string fixed_string(const char* data, std::size_t size) {
    const auto* end = static_cast<const char*>(std::memchr(data, '\0', size));
    return std::string(data, end == nullptr ? size : static_cast<std::size_t>(end - data));
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
    struct Fragment {
        CpioDocument document;
        BootRamdiskFragmentInfo info;
    };

    std::unique_ptr<boot_img> image;
    std::vector<Fragment> fragments;
    BootRamdiskInfo info;
    mutable std::string error;

    void fail(std::string message) const { error = std::move(message); }

    bool pack_fragment(const Fragment& fragment, std::vector<std::uint8_t>& packed) const {
        std::vector<std::uint8_t> raw;
        if (!fragment.document.dump(raw, kMaximumRamdiskSize)) {
            fail("failed to serialize ramdisk CPIO");
            return false;
        }
        if (is_supported_compression(fragment.info.compression)) {
            if (!compress_bytes(fragment.info.compression, byte_view(raw.data(), raw.size()), packed,
                                kMaximumRamdiskSize)) {
                fail("failed to restore ramdisk compression");
                return false;
            }
        } else if (fragment.info.compression == FileFormat::UNKNOWN) {
            packed = std::move(raw);
        } else {
            fail("unsupported ramdisk compression");
            return false;
        }
        if (packed.size() > std::numeric_limits<std::uint32_t>::max()) {
            fail("packed ramdisk is too large for the boot header");
            return false;
        }
        return true;
    }

    bool finish_image(std::vector<std::uint8_t>& rebuilt, std::size_t aosp_image_size,
                      std::size_t max_output_size) const {
        const boot_img& source = *image;
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
        return true;
    }

    bool build_standard(const std::vector<std::vector<std::uint8_t>>& packed_fragments,
                        std::vector<std::uint8_t>& output,
                        std::size_t max_output_size) const {
        const boot_img& source = *image;
        const auto& packed_ramdisk = packed_fragments.front();
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

        if (!finish_image(rebuilt, aosp_image_size, max_output_size)) {
            return false;
        }
        error.clear();
        output = std::move(rebuilt);
        return true;
    }

    bool build_vendor(const std::vector<std::vector<std::uint8_t>>& packed_fragments,
                      std::vector<std::uint8_t>& output,
                      std::size_t max_output_size) const {
        const boot_img& source = *image;
        const std::size_t page_size = source.hdr->page_size();
        const std::size_t header_space = source.hdr->hdr_space();
        if (page_size == 0 || header_space > source.map.size() ||
            source.hdr->dtb_size() > source.map.size() ||
            source.hdr->bootconfig_size() > source.map.size()) {
            fail("invalid vendor boot image block sizes");
            return false;
        }

        std::uint64_t total_packed_size = 0;
        for (const auto& packed : packed_fragments) {
            total_packed_size += packed.size();
            if (total_packed_size > std::numeric_limits<std::uint32_t>::max()) {
                fail("combined vendor ramdisk is too large for the boot header");
                return false;
            }
        }

        std::vector<std::uint8_t> ramdisk_table;
        if (source.hdr->vendor_ramdisk_table_size() != 0) {
            const std::size_t table_size = source.hdr->vendor_ramdisk_table_size();
            const std::size_t entry_size = source.hdr->vendor_ramdisk_table_entry_size();
            const std::size_t entry_count = source.hdr->vendor_ramdisk_table_entry_num();
            if (entry_count != packed_fragments.size() ||
                entry_size != sizeof(vendor_ramdisk_table_entry_v4) ||
                entry_count > table_size / entry_size) {
                fail("invalid vendor ramdisk table");
                return false;
            }
            ramdisk_table.assign(source.vendor_ramdisk_table,
                                 source.vendor_ramdisk_table + table_size);
            std::uint32_t offset = 0;
            for (std::size_t index = 0; index < entry_count; ++index) {
                vendor_ramdisk_table_entry_v4 entry{};
                std::memcpy(&entry, ramdisk_table.data() + index * entry_size, sizeof(entry));
                entry.ramdisk_offset = offset;
                entry.ramdisk_size =
                    static_cast<std::uint32_t>(packed_fragments[index].size());
                std::memcpy(ramdisk_table.data() + index * entry_size, &entry, sizeof(entry));
                offset += entry.ramdisk_size;
            }
        }

        std::vector<std::uint8_t> rebuilt;
        rebuilt.reserve(std::min(source.map.size(), max_output_size));
        if (!append_bytes(rebuilt, source.payload.data(), header_space, max_output_size)) {
            fail("rebuilt vendor boot image exceeds the configured size limit");
            return false;
        }
        for (const auto& packed : packed_fragments) {
            if (!append_bytes(rebuilt, packed.data(), packed.size(), max_output_size)) {
                fail("rebuilt vendor boot image exceeds the configured size limit");
                return false;
            }
        }
        if (!align_output(rebuilt, page_size, max_output_size) ||
            !append_bytes(rebuilt, source.dtb, source.hdr->dtb_size(), max_output_size) ||
            !align_output(rebuilt, page_size, max_output_size) ||
            !append_bytes(rebuilt, ramdisk_table.data(), ramdisk_table.size(), max_output_size) ||
            !align_output(rebuilt, page_size, max_output_size) ||
            !append_bytes(rebuilt, source.bootconfig, source.hdr->bootconfig_size(),
                          max_output_size) ||
            !align_output(rebuilt, page_size, max_output_size)) {
            fail("rebuilt vendor boot image exceeds the configured size limit");
            return false;
        }

        const std::size_t aosp_image_size = rebuilt.size();
        auto header = std::unique_ptr<dyn_img_hdr>(source.hdr->clone());
        header->set_ramdisk_size(static_cast<std::uint32_t>(total_packed_size));
        header->set_header_size(static_cast<std::uint32_t>(header->hdr_size()));
        if (header->hdr_size() > rebuilt.size()) {
            fail("vendor boot header does not fit its header block");
            return false;
        }
        std::memcpy(rebuilt.data(), header->raw_hdr(), header->hdr_size());
        if (!finish_image(rebuilt, aosp_image_size, max_output_size)) {
            return false;
        }
        error.clear();
        output = std::move(rebuilt);
        return true;
    }

    bool build(std::vector<std::uint8_t>& output, std::size_t max_output_size) const {
        if (!image || fragments.empty()) {
            fail("no boot image is loaded");
            return false;
        }
        if (image->map.size() > max_output_size) {
            fail("source boot image exceeds the configured output limit");
            return false;
        }

        std::vector<std::vector<std::uint8_t>> packed_fragments(fragments.size());
        for (std::size_t index = 0; index < fragments.size(); ++index) {
            if (!pack_fragment(fragments[index], packed_fragments[index])) {
                return false;
            }
        }
        return image->hdr->is_vendor()
                   ? build_vendor(packed_fragments, output, max_output_size)
                   : build_standard(packed_fragments, output, max_output_size);
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
        impl_->fail("only plain AOSP boot/init_boot/vendor_boot v3-v4 images are supported");
        return false;
    }
    if (candidate->hdr->ramdisk_size() == 0 || candidate->ramdisk == nullptr) {
        impl_->fail("boot image does not contain a ramdisk");
        return false;
    }

    struct PackedFragment {
        const std::uint8_t* data = nullptr;
        std::size_t size = 0;
        BootRamdiskFragmentInfo info;
    };
    std::vector<PackedFragment> packed_fragments;
    if (candidate->hdr->vendor_ramdisk_table_size() != 0) {
        boot_img::vendor_ramdisk_table_view table;
        try {
            table = candidate->vendor_ramdisk_tbl();
        } catch (const std::exception& error) {
            impl_->fail(error.what());
            return false;
        }
        const std::size_t table_size = candidate->hdr->vendor_ramdisk_table_size();
        const std::size_t entry_size = candidate->hdr->vendor_ramdisk_table_entry_size();
        if (!candidate->hdr->is_vendor() || table.empty() ||
            entry_size != sizeof(vendor_ramdisk_table_entry_v4) ||
            table.size() > table_size / entry_size ||
            table.size() > kCpioMaxEntryCount) {
            impl_->fail("invalid vendor ramdisk table");
            return false;
        }
        packed_fragments.reserve(table.size());
        std::size_t index = 0;
        for (const auto& entry : table) {
            if (entry.ramdisk_size == 0 ||
                entry.ramdisk_offset > candidate->hdr->ramdisk_size() ||
                entry.ramdisk_size >
                    candidate->hdr->ramdisk_size() - entry.ramdisk_offset) {
                impl_->fail("vendor ramdisk table entry is out of bounds");
                return false;
            }
            PackedFragment fragment;
            fragment.data = candidate->ramdisk + entry.ramdisk_offset;
            fragment.size = entry.ramdisk_size;
            fragment.info.index = index++;
            fragment.info.name =
                fixed_string(entry.ramdisk_name.data(), entry.ramdisk_name.size());
            if (fragment.info.name.empty()) {
                fragment.info.name = "ramdisk";
            }
            fragment.info.vendor_type = entry.ramdisk_type;
            fragment.info.board_id = entry.board_id;
            fragment.info.packed_size = entry.ramdisk_size;
            fragment.info.compression =
                check_fmt_lg(fragment.data, static_cast<unsigned>(fragment.size));
            fragment.info.is_vendor = true;
            packed_fragments.push_back(std::move(fragment));
        }
    } else {
        PackedFragment fragment;
        fragment.data = candidate->ramdisk;
        fragment.size = candidate->hdr->ramdisk_size();
        fragment.info.index = 0;
        fragment.info.name = candidate->hdr->is_vendor() ? "vendor_ramdisk" : "ramdisk";
        fragment.info.vendor_type =
            candidate->hdr->is_vendor() ? VENDOR_RAMDISK_TYPE_PLATFORM
                                        : VENDOR_RAMDISK_TYPE_NONE;
        fragment.info.packed_size = fragment.size;
        fragment.info.compression = candidate->r_fmt;
        fragment.info.is_vendor = candidate->hdr->is_vendor();
        packed_fragments.push_back(std::move(fragment));
    }

    std::vector<Impl::Fragment> loaded_fragments;
    loaded_fragments.reserve(packed_fragments.size());
    std::size_t total_raw_size = 0;
    for (const auto& packed : packed_fragments) {
        std::vector<std::uint8_t> raw;
        if (is_supported_compression(packed.info.compression)) {
            if (!decompress_bytes(packed.info.compression, byte_view(packed.data, packed.size), raw,
                                  kMaximumRamdiskSize)) {
                impl_->fail("failed to decompress ramdisk fragment " + packed.info.name);
                return false;
            }
        } else if (packed.info.compression == FileFormat::UNKNOWN) {
            raw.assign(packed.data, packed.data + packed.size);
        } else {
            impl_->fail("unsupported compression in ramdisk fragment " + packed.info.name);
            return false;
        }
        if (raw.size() > kMaximumRamdiskSize - total_raw_size) {
            impl_->fail("combined decompressed ramdisks exceed the configured limit");
            return false;
        }
        total_raw_size += raw.size();
        Impl::Fragment fragment;
        fragment.info = packed.info;
        if (!fragment.document.load(raw.data(), raw.size())) {
            impl_->fail("ramdisk fragment " + packed.info.name +
                        " is not a valid newc CPIO archive");
            return false;
        }
        loaded_fragments.push_back(std::move(fragment));
    }

    BootRamdiskInfo loaded_info;
    loaded_info.header_version = header_version;
    loaded_info.source_image_size = candidate->map.size();
    loaded_info.packed_ramdisk_size = candidate->hdr->ramdisk_size();
    loaded_info.compression = loaded_fragments.front().info.compression;
    loaded_info.has_kernel = candidate->hdr->kernel_size() != 0;
    loaded_info.has_avb_footer = candidate->flags[AVB_FLAG];
    loaded_info.is_vendor = candidate->hdr->is_vendor();
    loaded_info.ramdisk_count = loaded_fragments.size();

    impl_->image = std::move(candidate);
    impl_->fragments = std::move(loaded_fragments);
    impl_->info = loaded_info;
    impl_->error.clear();
    return true;
}

bool BootRamdiskDocument::loaded() const noexcept {
    return impl_->image != nullptr;
}

std::size_t BootRamdiskDocument::ramdisk_count() const noexcept {
    return impl_->fragments.size();
}

CpioDocument& BootRamdiskDocument::ramdisk() {
    return ramdisk(0);
}

const CpioDocument& BootRamdiskDocument::ramdisk() const {
    return ramdisk(0);
}

CpioDocument& BootRamdiskDocument::ramdisk(std::size_t index) {
    if (!loaded() || index >= impl_->fragments.size()) {
        throw std::out_of_range("ramdisk fragment index is out of range");
    }
    return impl_->fragments[index].document;
}

const CpioDocument& BootRamdiskDocument::ramdisk(std::size_t index) const {
    if (!loaded() || index >= impl_->fragments.size()) {
        throw std::out_of_range("ramdisk fragment index is out of range");
    }
    return impl_->fragments[index].document;
}

const BootRamdiskFragmentInfo& BootRamdiskDocument::ramdisk_info(std::size_t index) const {
    if (!loaded() || index >= impl_->fragments.size()) {
        throw std::out_of_range("ramdisk fragment index is out of range");
    }
    return impl_->fragments[index].info;
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
