#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boot_crypto.hpp"
#include "cpio.hpp"

inline constexpr std::size_t kBootImageDefaultMaxSize = 256U * 1024U * 1024U;

struct BootRamdiskInfo {
    std::uint32_t header_version = 0;
    std::uint64_t source_image_size = 0;
    std::uint64_t packed_ramdisk_size = 0;
    FileFormat compression = FileFormat::UNKNOWN;
    bool has_kernel = false;
    bool has_avb_footer = false;
};

// A no-shards boot/init_boot editor. The source image remains mapped while its
// ramdisk is represented by one persistent in-memory CPIO document.
class BootRamdiskDocument {
public:
    BootRamdiskDocument();
    ~BootRamdiskDocument();

    BootRamdiskDocument(BootRamdiskDocument&&) noexcept;
    BootRamdiskDocument& operator=(BootRamdiskDocument&&) noexcept;

    BootRamdiskDocument(const BootRamdiskDocument&) = delete;
    BootRamdiskDocument& operator=(const BootRamdiskDocument&) = delete;

    [[nodiscard]] bool load(const std::string& image_path);
    [[nodiscard]] bool loaded() const noexcept;

    CpioDocument& ramdisk();
    const CpioDocument& ramdisk() const;
    [[nodiscard]] const BootRamdiskInfo& info() const;
    [[nodiscard]] const std::string& last_error() const noexcept;

    // Serializes the CPIO, restores the source compression, and rebuilds the
    // boot image without creating unpacked workspace files.
    [[nodiscard]] bool dump(std::vector<std::uint8_t>& output,
                            std::size_t max_output_size = kBootImageDefaultMaxSize) const;
    [[nodiscard]] bool dump(const BootByteSink& sink,
                            std::size_t max_output_size = kBootImageDefaultMaxSize) const;
    [[nodiscard]] bool dump(const std::string& output_path,
                            std::size_t max_output_size = kBootImageDefaultMaxSize) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
