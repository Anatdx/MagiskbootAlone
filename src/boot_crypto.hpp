#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "base_host.hpp"
#include "function_ref.hpp"

// Subset of Magisk's FileFormat enum needed by magiskboot logic.
enum class FileFormat : std::uint8_t {
    UNKNOWN = 0,
    /* Boot formats */
    CHROMEOS = 1,
    AOSP = 2,
    AOSP_VENDOR = 3,
    DHTB = 4,
    BLOB = 5,
    /* Compression formats */
    GZIP = 6,
    ZOPFLI = 7,
    XZ = 8,
    LZMA = 9,
    BZIP2 = 10,
    LZ4 = 11,
    LZ4_LEGACY = 12,
    LZ4_LG = 13,
    LZOP = 14,
    /* Misc */
    MTK = 15,
    DTB = 16,
    ZIMAGE = 17,
};

// SHA helper using an external crypto library (OpenSSL if enabled).
class SHA {
public:
    enum class Algorithm {
        SHA1,
        SHA256,
    };

    explicit SHA(Algorithm algo);

    void update(byte_view data);
    void finalize_into(byte_data out);
    std::size_t output_size() const;

private:
    Algorithm alg_;
    void *ctx_;
};

std::unique_ptr<SHA> get_sha(bool use_sha1);
void sha256_hash(byte_view data, byte_data out);

// Compression helpers (gzip/lz4, and optional xz when built with liblzma).
using BootByteSink = FunctionRef<bool(const std::uint8_t*, std::size_t)>;

void compress_bytes(FileFormat format, byte_view in_bytes, int out_fd);
void decompress_bytes(FileFormat format, byte_view in_bytes, int out_fd);
[[nodiscard]] bool compress_bytes(
    FileFormat format,
    byte_view in_bytes,
    const BootByteSink& sink);
[[nodiscard]] bool decompress_bytes(
    FileFormat format,
    byte_view in_bytes,
    const BootByteSink& sink);
[[nodiscard]] bool compress_bytes(
    FileFormat format,
    byte_view in_bytes,
    std::vector<std::uint8_t>& output,
    std::size_t max_output_size);
[[nodiscard]] bool decompress_bytes(
    FileFormat format,
    byte_view in_bytes,
    std::vector<std::uint8_t>& output,
    std::size_t max_output_size);

// Format helpers
const char *fmt2name(FileFormat fmt);
bool fmt_compressed(FileFormat fmt);
bool fmt_compressed_any(FileFormat fmt);

// AVB1 boot image signature (Android BootSignature DER format).
// Verify: tail = image tail (DER blob), payload = boot payload; cert_pem = optional override.
bool avb_verify_boot_signature(byte_view tail, byte_view payload,
                               const char *cert_pem_path = nullptr);

// Sign payload; returns DER-encoded BootSignature or empty on failure.
// name defaults to "/boot"; cert_pem/key_pem null = use no key (returns empty).
std::vector<std::uint8_t> avb_sign_boot_image(byte_view payload, const char *name,
                                              const char *cert_pem_path,
                                              const char *key_pem_path);

// Legacy single-arg form for repack (no cert/key → returns empty when no default keys).
std::vector<std::uint8_t> sign_payload(byte_view payload);

