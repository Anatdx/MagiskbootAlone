#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "base_host.hpp"

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

// Compression helpers (gzip only in this standalone version).
void compress_bytes(FileFormat format, byte_view in_bytes, int out_fd);
void decompress_bytes(FileFormat format, byte_view in_bytes, int out_fd);

// Format helpers
const char *fmt2name(FileFormat fmt);
bool fmt_compressed(FileFormat fmt);
bool fmt_compressed_any(FileFormat fmt);

// AVB1 payload signing helper – stub in this standalone version.
std::vector<std::uint8_t> sign_payload(byte_view payload);

