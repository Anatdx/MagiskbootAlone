#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <zlib.h>
#ifdef USE_OPENSSL_SHA
#include <openssl/sha.h>
#endif

#include "base_host.hpp"
#include "boot_crypto.hpp"

// ===========================
// SHA‑1 / SHA‑256 via external lib (OpenSSL if enabled)
// ===========================

SHA::SHA(Algorithm algo) : alg_(algo), ctx_(nullptr) {
#ifdef USE_OPENSSL_SHA
    if (alg_ == Algorithm::SHA256) {
        auto *c = new SHA256_CTX;
        SHA256_Init(c);
        ctx_ = c;
    } else {
        auto *c = new SHA_CTX;
        SHA1_Init(c);
        ctx_ = c;
    }
#else
    (void)alg_;
    LOGE("SHA context not backed by any external implementation\n");
    std::abort();
#endif
}

void SHA::update(byte_view data) {
#ifdef USE_OPENSSL_SHA
    if (!ctx_) return;
    if (alg_ == Algorithm::SHA256) {
        auto *c = static_cast<SHA256_CTX *>(ctx_);
        SHA256_Update(c, data.data(), data.size());
    } else {
        auto *c = static_cast<SHA_CTX *>(ctx_);
        SHA1_Update(c, data.data(), data.size());
    }
#else
    (void)data;
#endif
}

void SHA::finalize_into(byte_data out) {
#ifdef USE_OPENSSL_SHA
    if (!ctx_) return;
    if (alg_ == Algorithm::SHA256) {
        if (out.size() < SHA256_DIGEST_LENGTH) {
            LOGE("SHA256 output buffer too small\n");
            std::abort();
        }
        auto *c = static_cast<SHA256_CTX *>(ctx_);
        SHA256_Final(out.data(), c);
        delete c;
    } else {
        if (out.size() < SHA_DIGEST_LENGTH) {
            LOGE("SHA1 output buffer too small\n");
            std::abort();
        }
        auto *c = static_cast<SHA_CTX *>(ctx_);
        SHA1_Final(out.data(), c);
        delete c;
    }
    ctx_ = nullptr;
#else
    (void)out;
#endif
}

std::size_t SHA::output_size() const {
#ifdef USE_OPENSSL_SHA
    return alg_ == Algorithm::SHA256 ? static_cast<std::size_t>(SHA256_DIGEST_LENGTH)
                                     : static_cast<std::size_t>(SHA_DIGEST_LENGTH);
#else
    return 0;
#endif
}

std::unique_ptr<SHA> get_sha(bool use_sha1) {
    return std::unique_ptr<SHA>(new SHA(use_sha1 ? SHA::Algorithm::SHA1
                                                 : SHA::Algorithm::SHA256));
}

void sha256_hash(byte_view data, byte_data out) {
    SHA ctx(SHA::Algorithm::SHA256);
    ctx.update(data);
    ctx.finalize_into(out);
}

// ===========================
// gzip helpers via zlib
// ===========================

namespace {

[[noreturn]] void unsupported_format(const char *op, FileFormat fmt) {
    LOGE("magiskboot: %s for format [%s] is not implemented in standalone C++ port\n",
         op, fmt2name(fmt));
    std::exit(1);
}

void zlib_deflate_gzip(byte_view in, int out_fd, int level) {
    z_stream strm{};
    if (deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        LOGE("deflateInit2 failed\n");
        throw std::runtime_error("deflateInit2 failed");
    }
    std::array<unsigned char, 64 * 1024> out_buf{};
    strm.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(in.data()));
    strm.avail_in = static_cast<uInt>(in.size());
    int ret;
    do {
        strm.next_out = out_buf.data();
        strm.avail_out = static_cast<uInt>(out_buf.size());
        ret = deflate(&strm, strm.avail_in ? Z_NO_FLUSH : Z_FINISH);
        if (ret == Z_STREAM_ERROR) {
            deflateEnd(&strm);
            LOGE("deflate stream error\n");
            throw std::runtime_error("deflate stream error");
        }
        std::size_t have = out_buf.size() - strm.avail_out;
        if (have > 0 && xwrite(out_fd, out_buf.data(), have) < 0) {
            deflateEnd(&strm);
            throw std::runtime_error("write failed");
        }
    } while (ret != Z_STREAM_END);
    deflateEnd(&strm);
}

void zlib_inflate_gzip(byte_view in, int out_fd) {
    z_stream strm{};
    if (inflateInit2(&strm, 15 + 32) != Z_OK) {
        LOGE("inflateInit2 failed\n");
        throw std::runtime_error("inflateInit2 failed");
    }
    std::array<unsigned char, 64 * 1024> out_buf{};
    strm.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(in.data()));
    strm.avail_in = static_cast<uInt>(in.size());
    int ret;
    do {
        strm.next_out = out_buf.data();
        strm.avail_out = static_cast<uInt>(out_buf.size());
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            LOGE("inflate failed (%d)\n", ret);
            inflateEnd(&strm);
            throw std::runtime_error("inflate failed");
        }
        std::size_t have = out_buf.size() - strm.avail_out;
        if (have > 0 && xwrite(out_fd, out_buf.data(), have) < 0) {
            inflateEnd(&strm);
            throw std::runtime_error("write failed");
        }
    } while (ret != Z_STREAM_END);
    inflateEnd(&strm);
}

} // namespace

void compress_bytes(FileFormat format, byte_view in_bytes, int out_fd) {
    switch (format) {
        case FileFormat::GZIP:
        case FileFormat::ZOPFLI:
            zlib_deflate_gzip(in_bytes, out_fd,
                              format == FileFormat::ZOPFLI ? Z_BEST_COMPRESSION
                                                           : Z_DEFAULT_COMPRESSION);
            break;
        default:
            unsupported_format("compress", format);
    }
}

void decompress_bytes(FileFormat format, byte_view in_bytes, int out_fd) {
    switch (format) {
        case FileFormat::GZIP:
        case FileFormat::ZOPFLI:
            zlib_inflate_gzip(in_bytes, out_fd);
            break;
        default:
            unsupported_format("decompress", format);
    }
}

const char *fmt2name(FileFormat fmt) {
    switch (fmt) {
        case FileFormat::CHROMEOS:   return "CHROMEOS";
        case FileFormat::AOSP:       return "AOSP";
        case FileFormat::AOSP_VENDOR:return "AOSP_VENDOR";
        case FileFormat::DHTB:       return "DHTB";
        case FileFormat::BLOB:       return "BLOB";
        case FileFormat::GZIP:       return "GZIP";
        case FileFormat::ZOPFLI:     return "ZOPFLI";
        case FileFormat::XZ:         return "XZ";
        case FileFormat::LZMA:       return "LZMA";
        case FileFormat::BZIP2:      return "BZIP2";
        case FileFormat::LZ4:        return "LZ4";
        case FileFormat::LZ4_LEGACY: return "LZ4_LEGACY";
        case FileFormat::LZ4_LG:     return "LZ4_LG";
        case FileFormat::LZOP:       return "LZOP";
        case FileFormat::MTK:        return "MTK";
        case FileFormat::DTB:        return "DTB";
        case FileFormat::ZIMAGE:     return "ZIMAGE";
        case FileFormat::UNKNOWN:
        default:
            return "UNKNOWN";
    }
}

bool fmt_compressed(FileFormat fmt) {
    switch (fmt) {
        case FileFormat::GZIP:
        case FileFormat::ZOPFLI:
        case FileFormat::XZ:
        case FileFormat::LZMA:
        case FileFormat::BZIP2:
        case FileFormat::LZ4:
        case FileFormat::LZ4_LEGACY:
        case FileFormat::LZ4_LG:
        case FileFormat::LZOP:
            return true;
        default:
            return false;
    }
}

bool fmt_compressed_any(FileFormat fmt) {
    return fmt_compressed(fmt);
}

std::vector<std::uint8_t> sign_payload(byte_view /*payload*/) {
    // Standalone version does not implement AVB1 signing.
    return {};
}

