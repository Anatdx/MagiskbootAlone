#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <zlib.h>
#include <lz4.h>
#include <lz4frame.h>
#ifdef USE_LIBLZMA
#include <lzma.h>
#endif
#ifdef USE_MBEDTLS
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#endif

#include "base_host.hpp"
#include "boot_crypto.hpp"

// ===========================
// SHA‑1 / SHA‑256: mbedTLS
// ===========================

#ifdef USE_MBEDTLS
namespace {

constexpr std::size_t SHA1_DIGEST_LEN = 20;
constexpr std::size_t SHA256_DIGEST_LEN = 32;

struct Sha1Holder { mbedtls_sha1_context ctx; };
struct Sha256Holder { mbedtls_sha256_context ctx; };

}  // namespace
#endif

SHA::SHA(Algorithm algo) : alg_(algo), ctx_(nullptr) {
#ifdef USE_MBEDTLS
    if (alg_ == Algorithm::SHA256) {
        auto* h = new Sha256Holder;
        mbedtls_sha256_init(&h->ctx);
        mbedtls_sha256_starts(&h->ctx, 0);  // 0 = SHA-256
        ctx_ = h;
    } else {
        auto* h = new Sha1Holder;
        mbedtls_sha1_init(&h->ctx);
        mbedtls_sha1_starts(&h->ctx);
        ctx_ = h;
    }
#else
    (void)alg_;
    LOGE("SHA: USE_MBEDTLS required\n");
    std::abort();
#endif
}

void SHA::update(byte_view data) {
#ifdef USE_MBEDTLS
    if (!ctx_) return;
    if (alg_ == Algorithm::SHA256) {
        auto* h = static_cast<Sha256Holder*>(ctx_);
        mbedtls_sha256_update(&h->ctx, data.data(), data.size());
    } else {
        auto* h = static_cast<Sha1Holder*>(ctx_);
        mbedtls_sha1_update(&h->ctx, data.data(), data.size());
    }
#else
    (void)data;
#endif
}

void SHA::finalize_into(byte_data out) {
#ifdef USE_MBEDTLS
    if (!ctx_) return;
    if (alg_ == Algorithm::SHA256) {
        if (out.size() < SHA256_DIGEST_LEN) {
            LOGE("SHA256 output buffer too small\n");
            std::abort();
        }
        auto* h = static_cast<Sha256Holder*>(ctx_);
        mbedtls_sha256_finish(&h->ctx, out.data());
        mbedtls_sha256_free(&h->ctx);
        delete h;
    } else {
        if (out.size() < SHA1_DIGEST_LEN) {
            LOGE("SHA1 output buffer too small\n");
            std::abort();
        }
        auto* h = static_cast<Sha1Holder*>(ctx_);
        mbedtls_sha1_finish(&h->ctx, out.data());
        mbedtls_sha1_free(&h->ctx);
        delete h;
    }
    ctx_ = nullptr;
#else
    (void)out;
#endif
}

std::size_t SHA::output_size() const {
#ifdef USE_MBEDTLS
    return alg_ == Algorithm::SHA256 ? SHA256_DIGEST_LEN : SHA1_DIGEST_LEN;
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

constexpr unsigned char LZ4_LEGACY_MAGIC[] = {0x02, 0x21, 0x4c, 0x18};
constexpr std::size_t LZ4_LEGACY_MAGIC_SIZE = sizeof(LZ4_LEGACY_MAGIC);
constexpr std::size_t LZ4_LEGACY_BLOCK_MAX = 8 * 1024 * 1024;  // 8MB max decompress per block (match Magisk)
constexpr std::size_t LZ4_LEGACY_COMPRESS_BLOCK = 64 * 1024;

[[noreturn]] void unsupported_format(const char *op, FileFormat fmt) {
    LOGE("magiskboot: %s for format [%s] is not implemented in standalone C++ port\n",
         op, fmt2name(fmt));
    throw std::runtime_error("unsupported compression format");
}

void emit(
    const BootByteSink& sink,
    const void* data,
    std::size_t size) {
    if (size != 0 &&
        !sink(static_cast<const std::uint8_t*>(data), size)) {
        throw std::runtime_error("compression output rejected");
    }
}

std::uint32_t read_le32(const std::uint8_t *p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

void lz4f_compress(byte_view in, const BootByteSink& sink) {
    std::size_t bound = LZ4F_compressFrameBound(in.size(), nullptr);
    std::vector<char> buf(bound);
    std::size_t n = LZ4F_compressFrame(buf.data(), bound, in.data(), in.size(), nullptr);
    if (LZ4F_isError(n)) {
        LOGE("LZ4F_compressFrame failed: %s\n", LZ4F_getErrorName(n));
        throw std::runtime_error("LZ4 frame compress failed");
    }
    emit(sink, buf.data(), n);
}

void lz4f_decompress(byte_view in, const BootByteSink& sink) {
    LZ4F_dctx *dctx = nullptr;
    if (LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION) != 0) {
        throw std::runtime_error("LZ4 frame init failed");
    }
    std::array<char, 64 * 1024> out_buf{};
    std::size_t src_pos = 0;
    std::size_t remaining_hint = 1;
    while (src_pos < in.size()) {
        std::size_t src_len = in.size() - src_pos;
        std::size_t dst_len = out_buf.size();
        std::size_t n = LZ4F_decompress(dctx, out_buf.data(), &dst_len,
                                        in.data() + src_pos, &src_len, nullptr);
        if (LZ4F_isError(n)) {
            LZ4F_freeDecompressionContext(dctx);
            throw std::runtime_error("LZ4 frame decompress failed");
        }
        src_pos += src_len;
        if (dst_len > 0) {
            try {
                emit(sink, out_buf.data(), dst_len);
            } catch (...) {
                LZ4F_freeDecompressionContext(dctx);
                throw;
            }
        }
        if (n == 0) {
            remaining_hint = 0;
            break;
        }
        remaining_hint = n;
        if (src_len == 0 && dst_len == 0) {
            LZ4F_freeDecompressionContext(dctx);
            throw std::runtime_error(
                "LZ4 frame decompressor made no progress");
        }
    }
    LZ4F_freeDecompressionContext(dctx);
    if (remaining_hint != 0 || src_pos != in.size()) {
        throw std::runtime_error("truncated LZ4 frame");
    }
}

void lz4_legacy_compress(byte_view in, const BootByteSink& sink) {
    emit(sink, LZ4_LEGACY_MAGIC, LZ4_LEGACY_MAGIC_SIZE);
    std::vector<char> c_buf(static_cast<std::size_t>(
        LZ4_compressBound(static_cast<int>(LZ4_LEGACY_COMPRESS_BLOCK))));
    const char *src = reinterpret_cast<const char *>(in.data());
    std::size_t remaining = in.size();
    while (remaining > 0) {
        int chunk = static_cast<int>(std::min<std::size_t>(remaining, LZ4_LEGACY_COMPRESS_BLOCK));
        int c_sz = LZ4_compress_default(src, c_buf.data(), chunk, static_cast<int>(c_buf.size()));
        if (c_sz <= 0) {
            throw std::runtime_error("LZ4 legacy compress failed");
        }
        std::uint32_t le = static_cast<std::uint32_t>(c_sz);
        emit(sink, &le, sizeof(le));
        emit(sink, c_buf.data(), static_cast<std::size_t>(c_sz));
        src += chunk;
        remaining -= static_cast<std::size_t>(chunk);
    }
}

// LZ4 legacy (block format: magic + [4-byte comp_sz LE][block]...) — match Magisk native
// On 32-bit, (off + comp_sz) can overflow; validate comp_sz against remaining bytes first.
constexpr std::size_t LZ4_LEGACY_COMP_BLOCK_MAX = 16 * 1024 * 1024;  // 16MB max compressed block
// Cap total decompressed size to avoid corrupt/malicious stream filling disk (e.g. many small blocks).
constexpr std::size_t LZ4_LEGACY_DECOMP_TOTAL_MAX = 256 * 1024 * 1024;  // 256MB

void lz4_legacy_decompress(byte_view in, const BootByteSink& sink) {
    if (in.size() <= LZ4_LEGACY_MAGIC_SIZE + 4) {
        LOGE("magiskboot: LZ4 legacy stream too short\n");
        throw std::runtime_error("LZ4 legacy too short");
    }
    if (std::memcmp(in.data(), LZ4_LEGACY_MAGIC, LZ4_LEGACY_MAGIC_SIZE) != 0) {
        LOGE("magiskboot: LZ4 legacy bad magic\n");
        throw std::runtime_error("LZ4 legacy bad magic");
    }
    std::vector<char> out_buf(LZ4_LEGACY_BLOCK_MAX);
    std::size_t off = LZ4_LEGACY_MAGIC_SIZE;
    std::size_t total_out = 0;
    while (off + 4 <= in.size()) {
        std::uint32_t comp_sz;
        std::memcpy(&comp_sz, in.data() + off, 4);
        off += 4;
        if (comp_sz == 0)
            break;
        const std::size_t block_avail = in.size() - off;  /* bytes left for compressed block */
        if (comp_sz > block_avail) {
            LOGE("magiskboot: LZ4 legacy block overrun (comp_sz %u > %zu)\n", comp_sz, block_avail);
            throw std::runtime_error("LZ4 legacy block overrun");
        }
        if (comp_sz > LZ4_LEGACY_COMP_BLOCK_MAX) {
            LOGE("magiskboot: LZ4 legacy block too large: %u\n", comp_sz);
            throw std::runtime_error("LZ4 legacy block too large");
        }
        int n = LZ4_decompress_safe(reinterpret_cast<const char *>(in.data()) + off,
                                    out_buf.data(), static_cast<int>(comp_sz),
                                    static_cast<int>(out_buf.size()));
        if (n < 0) {
            LOGE("magiskboot: LZ4_decompress_safe failed: %d\n", n);
            throw std::runtime_error("LZ4 legacy decompress failed");
        }
        const std::size_t n_u = static_cast<std::size_t>(n);
        if (total_out + n_u > LZ4_LEGACY_DECOMP_TOTAL_MAX) {
            LOGE("magiskboot: LZ4 legacy total decompressed size exceeds %zu\n",
                 LZ4_LEGACY_DECOMP_TOTAL_MAX);
            throw std::runtime_error("LZ4 legacy decompress output too large");
        }
        total_out += n_u;
        emit(sink, out_buf.data(), n_u);
        off += comp_sz;
    }
    if (off != in.size()) {
        throw std::runtime_error("truncated LZ4 legacy stream");
    }
}

void zlib_deflate_gzip(
    byte_view in,
    const BootByteSink& sink,
    int level) {
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
        if (have > 0) {
            try {
                emit(sink, out_buf.data(), have);
            } catch (...) {
                deflateEnd(&strm);
                throw;
            }
        }
    } while (ret != Z_STREAM_END);
    deflateEnd(&strm);
}

void zlib_inflate_gzip(byte_view in, const BootByteSink& sink) {
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
        if (ret != Z_OK && ret != Z_STREAM_END) {
            LOGE("inflate failed (%d)\n", ret);
            inflateEnd(&strm);
            throw std::runtime_error("inflate failed");
        }
        std::size_t have = out_buf.size() - strm.avail_out;
        if (have > 0) {
            try {
                emit(sink, out_buf.data(), have);
            } catch (...) {
                inflateEnd(&strm);
                throw;
            }
        }
    } while (ret != Z_STREAM_END);
    inflateEnd(&strm);
}

#ifdef USE_LIBLZMA
void xz_compress(byte_view in, const BootByteSink& sink) {
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_easy_encoder(&stream, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
    if (ret != LZMA_OK) {
        throw std::runtime_error("lzma_easy_encoder failed");
    }
    std::array<std::uint8_t, 64 * 1024> out_buf{};
    stream.next_in = in.data();
    stream.avail_in = in.size();
    lzma_action action = LZMA_RUN;
    while (true) {
        stream.next_out = out_buf.data();
        stream.avail_out = out_buf.size();
        if (stream.avail_in == 0) {
            action = LZMA_FINISH;
        }
        ret = lzma_code(&stream, action);
        if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
            lzma_end(&stream);
            throw std::runtime_error("xz compress failed");
        }
        const std::size_t produced = out_buf.size() - stream.avail_out;
        if (produced > 0) {
            try {
                emit(sink, out_buf.data(), produced);
            } catch (...) {
                lzma_end(&stream);
                throw;
            }
        }
        if (ret == LZMA_STREAM_END) {
            break;
        }
    }
    lzma_end(&stream);
}

void xz_decompress(byte_view in, const BootByteSink& sink) {
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_stream_decoder(&stream, UINT64_MAX, 0);
    if (ret != LZMA_OK) {
        throw std::runtime_error("lzma_stream_decoder failed");
    }
    std::array<std::uint8_t, 64 * 1024> out_buf{};
    stream.next_in = in.data();
    stream.avail_in = in.size();
    while (true) {
        stream.next_out = out_buf.data();
        stream.avail_out = out_buf.size();
        ret = lzma_code(&stream, LZMA_RUN);
        if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
            lzma_end(&stream);
            throw std::runtime_error("xz decompress failed");
        }
        const std::size_t produced = out_buf.size() - stream.avail_out;
        if (produced > 0) {
            try {
                emit(sink, out_buf.data(), produced);
            } catch (...) {
                lzma_end(&stream);
                throw;
            }
        }
        if (ret == LZMA_STREAM_END) {
            break;
        }
    }
    lzma_end(&stream);
}
#endif

void compress_to_sink(
    FileFormat format,
    byte_view in_bytes,
    const BootByteSink& sink) {
    switch (format) {
        case FileFormat::GZIP:
        case FileFormat::ZOPFLI:
            zlib_deflate_gzip(in_bytes, sink,
                              format == FileFormat::ZOPFLI ? Z_BEST_COMPRESSION
                                                           : Z_DEFAULT_COMPRESSION);
            break;
        case FileFormat::LZ4:
            lz4f_compress(in_bytes, sink);
            break;
        case FileFormat::LZ4_LEGACY:
        case FileFormat::LZ4_LG:
            lz4_legacy_compress(in_bytes, sink);
            break;
        case FileFormat::XZ:
#ifdef USE_LIBLZMA
            xz_compress(in_bytes, sink);
            break;
#else
            unsupported_format("compress", format);
#endif
        default:
            unsupported_format("compress", format);
    }
}

void decompress_to_sink(
    FileFormat format,
    byte_view in_bytes,
    const BootByteSink& sink) {
    switch (format) {
        case FileFormat::GZIP:
        case FileFormat::ZOPFLI:
            zlib_inflate_gzip(in_bytes, sink);
            break;
        case FileFormat::LZ4:
            lz4f_decompress(in_bytes, sink);
            break;
        case FileFormat::LZ4_LEGACY:
        case FileFormat::LZ4_LG:
            lz4_legacy_decompress(in_bytes, sink);
            break;
        case FileFormat::XZ:
#ifdef USE_LIBLZMA
            xz_decompress(in_bytes, sink);
            break;
#else
            unsupported_format("decompress", format);
#endif
        default:
            unsupported_format("decompress", format);
    }
}

bool transform_to_vector(
    FileFormat format,
    byte_view input,
    std::vector<std::uint8_t>& output,
    std::size_t max_output_size,
    bool compress) {
    std::vector<std::uint8_t> replacement;
    const BootByteSink sink =
        [&](const std::uint8_t* data, std::size_t size) {
            if (replacement.size() > max_output_size ||
                size > max_output_size - replacement.size()) {
                return false;
            }
            replacement.insert(replacement.end(), data, data + size);
            return true;
        };
    const bool success = compress
                             ? compress_bytes(format, input, sink)
                             : decompress_bytes(format, input, sink);
    if (!success) {
        return false;
    }
    output = std::move(replacement);
    return true;
}

} // namespace

bool compress_bytes(
    FileFormat format,
    byte_view in_bytes,
    const BootByteSink& sink) {
    if (!sink) {
        return false;
    }
    try {
        compress_to_sink(format, in_bytes, sink);
        return true;
    } catch (const std::exception& error) {
        LOGE("magiskboot: compression failed: %s\n", error.what());
        return false;
    }
}

bool decompress_bytes(
    FileFormat format,
    byte_view in_bytes,
    const BootByteSink& sink) {
    if (!sink) {
        return false;
    }
    try {
        decompress_to_sink(format, in_bytes, sink);
        return true;
    } catch (const std::exception& error) {
        LOGE("magiskboot: decompression failed: %s\n", error.what());
        return false;
    }
}

bool compress_bytes(
    FileFormat format,
    byte_view in_bytes,
    std::vector<std::uint8_t>& output,
    std::size_t max_output_size) {
    return transform_to_vector(
        format, in_bytes, output, max_output_size, true);
}

bool decompress_bytes(
    FileFormat format,
    byte_view in_bytes,
    std::vector<std::uint8_t>& output,
    std::size_t max_output_size) {
    return transform_to_vector(
        format, in_bytes, output, max_output_size, false);
}

void compress_bytes(FileFormat format, byte_view in_bytes, int out_fd) {
    if (out_fd < 0 ||
        !compress_bytes(
            format,
            in_bytes,
            [out_fd](const std::uint8_t* data, std::size_t size) {
                return xwrite(out_fd, data, size) ==
                       static_cast<ssize_t>(size);
            })) {
        throw std::runtime_error("compression failed");
    }
}

void decompress_bytes(FileFormat format, byte_view in_bytes, int out_fd) {
    if (out_fd < 0 ||
        !decompress_bytes(
            format,
            in_bytes,
            [out_fd](const std::uint8_t* data, std::size_t size) {
                return xwrite(out_fd, data, size) ==
                       static_cast<ssize_t>(size);
            })) {
        throw std::runtime_error("decompression failed");
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

// ===========================
// AVB1 BootSignature (DER) verify / sign
// ===========================

#ifdef USE_MBEDTLS
namespace {

constexpr unsigned char AVB0_MAGIC[] = {'A', 'V', 'B', '0'};

bool der_read_tlv(const std::uint8_t **p, const std::uint8_t *end,
                  std::uint8_t *tag, const std::uint8_t **content, std::size_t *content_len) {
    if (*p >= end) return false;
    *tag = *(*p)++;
    if (*p >= end) return false;
    std::size_t len = *(*p)++;
    if (len & 0x80) {
        int n = len & 0x7f;
        if (n > 4 || *p + n > end) return false;
        len = 0;
        for (int i = 0; i < n; i++) len = (len << 8) | (*p)[i];
        *p += n;
    }
    if (*p + len > end) return false;
    *content = *p;
    *content_len = len;
    *p += len;
    return true;
}

bool der_outer_sequence(byte_view tail, const std::uint8_t **seq_content,
                        std::size_t *seq_len) {
    const std::uint8_t *p = tail.data();
    const std::uint8_t *end = tail.data() + tail.size();
    while (p < end && *p == 0) p++;
    if (p >= end) return false;
    std::uint8_t tag;
    if (!der_read_tlv(&p, end, &tag, seq_content, seq_len)) return false;
    return tag == 0x30;
}

bool der_sequence_element(const std::uint8_t *seq, std::size_t seq_len, int index,
                          const std::uint8_t **elem_content, std::size_t *elem_len) {
    const std::uint8_t *p = seq;
    const std::uint8_t *end = seq + seq_len;
    std::uint8_t tag;
    for (int i = 0; i <= index; i++) {
        if (p >= end) return false;
        if (!der_read_tlv(&p, end, &tag, elem_content, elem_len)) return false;
        if (i < index) p = *elem_content + *elem_len;
    }
    return true;
}

bool der_attr_length(const std::uint8_t *attr, std::size_t attr_len, std::uint64_t *out_len) {
    const std::uint8_t *p = attr;
    const std::uint8_t *end = attr + attr_len;
    std::uint8_t tag;
    const std::uint8_t *c;
    std::size_t cl;
    if (!der_read_tlv(&p, end, &tag, &c, &cl)) return false;
    if (p >= end) return false;
    if (!der_read_tlv(&p, end, &tag, &c, &cl)) return false;
    if (tag != 0x02 || cl > 8) return false;
    *out_len = 0;
    for (std::size_t i = 0; i < cl; i++) *out_len = (*out_len << 8) | c[i];
    return true;
}

}  // namespace
#endif

bool avb_verify_boot_signature(byte_view tail, byte_view payload,
                               const char *cert_pem_path) {
#ifdef USE_MBEDTLS
    if (tail.size() < 4) return false;
    if (std::memcmp(tail.data(), AVB0_MAGIC, 4) == 0) return false;

    const std::uint8_t *seq_content = nullptr;
    std::size_t seq_len = 0;
    if (!der_outer_sequence(tail, &seq_content, &seq_len)) return false;

    const std::uint8_t *cert_content = nullptr;
    std::size_t cert_len = 0;
    if (!der_sequence_element(seq_content, seq_len, 1, &cert_content, &cert_len))
        return false;
    const std::uint8_t *attr_content = nullptr;
    std::size_t attr_len = 0;
    if (!der_sequence_element(seq_content, seq_len, 3, &attr_content, &attr_len))
        return false;
    const std::uint8_t *sig_content = nullptr;
    std::size_t sig_len = 0;
    if (!der_sequence_element(seq_content, seq_len, 4, &sig_content, &sig_len))
        return false;

    std::uint64_t attr_payload_len = 0;
    if (!der_attr_length(attr_content, attr_len, &attr_payload_len)) return false;
    if (payload.size() != attr_payload_len) return false;

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse(&crt, cert_content, cert_len);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }
    if (cert_pem_path) {
        mbedtls_x509_crt_free(&crt);
        mbedtls_x509_crt_init(&crt);
        if (mbedtls_x509_crt_parse_file(&crt, cert_pem_path) != 0) {
            mbedtls_x509_crt_free(&crt);
            return false;
        }
    }

    unsigned char digest[32];
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, payload.data(), payload.size());
    mbedtls_sha256_update(&sha, attr_content, attr_len);
    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);

    ret = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                            sig_content, sig_len);
    mbedtls_x509_crt_free(&crt);
    return ret == 0;
#else
    (void)tail;
    (void)payload;
    (void)cert_pem_path;
    return false;
#endif
}

std::vector<std::uint8_t> avb_sign_boot_image(byte_view payload, const char *name,
                                               const char *cert_pem_path,
                                               const char *key_pem_path) {
#ifdef USE_MBEDTLS
    if (!cert_pem_path || !key_pem_path) return {};

    mbedtls_x509_crt crt;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&pkey);

    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static int rng_seeded = 0;
    if (rng_seeded == 0) {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0) != 0) {
            mbedtls_x509_crt_free(&crt);
            mbedtls_pk_free(&pkey);
            return {};
        }
        rng_seeded = 1;
    }
    if (mbedtls_x509_crt_parse_file(&crt, cert_pem_path) != 0 ||
        mbedtls_pk_parse_keyfile(&pkey, key_pem_path, nullptr,
                                 mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pkey);
        return {};
    }
    if (mbedtls_pk_can_do(&pkey, MBEDTLS_PK_RSA) == 0) {
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pkey);
        return {};
    }

    const char *name_str = name && name[0] ? name : "/boot";
    std::uint64_t payload_len = payload.size();
    std::size_t name_len = std::strlen(name_str);
    std::vector<std::uint8_t> attr_der;
    attr_der.push_back(0x30);
    std::size_t attr_inner = 1 + (name_len >= 128 ? 2 : 1) + name_len + 1 + 1 + 1 + 8;
    if (name_len < 128) {
        attr_der.push_back(static_cast<std::uint8_t>(attr_inner));
    } else {
        attr_der.push_back(0x82);
        attr_der.push_back(static_cast<std::uint8_t>(attr_inner >> 8));
        attr_der.push_back(static_cast<std::uint8_t>(attr_inner));
    }
    attr_der.push_back(0x13);
    attr_der.push_back(static_cast<std::uint8_t>(name_len));
    attr_der.insert(attr_der.end(), name_str, name_str + name_len);
    attr_der.push_back(0x02);
    attr_der.push_back(8);
    for (int i = 7; i >= 0; i--)
        attr_der.push_back(static_cast<std::uint8_t>(payload_len >> (i * 8)));

    unsigned char digest[32];
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, payload.data(), payload.size());
    mbedtls_sha256_update(&sha, attr_der.data(), attr_der.size());
    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);

    std::size_t sig_size = mbedtls_pk_get_len(&pkey);
    std::vector<std::uint8_t> sig(sig_size);
    std::size_t sig_len = 0;
    if (mbedtls_pk_sign(&pkey, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                        sig.data(), sig_size, &sig_len,
                        mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pkey);
        return {};
    }
    sig.resize(sig_len);

    const unsigned char *cert_der = crt.raw.p;
    std::size_t cert_der_len = crt.raw.len;
    const unsigned char alg_der[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00
    };
    std::vector<std::uint8_t> out;
    out.push_back(0x30);
    std::size_t total = 3 + cert_der_len + sizeof(alg_der) + attr_der.size() +
                        (sig_len >= 128 ? 3u : 2u) + sig_len;
    if (total < 128) {
        out.push_back(static_cast<std::uint8_t>(total));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(total >> 8));
        out.push_back(static_cast<std::uint8_t>(total));
    }
    out.push_back(0x02);
    out.push_back(0x01);
    out.push_back(0x01);
    out.insert(out.end(), cert_der, cert_der + cert_der_len);
    out.insert(out.end(), alg_der, alg_der + sizeof(alg_der));
    out.insert(out.end(), attr_der.begin(), attr_der.end());
    out.push_back(0x04);
    if (sig_len < 128) {
        out.push_back(static_cast<std::uint8_t>(sig_len));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(sig_len >> 8));
        out.push_back(static_cast<std::uint8_t>(sig_len));
    }
    out.insert(out.end(), sig.begin(), sig.end());
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&pkey);
    return out;
#else
    (void)payload;
    (void)name;
    (void)cert_pem_path;
    (void)key_pem_path;
    return {};
#endif
}

std::vector<std::uint8_t> sign_payload(byte_view payload) {
#ifdef USE_MBEDTLS
    (void)payload;
#endif
    return {};
}

