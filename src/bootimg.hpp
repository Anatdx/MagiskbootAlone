#pragma once

#include <array>
#include <bitset>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

#include "base_host.hpp"
#include "boot_crypto.hpp"
#include "magiskboot.hpp"

/******************
 * Special Headers
 *****************/

struct mtk_hdr {
    uint32_t magic;                    /* MTK magic */
    uint32_t size;                     /* Size of the content */
    std::array<char, 32> name;         /* The type of the header */
    std::array<char, 472> padding;     /* Padding to 512 bytes */
} __attribute__((packed));

struct dhtb_hdr {
    std::array<char, 8> magic;         /* DHTB magic */
    std::array<uint8_t, 40> checksum; /* Payload SHA256 */
    uint32_t size;                     /* Payload size */
    std::array<char, 460> padding;     /* Padding to 512 bytes */
} __attribute__((packed));

struct blob_hdr {
    std::array<char, 20> secure_magic; /* "-SIGNED-BY-SIGNBLOB-" */
    uint32_t datalen;
    uint32_t signature;
    std::array<char, 16> magic;         /* "MSM-RADIO-UPDATE" */
    uint32_t hdr_version;
    uint32_t hdr_size;
    uint32_t part_offset;
    uint32_t num_parts;
    std::array<uint32_t, 7> unknown;
    std::array<char, 4> name;
    uint32_t offset;
    uint32_t size;
    uint32_t version;
} __attribute__((packed));

struct zimage_hdr {
    std::array<uint32_t, 9> code;
    uint32_t magic;   /* zImage magic */
    uint32_t start;   /* absolute load/run zImage address */
    uint32_t end;     /* zImage end address */
    uint32_t endian;  /* endianness flag */
} __attribute__((packed));

/**************
 * AVB Headers
 **************/

constexpr size_t AVB_FOOTER_MAGIC_LEN = 4;
constexpr size_t AVB_MAGIC_LEN = 4;
constexpr size_t AVB_RELEASE_STRING_SIZE = 48;

struct AvbFooter {
    std::array<uint8_t, AVB_FOOTER_MAGIC_LEN> magic;
    uint32_t version_major;
    uint32_t version_minor;
    uint64_t original_image_size;
    uint64_t vbmeta_offset;
    uint64_t vbmeta_size;
    std::array<uint8_t, 28> reserved;
} __attribute__((packed));

struct AvbVBMetaImageHeader {
    std::array<uint8_t, AVB_MAGIC_LEN> magic;
    uint32_t required_libavb_version_major;
    uint32_t required_libavb_version_minor;
    uint64_t authentication_data_block_size;
    uint64_t auxiliary_data_block_size;
    uint32_t algorithm_type;
    uint64_t hash_offset;
    uint64_t hash_size;
    uint64_t signature_offset;
    uint64_t signature_size;
    uint64_t public_key_offset;
    uint64_t public_key_size;
    uint64_t public_key_metadata_offset;
    uint64_t public_key_metadata_size;
    uint64_t descriptors_offset;
    uint64_t descriptors_size;
    uint64_t rollback_index;
    uint32_t flags;
    uint32_t rollback_index_location;
    std::array<uint8_t, AVB_RELEASE_STRING_SIZE> release_string;
    std::array<uint8_t, 80> reserved;
} __attribute__((packed));

/*********************
 * Boot Image Headers
 *********************/

constexpr size_t BOOT_MAGIC_SIZE = 8;
constexpr size_t BOOT_NAME_SIZE = 16;
constexpr size_t BOOT_ID_SIZE = 32;
constexpr size_t BOOT_ARGS_SIZE = 512;
constexpr size_t BOOT_EXTRA_ARGS_SIZE = 1024;
constexpr size_t VENDOR_BOOT_ARGS_SIZE = 2048;
constexpr size_t VENDOR_RAMDISK_NAME_SIZE = 32;
constexpr size_t VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE = 16;

enum VendorRamdiskType : uint32_t {
    VENDOR_RAMDISK_TYPE_NONE = 0,
    VENDOR_RAMDISK_TYPE_PLATFORM = 1,
    VENDOR_RAMDISK_TYPE_RECOVERY = 2,
    VENDOR_RAMDISK_TYPE_DLKM = 3,
};

struct boot_img_hdr_v0_common {
    std::array<char, BOOT_MAGIC_SIZE> magic;
    uint32_t kernel_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
} __attribute__((packed));

struct boot_img_hdr_v0 : public boot_img_hdr_v0_common {
    uint32_t tags_addr;
    union {
        uint32_t unknown;
        uint32_t page_size;
    };
    union {
        uint32_t header_version;
        uint32_t extra_size;
    };
    uint32_t os_version;
    std::array<char, BOOT_NAME_SIZE> name;
    std::array<char, BOOT_ARGS_SIZE> cmdline;
    std::array<char, BOOT_ID_SIZE> id;
    std::array<char, BOOT_EXTRA_ARGS_SIZE> extra_cmdline;
} __attribute__((packed));

struct boot_img_hdr_v1 : public boot_img_hdr_v0 {
    uint32_t recovery_dtbo_size;
    uint64_t recovery_dtbo_offset;
    uint32_t header_size;
} __attribute__((packed));

struct boot_img_hdr_v2 : public boot_img_hdr_v1 {
    uint32_t dtb_size;
    uint64_t dtb_addr;
} __attribute__((packed));

constexpr size_t BOOT_PXA_NAME_SIZE = 24;

struct boot_img_hdr_pxa : public boot_img_hdr_v0_common {
    uint32_t extra_size;
    uint32_t unknown;
    uint32_t tags_addr;
    uint32_t page_size;
    std::array<char, BOOT_PXA_NAME_SIZE> name;
    std::array<char, BOOT_ARGS_SIZE> cmdline;
    std::array<char, BOOT_ID_SIZE> id;
    std::array<char, BOOT_EXTRA_ARGS_SIZE> extra_cmdline;
} __attribute__((packed));

constexpr size_t BOOT_V3_CMDLINE_SIZE = BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE;

struct boot_img_hdr_v3 {
    std::array<uint8_t, BOOT_MAGIC_SIZE> magic;
    uint32_t kernel_size;
    uint32_t ramdisk_size;
    uint32_t os_version;
    uint32_t header_size;
    std::array<uint32_t, 4> reserved;
    uint32_t header_version;
    std::array<char, BOOT_V3_CMDLINE_SIZE> cmdline;
} __attribute__((packed));

struct boot_img_hdr_vnd_v3 {
    std::array<uint8_t, BOOT_MAGIC_SIZE> magic;
    uint32_t header_version;
    uint32_t page_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_addr;
    uint32_t ramdisk_size;
    std::array<char, VENDOR_BOOT_ARGS_SIZE> cmdline;
    uint32_t tags_addr;
    std::array<char, BOOT_NAME_SIZE> name;
    uint32_t header_size;
    uint32_t dtb_size;
    uint64_t dtb_addr;
} __attribute__((packed));

struct boot_img_hdr_v4 : public boot_img_hdr_v3 {
    uint32_t signature_size;
} __attribute__((packed));

struct boot_img_hdr_vnd_v4 : public boot_img_hdr_vnd_v3 {
    uint32_t vendor_ramdisk_table_size;
    uint32_t vendor_ramdisk_table_entry_num;
    uint32_t vendor_ramdisk_table_entry_size;
    uint32_t bootconfig_size;
} __attribute__((packed));

struct vendor_ramdisk_table_entry_v4 {
    uint32_t ramdisk_size;
    uint32_t ramdisk_offset;
    uint32_t ramdisk_type;
    std::array<char, VENDOR_RAMDISK_NAME_SIZE> ramdisk_name;
    std::array<uint32_t, VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE> board_id;
} __attribute__((packed));

/*******************************
 * Polymorphic Universal Header
 *******************************/

#define decl_val(name, len) \
virtual uint##len##_t name() const { return 0; }

/* Use set_* getter/setter to avoid returning ref to packed member (Clang/GCC). */
#define decl_var(name, len) \
virtual void set_##name(uint##len##_t v) { (void)v; } \
decl_val(name, len)

#define decl_str(name) \
virtual char *name() { return nullptr; } \
virtual const char *name() const { return nullptr; }

struct dyn_img_hdr {
    virtual bool is_vendor() const = 0;
    decl_var(kernel_size, 32)
    decl_var(ramdisk_size, 32)
    decl_var(second_size, 32)
    decl_val(page_size, 32)
    decl_val(header_version, 32)
    decl_var(extra_size, 32)
    decl_var(os_version, 32)
    decl_str(name)
    decl_str(cmdline)
    decl_str(id)
    decl_str(extra_cmdline)
    decl_var(recovery_dtbo_size, 32)
    decl_var(recovery_dtbo_offset, 64)
    decl_var(header_size, 32)
    decl_var(dtb_size, 32)
    decl_val(signature_size, 32)
    decl_val(vendor_ramdisk_table_size, 32)
    decl_val(vendor_ramdisk_table_entry_num, 32)
    decl_val(vendor_ramdisk_table_entry_size, 32)
    decl_var(bootconfig_size, 32)

    virtual ~dyn_img_hdr() { free(raw); }
    virtual size_t hdr_size() const = 0;
    virtual size_t hdr_space() const { return page_size(); }
    virtual dyn_img_hdr *clone() const = 0;

    const void *raw_hdr() const { return raw; }
    void print() const;
    void dump_hdr_file() const;
    void load_hdr_file();

protected:
    union {
        boot_img_hdr_v2 *v2_hdr;
        boot_img_hdr_v4 *v4_hdr;
        boot_img_hdr_vnd_v4 *v4_vnd;
        boot_img_hdr_pxa *hdr_pxa;
        void *raw;
    };
};

#undef decl_var
#undef decl_val
#undef decl_str

#define __impl_cls(name, hdr)           \
protected: name() = default;            \
public:                                 \
explicit name(const void *p, ssize_t sz = -1) {  \
    if (sz < 0) sz = sizeof(hdr);       \
    raw = calloc(sizeof(hdr), 1);       \
    memcpy(raw, p, sz);                 \
}                                       \
size_t hdr_size() const override {      \
    return sizeof(hdr);                 \
}                                       \
dyn_img_hdr *clone() const override {   \
    return new name(raw);             \
}

#define __impl_val(name, hdr_name) \
decltype(std::declval<const dyn_img_hdr>().name()) name() const override { return (hdr_name)->name; }

#define __impl_var(name, hdr_name) \
void set_##name(decltype((hdr_name)->name) v) override { (hdr_name)->name = v; } \
__impl_val(name, hdr_name)

#define __impl_str(name, hdr_name) \
char *name() override { return (hdr_name)->name.data(); } \
const char *name() const override { return (hdr_name)->name.data(); }

#define impl_cls(ver)  __impl_cls(dyn_img_##ver, boot_img_hdr_##ver)
#define impl_val(name) __impl_val(name, v2_hdr)
#define impl_var(name) __impl_var(name, v2_hdr)
#define impl_str(name) __impl_str(name, v2_hdr)

struct dyn_img_hdr_boot : public dyn_img_hdr {
    bool is_vendor() const final { return false; }
};

struct dyn_img_common : public dyn_img_hdr_boot {
    impl_var(kernel_size)
    impl_var(ramdisk_size)
    impl_var(second_size)
};

struct dyn_img_v0 : public dyn_img_common {
    impl_cls(v0)
    impl_val(page_size)
    impl_var(extra_size)
    impl_var(os_version)
    impl_str(name)
    impl_str(cmdline)
    impl_str(id)
    impl_str(extra_cmdline)
};

struct dyn_img_v1 : public dyn_img_v0 {
    impl_cls(v1)
    impl_val(header_version)
    impl_var(recovery_dtbo_size)
    impl_var(recovery_dtbo_offset)
    impl_var(header_size)
    void set_extra_size(uint32_t) override {}
    uint32_t extra_size() const override { return 0; }
};

struct dyn_img_v2 : public dyn_img_v1 {
    impl_cls(v2)
    impl_var(dtb_size)
};

#undef impl_val
#undef impl_var
#undef impl_str
#define impl_val(name) __impl_val(name, hdr_pxa)
#define impl_var(name) __impl_var(name, hdr_pxa)
#define impl_str(name) __impl_str(name, hdr_pxa)

struct dyn_img_pxa : public dyn_img_common {
    impl_cls(pxa)
    impl_var(extra_size)
    impl_val(page_size)
    impl_str(name)
    impl_str(cmdline)
    impl_str(id)
    impl_str(extra_cmdline)
};

#undef impl_val
#undef impl_var
#undef impl_str
#define impl_val(name) __impl_val(name, v4_hdr)
#define impl_var(name) __impl_var(name, v4_hdr)
#define impl_str(name) __impl_str(name, v4_hdr)

struct dyn_img_v3 : public dyn_img_hdr_boot {
    impl_cls(v3)
    impl_var(kernel_size)
    impl_var(ramdisk_size)
    impl_var(os_version)
    impl_var(header_size)
    impl_val(header_version)
    impl_str(cmdline)
    uint32_t page_size() const override { return 4096; }
    char *extra_cmdline() override { return &v4_hdr->cmdline[BOOT_ARGS_SIZE]; }
    const char *extra_cmdline() const override { return &v4_hdr->cmdline[BOOT_ARGS_SIZE]; }
};

struct dyn_img_v4 : public dyn_img_v3 {
    impl_cls(v4)
    impl_val(signature_size)
};

struct dyn_img_hdr_vendor : public dyn_img_hdr {
    bool is_vendor() const final { return true; }
};

#undef impl_val
#undef impl_var
#undef impl_str
#define impl_val(name) __impl_val(name, v4_vnd)
#define impl_var(name) __impl_var(name, v4_vnd)
#define impl_str(name) __impl_str(name, v4_vnd)

struct dyn_img_vnd_v3 : public dyn_img_hdr_vendor {
    impl_cls(vnd_v3)
    impl_val(header_version)
    impl_val(page_size)
    impl_var(ramdisk_size)
    impl_str(cmdline)
    impl_str(name)
    impl_var(header_size)
    impl_var(dtb_size)
    size_t hdr_space() const override { return align_to(hdr_size(), page_size()); }
    char *extra_cmdline() override { return &v4_vnd->cmdline[BOOT_ARGS_SIZE]; }
    const char *extra_cmdline() const override { return &v4_vnd->cmdline[BOOT_ARGS_SIZE]; }
};

struct dyn_img_vnd_v4 : public dyn_img_vnd_v3 {
    impl_cls(vnd_v4)
    impl_val(vendor_ramdisk_table_size)
    impl_val(vendor_ramdisk_table_entry_num)
    impl_val(vendor_ramdisk_table_entry_size)
    impl_var(bootconfig_size)
};

#undef __impl_cls
#undef __impl_val
#undef __impl_var
#undef __impl_str
#undef impl_cls
#undef impl_val
#undef impl_var
#undef impl_str

/******************
 * Full Boot Image
 ******************/

enum {
    MTK_KERNEL,
    MTK_RAMDISK,
    CHROMEOS_FLAG,
    DHTB_FLAG,
    SEANDROID_FLAG,
    LG_BUMP_FLAG,
    SHA256_FLAG,
    BLOB_FLAG,
    NOOKHD_FLAG,
    ACCLAIM_FLAG,
    AMONET_FLAG,
    AVB1_SIGNED_FLAG,
    AVB_FLAG,
    ZIMAGE_KERNEL,
    BOOT_FLAGS_MAX
};

struct boot_img {
    struct vendor_ramdisk_table_view {
        const vendor_ramdisk_table_entry_v4 *ptr = nullptr;
        std::size_t count = 0;

        const vendor_ramdisk_table_entry_v4 *begin() const { return ptr; }
        const vendor_ramdisk_table_entry_v4 *end() const { return ptr + count; }
        std::size_t size() const { return count; }
        bool empty() const { return count == 0; }
    };

    const mmap_data map;
    dyn_img_hdr *hdr = nullptr;
    std::bitset<BOOT_FLAGS_MAX> flags;
    FileFormat k_fmt;
    FileFormat r_fmt;
    FileFormat e_fmt;

    byte_view payload;
    byte_view tail;

    const mtk_hdr *k_hdr = nullptr;
    const mtk_hdr *r_hdr = nullptr;

    struct {
        const zimage_hdr *hdr = nullptr;
        uint32_t hdr_sz = 0;
        byte_view tail{};
    } z_info;

    const AvbFooter *avb_footer = nullptr;
    const AvbVBMetaImageHeader *vbmeta = nullptr;

    const uint8_t *kernel = nullptr;
    const uint8_t *ramdisk = nullptr;
    const uint8_t *second = nullptr;
    const uint8_t *extra = nullptr;
    const uint8_t *recovery_dtbo = nullptr;
    const uint8_t *dtb = nullptr;
    const uint8_t *signature = nullptr;
    const uint8_t *vendor_ramdisk_table = nullptr;
    const uint8_t *bootconfig = nullptr;

    byte_view kernel_dtb;

    explicit boot_img(const char *);
    ~boot_img();

    bool parse_image(const uint8_t *addr, FileFormat type);
    void parse_zimage();
    const uint8_t *parse_hdr(const uint8_t *addr, FileFormat type);
    vendor_ramdisk_table_view vendor_ramdisk_tbl() const;

    // AVB1 verify stub: upstream implements in Rust; we return false (no AVB1 detection)
    bool verify() const noexcept { return false; }
};
