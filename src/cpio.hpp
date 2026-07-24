#pragma once

#include <sys/types.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using CpioNodeId = std::uint64_t;

inline constexpr CpioNodeId kCpioRootNodeId = 0;
inline constexpr std::size_t kCpioDefaultMaxContentSize = 512U * 1024U * 1024U;
inline constexpr std::size_t kCpioMaxEntryCount = 262144U;
inline constexpr std::size_t kCpioMaxPathSize = 65536U;

struct CpioEntry {
    CpioNodeId id = kCpioRootNodeId;
    std::uint64_t order = 0;
    bool synthetic = false;
    std::uint32_t ino = 0;
    std::uint32_t mode = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint32_t nlink = 1;
    std::uint32_t mtime = 0;
    std::uint32_t dev_major = 0;
    std::uint32_t dev_minor = 0;
    std::uint32_t rdev_major = 0;
    std::uint32_t rdev_minor = 0;
    std::uint32_t check = 0;
    std::vector<std::uint8_t> data;
};

struct CpioNodeInfo {
    CpioNodeId id = kCpioRootNodeId;
    CpioNodeId parent_id = kCpioRootNodeId;
    std::string name;
    std::string path;
    bool synthetic = false;
    std::uint32_t ino = 0;
    std::uint32_t mode = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint32_t nlink = 1;
    std::uint32_t mtime = 0;
    std::uint32_t dev_major = 0;
    std::uint32_t dev_minor = 0;
    std::uint32_t rdev_major = 0;
    std::uint32_t rdev_minor = 0;
    std::uint64_t size = 0;
    std::optional<std::string> link_target;
};

struct CpioMetadataPatch {
    std::optional<std::uint32_t> permissions;
    std::optional<std::uint32_t> uid;
    std::optional<std::uint32_t> gid;
    std::optional<std::uint32_t> mtime;
};

using CpioDataSink = std::function<bool(const std::uint8_t*, std::size_t)>;
using CpioDataSource = std::function<ssize_t(std::uint8_t*, std::size_t)>;

class CpioArchive {
public:
    bool load(const std::string& path);
    bool load(const std::uint8_t* data, std::size_t size);
    bool load_fd(int fd, std::size_t max_bytes = kCpioDefaultMaxContentSize);
    [[nodiscard]] bool dump(const std::string& path) const;
    [[nodiscard]] bool dump_fd(int fd) const;
    [[nodiscard]] bool dump(const CpioDataSink& sink) const;
    [[nodiscard]] bool dump(
        std::vector<std::uint8_t>& output,
        std::size_t max_bytes = kCpioDefaultMaxContentSize) const;

    [[nodiscard]] std::optional<CpioNodeId> find(std::string_view path) const;
    [[nodiscard]] std::optional<CpioNodeInfo> stat(CpioNodeId id) const;
    [[nodiscard]] std::vector<CpioNodeInfo> list(CpioNodeId directory_id) const;
    [[nodiscard]] bool read_content(CpioNodeId id, const CpioDataSink& sink) const;
    [[nodiscard]] bool read_content(
        CpioNodeId id,
        std::uint64_t offset,
        std::uint64_t length,
        const CpioDataSink& sink) const;
    bool replace_content(CpioNodeId id, const CpioDataSource& source,
                         std::size_t max_bytes = kCpioDefaultMaxContentSize);
    bool update_metadata(CpioNodeId id, const CpioMetadataPatch& patch);
    bool create_file(CpioNodeId parent_id, std::string_view name, std::uint32_t permissions,
                     std::uint32_t uid, std::uint32_t gid, const CpioDataSource& source,
                     CpioNodeId* created_id = nullptr,
                     std::size_t max_bytes = kCpioDefaultMaxContentSize);
    bool create_directory(CpioNodeId parent_id, std::string_view name, std::uint32_t permissions,
                          std::uint32_t uid, std::uint32_t gid, CpioNodeId* created_id = nullptr);
    bool create_symbolic_link(CpioNodeId parent_id, std::string_view name, std::string_view target,
                              std::uint32_t uid, std::uint32_t gid,
                              CpioNodeId* created_id = nullptr);
    bool create_hard_link(CpioNodeId parent_id, std::string_view name, CpioNodeId target_id,
                          CpioNodeId* created_id = nullptr);
    bool copy(CpioNodeId id, CpioNodeId destination_id, std::string_view new_name,
              CpioNodeId* created_id = nullptr);
    bool remove(CpioNodeId id, bool recursive);
    bool move(CpioNodeId id, CpioNodeId destination_id, std::string_view new_name);

    [[nodiscard]] bool exists(const std::string& path) const;
    [[nodiscard]] int test() const;

    bool add(std::uint32_t mode, std::string_view cpio_path, const std::string& src_file);
    bool mkdir(std::uint32_t mode, const std::string& path);
    bool rm(const std::string& path, bool recursive = false);
    bool mv(const std::string& from, const std::string& to);
    bool ln(const std::string& src, const std::string& dst);
    void ls(const std::string& path, bool recursive) const;
    bool extract(const std::string& path, const std::string& out) const;
    bool extract_all() const;
    bool patch(bool keep_verity, bool keep_force_encrypt);
    bool backup(const std::string& origin, bool skip_compress);
    bool restore();

private:
    bool extract_entry(const std::string& normalized_path, const std::string& out) const;
    bool parse(const std::uint8_t* data, std::size_t size);
    [[nodiscard]] CpioEntry* entry_by_id(CpioNodeId id);
    [[nodiscard]] const CpioEntry* entry_by_id(CpioNodeId id) const;
    [[nodiscard]] const CpioEntry* content_entry(const CpioEntry& entry) const;
    [[nodiscard]] CpioEntry* content_entry(CpioEntry& entry);
    [[nodiscard]] std::optional<std::string> path_by_id(CpioNodeId id) const;
    [[nodiscard]] std::optional<std::string> child_path(CpioNodeId parent_id,
                                                        std::string_view name) const;
    [[nodiscard]] CpioNodeInfo node_info(const std::string& path, const CpioEntry& entry) const;
    [[nodiscard]] CpioEntry make_entry(std::uint32_t mode);
    void ensure_parent_directories(const std::string& path);
    void materialize(CpioEntry& entry);
    void refresh_hard_link_count(std::uint32_t ino, std::uint32_t dev_major,
                                 std::uint32_t dev_minor);
    static std::string normalize_path(const std::string& path);
    std::map<std::string, CpioEntry> entries_;
    CpioNodeId next_node_id_ = 1;
    std::uint64_t next_order_ = 1;
    std::uint32_t next_inode_ = 1;
};

// The advanced API models an archive as a persistent in-memory document. Keep
// the historical name available to existing embedders and CLI code.
using CpioDocument = CpioArchive;

int cpio_commands(const std::string& file, const std::vector<std::string>& cmds);
