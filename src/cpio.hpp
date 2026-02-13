#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct CpioEntry {
    std::uint32_t mode = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint32_t rdev_major = 0;
    std::uint32_t rdev_minor = 0;
    std::vector<std::uint8_t> data;
};

class CpioArchive {
public:
    bool load(const std::string& path);
    bool dump(const std::string& path) const;

    bool exists(const std::string& path) const;
    int test() const;

    bool add(std::uint32_t mode, const std::string& path, const std::string& src_file);
    bool mkdir(std::uint32_t mode, const std::string& path);
    bool rm(const std::string& path);
    bool mv(const std::string& from, const std::string& to);

private:
    static std::string normalize_path(const std::string& path);
    std::map<std::string, CpioEntry> entries_;
};

int cpio_commands(const std::string& file, const std::vector<std::string>& cmds);
