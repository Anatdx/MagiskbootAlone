#include <cstdio>
#include <string>
#include <vector>

#include "cpio.hpp"
#include "magiskboot.hpp"

// Entry point when linked into ksud (multi-call binary). Standalone build defines main() below.
int magiskboot_main(int argc, char **argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "Usage:\n"
                     "  magiskboot unpack <boot.img> [--skip-decomp] [--hdr]\n"
                     "  magiskboot repack <in-boot.img> <out-boot.img> [--skip-comp]\n"
                     "  magiskboot split-dtb <kernel-or-boot.img> [--skip-decomp]\n"
                     "  magiskboot cpio <ramdisk.cpio> <command> [command...]\n");
        return 1;
    }

    std::string cmd = argv[1];
    try {
        if (cmd == "unpack") {
            const char *img = argv[2];
            bool skip_decomp = false;
            bool hdr = false;
            for (int i = 3; i < argc; ++i) {
                if (std::string(argv[i]) == "--skip-decomp") skip_decomp = true;
                if (std::string(argv[i]) == "--hdr") hdr = true;
            }
            return unpack(img, skip_decomp, hdr);
        } else if (cmd == "repack") {
            if (argc < 4) {
                std::fprintf(stderr, "repack needs <in-boot.img> <out-boot.img>\n");
                return 1;
            }
            const char *src = argv[2];
            const char *dst = argv[3];
            bool skip_comp = false;
            for (int i = 4; i < argc; ++i) {
                if (std::string(argv[i]) == "--skip-comp") skip_comp = true;
            }
            repack(src, dst, skip_comp);
            return 0;
        } else if (cmd == "split-dtb") {
            const char *img = argv[2];
            bool skip_decomp = false;
            for (int i = 3; i < argc; ++i) {
                if (std::string(argv[i]) == "--skip-decomp") skip_decomp = true;
            }
            return split_image_dtb(img, skip_decomp);
        } else if (cmd == "cpio") {
            if (argc < 4) {
                std::fprintf(stderr, "cpio needs <ramdisk.cpio> <command> [command...]\n");
                return 1;
            }
            std::vector<std::string> commands;
            for (int i = 3; i < argc; ++i) {
                commands.emplace_back(argv[i]);
            }
            return cpio_commands(argv[2], commands);
        } else {
            std::fprintf(stderr, "Unknown command: %s\n", cmd.c_str());
            return 1;
        }
    } catch (const std::exception &e) {
        std::fprintf(stderr, "magiskboot error: %s\n", e.what());
        return 1;
    }
}

// Only define main when building this repo as standalone; when embedded (e.g. in ksud), embedder sets MAGISKBOOT_ALONE_AVAILABLE.
#if defined(MAGISKBOOT_STANDALONE) && !defined(MAGISKBOOT_ALONE_AVAILABLE)
int main(int argc, char **argv) {
    return magiskboot_main(argc, argv);
}
#endif

