#include <cstdio>
#include <string>

#include "magiskboot.hpp"

int main(int argc, char **argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "Usage:\n"
                     "  magiskboot unpack <boot.img> [--skip-decomp] [--hdr]\n"
                     "  magiskboot repack <in-boot.img> <out-boot.img> [--skip-comp]\n"
                     "  magiskboot split-dtb <kernel-or-boot.img> [--skip-decomp]\n");
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
        } else {
            std::fprintf(stderr, "Unknown command: %s\n", cmd.c_str());
            return 1;
        }
    } catch (const std::exception &e) {
        std::fprintf(stderr, "magiskboot error: %s\n", e.what());
        return 1;
    }
}

