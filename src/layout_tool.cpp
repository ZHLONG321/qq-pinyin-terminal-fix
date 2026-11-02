#define WIN32_LEAN_AND_MEAN
#include "qq_layout.h"
#include <cstdio>
#include <exception>

// 手动工具也调用这份扫描代码，避免 Python 和代理各维护一组特征。
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        fputs("用法：qq_layout.exe QQPinyinTSF.dll\n", stderr);
        return 1;
    }
    try {
        auto layout = find_qq_layout(QqImage::from_file(argv[1]));
        printf("{\"flags_offset\":%u,\"tls_indices\":[", layout.flags_offset);
        bool comma = false;
        for (auto rva : layout.tls_indices) {
            printf("%s%u", comma ? "," : "", rva);
            comma = true;
        }
        fputs("],\"tables\":[", stdout);
        comma = false;
        for (const auto& table : layout.tables) {
            printf("%s{\"object_offset\":%u,\"rva\":%u}", comma ? "," : "", table.object_offset, table.rva);
            comma = true;
        }
        fputs("],\"checks\":[", stdout);
        comma = false;
        for (const auto& check : layout.checks) {
            printf("%s{\"rva\":%u,\"bytes\":\"", comma ? "," : "", check.rva);
            for (auto value : check.bytes) printf("%02x", static_cast<unsigned>(value));
            fputs("\"}", stdout);
            comma = true;
        }
        puts("]}");
        return 0;
    } catch (const std::exception& error) {
        fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
