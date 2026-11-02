#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

// 扫描结果只保存相对位置，供代理和手动工具共同使用。
struct QqTable { uint32_t object_offset; uint32_t rva; };
struct QqCheck { uint32_t rva; std::vector<unsigned char> bytes; };
struct QqLayout {
    uint32_t flags_offset = 0;
    std::vector<uint32_t> tls_indices;
    std::vector<QqTable> tables;
    std::vector<QqCheck> checks;
};

struct QqImage {
    std::vector<unsigned char> bytes;
    uint64_t address_base = 0;
    static QqImage from_file(const wchar_t* path);
    static QqImage from_module(HMODULE module);
};

QqLayout find_qq_layout(const QqImage& image);
