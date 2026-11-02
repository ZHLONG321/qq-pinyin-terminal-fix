#define WIN32_LEAN_AND_MEAN
#include "qq_layout.h"
#include "../third_party/hde64/hde64.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>

namespace {
[[noreturn]] void invalid() { throw std::runtime_error("无法识别 QQ 输入法文件的结构。"); }
bool fits(size_t size, uint64_t pos, uint64_t count) { return pos <= size && count <= size - pos; }
template<class T> T read(const std::vector<unsigned char>& bytes, uint64_t pos) {
    if (!fits(bytes.size(), pos, sizeof(T))) invalid();
    T value{};
    memcpy(&value, bytes.data() + pos, sizeof(value));
    return value;
}
IMAGE_NT_HEADERS64 headers(const std::vector<unsigned char>& bytes) {
    auto dos = read<IMAGE_DOS_HEADER>(bytes, 0);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) invalid();
    auto nt = read<IMAGE_NT_HEADERS64>(bytes, static_cast<uint32_t>(dos.e_lfanew));
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) invalid();
    return nt;
}
std::vector<IMAGE_SECTION_HEADER> sections(const std::vector<unsigned char>& bytes) {
    auto nt = headers(bytes);
    auto dos = read<IMAGE_DOS_HEADER>(bytes, 0);
    uint64_t pos = static_cast<uint32_t>(dos.e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                   nt.FileHeader.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> result;
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
        result.push_back(read<IMAGE_SECTION_HEADER>(bytes, pos + i * sizeof(IMAGE_SECTION_HEADER)));
    return result;
}
struct View {
    const QqImage& image;
    IMAGE_NT_HEADERS64 nt;
    std::vector<IMAGE_SECTION_HEADER> parts;
    explicit View(const QqImage& value) : image(value), nt(headers(value.bytes)), parts(sections(value.bytes)) {
        if (nt.OptionalHeader.SizeOfImage != image.bytes.size()) invalid();
        for (const auto& s : parts)
            if (!fits(image.bytes.size(), s.VirtualAddress, s.Misc.VirtualSize)) invalid();
    }
    template<class T> T at(uint64_t pos) const { return read<T>(image.bytes, pos); }
    bool range(uint64_t pos, uint64_t count) const { return fits(image.bytes.size(), pos, count); }
    bool part(uint64_t pos, uint64_t count, DWORD required, DWORD forbidden = 0) const {
        if (!range(pos, count)) return false;
        for (const auto& s : parts)
            if ((s.Characteristics & required) == required && !(s.Characteristics & forbidden) &&
                pos >= s.VirtualAddress && pos - s.VirtualAddress <= s.Misc.VirtualSize &&
                count <= s.Misc.VirtualSize - (pos - s.VirtualAddress)) return true;
        return false;
    }
    bool code(uint64_t pos) const { return part(pos, 1, IMAGE_SCN_MEM_EXECUTE); }
    bool data(uint64_t pos, uint64_t count) const {
        return part(pos, count, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_EXECUTE);
    }
    uint32_t rva(uint64_t address) const {
        if (address < image.address_base || !range(address - image.address_base, 1)) invalid();
        return static_cast<uint32_t>(address - image.address_base);
    }
    bool pointer(uint64_t address, size_t count) const {
        return address >= image.address_base && range(address - image.address_base, count);
    }
    bool name(uint64_t pos, const char* value) const {
        size_t length = strlen(value) + 1;
        return range(pos, length) && !memcmp(image.bytes.data() + pos, value, length);
    }
    bool decode(uint32_t pos, hde64s& h) const {
        if (!code(pos)) return false;
        // HDE 可能预读；使用有填充的局部副本，不读出映像范围。
        unsigned char buffer[32]{};
        size_t count = (std::min)(sizeof(buffer), image.bytes.size() - pos);
        memcpy(buffer, image.bytes.data() + pos, count);
        hde64_disasm(buffer, &h);
        return h.len && !(h.flags & F_ERROR) && part(pos, h.len, IMAGE_SCN_MEM_EXECUTE);
    }
    std::vector<RUNTIME_FUNCTION> functions() const {
        auto d = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!range(d.VirtualAddress, d.Size) || d.Size % sizeof(RUNTIME_FUNCTION)) invalid();
        std::vector<RUNTIME_FUNCTION> result;
        for (uint64_t p = d.VirtualAddress; p < static_cast<uint64_t>(d.VirtualAddress) + d.Size;
             p += sizeof(RUNTIME_FUNCTION)) {
            auto f = at<RUNTIME_FUNCTION>(p);
            if (f.BeginAddress >= f.EndAddress || !part(f.BeginAddress, f.EndAddress - f.BeginAddress,
                                                       IMAGE_SCN_MEM_EXECUTE)) invalid();
            result.push_back(f);
        }
        return result;
    }
    QqCheck check(uint32_t pos, uint32_t count) const {
        if (!range(pos, count)) invalid();
        return {pos, {image.bytes.begin() + pos, image.bytes.begin() + pos + count}};
    }
};

int64_t displacement(const hde64s& h) {
    if (h.flags & F_DISP32) return static_cast<int32_t>(h.disp.disp32);
    if (h.flags & F_DISP8) return static_cast<int8_t>(h.disp.disp8);
    return 0;
}
// 只接受单个基址加位移；带动态下标的地址不能当作固定对象成员。
int memory_base(const hde64s& h) {
    if (!(h.flags & F_MODRM) || h.modrm_mod == 3 || h.p_67 || h.p_seg) return -1;
    if (h.flags & F_SIB) {
        if (h.sib_index != 4 || h.rex_x || (h.modrm_mod == 0 && h.sib_base == 5)) return -1;
        return h.sib_base + h.rex_b * 8;
    }
    if (h.modrm_mod == 0 && h.modrm_rm == 5) return -1;
    return h.modrm_rm + h.rex_b * 8;
}
uint32_t relative(const View& v, uint32_t pos, const hde64s& h, int64_t value) {
    int64_t target = static_cast<int64_t>(pos) + h.len + value;
    if (target < 0 || !v.range(static_cast<uint64_t>(target), 1)) invalid();
    return static_cast<uint32_t>(target);
}
bool rip(const hde64s& h) {
    return (h.flags & F_MODRM) && h.modrm_mod == 0 && h.modrm_rm == 5 && !h.p_67 && !h.p_seg;
}

struct Table { QqTable value; uint32_t type; uint32_t hierarchy; };
std::vector<Table> find_tables(const View& v) {
    std::vector<Table> result;
    // 从虚函数表前的完整对象定位信息反查，不使用厂商类名或固定表地址。
    for (const auto& s : v.parts) {
        if (!(s.Characteristics & IMAGE_SCN_MEM_READ) ||
            s.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) continue;
        uint64_t end = static_cast<uint64_t>(s.VirtualAddress) + s.Misc.VirtualSize;
        for (uint64_t p = (s.VirtualAddress + 7ULL) & ~7ULL; p + 4 * sizeof(uint64_t) <= end; p += 8) {
            uint64_t locator = v.at<uint64_t>(p);
            if (!v.pointer(locator, 24)) continue;
            uint32_t col = v.rva(locator);
            if (!v.data(col, 24) || v.at<uint32_t>(col) != 1 || v.at<uint32_t>(col + 8) != 0 ||
                v.at<uint32_t>(col + 20) != col) continue;
            bool methods = true;
            for (unsigned i = 1; i <= 3; ++i) {
                uint64_t fn = v.at<uint64_t>(p + i * 8);
                if (!v.pointer(fn, 1) || !v.code(v.rva(fn))) methods = false;
            }
            if (!methods) continue;
            result.push_back({{v.at<uint32_t>(col + 4), static_cast<uint32_t>(p + 8)},
                              v.at<uint32_t>(col + 12), v.at<uint32_t>(col + 16)});
        }
    }
    return result;
}
bool processor_interface(const View& v, const Table& table) {
    uint32_t chd = table.hierarchy;
    if (!v.data(chd, 16)) return false;
    uint32_t count = v.at<uint32_t>(chd + 8), array = v.at<uint32_t>(chd + 12);
    if (!count || !v.data(array, static_cast<uint64_t>(count) * 4)) return false;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t bcd = v.at<uint32_t>(static_cast<uint64_t>(array) + i * 4ULL);
        if (!v.data(bcd, 24)) return false;
        uint32_t td = v.at<uint32_t>(bcd);
        if (v.at<int32_t>(bcd + 12) == -1 && v.at<uint32_t>(bcd + 8) == table.value.object_offset &&
            (v.name(static_cast<uint64_t>(td) + 16, ".?AUITfTextInputProcessorEx@@") ||
             v.name(static_cast<uint64_t>(td) + 16, ".?AVITfTextInputProcessorEx@@"))) return true;
    }
    return false;
}

struct Origin { enum Kind { unknown, object, flags, stack } kind = unknown; int64_t offset = 0; };
struct StackValue { Origin value; unsigned width; };
std::map<uint32_t, QqCheck> activation_stores(const View& v, uint32_t start, uint32_t this_offset) {
    std::array<Origin, 16> regs{};
    regs[1] = {Origin::object, this_offset};
    regs[9] = {Origin::flags, 0}; // ActivateEx 的第四个参数 dwFlags。
    regs[4] = {Origin::stack, 0};
    std::map<int64_t, StackValue> stack;
    auto save = [&](int64_t address, unsigned width, Origin value) {
        for (auto it = stack.begin(); it != stack.end();) {
            if (it->first < address + width && address < it->first + it->second.width)
                it = stack.erase(it);
            else ++it;
        }
        if (value.kind != Origin::unknown) stack.emplace(address, StackValue{value, width});
    };
    std::map<uint32_t, QqCheck> stores;
    std::set<uint32_t> visited;
    uint32_t p = start;
    while (visited.insert(p).second) {
        hde64s h{};
        if (!v.decode(p, h)) return {};
        // 参数跟踪只支持默认地址宽度及普通整数操作。
        if (h.p_67 || h.p_seg || h.p_lock) return {};
        unsigned width = h.rex_w ? 8 : h.p_66 ? 2 : 4;
        int rm = h.modrm_rm + h.rex_b * 8, reg = h.modrm_reg + h.rex_r * 8;
        int base = memory_base(h);
        Origin address = base >= 0 ? regs[static_cast<size_t>(base)] : Origin{};
        address.offset += displacement(h);
        if (h.opcode == 0xe9 || h.opcode == 0xeb) {
            int64_t delta = h.opcode == 0xe9 ? static_cast<int32_t>(h.imm.imm32) : static_cast<int8_t>(h.imm.imm8);
            p = relative(v, p, h, delta);
            continue;
        }
        // 不跨调用和条件分支猜测寄存器值；只追踪参数首次保存的直线路径。
        if (h.opcode == 0xe8 || h.opcode == 0xc3 || h.opcode == 0xc2 ||
            (h.opcode == 0xff && h.modrm_reg >= 2 && h.modrm_reg <= 5) ||
            (h.opcode >= 0x70 && h.opcode <= 0x7f) ||
            (h.opcode == 0x0f && h.opcode2 >= 0x80 && h.opcode2 <= 0x8f)) break;
        if (!h.opcode2 && (h.opcode == 0x89 || h.opcode == 0x8b)) {
            int dest = h.opcode == 0x89 ? rm : reg;
            int source = h.opcode == 0x89 ? reg : rm;
            if (h.modrm_mod == 3) {
                regs[dest] = regs[source];
                if (width < 4 || (width != 8 && regs[dest].kind != Origin::flags)) regs[dest] = {};
            } else if (h.opcode == 0x8b) {
                auto saved = stack.find(address.offset);
                regs[dest] = address.kind == Origin::stack && saved != stack.end() &&
                    saved->second.width >= width ? saved->second.value : Origin{};
                if (width < 4 || (width != 8 && regs[dest].kind != Origin::flags)) regs[dest] = {};
            } else {
                if (address.kind == Origin::object && regs[source].kind == Origin::flags && !h.rex_w && !h.p_66 &&
                    address.offset >= 0 && address.offset <= UINT32_MAX && address.offset % 4 == 0)
                    stores.emplace(static_cast<uint32_t>(address.offset), v.check(p, h.len));
                if (address.kind == Origin::stack) save(address.offset, width, regs[source]);
                else if (address.kind == Origin::unknown) stack.clear();
            }
        } else if (h.opcode == 0x8d && h.rex_w) {
            regs[reg] = address;
        } else if ((h.opcode == 0x81 || h.opcode == 0x83) && h.modrm_mod == 3) {
            int64_t amount = h.opcode == 0x83 ? static_cast<int8_t>(h.imm.imm8) : static_cast<int32_t>(h.imm.imm32);
            if (h.rex_w && (h.modrm_reg == 0 || h.modrm_reg == 5) &&
                (regs[rm].kind == Origin::object || regs[rm].kind == Origin::stack))
                regs[rm].offset += h.modrm_reg == 0 ? amount : -amount;
            else if (h.modrm_reg != 7) regs[rm] = {};
        } else if (h.opcode >= 0x50 && h.opcode <= 0x57) {
            if (h.p_66 || regs[4].kind != Origin::stack) return {};
            regs[4].offset -= 8;
            save(regs[4].offset, 8, regs[(h.opcode & 7) + h.rex_b * 8]);
        } else if (h.opcode >= 0x58 && h.opcode <= 0x5f) {
            int dest = (h.opcode & 7) + h.rex_b * 8;
            if (h.p_66 || regs[4].kind != Origin::stack || dest == 4) return {};
            auto saved = stack.find(regs[4].offset);
            regs[dest] = saved != stack.end() && saved->second.width == 8 ? saved->second.value : Origin{};
            regs[4].offset += 8;
        } else if (h.opcode == 0x31 || h.opcode == 0x33) {
            if (h.modrm_mod == 3) regs[h.opcode == 0x31 ? rm : reg] = {};
            else if (h.opcode == 0x33) regs[reg] = {};
            else if (address.kind == Origin::stack) save(address.offset, width, {});
            else if (address.kind == Origin::unknown) stack.clear();
        } else if (h.opcode >= 0xb8 && h.opcode <= 0xbf) {
            regs[(h.opcode & 7) + h.rex_b * 8] = {};
        } else if (h.opcode == 0xc7 && h.modrm_reg == 0) {
            if (h.modrm_mod == 3) regs[rm] = {};
            else if (address.kind == Origin::stack) save(address.offset, width, {});
            else if (address.kind == Origin::unknown) stack.clear();
        } else if (h.opcode == 0x90 || h.opcode == 0x85 || h.opcode == 0x84 ||
                   h.opcode == 0x39 || h.opcode == 0x3b ||
                   (h.opcode == 0x0f && (h.opcode2 == 0x1f || h.opcode2 == 0x1e))) {
            // NOP、ENDBR、比较和测试不改变被追踪的参数。
        } else return {};
        p += h.len;
    }
    return stores;
}

std::map<uint32_t, std::vector<QqCheck>> flag_tests(const View& v) {
    std::map<uint32_t, std::vector<QqCheck>> result;
    for (const auto& f : v.functions()) {
        for (uint32_t p = f.BeginAddress; p < f.EndAddress;) {
            hde64s h{};
            if (!v.decode(p, h) || h.len > f.EndAddress - p) break;
            int base = memory_base(h);
            int64_t offset = displacement(h);
            if ((h.opcode == 0xf6 || (h.opcode == 0xf7 && !h.p_66)) && h.modrm_reg == 0 &&
                base >= 0 && base != 4 && offset >= 0 && offset <= UINT32_MAX &&
                (h.opcode == 0xf6 ? h.imm.imm8 : h.imm.imm32) == 0x40)
                result[static_cast<uint32_t>(offset)].push_back(v.check(p, h.len));
            p += h.len;
        }
    }
    return result;
}

std::set<uint32_t> tls_imports(const View& v) {
    std::set<uint32_t> slots;
    auto d = v.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!v.range(d.VirtualAddress, d.Size)) invalid();
    for (uint64_t p = d.VirtualAddress; p + sizeof(IMAGE_IMPORT_DESCRIPTOR) <=
         static_cast<uint64_t>(d.VirtualAddress) + d.Size; p += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        auto item = v.at<IMAGE_IMPORT_DESCRIPTOR>(p);
        if (!item.Name) break;
        if (!item.OriginalFirstThunk) continue;
        for (uint64_t i = 0; v.range(item.OriginalFirstThunk + i * 8, 8); ++i) {
            uint64_t name = v.at<uint64_t>(item.OriginalFirstThunk + i * 8);
            if (!name) break;
            if (!(name & IMAGE_ORDINAL_FLAG64) && name <= UINT32_MAX - 2 &&
                v.name(static_cast<uint32_t>(name + 2), "TlsGetValue")) {
                uint64_t slot = item.FirstThunk + i * 8;
                if (slot > UINT32_MAX || !v.range(slot, 8)) invalid();
                slots.insert(static_cast<uint32_t>(slot));
            }
        }
    }
    return slots;
}
bool tls_call(const View& v, uint32_t p, const std::set<uint32_t>& imports) {
    std::set<uint32_t> visited;
    bool first = true;
    while (visited.insert(p).second) {
        hde64s h{};
        if (!v.decode(p, h)) return false;
        if (h.opcode == 0xff && (h.modrm_reg == 2 || h.modrm_reg == 4) && rip(h))
            return imports.count(relative(v, p, h, displacement(h))) != 0;
        if (!(first && h.opcode == 0xe8) && h.opcode != 0xe9 && h.opcode != 0xeb) return false;
        first = false;
        p = relative(v, p, h, h.opcode == 0xeb ? static_cast<int8_t>(h.imm.imm8) : static_cast<int32_t>(h.imm.imm32));
    }
    return false;
}
void find_tls(const View& v, QqLayout& layout) {
    auto imports = tls_imports(v);
    std::set<uint32_t> found;
    for (const auto& f : v.functions()) {
        // 按函数内的指令边界扫描，避免从操作数或 REX 前缀中间开始匹配。
        for (uint32_t p = f.BeginAddress; p < f.EndAddress;) {
            hde64s load{};
            if (!v.decode(p, load) || load.len > f.EndAddress - p) break;
            uint32_t next = p + load.len;
            if (load.opcode != 0x8b || load.rex_w || load.p_66 ||
                load.modrm_reg != 1 || load.rex_r || !rip(load)) { p = next; continue; }
            uint32_t index = relative(v, p, load, displacement(load));
            hde64s call{};
            if (index % 4 == 0 && v.part(index, 4, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) &&
                v.decode(next, call) && call.len <= f.EndAddress - next && tls_call(v, next, imports)) {
                found.insert(index);
                layout.checks.push_back(v.check(p, load.len + call.len));
            }
            p = next;
        }
    }
    layout.tls_indices.assign(found.begin(), found.end());
}
} // namespace

QqImage QqImage::from_file(const wchar_t* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    auto length = file.tellg();
    if (!file || length <= 0) throw std::runtime_error("无法读取 QQ 输入法文件。");
    std::vector<unsigned char> raw(static_cast<size_t>(length));
    file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(raw.data()), length)) invalid();
    auto nt = headers(raw);
    auto parts = sections(raw);
    uint64_t mapped_end = nt.OptionalHeader.SizeOfHeaders;
    for (const auto& s : parts) {
        if (!fits(raw.size(), s.PointerToRawData, s.SizeOfRawData)) invalid();
        mapped_end = (std::max)(mapped_end, static_cast<uint64_t>(s.VirtualAddress) +
                               (std::max)(s.SizeOfRawData, s.Misc.VirtualSize));
    }
    // SizeOfImage 必须由实际节布局支持，防止损坏的头要求分配任意大小。
    if (!nt.OptionalHeader.SectionAlignment || mapped_end > nt.OptionalHeader.SizeOfImage ||
        nt.OptionalHeader.SizeOfImage - mapped_end >= nt.OptionalHeader.SectionAlignment ||
        !fits(raw.size(), 0, nt.OptionalHeader.SizeOfHeaders)) invalid();
    QqImage result;
    result.address_base = nt.OptionalHeader.ImageBase;
    result.bytes.resize(nt.OptionalHeader.SizeOfImage);
    memcpy(result.bytes.data(), raw.data(), nt.OptionalHeader.SizeOfHeaders);
    for (const auto& s : parts)
        if (s.SizeOfRawData) memcpy(result.bytes.data() + s.VirtualAddress,
                                   raw.data() + s.PointerToRawData, s.SizeOfRawData);
    return result;
}

QqImage QqImage::from_module(HMODULE module) {
    QqImage result;
    result.address_base = reinterpret_cast<uintptr_t>(module);
    IMAGE_DOS_HEADER dos{};
    SIZE_T count = 0;
    auto process = GetCurrentProcess();
    if (!ReadProcessMemory(process, module, &dos, sizeof(dos), &count) ||
        count != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) invalid();
    IMAGE_NT_HEADERS64 nt{};
    auto base = reinterpret_cast<const unsigned char*>(module);
    MEMORY_BASIC_INFORMATION memory{};
    if (!VirtualQuery(base + dos.e_lfanew, &memory, sizeof(memory)) || memory.AllocationBase != module ||
        !ReadProcessMemory(process, base + dos.e_lfanew, &nt, sizeof(nt), &count) || count != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) invalid();
    uint64_t allocation_end = 0;
    while (allocation_end < nt.OptionalHeader.SizeOfImage) {
        if (!VirtualQuery(base + allocation_end, &memory, sizeof(memory)) || memory.AllocationBase != module) invalid();
        allocation_end = reinterpret_cast<uintptr_t>(memory.BaseAddress) - result.address_base + memory.RegionSize;
    }
    result.bytes.resize(nt.OptionalHeader.SizeOfImage);
    for (size_t p = 0; p < result.bytes.size();) {
        if (!VirtualQuery(base + p, &memory, sizeof(memory))) invalid();
        size_t end = (std::min)(result.bytes.size(),
                               static_cast<size_t>(reinterpret_cast<uintptr_t>(memory.BaseAddress) - result.address_base + memory.RegionSize));
        if (end <= p) invalid();
        if (memory.State == MEM_COMMIT && !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            !ReadProcessMemory(process, base + p, result.bytes.data() + p, end - p, &count)) invalid();
        p = end;
    }
    return result;
}

QqLayout find_qq_layout(const QqImage& image) {
    View v(image);
    auto tables = find_tables(v);
    auto tests = flag_tests(v);
    std::vector<QqLayout> candidates;
    for (const auto& table : tables) {
        // COM 的三个 IUnknown 方法、Activate、Deactivate 后是 ActivateEx。
        if (!processor_interface(v, table) || !v.data(table.value.rva, 6 * sizeof(uint64_t))) continue;
        uint64_t method = v.at<uint64_t>(table.value.rva + 5 * sizeof(uint64_t));
        if (!v.pointer(method, 1) || !v.code(v.rva(method))) continue;
        auto stores = activation_stores(v, v.rva(method), table.value.object_offset);
        std::vector<std::pair<uint32_t, QqCheck>> matching;
        for (const auto& store : stores) if (tests.count(store.first)) matching.push_back(store);
        if (matching.size() != 1) continue;
        QqLayout layout;
        layout.flags_offset = matching[0].first;
        layout.checks.push_back(matching[0].second);
        layout.checks.insert(layout.checks.end(), tests.at(layout.flags_offset).begin(), tests.at(layout.flags_offset).end());
        std::map<uint32_t, uint32_t> offsets;
        bool unambiguous = true;
        for (const auto& item : tables) {
            if (item.type != table.type || item.hierarchy != table.hierarchy) continue;
            auto [it, inserted] = offsets.emplace(item.value.object_offset, item.value.rva);
            if ((!inserted && it->second != item.value.rva) || item.value.object_offset % sizeof(void*) ||
                item.value.object_offset + sizeof(void*) > layout.flags_offset) unambiguous = false;
        }
        if (!unambiguous || !offsets.count(0)) continue;
        for (const auto& [offset, rva] : offsets) layout.tables.push_back({offset, rva});
        find_tls(v, layout);
        if (!layout.tls_indices.empty()) candidates.push_back(std::move(layout));
    }
    if (candidates.size() != 1) throw std::runtime_error("无法唯一找到 QQ 拼音的候选框标志和线程状态。");
    return std::move(candidates.front());
}
