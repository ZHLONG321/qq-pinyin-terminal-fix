#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include "qq_layout.h"
#include <exception>
#include <utility>

// 原引擎通过完整路径加载；所有初始化都发生在导出函数被调用时。
static HMODULE self_module;
static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
static FARPROC exports[18];
static unsigned char* tsf_base;
static QqLayout* layout;
static constexpr const char* names[] = {
    "ImeFreeEnv", "ImeGetEnv", "ImeSetCompositionString", "ImeConfigure",
    "ImeConversionList", "ImeDestroy", "ImeEnumRegisterWord", "ImeEscape",
    "ImeExtension", "ImeGetRegisterWordStyle", "ImeInquire", "ImeProcessKey",
    "ImeRegisterWord", "ImeSelect", "ImeSetActiveContext", "ImeToAsciiEx",
    "ImeUnregisterWord", "NotifyIME"
};

static BOOL CALLBACK initialize(PINIT_ONCE, PVOID, PVOID*) {
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(self_module, path, ARRAYSIZE(path));
    if (!length || length >= ARRAYSIZE(path)) return FALSE;
    wchar_t* name = wcsrchr(path, L'\\');
    if (!name || wcscpy_s(name + 1, ARRAYSIZE(path) - (name + 1 - path), L"QQPinyinOriginal.dll")) return FALSE;
    HMODULE engine = LoadLibraryW(path);
    if (!engine) {
        OutputDebugStringW(L"QQ terminal fix: cannot load QQPinyinOriginal.dll\n");
        return FALSE;
    }
    // 导出地址交给调用者后，原引擎需要保留到进程退出。
    bool complete = true;
    for (size_t i = 0; i < ARRAYSIZE(names); ++i) {
        exports[i] = GetProcAddress(engine, names[i]);
        if (!exports[i]) complete = false;
    }
    if (!complete) {
        OutputDebugStringW(L"QQ terminal fix: original engine exports do not match\n");
        // 此时尚未公开任何地址，可以正常释放本次加载的引用。
        FreeLibrary(engine);
        ZeroMemory(exports, sizeof(exports));
        return FALSE;
    }
    length = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    if (!length || length >= ARRAYSIZE(path)) return TRUE;
    name = wcsrchr(path, L'\\');
    if (!name || _wcsicmp(name + 1, L"WindowsTerminal.exe")) return TRUE;
    HMODULE tsf = GetModuleHandleW(L"QQPinyinTSF.dll");
    if (tsf) {
        try {
            auto found = find_qq_layout(QqImage::from_module(tsf));
            layout = new QqLayout(std::move(found));
            tsf_base = reinterpret_cast<unsigned char*>(tsf);
        } catch (const std::exception&) {
            OutputDebugStringW(L"QQ terminal fix: cannot identify TSF layout; forwarding without applying fix\n");
        }
    }
    return TRUE;
}

static unsigned char* current_service(DWORD index) {
    // 每个候选线程索引都要由整组接口表确认，不能凭非空指针判断。
    __try {
        auto service = static_cast<unsigned char*>(TlsGetValue(index));
        if (!service || reinterpret_cast<uintptr_t>(service) % alignof(void*)) return nullptr;
        auto table = *reinterpret_cast<void**>(service);
        for (const auto& candidate : layout->tables) {
            if (table != tsf_base + candidate.rva) continue;
            auto object = service - candidate.object_offset;
            bool valid = true;
            for (const auto& expected : layout->tables)
                if (*reinterpret_cast<void**>(object + expected.object_offset) != tsf_base + expected.rva) valid = false;
            if (valid) return object;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return nullptr;
}

static void fix_current_thread() {
    if (!tsf_base || !layout) return;
    __try {
        unsigned char* service = nullptr;
        for (auto rva : layout->tls_indices) {
            DWORD index = *reinterpret_cast<DWORD*>(tsf_base + rva);
            auto candidate = current_service(index);
            if (!candidate) continue;
            if (service && service != candidate) return;
            service = candidate;
        }
        if (!service) return;
        auto flags = reinterpret_cast<volatile LONG*>(service + layout->flags_offset);
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQuery(const_cast<LONG*>(flags), &memory, sizeof(memory))) return;
        if (memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return;
        DWORD protection = memory.Protect & 0xff;
        if (protection != PAGE_READWRITE && protection != PAGE_WRITECOPY &&
            protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY) return;
        if ((*flags & 0x40) != 0) {
            InterlockedAnd(flags, ~0x40L);
            OutputDebugStringW(L"QQ terminal fix: candidate window suppression cleared\n");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"QQ terminal fix: current QQ object is unavailable\n");
    }
}

static uintptr_t WINAPI unavailable() { SetLastError(ERROR_PROC_NOT_FOUND); return 0; }

extern "C" FARPROC ResolveImeExport(unsigned index) {
    DWORD saved_error = GetLastError();
    FARPROC result = reinterpret_cast<FARPROC>(&unavailable);
    if (index < ARRAYSIZE(exports) && InitOnceExecuteOnce(&once, initialize, nullptr, nullptr)) {
        fix_current_thread();
        result = exports[index];
    }
    SetLastError(saved_error);
    return result;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) self_module = instance;
    return TRUE;
}
