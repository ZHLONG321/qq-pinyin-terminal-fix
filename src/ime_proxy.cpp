#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cwchar>

// 原引擎通过完整路径加载；所有初始化都发生在导出函数被调用时。
static HMODULE self_module;
static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
static FARPROC exports[18];
static unsigned char* tsf_base;
static constexpr const char* names[] = {
    "ImeFreeEnv", "ImeGetEnv", "ImeSetCompositionString", "ImeConfigure",
    "ImeConversionList", "ImeDestroy", "ImeEnumRegisterWord", "ImeEscape",
    "ImeExtension", "ImeGetRegisterWordStyle", "ImeInquire", "ImeProcessKey",
    "ImeRegisterWord", "ImeSelect", "ImeSetActiveContext", "ImeToAsciiEx",
    "ImeUnregisterWord", "NotifyIME"
};

static bool matches_layout(HMODULE module) {
    // 检查实际判断标志的指令，而不是按整个文件的校验值限定版本。
    // test byte ptr [rbx+0x3b9c], 0x40；0x3b9c 即保存标志的位置。
    __try {
        auto base = reinterpret_cast<unsigned char*>(module);
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt->OptionalHeader.SizeOfImage < 0x2a340) return false;
        constexpr unsigned char instruction[] = {0xf6, 0x83, 0x9c, 0x3b, 0, 0, 0x40};
        constexpr uintptr_t sites[] = {0x5b5c, 0xa327, 0xa4ad, 0xafbd};
        for (auto site : sites)
            if (memcmp(base + site, instruction, sizeof(instruction))) return false;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

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
    if (tsf && matches_layout(tsf)) {
        tsf_base = reinterpret_cast<unsigned char*>(tsf);
    } else {
        OutputDebugStringW(L"QQ terminal fix: TSF layout differs; forwarding without applying fix\n");
    }
    return TRUE;
}

static void fix_current_thread() {
    if (!tsf_base) return;
    // TlsGetValue 读取当前调用线程，与 TSF 保存对象时使用的线程一致。
    __try {
        DWORD index = *reinterpret_cast<DWORD*>(tsf_base + 0x2a33c);
        auto service = static_cast<unsigned char*>(TlsGetValue(index));
        if (!service || reinterpret_cast<uintptr_t>(service) % alignof(void*)) return;
        if (*reinterpret_cast<void**>(service) != tsf_base + 0x21cc8) return;
        constexpr uintptr_t expected[] = {
            0x21c40, 0x21c70, 0x21ca0, 0x21cc8, 0x21d00,
            0x21d30, 0x21d68, 0x21db8, 0x21de0, 0x21e10
        };
        unsigned seen = 0;
        for (size_t i = 0; i < ARRAYSIZE(expected); ++i) {
            auto table = reinterpret_cast<uintptr_t*>(service)[i];
            unsigned match = 0;
            for (size_t j = 0; j < ARRAYSIZE(expected); ++j)
                if (table == reinterpret_cast<uintptr_t>(tsf_base) + expected[j]) match = 1u << j;
            if (!match || (seen & match)) return;
            seen |= match;
        }
        auto flags = reinterpret_cast<volatile LONG*>(service + 15260);
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
