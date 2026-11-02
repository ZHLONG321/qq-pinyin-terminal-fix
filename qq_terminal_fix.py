"""解除当前 Terminal 进程内 QQ 拼音对候选框通知的屏蔽。"""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from typing import TypedDict, cast


SESSION = os.environ.get('CODEX_THREAD_ID') or 'manual-memory-fix'
CONSOLE = 0x40


class ObjectTable(TypedDict):
    object_offset: int
    rva: int


class InstructionCheck(TypedDict):
    rva: int
    bytes: str


class Layout(TypedDict):
    flags_offset: int
    tls_indices: list[int]
    tables: list[ObjectTable]
    checks: list[InstructionCheck]


class TEB(c.Structure):
    # 字段次序来自本机 Windows SDK 的 winternl.h。
    _fields_ = [('Reserved1', c.c_void_p * 12), ('ProcessEnvironmentBlock', c.c_void_p),
                ('Reserved2', c.c_void_p * 399), ('Reserved3', c.c_ubyte * 1952),
                ('TlsSlots', c.c_void_p * 64), ('Reserved4', c.c_ubyte * 8),
                ('Reserved5', c.c_void_p * 26), ('ReservedForOle', c.c_void_p),
                ('Reserved6', c.c_void_p * 4), ('TlsExpansionSlots', c.c_void_p)]


class THREAD_BASIC_INFORMATION(c.Structure):
    _fields_ = [('ExitStatus', c.c_long), ('TebBaseAddress', c.c_void_p),
                ('ProcessId', c.c_void_p), ('ThreadId', c.c_void_p),
                ('AffinityMask', c.c_size_t), ('Priority', c.c_long), ('BasePriority', c.c_long)]


class Target:
    def __init__(self, pid, tid, writable):
        self.pid = pid
        self.tid = tid
        self.layout_cache: tuple[str, Layout] | None = None
        self.k = c.WinDLL('kernel32', use_last_error=True)
        self.p = c.WinDLL('psapi', use_last_error=True)
        self.n = c.WinDLL('ntdll', use_last_error=True)
        self.k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.k.OpenProcess.restype = w.HANDLE
        self.k.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.k.OpenThread.restype = w.HANDLE
        self.k.CloseHandle.argtypes = [w.HANDLE]
        self.k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
        self.k.GetProcessTimes.argtypes = [w.HANDLE, c.POINTER(w.FILETIME), c.POINTER(w.FILETIME), c.POINTER(w.FILETIME), c.POINTER(w.FILETIME)]
        self.k.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
        self.k.WriteProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
        self.p.EnumProcessModulesEx.argtypes = [w.HANDLE, c.POINTER(w.HMODULE), w.DWORD, c.POINTER(w.DWORD), w.DWORD]
        self.p.GetModuleFileNameExW.argtypes = [w.HANDLE, w.HMODULE, w.LPWSTR, w.DWORD]
        self.n.NtQueryInformationThread.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)]
        self.n.NtQueryInformationThread.restype = c.c_long
        self.process = self.k.OpenProcess(0x410 | (0x28 if writable else 0), False, pid)
        if not self.process:
            raise c.WinError(c.get_last_error())

    def close(self):
        self.k.CloseHandle(self.process)

    def read(self, address, size):
        buffer = c.create_string_buffer(size)
        count = c.c_size_t()
        if not self.k.ReadProcessMemory(self.process, address, buffer, size, c.byref(count)) or count.value != size:
            raise c.WinError(c.get_last_error())
        return buffer.raw

    def pointer(self, address):
        return struct.unpack('<Q', self.read(address, 8))[0]

    def layout_for(self, path: Path, fingerprint: str) -> Layout:
        if self.layout_cache is not None and self.layout_cache[0] == fingerprint:
            return self.layout_cache[1]
        scanner = Path(__file__).resolve().parent / 'dist/x64/qq_layout.exe'
        if not scanner.is_file():
            raise RuntimeError('找不到自动查找工具，请先运行 uv run build.py。')
        result = subprocess.run([str(scanner), str(path)], capture_output=True, encoding='utf-8')
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or '无法找到 QQ 拼音的候选框控制位置。')
        layout = cast(Layout, json.loads(result.stdout))
        self.layout_cache = fingerprint, layout
        return layout

    def resolve(self):
        image = c.create_unicode_buffer(32768)
        length = w.DWORD(len(image))
        if not self.k.QueryFullProcessImageNameW(self.process, 0, image, c.byref(length)):
            raise c.WinError(c.get_last_error())
        if Path(image.value).name.lower() != 'windowsterminal.exe':
            raise RuntimeError('指定进程不是 Windows Terminal。')
        times = [w.FILETIME() for _ in range(4)]
        if not self.k.GetProcessTimes(self.process, *(c.byref(value) for value in times)):
            raise c.WinError(c.get_last_error())
        birth = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        modules = (w.HMODULE * 2048)()
        needed = w.DWORD()
        if not self.p.EnumProcessModulesEx(self.process, modules, c.sizeof(modules), c.byref(needed), 3):
            raise c.WinError(c.get_last_error())
        if needed.value > c.sizeof(modules):
            raise RuntimeError('模块列表没有读全。')
        module_base = None
        module_digest = ''
        layout: Layout | None = None
        for module in modules[:needed.value // c.sizeof(w.HMODULE)]:
            path = c.create_unicode_buffer(32768)
            if not self.p.GetModuleFileNameExW(self.process, module, path, len(path)):
                raise c.WinError(c.get_last_error())
            if Path(path.value).name.lower() == 'qqpinyintsf.dll':
                data = Path(path.value).read_bytes()
                module_digest = hashlib.sha256(data).hexdigest()
                pe = struct.unpack_from('<I', data, 0x3c)[0]
                if struct.unpack_from('<H', data, pe + 4)[0] != 0x8664:
                    raise RuntimeError('请使用 64 位 QQ 拼音组件。')
                module_base = module
                layout = self.layout_for(Path(path.value), module_digest)
                break
        if module_base is None or layout is None:
            raise RuntimeError('这个进程还没有加载 QQ 拼音。先在目标窗口选中 QQ 拼音。')
        # 用本次扫描找到的指令核对正在运行的模块，防止磁盘文件已更新。
        for check in layout['checks']:
            instruction = bytes.fromhex(check['bytes'])
            if self.read(module_base + check['rva'], len(instruction)) != instruction:
                raise RuntimeError('正在运行的 QQ 拼音与磁盘文件不同，请重新打开 Terminal。')
        thread = self.k.OpenThread(0x40, False, self.tid)
        if not thread:
            raise c.WinError(c.get_last_error())
        try:
            info = THREAD_BASIC_INFORMATION()
            status = self.n.NtQueryInformationThread(thread, 0, c.byref(info), c.sizeof(info), None)
            if status < 0 or info.ProcessId != self.pid or info.ThreadId != self.tid:
                raise RuntimeError('线程不属于指定的 Terminal 进程，或线程状态无法读取。')
        finally:
            self.k.CloseHandle(thread)
        found: set[int] = set()
        for index_rva in layout['tls_indices']:
            index = struct.unpack('<I', self.read(module_base + index_rva, 4))[0]
            if index < 64:
                slot = info.TebBaseAddress + TEB.TlsSlots.offset + index * 8
            else:
                expansion = self.pointer(info.TebBaseAddress + TEB.TlsExpansionSlots.offset)
                if not expansion:
                    continue
                slot = expansion + (index - 64) * 8
            try:
                pointer = self.pointer(slot)
                if not pointer or pointer % 8:
                    continue
                table_pointer = self.pointer(pointer)
                for table in layout['tables']:
                    if table_pointer != module_base + table['rva']:
                        continue
                    candidate = pointer - table['object_offset']
                    if all(self.pointer(candidate + other['object_offset']) == module_base + other['rva']
                           for other in layout['tables']):
                        found.add(candidate)
            except OSError:
                continue
        if len(found) != 1:
            raise RuntimeError('无法在目标线程中唯一找到 QQ 拼音对象，请先在目标窗口选中 QQ 拼音。')
        service = found.pop()
        flags_offset = layout['flags_offset']
        flags = struct.unpack('<I', self.read(service + flags_offset, 4))[0]
        return {'pid': self.pid, 'tid': self.tid, 'process_created': birth,
                'module_base': module_base, 'module_sha256': module_digest, 'service': service,
                'flags_address': service + flags_offset, 'flags': flags}

    def write_flags(self, state, expected, replacement):
        current = self.resolve()
        if any(current[key] != state[key] for key in ['process_created', 'module_base', 'service', 'flags_address']):
            raise RuntimeError('操作前 QQ 拼音对象发生变化，请重新读取。')
        if current['flags'] != expected:
            raise RuntimeError('操作前输入法状态发生变化，请重新读取。')
        value = w.DWORD(replacement)
        count = c.c_size_t()
        ok = self.k.WriteProcessMemory(self.process, state['flags_address'], c.byref(value), c.sizeof(value), c.byref(count))
        written = struct.unpack('<I', self.read(state['flags_address'], 4))[0]
        if not ok or count.value != 4 or written != replacement:
            raise RuntimeError(f'写入未得到预期结果；当前值为 {written:#x}，原值为 {expected:#x}。恢复记录已保留。')


def ui_thread(pid):
    user = c.WinDLL('user32', use_last_error=True)
    callback_type = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    user.EnumWindows.argtypes = [callback_type, w.LPARAM]
    user.EnumWindows.restype = w.BOOL
    user.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, c.c_int]
    user.GetWindowThreadProcessId.argtypes = [w.HWND, c.POINTER(w.DWORD)]
    found = set()
    @callback_type
    def collect(hwnd, _):
        owner = w.DWORD()
        tid = user.GetWindowThreadProcessId(hwnd, c.byref(owner))
        name = c.create_unicode_buffer(256)
        user.GetClassNameW(hwnd, name, len(name))
        if owner.value == pid and name.value == 'CASCADIA_HOSTING_WINDOW_CLASS':
            found.add(tid)
        return True
    if not user.EnumWindows(collect, 0):
        raise c.WinError(c.get_last_error())
    if len(found) != 1:
        raise RuntimeError('无法唯一确定窗口线程，请使用 --tid 指定目标线程。')
    return found.pop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'apply', 'restore'])
    parser.add_argument('--pid', type=int, required=True, help='目标 Windows Terminal 进程号')
    parser.add_argument('--tid', type=int, help='目标窗口线程号；单线程窗口自动读取')
    args = parser.parse_args()
    if c.sizeof(c.c_void_p) != 8:
        raise RuntimeError('请使用 64 位 Python。')
    target = Target(args.pid, args.tid or ui_thread(args.pid), args.action != 'status')
    try:
        state = target.resolve()
        flags = cast(int, state['flags'])
        print(json.dumps({**state, 'console_ui_blocked': bool(flags & CONSOLE)}, ensure_ascii=False, indent=2), flush=True)
        if args.action == 'status':
            return
        records = Path(__file__).parent / 'tmp' / SESSION
        record = records / f"restore-{state['pid']}-{state['tid']}-{state['process_created']}-{state['service']}.json"
        if args.action == 'restore' and not record.exists():
            previous = list(records.parent.glob('*/' + record.name))
            if len(previous) != 1:
                raise RuntimeError('没有找到唯一匹配当前输入法对象的恢复记录。')
            record = previous[0]
        if args.action == 'apply':
            if not flags & CONSOLE:
                print('QQ 拼音当前没有因控制台标志屏蔽候选框。', flush=True)
                return
            saved = {**state, 'original': flags, 'patched': flags & ~CONSOLE}
            records.mkdir(parents=True, exist_ok=True)
            if record.exists():
                if json.loads(record.read_text(encoding='utf-8')) != saved:
                    raise RuntimeError('现有恢复记录与当前对象不一致。')
            else:
                with record.open('x', encoding='utf-8') as file:
                    json.dump(saved, file, ensure_ascii=False, indent=2)
                    file.flush()
                    os.fsync(file.fileno())
            print(f'恢复命令：uv run --offline --no-project python qq_terminal_fix.py restore --pid {state["pid"]} --tid {state["tid"]}', flush=True)
            target.write_flags(state, saved['original'], saved['patched'])
            print('已解除当前 QQ 拼音对象对候选框通知的屏蔽。回到 Terminal，重新开始输入拼音。', flush=True)
        else:
            saved = json.loads(record.read_text(encoding='utf-8'))
            keys = ['pid', 'tid', 'process_created', 'module_base', 'module_sha256', 'service', 'flags_address']
            if any(saved[key] != state[key] for key in keys) or saved['original'] & ~CONSOLE != saved['patched']:
                raise RuntimeError('恢复记录不属于当前输入法对象。')
            if state['flags'] == saved['original']:
                print('QQ 拼音已经是记录中的原始状态。', flush=True)
                return
            target.write_flags(state, saved['patched'], saved['original'])
            print('已恢复原始状态。', flush=True)
    finally:
        target.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
