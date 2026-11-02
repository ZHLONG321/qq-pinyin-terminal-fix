"""修复候选框，或恢复 QQ 拼音原来的 64 位引擎。"""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path
import shutil
import struct
import sys
import uuid
import winreg

ROOT = Path(__file__).resolve().parent
WORK = ROOT / 'tmp' / (os.environ.get('CODEX_THREAD_ID') or uuid.uuid4().hex)
# 这段固定提示也在早期代理中，用来识别本工具自己的文件。
PROXY_MARKER = 'QQ terminal fix: cannot load QQPinyinOriginal.dll\n'.encode('utf-16le')


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_proxy(path: Path) -> bool:
    return path.is_file() and PROXY_MARKER in path.read_bytes()


def copy_access(source: Path, destination: Path) -> None:
    """让代理使用原引擎的访问权限，包括 Windows 应用包的读取权限。"""
    api = c.WinDLL('advapi32', use_last_error=True)
    api.GetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    api.GetFileSecurityW.restype = w.BOOL
    api.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
    api.GetSecurityDescriptorControl.restype = w.BOOL
    api.SetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p]
    api.SetFileSecurityW.restype = w.BOOL
    length = w.DWORD()
    api.GetFileSecurityW(str(source), 4, None, 0, c.byref(length))
    if not length.value:
        raise c.WinError(c.get_last_error())
    descriptor = c.create_string_buffer(length.value)
    if not api.GetFileSecurityW(str(source), 4, descriptor, length, c.byref(length)):
        raise c.WinError(c.get_last_error())
    control = w.WORD()
    revision = w.DWORD()
    if not api.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)):
        raise c.WinError(c.get_last_error())
    inheritance = 0x80000000 if control.value & 0x1000 else 0x20000000
    if not api.SetFileSecurityW(str(destination), 4 | inheritance, descriptor):
        raise c.WinError(c.get_last_error())


def locate() -> tuple[Path, Path, Path]:
    key = r'CLSID\{AE51F1C0-807F-4A64-AC55-F2ADF92E2603}\InprocServer32'
    with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
        value, kind = winreg.QueryValueEx(handle, '')
    if kind != winreg.REG_SZ or not isinstance(value, str):
        raise RuntimeError('QQ 拼音注册的组件路径格式不匹配。')
    tsf = Path(value).resolve(strict=True)
    if tsf.name.lower() != 'qqpinyintsf.dll':
        raise RuntimeError('注册的组件不是 QQPinyinTSF.dll。')
    engine = tsf.parent / 'QQPinyin.ime'
    original = tsf.parent / 'QQPinyinOriginal.dll'
    # 两个操作对象必须是注册组件目录中的直接子文件。
    for path in (engine, original):
        if path.is_symlink() or path.resolve().parent != tsf.parent:
            raise RuntimeError('输入法文件路径不是预期的直接子文件。')
    return tsf, engine, original


def apply_proxy(action: str) -> None:
    if os.name != 'nt' or c.sizeof(c.c_void_p) != 8:
        raise RuntimeError('请在 64 位 Windows 中运行这个工具。')
    tsf, engine, original = locate()
    engine_is_proxy = is_proxy(engine)
    original_available = original.is_file() and not is_proxy(original)
    print(f'QQ 拼音目录：{tsf.parent}', flush=True)
    if action == 'status':
        if engine_is_proxy and original_available:
            print('当前使用候选框修复代理。', flush=True)
        elif engine.is_file() and not engine_is_proxy and not original.exists():
            print('当前使用原来的 QQ 拼音引擎。', flush=True)
        else:
            print('无法分清当前输入法文件，请查看上面目录中的 QQPinyin.ime 和 QQPinyinOriginal.dll。', flush=True)
        return
    WORK.mkdir(parents=True, exist_ok=True)
    if action == 'fix':
        replacing_proxy = engine_is_proxy and original_available
        if not replacing_proxy and (not engine.is_file() or engine_is_proxy or original.exists()):
            raise RuntimeError('输入法文件不完整，或原文件备份的名字已被占用，请先查看 QQ 拼音目录。')
        artifact = ROOT / 'dist/x64/QQPinyin.ime'
        if not artifact.is_file():
            raise RuntimeError('找不到编译好的代理，请先运行 uv run build.py。')
        if not is_proxy(artifact):
            raise RuntimeError('编译目录中的文件不是本工具的代理，请重新运行 uv run build.py。')
        proxy_hash = digest(artifact)
        engine_hash = digest(engine)
        if replacing_proxy and engine_hash == proxy_hash:
            copy_access(original, engine)
            print('修复文件已经放好。关掉所有 Terminal 窗口再打开即可。', flush=True)
            return
        data = artifact.read_bytes()
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        if data[:2] != b'MZ' or struct.unpack_from('<H', data, pe + 4)[0] != 0x8664:
            raise RuntimeError('代理文件不是 64 位 Windows DLL。')
        backup = WORK / f'QQPinyin-before-proxy-{engine_hash}.ime'
        if backup.exists() and digest(backup) != engine_hash:
            raise RuntimeError('项目中的原文件备份与预期不符。')
        if not backup.exists():
            shutil.copyfile(engine, backup)
        if digest(backup) != engine_hash:
            raise RuntimeError('原文件备份没有正确保存。')
        staging = WORK / f'QQPinyin-proxy-staged-{proxy_hash}.ime'
        if staging.exists():
            if digest(staging) != proxy_hash:
                raise RuntimeError('已有不同的暂存文件，请先查看上次安装结果。')
        else:
            with staging.open('xb') as output:
                output.write(data)
                output.flush()
        if digest(staging) != proxy_hash:
            raise RuntimeError('代理暂存文件没有正确保存。')
        # 原引擎在原目录保留；更新时另存旧代理，出错就放回。
        previous = WORK / f'QQPinyin-proxy-replaced-{uuid.uuid4().hex}.ime' if replacing_proxy else original
        if replacing_proxy:
            shutil.move(str(engine), str(previous))
        else:
            engine.rename(previous)
        try:
            shutil.move(str(staging), str(engine))
            copy_access(original, engine)
        except OSError:
            if engine.exists():
                shutil.move(str(engine), str(WORK / f'QQPinyin-proxy-failed-{uuid.uuid4().hex}.ime'))
            shutil.move(str(previous), str(engine))
            raise
        print('修复文件已放好。关掉所有 Terminal 窗口再打开即可，也可以重启电脑。', flush=True)
    else:
        if engine.is_file() and not engine_is_proxy and not original.exists():
            print('当前使用原来的引擎。', flush=True)
            return
        if not original_available or (engine.exists() and not engine_is_proxy):
            raise RuntimeError('找不到可恢复的原文件，或当前输入法文件不是本工具的代理。')
        saved = WORK / f'QQPinyin-proxy-restored-{uuid.uuid4().hex}.ime'
        moved = engine.exists()
        if moved:
            shutil.move(str(engine), str(saved))
        try:
            original.rename(engine)
        except OSError:
            if moved:
                shutil.move(str(saved), str(engine))
            raise
        print('原来的 QQ 拼音引擎已放回。关掉所有 Terminal 窗口再打开即可。', flush=True)


def run(action: str) -> int:
    result = 0
    try:
        apply_proxy(action)
    except PermissionError as error:
        print(f'文件访问被拒绝：{error}\n请用管理员权限打开终端，再运行同一条命令。', file=sys.stderr, flush=True)
        result = 1
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(str(error), file=sys.stderr, flush=True)
        result = 1
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'fix', 'restore'))
    raise SystemExit(run(parser.parse_args().action))
