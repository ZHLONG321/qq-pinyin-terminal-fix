"""从源码构建 64 位 QQ 拼音代理和查找工具。"""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import winreg


ROOT = Path(__file__).resolve().parent


def find_toolchain() -> tuple[Path, Path, str]:
    """通过 Visual Studio 安装信息和 Windows SDK 注册项寻找编译工具。"""
    locator = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    if not locator.is_file():
        raise RuntimeError('找不到 Visual Studio 构建工具，请安装“使用 C++ 的桌面开发”。')
    installation = subprocess.check_output(
        [str(locator), '-utf8', '-latest', '-products', '*', '-requires',
         'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
        encoding='utf-8',
    ).strip()
    if not installation:
        raise RuntimeError('找不到 MSVC x64 工具，请在 Visual Studio Installer 中添加 C++ 构建工具。')
    studio = Path(installation)
    version = (studio / 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt').read_text(encoding='utf-8-sig').strip()
    msvc = studio / 'VC/Tools/MSVC' / version
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows Kits\Installed Roots') as key:
        sdk_path, _ = winreg.QueryValueEx(key, 'KitsRoot10')
    if not isinstance(sdk_path, str):
        raise RuntimeError('Windows SDK 注册路径格式不正确。')
    sdk = Path(sdk_path)
    versions = [p.name for p in (sdk / 'Include').iterdir()
                if p.is_dir() and p.name.startswith('10.') and all(
                    (sdk / part / p.name / leaf).is_dir()
                    for part, leaf in (('Include', 'ucrt'), ('Include', 'shared'), ('Include', 'um'),
                                       ('Lib', 'ucrt/x64'), ('Lib', 'um/x64')))]
    if not versions:
        raise RuntimeError('找不到完整的 Windows 10/11 SDK，请通过 Visual Studio Installer 添加。')
    sdk_version = max(versions, key=lambda name: tuple(map(int, name.split('.'))))
    if not all((msvc / 'bin/Hostx64/x64' / name).is_file() for name in ('cl.exe', 'ml64.exe', 'link.exe')):
        raise RuntimeError('MSVC 缺少 x64 编译器、汇编器或链接器。')
    return msvc, sdk, sdk_version


def main() -> None:
    if os.name != 'nt' or sys.maxsize <= 2**32:
        raise RuntimeError('请使用 64 位 Windows 和 64 位 Python。')
    print('寻找 MSVC 和 Windows SDK…', flush=True)
    msvc, sdk, sdk_version = find_toolchain()
    work = ROOT / 'tmp' / (os.environ.get('CODEX_THREAD_ID') or uuid.uuid4().hex) / 'build'
    work.mkdir(parents=True, exist_ok=True)
    tools = msvc / 'bin/Hostx64/x64'
    environment = dict(os.environ)
    environment['PATH'] = str(tools) + os.pathsep + environment.get('PATH', '')
    environment['INCLUDE'] = os.pathsep.join(map(str, [msvc / 'include', *[
        sdk / 'Include' / sdk_version / name for name in ('ucrt', 'shared', 'um')]]))
    environment['LIB'] = os.pathsep.join(map(str, [msvc / 'lib/x64', *[
        sdk / 'Lib' / sdk_version / name for name in ('ucrt/x64', 'um/x64')]]))
    staged = work / 'QQPinyin.ime'
    commands = [
        [str(tools / 'cl.exe'), '/nologo', '/utf-8', '/W3', '/O2', '/MT', '/c',
         '/Fo' + str(work / 'hde64.obj'), str(ROOT / 'third_party/hde64/hde64.c')],
        [str(tools / 'cl.exe'), '/nologo', '/utf-8', '/std:c++17', '/W4', '/WX', '/O2', '/MT', '/EHsc', '/c',
         '/Fo' + str(work / 'qq_layout.obj'), str(ROOT / 'src/qq_layout.cpp')],
        [str(tools / 'ml64.exe'), '/nologo', '/c', '/Fo' + str(work / 'ime_proxy_asm.obj'), str(ROOT / 'src/ime_proxy.asm')],
        [str(tools / 'cl.exe'), '/nologo', '/utf-8', '/std:c++17', '/W4', '/WX', '/O2', '/MT', '/EHsc', '/LD',
         '/Fo' + str(work / 'ime_proxy.obj'), '/Fd' + str(work / 'ime_proxy.pdb'),
         str(ROOT / 'src/ime_proxy.cpp'), str(work / 'ime_proxy_asm.obj'), str(work / 'qq_layout.obj'), str(work / 'hde64.obj'),
         '/link', '/DEF:' + str(ROOT / 'src/ime_proxy.def'), '/OUT:' + str(staged),
         '/IMPLIB:' + str(work / 'ime_proxy.lib'), '/Brepro', '/DYNAMICBASE', '/NXCOMPAT'],
        [str(tools / 'cl.exe'), '/nologo', '/utf-8', '/std:c++17', '/W4', '/WX', '/O2', '/MT', '/EHsc',
         '/Fo' + str(work / 'layout_tool.obj'), '/Fe' + str(work / 'qq_layout.exe'),
         str(ROOT / 'src/layout_tool.cpp'), str(work / 'qq_layout.obj'), str(work / 'hde64.obj'),
         '/link', '/Brepro', '/DYNAMICBASE', '/NXCOMPAT'],
    ]
    print(f'MSVC {msvc.name}，Windows SDK {sdk_version}', flush=True)
    for command in commands:
        print(f'运行 {Path(command[0]).name}…', flush=True)
        subprocess.run(command, env=environment, cwd=work, check=True)
    output = ROOT / 'dist/x64/QQPinyin.ime'
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(staged, output)
    shutil.copyfile(work / 'qq_layout.exe', output.parent / 'qq_layout.exe')
    shutil.copyfile(ROOT / 'third_party/hde64/LICENSE.txt', output.parent / 'HDE64-LICENSE.txt')
    print(f'构建完成：{output.relative_to(ROOT)}', flush=True)
    print(f'SHA-256：{hashlib.sha256(output.read_bytes()).hexdigest()}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f'构建失败：{error}', file=sys.stderr, flush=True)
        raise SystemExit(1)
