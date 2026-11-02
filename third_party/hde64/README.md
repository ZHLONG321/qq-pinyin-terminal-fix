# HDE64 指令解析器

来自 [MinHook v1.3.4](https://github.com/TsudaKageyu/minhook/tree/v1.3.4/src/hde)，作者为 Vyacheslav Patkov。许可证见 [LICENSE.txt](LICENSE.txt)。

本项目使用它读取 x64 指令的长度、寄存器、地址和偏移。没有引入 MinHook 的挂钩功能。

`hde64.h` 中的 `pstdint.h` 改为编译器自带的 `stdint.h`，其余源码保持上游内容。
