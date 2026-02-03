# GDB 基础使用指南

> **💡 静态 vs 动态分析**
> - **静态分析**（分析二进制结构）：优先使用 Ghidra MCP → radare2 → objdump（详见 [static_analysis.md](static_analysis.md)）
> - **动态分析**（运行时调试）：使用 GDB（本文档）
> - 两者结合使用效果最佳：先用静态分析找到目标，再用 GDB 验证

## GDB 是什么

GDB (GNU Debugger) 是最常用的 Linux 调试器，用于分析程序运行时行为、查找 bug、理解程序流程。

在 CTF 中，GDB 用于：
- 动态分析二进制
- 查看内存和寄存器状态
- 验证漏洞利用效果
- 找到关键地址（如缓冲区地址）

## 启动 GDB

```bash
# 调试程序
gdb ./program

# 调试带参数的程序
gdb --args ./program arg1 arg2

# 附加到运行中的进程
gdb -p <pid>

# 静默模式（不显示版权信息）
gdb -q ./program
```

## 基本命令

### 运行控制

```bash
(gdb) run                  # 运行程序
(gdb) run < input.txt      # 从文件读取输入
(gdb) start                # 运行并在 main 停止

(gdb) continue             # 继续执行（简写：c）
(gdb) step                 # 单步执行（进入函数）（简写：s）
(gdb) next                 # 单步执行（跳过函数）（简写：n）
(gdb) stepi                # 单步执行一条汇编（简写：si）
(gdb) nexti                # 单步执行一条汇编，跳过call（简写：ni）

(gdb) finish               # 执行到当前函数返回
(gdb) until <location>     # 执行到指定位置
```

### 断点

```bash
# 设置断点
(gdb) break main              # 在 main 函数设断点（简写：b）
(gdb) break *0x401234         # 在地址 0x401234 设断点
(gdb) break vuln.c:10         # 在文件 vuln.c 第10行设断点
(gdb) break func if i > 10    # 条件断点

# 查看断点
(gdb) info breakpoints        # 列出所有断点（简写：i b）

# 删除断点
(gdb) delete 1                # 删除编号为1的断点
(gdb) delete                  # 删除所有断点
(gdb) disable 1               # 暂时禁用断点1
(gdb) enable 1                # 启用断点1
```

### 查看信息

```bash
# 查看寄存器
(gdb) info registers          # 所有寄存器（简写：i r）
(gdb) info registers rax rbx  # 指定寄存器
(gdb) p/x $rax                # 打印 RAX（十六进制）

# 查看内存
(gdb) x/nfu <address>         # 查看内存
  # n = 数量
  # f = 格式（x=十六进制, d=十进制, s=字符串, i=指令）
  # u = 单位（b=字节, h=半字, w=字, g=8字节）

# 常用示例
(gdb) x/32wx $rsp             # 查看栈上32个字（十六进制）
(gdb) x/s 0x401234            # 查看字符串
(gdb) x/10i $rip              # 查看接下来10条指令
(gdb) x/gx $rbp+8             # 查看返回地址

# 查看变量
(gdb) print var               # 打印变量（简写：p）
(gdb) print &var              # 打印变量地址
(gdb) p/x var                 # 十六进制打印
(gdb) p sizeof(var)           # 变量大小

# 查看栈帧
(gdb) backtrace               # 查看调用栈（简写：bt）
(gdb) frame 0                 # 切换到栈帧0
(gdb) info frame              # 当前栈帧信息

# 查看代码
(gdb) list                    # 显示源代码（如果有）
(gdb) disassemble main        # 反汇编函数（简写：disas）
(gdb) disas /r main           # 反汇编并显示机器码
```

## CTF 常用技巧

### 1. 查找偏移量

```bash
# 使用 cyclic 模式
(gdb) run
# 输入 cyclic(100) 生成的模式
# 程序崩溃后查看崩溃地址
(gdb) info registers rip
# 假设 RIP = 0x6161616161616162
# 在 pwntools 中：cyclic_find(0x6161616161616162)
```

### 2. 查看栈布局

```bash
# 在函数入口设断点
(gdb) break vulnerable_func
(gdb) run

# 查看栈
(gdb) x/32gx $rsp             # 查看32个8字节
(gdb) x/32gx $rbp-64          # 从RBP往下64字节开始查看

# 找到缓冲区地址
(gdb) p/x &buf                # 打印 buf 地址
(gdb) x/s &buf                # 查看 buf 内容
```

### 3. 验证 Shellcode

```bash
# 在 shellcode 位置设断点
(gdb) break *0x7fffffffde00   # buf 地址

# 单步执行 shellcode
(gdb) si
(gdb) si
# 查看每一步的效果
(gdb) info registers
(gdb) x/10i $rip              # 查看接下来的指令
```

### 4. 追踪系统调用

```bash
# 捕获系统调用
(gdb) catch syscall           # 所有系统调用
(gdb) catch syscall execve    # 只捕获 execve

(gdb) continue
# 在系统调用前会停下
(gdb) info registers          # 查看参数
# RAX = 系统调用号
# RDI = 第一个参数
# ...
```

## pwndbg / peda / gef 扩展

这些是 GDB 的增强插件，提供更友好的界面和额外功能：

### pwndbg 常用命令

```bash
# 自动显示上下文
pwndbg> context               # 显示寄存器、代码、栈

# 搜索
pwndbg> search "/bin/sh"      # 搜索字符串
pwndbg> search -p 0x41414141  # 搜索模式

# ROP gadgets
pwndbg> rop --grep "pop rdi"  # 搜索 ROP gadgets

# 堆分析
pwndbg> heap                  # 查看堆状态
pwndbg> bins                  # 查看 bins

# 查看保护
pwndbg> checksec              # 查看二进制保护机制
```

## GDB 脚本

可以创建 GDB 脚本自动化调试：

```bash
# script.gdb
break main
run
x/32wx $rsp
continue
```

使用脚本：
```bash
gdb -x script.gdb ./program
```

## Python 集成（pwntools）

```python
from pwn import *

# 启动 GDB
p = gdb.debug('./vuln', '''
    break vulnerable_func
    continue
''')

# 或者附加到已存在的进程
p = process('./vuln')
gdb.attach(p, '''
    break *0x401234
    continue
''')
```

## 常见问题

### 符号剥离（Stripped Binary）

如果二进制没有符号，无法用函数名设断点：
```bash
# 错误
(gdb) break main             # "No symbol table"

# 正确：使用地址
(gdb) break *0x401234        # 从 Ghidra 获取地址
```

### ASLR 导致地址变化

```bash
# 临时关闭 ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# 或在 GDB 中
(gdb) set disable-randomization on
```

## 快速参考卡

| 任务 | 命令 |
|------|------|
| 运行程序 | `run` / `r` |
| 设断点 | `break *0x401234` / `b main` |
| 单步（汇编）| `stepi` / `si` |
| 继续执行 | `continue` / `c` |
| 查看寄存器 | `info registers` / `i r` |
| 查看栈 | `x/32gx $rsp` |
| 查看指令 | `x/10i $rip` |
| 查看字符串 | `x/s <addr>` |
| 反汇编 | `disassemble main` / `disas` |
| 打印变量 | `print var` / `p/x var` |
| 调用栈 | `backtrace` / `bt` |

## 总结

GDB 是 CTF 必备工具，重点掌握：
1. 设置断点和单步执行
2. 查看内存和寄存器
3. 验证漏洞利用效果
4. 动态获取运行时地址

多练习，熟能生巧！
