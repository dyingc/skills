# 栈溢出（Stack Overflow）

## 基本概念

栈溢出是最常见的二进制漏洞之一，发生在程序向固定大小的栈缓冲区写入超过其容量的数据时。

## 栈的内存布局

在 x86-64 架构中，栈的典型布局（从低地址到高地址）：

```
高地址 (0x7fff...)
    ↑
    | 函数参数（如果超过6个）
    | ...
    |─────────────────
    | 返回地址 (8字节)    ← 函数返回时跳转到这里
    |─────────────────
    | saved RBP (8字节)  ← 调用者的栈帧基址
    |─────────────────
    | 局部变量 n
    | ...
    | 局部变量 2
    | 局部变量 1
    | buf[63]
    | buf[62]
    | ...
    | buf[1]
    | buf[0]           ← RSP (栈顶指针)
    ↓
低地址

注意：栈向低地址增长！
```

## 漏洞原理

当使用不安全的函数（如 `gets()`, `strcpy()`, `sprintf()` 等）向缓冲区写入数据时，如果没有检查长度，就可能写入超过缓冲区大小的数据：

```c
void vulnerable_function() {
    char buf[64];
    gets(buf);  // 危险！没有长度检查
    // ...
}
```

如果输入超过 64 字节，超出的部分会覆盖：
1. 其他局部变量
2. Saved RBP
3. 返回地址 ← **关键！控制程序流程**

## 利用方式

### 基础利用：覆盖返回地址

1. **确定偏移量**：从缓冲区起始到返回地址的距离
   ```python
   # 使用 cyclic 模式
   from pwn import *
   payload = cyclic(100)
   # 程序崩溃后，查看崩溃地址
   # cyclic_find(崩溃地址) 得到偏移量
   ```

2. **构造 payload**：
   ```python
   offset = 72  # 假设偏移量是72
   target = 0x401234  # 要跳转到的地址
   payload = b'A' * offset + p64(target)
   ```

3. **发送 payload**：
   ```python
   from pwn import *
   p = process('./vuln')
   p.sendline(payload)
   p.interactive()
   ```

## 常见危险函数

| 函数 | 危险原因 | 安全替代 |
|------|---------|---------|
| `gets()` | 无长度限制 | `fgets()` |
| `strcpy()` | 不检查目标缓冲区大小 | `strncpy()`, `strlcpy()` |
| `sprintf()` | 可能溢出 | `snprintf()` |
| `scanf("%s")` | 无长度限制 | `scanf("%63s")` 限制长度 |

## 调试技巧

### 用 GDB 查看栈布局

```bash
# 在 vulnerable_function 入口设断点
gdb ./vuln
(gdb) break vulnerable_function
(gdb) run

# 查看栈内容
(gdb) x/32wx $rsp    # 查看栈上32个word（十六进制）
(gdb) x/32gx $rsp    # 查看栈上32个8字节（十六进制）

# 查看寄存器
(gdb) info registers
(gdb) p/x $rbp       # 查看RBP
(gdb) p/x $rsp       # 查看RSP
```

### 确认溢出效果

```bash
# 输入大量'A'后，查看返回地址
(gdb) x/gx $rbp+8    # 返回地址在 saved RBP 之后

# 单步到函数返回
(gdb) finish

# 如果返回地址被覆盖，会看到类似：
# Cannot access memory at address 0x4141414141414141
```

## 保护机制

现代系统有多种保护机制防止栈溢出利用：

- **Stack Canary（栈金丝雀）**：在返回地址前放置随机值，返回前检查
- **NX/DEP（不可执行栈）**：标记栈为不可执行
- **ASLR/PIE（地址随机化）**：每次运行时栈地址随机

这些保护机制需要不同的绕过技术（后续会学习）。

## 总结

栈溢出利用的核心思路：
1. 找到可以溢出的缓冲区
2. 计算偏移量（到返回地址的距离）
3. 覆盖返回地址为目标地址
4. 触发函数返回，劫持控制流

这是最基础的利用技术，后续的 ROP、shellcode 注入等都建立在此基础上。
