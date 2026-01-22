# 内存检查模式

## 目录
- [x 命令格式](#x-命令格式)
- [常用检查模式](#常用检查模式)
- [寄存器检查](#寄存器检查)
- [栈帧分析](#栈帧分析)
- [堆检查](#堆检查)

## x 命令格式

```
x/NFU <address>
```

| 参数 | 说明 | 选项 |
|------|------|------|
| N | 数量 | 任意正整数 |
| F | 格式 | `x`(hex) `d`(decimal) `u`(unsigned) `o`(octal) `t`(binary) `a`(addr) `c`(char) `s`(string) `i`(instruction) |
| U | 单位 | `b`(byte) `h`(halfword/2B) `w`(word/4B) `g`(giant/8B) |

## 常用检查模式

### 字节序列（十六进制）
```gdb
x/32bx $rsp          # 栈顶 32 字节
x/64bx 0x7fff1234    # 指定地址 64 字节
x/16bx $rdi          # RDI 指向的 16 字节
```

### 字符串
```gdb
x/s $rdi             # RDI 指向的字符串
x/s 0x555555556000   # 指定地址的字符串
x/4s $rsp            # 栈上连续 4 个字符串
```

### 指针/地址
```gdb
x/4gx $rsp           # 栈顶 4 个 8 字节值（64位指针）
x/8wx $rbp           # RBP 处 8 个 4 字节值（32位值）
x/gx $rdi            # RDI 指向的 8 字节值
```

### 反汇编
```gdb
x/10i $rip           # 当前位置 10 条指令
x/5i *0x555555555a10 # 指定地址 5 条指令
x/20i $rip-0x10      # 当前位置前后的指令
```

### 有符号/无符号整数
```gdb
x/4wd $rsp           # 4 个有符号 32 位整数
x/4wu $rsp           # 4 个无符号 32 位整数
x/2gd $rdi           # 2 个有符号 64 位整数
```

## 寄存器检查

### x86-64 通用寄存器

| 寄存器 | 用途 | 检查场景 |
|--------|------|----------|
| `$rax` | 返回值 | 函数返回后 |
| `$rdi` | 第1参数 | 函数调用前 |
| `$rsi` | 第2参数 | 函数调用前 |
| `$rdx` | 第3参数 | 函数调用前 |
| `$rcx` | 第4参数 | 函数调用前 |
| `$r8`  | 第5参数 | 函数调用前 |
| `$r9`  | 第6参数 | 函数调用前 |
| `$rsp` | 栈指针 | 栈操作时 |
| `$rbp` | 帧指针 | 栈帧分析 |
| `$rip` | 指令指针 | 控制流分析 |

### 检查命令
```gdb
info registers                # 所有通用寄存器
info registers rax rbx rdi    # 指定寄存器
info all-registers            # 所有寄存器（含浮点、向量）
print $rax                    # 单个寄存器值
print/x $rax                  # 十六进制显示
```

### 条件标志
```gdb
info registers eflags         # 标志寄存器
print $eflags                 # 标志值
```

| 标志 | 含义 | 影响跳转 |
|------|------|----------|
| ZF | 零标志 | je, jne |
| SF | 符号标志 | js, jns |
| CF | 进位标志 | jc, jnc, ja, jb |
| OF | 溢出标志 | jo, jno |

## 栈帧分析

### 查看调用栈
```gdb
backtrace            # 调用栈（简略）
bt full              # 调用栈（含局部变量）
info frame           # 当前帧详情
info frame 2         # 第2帧详情
```

### 栈内容检查
```gdb
# 典型 64 位栈帧布局
x/16gx $rsp          # 栈顶 128 字节

# 返回地址（通常在 RBP+8）
x/gx $rbp+8

# 保存的 RBP（通常在 RBP）
x/gx $rbp

# 局部变量区域
x/8gx $rbp-0x40
```

### 函数参数（栈传递，超过6个参数时）
```gdb
# 第7个参数及以后在栈上
x/gx $rsp+0x00       # 第7参数
x/gx $rsp+0x08       # 第8参数
```

## 堆检查

### 基本堆块检查
```gdb
# malloc 返回的指针指向用户数据
# chunk header 在用户数据前 0x10 字节（64位）

# 查看 chunk header
x/2gx $rax-0x10      # prev_size 和 size

# 查看用户数据
x/8gx $rax           # 用户数据区域
```

### glibc malloc 结构

| 偏移 | 字段 | 说明 |
|------|------|------|
| -0x10 | prev_size | 前一块大小（空闲时） |
| -0x08 | size | 当前块大小 + 标志位 |
| +0x00 | fd | 前向指针（空闲时） |
| +0x08 | bk | 后向指针（空闲时） |

### size 字段标志位
```
size 字段最低 3 位:
  bit 0 (P): PREV_INUSE - 前一块正在使用
  bit 1 (M): IS_MMAPPED - 通过 mmap 分配
  bit 2 (N): NON_MAIN_ARENA - 非主 arena
```

## 实用技巧

### 地址表达式
```gdb
x/s *((char**)$rdi)       # 指针的指针
x/gx $rsp+8*3             # 栈偏移计算
x/wx *(int*)($rbp-0x10)   # 带类型转换
```

### 内存搜索
```gdb
find /b 0x7fff0000, 0x7fffffff, 0x41, 0x41, 0x41, 0x41   # 搜索 "AAAA"
find /w 0x555555554000, +0x10000, 0xdeadbeef             # 搜索 4 字节值
```

### 内存映射
```gdb
info proc mappings        # 所有内存映射
maintenance info sections # 段信息
```
