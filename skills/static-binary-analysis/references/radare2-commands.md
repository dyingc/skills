# Radare2 工具参考 (Ghidra MCP 补充)

仅在 Ghidra MCP 工具无法满足需求时使用这些工具。

## 目录
1. [二进制对比 (radiff2)](#二进制对比-radiff2)
2. [二进制信息 (rabin2)](#二进制信息-rabin2)
3. [汇编/反汇编 (rasm2)](#汇编反汇编-rasm2)
4. [哈希计算 (rahash2)](#哈希计算-rahash2)
5. [数据搜索 (rafind2)](#数据搜索-rafind2)
6. [数值转换 (rax2)](#数值转换-rax2)
7. [完整分析 (radare2)](#完整分析-radare2)

---

## 二进制对比 (radiff2)

**Ghidra缺失**: 无内置二进制diff功能

### 基本用法
```bash
# 字节级对比
radiff2 file1 file2

# 代码块对比（更智能）
radiff2 -c file1 file2

# 输出diff统计
radiff2 -s file1 file2

# 图形化对比（生成dot格式）
radiff2 -g main file1 file2
```

### 补丁分析
```bash
# 找出补丁修改了什么
radiff2 -c vuln_binary patched_binary

# 详细对比指定函数
radiff2 -g target_func old new > diff.dot
```

---

## 二进制信息 (rabin2)

**Ghidra缺失**: 快速命令行查询，无需打开GUI

### 快速信息提取
```bash
# 文件基本信息
rabin2 -I binary

# 导入表
rabin2 -i binary

# 导出表
rabin2 -E binary

# 所有字符串
rabin2 -z binary

# 宽字符串
rabin2 -zz binary

# 段信息
rabin2 -S binary

# 符号表
rabin2 -s binary

# 入口点
rabin2 -e binary

# 库依赖
rabin2 -l binary
```

### 安全检查
```bash
# 检查保护机制 (canary, NX, PIE, RELRO)
rabin2 -I binary | grep -E "canary|nx|pic|relro"
```

---

## 汇编/反汇编 (rasm2)

**Ghidra缺失**: 快速单条指令操作，无需完整分析

### 反汇编
```bash
# 反汇编十六进制
rasm2 -d "554889e5"

# 指定架构
rasm2 -a x86 -b 64 -d "554889e5"

# 从文件反汇编
rasm2 -d -f shellcode.bin
```

### 汇编
```bash
# 汇编指令
rasm2 "push rbp; mov rbp, rsp"

# 指定架构
rasm2 -a x86 -b 64 "syscall"

# 输出原始字节到文件
rasm2 -a x86 -b 64 "nop" -F > nop.bin
```

### 架构列表
```bash
rasm2 -L    # 列出支持的架构
```

---

## 哈希计算 (rahash2)

**Ghidra缺失**: 快速哈希计算

### 基本用法
```bash
# 默认SHA256
rahash2 binary

# 指定算法
rahash2 -a md5 binary
rahash2 -a sha1 binary
rahash2 -a crc32 binary

# 多种算法
rahash2 -a md5,sha1,sha256 binary

# 指定范围
rahash2 -a md5 -f 0x1000 -t 0x2000 binary
```

### 列出支持的算法
```bash
rahash2 -L
```

---

## 数据搜索 (rafind2)

**Ghidra缺失**: 原始字节模式搜索

### 基本搜索
```bash
# 搜索字符串
rafind2 -s "password" binary

# 搜索十六进制
rafind2 -x "deadbeef" binary

# 搜索宽字符串
rafind2 -S "password" binary
```

### 高级搜索
```bash
# 正则搜索
rafind2 -e "pass.*word" binary

# 搜索并显示上下文
rafind2 -s "admin" -c binary

# 从指定偏移搜索
rafind2 -s "flag" -f 0x1000 binary
```

---

## 数值转换 (rax2)

**Ghidra缺失**: 快速进制/格式转换

### 进制转换
```bash
# 十进制转十六进制
rax2 255        # 0xff

# 十六进制转十进制
rax2 0xff       # 255

# 二进制
rax2 0b1111     # 15
rax2 -b 15      # 0b1111
```

### 表达式计算
```bash
# 计算
rax2 "0x100+0x50"   # 336

# 负数（补码）
rax2 -1             # 0xffffffffffffffff

# 字符串转十六进制
rax2 -s "ABC"       # 414243

# 十六进制转字符串
rax2 -S 414243      # ABC
```

### 常用转换
```bash
rax2 -e 0x41424344   # 小端序
rax2 -k 1024         # 人类可读大小 (1K)
```

---

## 完整分析 (radare2)

**使用场景**: Ghidra项目未打开时的应急分析

### 快速分析模式
```bash
# 打开并分析
r2 -A binary

# 仅打开不分析
r2 binary
```

### 常用命令（r2 shell内）
```
aaa         # 完整分析
afl         # 列出函数
pdf @main   # 反汇编main
pdc @main   # 反编译main（伪代码）
iz          # 列出字符串
ii          # 导入表
ie          # 入口点
axt addr    # 交叉引用到addr
axf addr    # 从addr的引用
s addr      # 跳转到地址
```

### 非交互模式
```bash
# 执行单条命令
r2 -c "aaa; afl" binary

# 执行多条命令
r2 -c "aaa; pdf @main; q" binary

# 静默模式
r2 -q -c "iz" binary
```

---

## 使用决策

| 需求 | 优先工具 | 备选 |
|------|----------|------|
| 反编译函数 | Ghidra: decompile_function | r2: pdc |
| 反汇编函数 | Ghidra: disassemble_function | r2: pdf |
| 交叉引用 | Ghidra: get_xrefs_to/from | r2: axt/axf |
| 字符串列表 | Ghidra: list_strings | rabin2 -z |
| 导入/导出 | Ghidra: list_imports/exports | rabin2 -i/-E |
| 二进制对比 | **radiff2** | 无Ghidra替代 |
| 单指令汇编 | **rasm2** | 无Ghidra替代 |
| 字节搜索 | **rafind2** | Ghidra搜索较慢 |
| 哈希计算 | **rahash2** | 无Ghidra替代 |
| 进制转换 | **rax2** | 无Ghidra替代 |
| 保护检查 | **rabin2 -I** | Ghidra需手动查看 |
