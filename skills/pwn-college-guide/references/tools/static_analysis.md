# 静态分析工具使用指南

## 工具优先级策略

在分析二进制文件时，按照以下优先级选择工具：

```
优先级 1: Ghidra MCP (通过 MCP 工具调用)
优先级 2: radare2 系列工具 (radare2, ragg2, rabin2 等)
优先级 3: 其他工具 (objdump, readelf, strings 等) - 仅当前两者不可用或无法解决问题时使用
```

**为什么这个顺序？**
- Ghidra 提供最全面的分析（反编译、交叉引用、控制流图）
- radare2 功能强大，命令行友好，适合快速分析
- objdump/readelf 等工具功能单一，信息碎片化

---

## 优先级 1: Ghidra MCP

Ghidra 是最强大的静态分析工具，通过 MCP 工具可以程序化调用。

### 核心 MCP 工具

**函数分析：**
- `decompile_function` - 反编译函数获取 C 伪代码
- `disassemble_function` - 获取函数的汇编代码
- `get_function_by_address` - 通过地址获取函数信息
- `list_functions` - 列出所有函数

**交叉引用分析：**
- `get_xrefs_to` - 获取引用到指定地址的所有位置
- `get_xrefs_from` - 获取从指定地址引用的所有位置
- `get_function_xrefs` - 获取引用指定函数的所有位置

**字符串和数据：**
- `list_strings` - 列出所有定义的字符串
- `list_data_items` - 列出定义的数据标签和值
- `list_imports` - 列出导入的符号
- `list_exports` - 列出导出的函数/符号

**程序结构：**
- `list_segments` - 列出所有内存段
- `list_classes` - 列出所有命名空间/类

### 使用场景

**场景 1: 查找漏洞函数**
```python
# 通过 name 参数反编译函数
decompile_function(name="vulnerable_function")

# 或通过地址反编译
decompile_function_by_address(address="0x401234")
```

**场景 2: 查找危险函数的调用位置**
```python
# 找到所有调用 gets() 的位置
get_function_xrefs(name="gets")
```

**场景 3: 查找字符串引用**
```python
# 列出所有字符串
list_strings(filter="flag")

# 获取字符串的交叉引用
get_xrefs_to(address="0x402000")
```

**场景 4: 理解程序结构**
```python
# 查看所有内存段
list_segments()

# 查看导入的函数
list_imports()
```

### 最佳实践

1. **从 list_functions 开始** - 快速了解程序有哪些函数
2. **用 list_strings 找关键线索** - "flag", "password", "WIN" 等字符串
3. **用 get_xrefs_to 追踪引用** - 找到谁引用了关键数据
4. **用 decompile_function 理解逻辑** - 反编译比汇编更易读

---

## 优先级 2: radare2 系列工具

radare2 是强大的命令行逆向工程框架，适合快速分析。

### r2 - 主要逆向工具

**基本分析流程：**
```bash
# 打开二进制并分析
r2 /path/to/binary
[0x00000000]> aaa        # 深度分析
[0x00000000]> afl        # 列出所有函数 (list functions)
[0x00000000]> afl~main   # 过滤包含 "main" 的函数
```

**查看函数：**
```bash
[0x00000000]> pdf @main  # 打印 main 函数反汇编 (print function disassembly)
[0x00000000]> pdd @main  # 反编译为 C 代码 (需要 r2ghidra 插件)
```

**搜索：**
```bash
[0x00000000]> /          # 搜索字符串
[0x00000000]> /R "binsh" # 搜索 ROP gadgets
[0x00000000]> /x 41414141  # 搜索十六进制模式
```

**查看信息：**
```bash
[0x00000000]> ii         # 导入函数 (imports)
[0x00000000]> iE         # 导出函数 (exports)
[0x00000000]> iz         # 字符串 (strings)
[0x00000000]> is         # 符号 (symbols)
[0x00000000]> iS         # 段 (sections)
```

**交叉引用：**
```bash
[0x00000000]> axt @sym.imp.gets   # 获取引用 gets 的位置 (xrefs to)
[0x00000000]> axf @main           # 获取 main 引用的位置 (xrefs from)
```

**查看栈帧：**
```bash
[0x00000000]> afl~vuln   # 找到漏洞函数地址
[0x00000000]> s sym.vuln # 切换到函数
[0x00000000]> pdf        # 查看函数
[0x00000000]> pxr 100 @rsp  # 查看栈布局
```

### radare2 常用命令速查

| 命令 | 说明 |
|------|------|
| `aaa` | 深度分析 |
| `afl` | 列出函数 |
| `pdf @func` | 打印函数反汇编 |
| `ii` | 导入函数 |
| `iz` | 字符串 |
| `/pattern` | 搜索 |
| `axt @addr` | 交叉引用到 |
| `axf @addr` | 交叉引用从 |

### rabin2 - 二进制信息提取

rabin2 用于快速提取二进制信息，无需进入 r2 交互模式。

```bash
# 查看所有信息
rabin2 -I /path/to/binary

# 查看段
rabin2 -S /path/to/binary

# 查看字符串
rabin2 -z /path/to/binary

# 查看导入
rabin2 -i /path/to/binary

# 查看入口点
rabin2 -e /path/to/binary

# 查看依赖
rabin2 -d /path/to/binary
```

### ragg2 - 模式生成器

生成测试模式，用于模糊测试或查找偏移：

```bash
# 生成 cyclic 模式
ragg2 -P 100  # 生成 100 字节的 de Bruijn 序列

# 生成特定模式
ragg2 -P 100 -r  # 随机模式
```

---

## 优先级 3: 其他工具

**仅在 Ghidra MCP 和 radare2 不可用时使用。**

### objdump - 反汇编

```bash
# Intel 语法反汇编（推荐）
objdump -M intel -d /path/to/binary

# 只反汇编特定函数
objdump -M intel -d /path/to/binary | grep -A 50 "main."

# 查看所有段头部
objdump -h /path/to/binary
```

**限制：** 只能反汇编，无交叉引用，无函数边界识别（strip 后）。

### readelf - ELF 信息

```bash
# 查看程序头
readelf -l /path/to/binary

# 查看段信息
readelf -S /path/to/binary

# 查看符号表
readelf -s /path/to/binary

# 查看重定位
readelf -r /path/to/binary

# 查看动态段
readelf -d /path/to/binary
```

**限制：** 只提供结构信息，不反汇编。

### strings - 提取字符串

```bash
# 提取所有可打印字符串
strings /path/to/binary

# 查找特定字符串
strings /path/to/binary | grep -i flag

# 指定最小长度
strings -n 10 /path/to/binary

# 查看字符串在文件中的偏移
strings -t x /path/to/binary
```

**限制：** 无上下文，不知道哪里引用了字符串。

### nm - 符号表

```bash
# 查看所有符号
nm /path/to/binary

# 只看未定义符号（需要外部库）
nm -u /path/to/binary

# 只看调试符号
nm -a /path/to/binary
```

**限制：** strip 后无符号。

### file - 文件类型

```bash
file /path/to/binary
# 输出: ELF 64-bit LSB executable, x86-64, ...
```

---

## 典型工作流程示例

### 场景：栈溢出分析

```bash
# 步骤 1: 快速检查二进制
file challenge
readelf -l challenge

# 步骤 2: 启动 radare2 分析
r2 challenge
[0x00000000]> aaa
[0x00000000]> afl        # 列出所有函数
[0x00000000]> iz         # 查看字符串
[0x00000000]> ii         # 查看导入（找危险函数）

# 步骤 3: 分析漏洞函数
[0x00000000]> pdf @main  # 查看 main
[0x00000000]> axt @sym.imp.gets  # 谁调用了 gets？

# 步骤 4: 如果有 Ghidra，反编译获取 C 代码
# 在主环境调用 Ghidra MCP 工具
decompile_function(name="vulnerable_function")
```

### 场景：ROP 挑战

```bash
# 步骤 1: 检查保护
r2 challenge
[0x00000000]> iI         # 检查 NX, PIE, Canary

# 步骤 2: 搜索 gadgets
[0x00000000]> /R "pop rdi"
[0x00000000]> /R "ret"

# 步骤 3: 找有用函数
[0x00000000]> afl~system;win;exec

# 步骤 4: 查找字符串
[0x00000000]> /bin/sh
[0x00000000]> iz~bin
```

### 场景：格式化字符串

```bash
# 步骤 1: 找到格式化字符串函数调用
r2 challenge
[0x00000000]> ii~printf,sprintf

# 步骤 2: 分析引用位置
[0x00000000]> axt @sym.imp.printf

# 步骤 3: 反汇编查看用户输入是否直接作为格式字符串
[0x00000000]> pdf @main
```

---

## 快速决策树

```
需要分析二进制
    |
    ├─ 有 Ghidra MCP？
    │   └─ 是 → 使用 Ghidra MCP 工具
    │           - decompile_function() 理解逻辑
    │           - get_xrefs_*() 追踪引用
    │           - list_strings() 找线索
    │
    ├─ 有 radare2？
    │   └─ 是 → 使用 radare2
    │           - aaa + afl 列函数
    │           - pdf @func 查看函数
    │           - ii/iz 查导入和字符串
    │
    └─ 都没有？
        └─ 使用基础工具
            - objdump -M intel -d 反汇编
            - readelf 查看结构
            - strings 提取字符串
```

---

## 总结

1. **Ghidra MCP**: 最全面，反编译 + 交叉引用 + 自动分析
2. **radare2**: 快速命令行分析，适合探索和搜索
3. **objdump/readelf**: 功能单一，仅作备选

**记住**：好的工具选择能显著提高分析效率。优先使用 Ghidra MCP 和 radare2，它们提供的功能远超基础工具。
