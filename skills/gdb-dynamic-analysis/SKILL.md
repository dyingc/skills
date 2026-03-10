---
name: gdb-dynamic-analysis
description: >
  Dynamic binary analysis using GDB MCP for runtime debugging and verification. Use this skill when the user asks to: (1) Verify static analysis hypotheses at runtime, (2) Debug or trace program execution flow, (3) Set breakpoints and inspect memory/registers at specific points, (4) Observe actual program behavior during execution, (5) Validate assumptions from static analysis, (6) Step through code interactively. This skill complements static analysis by providing runtime validation.
---

# GDB 动态二进制分析

## 核心行为

**语言**: 始终使用**简体中文**回复。汇编、代码、函数名、地址保持原样。

**角色**: 对等的逆向工程同事，直接坦率。

**用户背景**: 安全研究员，熟悉汇编、gdb、逆向工程、漏洞分析。

## 工具参考

**主要工具**: GDB MCP（参见 [references/gdb-mcp-tools.md](references/gdb-mcp-tools.md)）

| 场景 | 工具 |
|------|------|
| 会话管理 | `gdb_start`, `gdb_terminate`, `gdb_list_sessions`, `gdb_attach` |
| 程序加载 | `gdb_load`, `gdb_load_core` |
| 执行控制 | `gdb_continue`, `gdb_step`, `gdb_next`, `gdb_finish` |
| 断点管理 | `gdb_set_breakpoint` + `gdb_command` (删除/列出断点) |
| 状态检查 | `gdb_info_registers`, `gdb_examine`, `gdb_backtrace`, `gdb_print` |
| 任意命令 | `gdb_command` (执行任意 GDB 命令) |

## 分析工作流

### 工作流类型选择

根据分析目标选择合适的启动方式：

| 场景 | 工作流 | 关键工具 |
|------|--------|----------|
| 标准二进制调试 | 从零启动调试 | `gdb_load` + `gdb_command "starti"` |
| 附加到运行进程 | 调试服务/守护进程 | `gdb_start` + `gdb_attach` |
| 崩溃分析 | 分析核心转储 | `gdb_load_core` |

### 工作流 1: 标准二进制调试（从零启动）

#### 1. 会话启动
```
□ gdb_start: 创建 GDB 会话，返回 sessionId
□ gdb_load <sessionId> <program> [args]: 加载目标程序
□ gdb_command <sessionId> "starti": 启动程序（停在入口点）
□ gdb_command <sessionId> "info files": 获取基地址（用于 ASLR 计算）
```

#### 2. 断点设置
```
□ 计算实际地址: 基地址 + 静态偏移
□ gdb_set_breakpoint <sessionId> <location>: 设置断点
□ gdb_command <sessionId> "info breakpoints": 确认断点已设置
```

#### 3. 执行与检查
```
□ gdb_continue <sessionId>: 运行到断点
□ gdb_info_registers <sessionId>: 检查寄存器状态
□ gdb_examine <sessionId> <address> [format] [count]: 检查内存
□ gdb_backtrace <sessionId>: 查看调用栈
□ gdb_print <sessionId> <expression>: 计算表达式值
```

#### 4. 单步执行（可选）
```
□ gdb_step <sessionId> [instructions]: 步进（进入函数）
□ gdb_next <sessionId> [instructions]: 步过（跳过函数）
□ gdb_finish <sessionId>: 运行到当前函数返回
```

#### 5. 清理
```
□ gdb_terminate <sessionId>: 关闭会话（必须）
```

### 工作流 2: 附加到运行进程

**使用场景**: 调试正在运行的服务、守护进程、或长时间运行的程序

#### 1. 创建会话并附加
```
□ gdb_start: 创建 GDB 会话
□ gdb_attach <sessionId> <pid>: 附加到运行进程
```

**获取 PID**: `ps aux | grep <program>` 或 `pgrep <program>`

#### 2. 设置断点与观察
```
□ gdb_set_breakpoint <sessionId> <location>: 设置断点
□ gdb_continue <sessionId>: 继续执行
```

#### 3. 检查状态
```
□ gdb_backtrace <sessionId>: 查看当前调用栈
□ gdb_info_registers <sessionId>: 检查寄存器
□ gdb_print <sessionId> <variable>: 检查变量值
```

#### 4. 清理
```
□ gdb_command <sessionId> "detach": 分离进程（让进程继续运行）
□ gdb_terminate <sessionId>: 关闭会话
```

**注意**: 附加后进程会暂停。使用 `gdb_continue` 恢复执行。

### 工作流 3: 核心转储分析（事后调试）

**使用场景**: 分析程序崩溃现场，无需复现崩溃

#### 1. 加载核心转储
```
□ gdb_start: 创建 GDB 会话
□ gdb_load_core <sessionId> <program> <core_path>: 加载核心转储文件
```

**核心转储位置**: 通常在 `/var/lib/systemd/coredump/` 或当前目录（需启用 ulimit -c unlimited）

#### 2. 检查崩溃现场
```
□ gdb_backtrace <sessionId> [full]: 查看崩溃调用栈
  └─ full=True: 显示每个帧的局部变量
□ gdb_info_registers <sessionId>: 查看崩溃时寄存器状态
□ gdb_print <sessionId> <variable>: 检查关键变量值
```

#### 3. 分析内存
```
□ gdb_examine <sessionId> <address> "x" <count>: 查看崩溃点附近内存
□ gdb_command <sessionId> "info proc mappings": 检查内存映射
□ gdb_print <sessionId> "*((type*)address)": 类型化访问内存
```

#### 4. 清理
```
□ gdb_terminate <sessionId>: 关闭会话
```

### 新工具详细说明

#### gdb_print - 表达式求值

计算并显示 C 表达式的值。

**适用场景**:
- 检查变量值（无需知道类型）
- 计算复杂表达式（指针解引用、数组访问）
- 类型转换访问内存
- 验证假设条件

**示例**:
```python
# 简单变量
gdb_print(session_id, "x")

# 指针解引用
gdb_print(session_id, "*ptr")

# 数组访问
gdb_print(session_id, "array[5]")

# 结构体字段
gdb_print(session_id, "ptr->field")

# 类型转换 + 指针解引用
gdb_print(session_id, "*((int*)0x7fffffffde00)")

# 寄存器运算
gdb_print(session_id, "$rax + $rbx")

# 位运算
gdb_print(session_id, "$rax & 0xff")
```

**vs gdb_examine**: `gdb_print` 理解类型和符号，`gdb_examine` 是原始内存查看

#### gdb_finish - 运行到函数返回

继续执行直到当前函数返回。

**适用场景**:
- 快速跳出当前函数
- 检查函数返回值（返回后自动停在调用者）
- 避免手动单步执行完整个函数

**行为**:
- 停在函数返回后的第一条指令
- 返回值存储在 `$rax`（x86-64）
- 可立即使用 `gdb_print` 检查返回值

**示例**:
```python
# 调用函数后停在函数内
gdb_step(session_id)  # 进入函数

# 跳过函数内部实现，直接检查返回值
gdb_finish(session_id)  # 返回到调用者
gdb_info_registers(session_id, "rax")  # 检查返回值
```

**⚠️ 注意**: 在 `main()` 或调用 `exit()` 的函数中使用会挂起（参见 [deadlock-prevention.md](references/deadlock-prevention.md)）

#### gdb_attach - 附加到运行进程

附加到已经运行的进程进行调试。

**适用场景**:
- 调试运行中的服务/守护进程
- 分析生产环境问题（测试环境）
- 调试长时间运行后才出现的问题
- 避免重启程序

**限制**:
- 需要 root 权限或相同用户权限
- 附加后进程暂停
- 某些安全机制可能阻止附加（ptrace_scope）

**示例**:
```python
# 查找进程 PID
# $ pgrep nginx
# 1234

# 附加到进程
session_id = gdb_start()
gdb_attach(session_id, 1234)

# 设置断点并继续
gdb_set_breakpoint(session_id, "handle_request")
gdb_continue(session_id)

# ... 调试 ...

# 分离进程（不终止）
gdb_command(session_id, "detach")
gdb_terminate(session_id)
```

**检查 ptrace_scope**:
```bash
$ cat /proc/sys/kernel/yama/ptrace_scope
# 0: 允许附加（默认）
# 1: 限制附加（仅父进程）
# 2: 仅附加到子进程
# 3: 完全禁用
```

临时修改: `sudo sysctl -w kernel.yama.ptrace_scope=0`

#### gdb_load_core - 核心转储分析

加载核心转储文件进行事后分析。

**适用场景**:
- 分析难以复现的崩溃
- 检查崩溃时的完整状态
- 生产环境崩溃分析
- 收集用户崩溃报告

**启用核心转储**:
```bash
# 临时启用
ulimit -c unlimited

# 永久启用（添加到 ~/.bashrc 或 /etc/profile）
echo "ulimit -c unlimited" >> ~/.bashrc

# 配置核心转储路径（/proc/sys/kernel/core_pattern）
```

**示例**:
```python
# 程序崩溃，生成 core.12345 文件
session_id = gdb_start()

# 加载核心转储
gdb_load_core(
    session_id,
    "/path/to/crashing_program",
    "/var/lib/systemd/coredump/core.12345"
)

# 检查崩溃位置
gdb_backtrace(session_id, full=True)
# 输出:
# #0  0x00007ffff7a4f128 in raise () from /lib64/libc.so.6
# #1  0x00007ffff7a38154 in abort () from /lib64/libc.so.6
# #2  0x0000555555554a8f in crash_function (ptr=0x0) at test.c:42
#     ptr = 0x0

# 检查关键变量
gdb_print(session_id, "ptr")
# 输出: $1 = (char *) 0x0

# 检查崩溃时寄存器
gdb_info_registers(session_id)
# 输出: rax 0x0 0, rdi 0x0 0, ...

gdb_terminate(session_id)
```

**核心转储位置**:
- Ubuntu: `/var/lib/systemd/coredump/` (systemd-coredump)
- 默认: 当前目录 `core` 或 `core.<pid>`
- 自定义: `/proc/sys/kernel/core_pattern`

### 程序加载方式对比

| 方式 | 工具 | 状态 | 使用场景 |
|------|------|------|----------|
| 方式 A | `gdb_load` | 推荐 | 需要传递命令行参数 |
| 方式 B | `gdb_command "file"` | 灵活 | 快速测试，无参数 |

**方式 A 示例**:
```python
gdb_load(session_id, "/bin/ls", ["-l", "/tmp"])
gdb_command(session_id, "starti")
```

**方式 B 示例**:
```python
gdb_command(session_id, "file /bin/ls")
gdb_command(session_id, "set args -l /tmp")
gdb_command(session_id, "starti")
```

### 单步执行策略

| 命令 | 行为 | 适用场景 |
|------|------|----------|
| `gdb_step` | 进入函数调用 | 需要检查函数内部实现 |
| `gdb_next` | 跳过函数调用 | 只关注当前函数逻辑 |
| `gdb_finish` | 运行到函数返回 | 快速跳出当前函数 |
| `gdb_continue` | 运行到下一个断点 | 跳过大段代码 |

**典型流程**:
```python
# 停在函数调用处
gdb_next(session_id)  # 跳过不感兴趣的函数

# 需要深入检查时
gdb_step(session_id)  # 进入函数
# ... 检查函数内部 ...
gdb_finish(session_id)  # 快速返回

# 继续到下一个关键点
gdb_continue(session_id)
```

## 关键约束

### ASLR 地址计算
程序每次运行时加载地址不同：
```
实际地址 = 基地址 + 静态偏移

示例:
- 静态分析得到 main 偏移: 0x12f0
- 运行时基地址 (info files): 0x555555554000
- 实际断点地址: 0x5555555552f0
```

使用 `scripts/aslr_calc.py` 简化计算。

### 输入处理
程序需要 stdin 输入时：
```gdb
run < input.txt
```
使用 `scripts/create_input.py` 生成测试输入。

### GDB 扩展
**禁用扩展**（GEF、Pwndbg 等）以保持一致的输出格式：
```gdb
set pagination off
set confirm off
```

### 内存检查格式
参见 [references/inspection-patterns.md](references/inspection-patterns.md) 获取详细格式。

常用格式:
- `x/Nbx <addr>`: N 字节，十六进制
- `x/s <addr>`: 字符串
- `x/Ni <addr>`: N 条指令

## GDB 脚本

复杂多步骤场景可使用 GDB 脚本自动化。

**重要**: 脚本开发遵循严格流程，避免死锁。

参见:
- [references/scripting-workflow.md](references/scripting-workflow.md): 脚本开发流程
- [references/deadlock-prevention.md](references/deadlock-prevention.md): 死锁预防

## 与静态分析配合

**典型工作流**: 静态分析 → 动态验证 → 回注释

### 静态分析提供的信息

从 **static-binary-analysis** 技能获取:
- 目标函数的偏移地址（通过 `decompile_function`）
- 反编译代码作为参考
- 交叉引用确定断点位置（通过 `get_xrefs_to`）
- 函数原型和参数类型（用于 `gdb_print` 表达式）

### 动态验证场景

#### 场景 1: 验证函数调用约定

静态分析显示函数 `sub_4012ab` 接收 3 个参数：

```python
# 静态分析: sub_4012ab(char* arg1, int arg2, void* arg3)

# 动态验证: 设置断点并检查参数
session_id = gdb_start()
gdb_load(session_id, "/path/to/binary")
gdb_command(session_id, "starti")

# 获取基地址并计算函数地址
# ... ASLR 计算 ...

gdb_set_breakpoint(session_id, "*0x5555555552ab")
gdb_continue(session_id)

# 检查参数（x86-64 System V AMD64 ABI）
gdb_print(session_id, "$rdi")  # arg1
gdb_print(session_id, "$rsi")  # arg2
gdb_print(session_id, "$rdx")  # arg3
```

#### 场景 2: 验证缓冲区溢出假设

静态分析发现可疑的 `strcpy` 调用：

```python
# 静态分析: strcpy(buffer, user_input)

# 动态验证: 观察运行时行为
gdb_set_breakpoint(session_id, "*<strcpy_address>")
gdb_continue(session_id)

# 断点命中后检查
gdb_print(session_id, "$rdi")  # buffer 地址
gdb_print(session_id, "$rsi")  # user_input 地址

# 检查缓冲区大小
gdb_examine(session_id, "$rdi-0x10", "x", 2)  # malloc chunk header
gdb_print(session_id, "strlen($rsi)")  # 输入长度

# 单步执行观察溢出
gdb_step(session_id)
gdb_examine(session_id, "$rdi", "x", 32)  # 查看溢出后的内存
```

#### 场景 3: 核心转储验证静态分析结论

生产环境程序崩溃，静态分析怀疑是空指针解引用：

```python
# 静态分析: functionX 可能解引用空指针

# 加载核心转储
session_id = gdb_start()
gdb_load_core(session_id, "/path/to/binary", "/var/lib/systemd/coredump/core.12345")

# 检查崩溃位置
gdb_backtrace(session_id)
# #0  0x4012ab in functionX (ptr=0x0) at file.c:42

# 验证静态分析假设
gdb_print(session_id, "ptr")  # 确认为 0x0

gdb_terminate(session_id)
```

### 验证后的反馈

**将动态分析发现反馈到静态分析**:

1. **添加注释**: 在 Ghidra 中记录实际运行时行为
   - 函数参数验证结果
   - 缓冲区实际使用情况
   - 返回值含义

2. **重命名函数/变量**: 根据运行时观察更新命名
   ```python
   # 动态分析发现
   gdb_print(session_id, "$rdi")  # 输出: "/etc/config.conf"
   # → Ghidra 重命名: arg1 → config_path
   ```

3. **验证反编译结果**: 对比反编译代码与实际行为
   - 类型推断是否正确
   - 控制流分析是否准确
   - 数据流分析是否完整

### 混合分析技巧

#### 使用 gdb_print 验证类型假设

静态分析推断某个地址是结构体：

```python
# 静态分析: 可能是结构体 { int a; char* b; int c; }

# 动态验证: 构造类型化访问
gdb_print(session_id, "*((int*)$rdi)")           # 验证字段 a
gdb_print(session_id, "*((char**)$rdi+1)")      # 验证字段 b
gdb_print(session_id, "*((int*)$rdi+2)")        # 验证字段 c

# 或定义 GDB 便利类型
gdb_command(session_id, "set $struct_ptr = (struct my_struct*)$rdi")
gdb_print(session_id, "$struct_ptr->a")
gdb_print(session_id, "$struct_ptr->b")
```

#### 使用条件断点验证特定条件

静态分析发现循环在特定条件下有漏洞：

```python
# 静态分析: for (i = 0; i <= len; i++) { ... }  # off-by-one

# 动态验证: 仅在最后一次迭代时检查
gdb_set_breakpoint(session_id, "*<loop_body_address>", "i == len")
gdb_continue(session_id)

# 检查最后一次迭代时的状态
gdb_examine(session_id, "$rsp+0x40", "x", 16)  # 栈缓冲区
```

### 常见验证模式

| 静态分析假设 | 动态验证方法 |
|-------------|-------------|
| 函数返回值含义 | `gdb_finish` + `gdb_info_registers rax` |
| 指针是否为空 | `gdb_print` 检查指针值 |
| 缓冲区溢出 | `gdb_examine` 观察溢出前后内存 |
| 整数溢出 | `gdb_print` 计算表达式结果 |
| 函数指针调用 | `gdb_step` 跟踪实际调用目标 |
| 全局变量访问 | `gdb_examine` 检查全局内存 |
| 字符串格式化漏洞 | 观察 `printf` 类函数参数 |

## 辅助脚本

位于 `scripts/` 目录:

- **aslr_calc.py**: `python scripts/aslr_calc.py <base_addr> <offset>` - ASLR 地址计算
- **create_input.py**: `python scripts/create_input.py <type> [options]` - 生成测试输入

## 参考文档

- [GDB MCP 工具参考](references/gdb-mcp-tools.md): 所有可用工具的详细用法
- [内存检查模式](references/inspection-patterns.md): 内存/寄存器检查格式
- [脚本开发流程](references/scripting-workflow.md): GDB 脚本开发最佳实践
- [死锁预防](references/deadlock-prevention.md): 脚本死锁场景及预防

## 故障排除

| 问题 | 解决方案 |
|------|----------|
| 断点未命中 | 检查地址计算（基地址 + 偏移）；确认代码路径可达 |
| 会话异常 | `gdb_terminate` 后重新创建；检查二进制路径和权限 |
| 内存读取失败 | `info proc mappings` 检查内存布局；确认地址已映射 |
| 脚本死锁 | 终止会话，重新开始；参见 [deadlock-prevention.md](references/deadlock-prevention.md) |
