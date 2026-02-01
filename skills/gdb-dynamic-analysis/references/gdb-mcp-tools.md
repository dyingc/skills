# GDB MCP 工具参考

## 目录
- [会话管理](#会话管理)
- [程序加载](#程序加载)
- [执行控制](#执行控制)
- [断点管理](#断点管理)
- [状态检查](#状态检查)
- [通用命令](#通用命令)

## 会话管理

### gdb_start
创建新的 GDB 调试会话。

```python
gdb_start(gdbPath="gdb", workingDir="/path/to/dir")
```

**参数**:
- `gdbPath` (可选): GDB 可执行文件路径（默认 "gdb"）
- `workingDir` (可选): 工作目录

**返回**: `sessionId` - 后续所有操作需要此 ID

**示例**:
```python
session_id = gdb_start(workingDir="/tmp/debug")
```

### gdb_terminate
关闭 GDB 会话。**必须调用**以清理资源。

```python
gdb_terminate(sessionId)
```

### gdb_list_sessions
列出所有活动会话。

```python
gdb_list_sessions()
```

**返回**: 活动会话列表

### gdb_attach
附加到正在运行的进程。

```python
gdb_attach(sessionId, pid)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `pid`: 要附加的进程 ID

**使用场景**: 调试正在运行的服务或进程

## 程序加载

### gdb_load
加载程序到 GDB 进行调试。

```python
gdb_load(sessionId, program, arguments=None)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `program`: 程序路径
- `arguments` (可选): 命令行参数数组

**返回**: 无

**注意**: 加载后还需使用 `gdb_command` 执行 `run` 或 `start` 命令启动程序

**示例**:
```python
# 加载程序
gdb_load(session_id, "/path/to/binary", ["--arg1", "value1"])

# 启动程序
gdb_command(session_id, "starti")  # 停在入口点
```

### gdb_load_core
加载核心转储文件进行事后分析。

```python
gdb_load_core(sessionId, program, corePath)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `program`: 程序可执行文件路径
- `corePath`: 核心转储文件路径

**使用场景**: 分析崩溃现场

## 执行控制

### gdb_continue
继续执行直到下一个断点或程序结束。

```python
gdb_continue(sessionId)
```

### gdb_step
单步执行，**进入**函数调用（step into）。

```python
gdb_step(sessionId, instructions=False)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `instructions` (可选): 是否按指令步进而非源代码行（默认 false）

**示例**:
```python
gdb_step(session_id)           # 按源代码行步进
gdb_step(session_id, True)     # 按指令步进
```

### gdb_next
单步执行，**跳过**函数调用（step over）。

```python
gdb_next(sessionId, instructions=False)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `instructions` (可选): 是否按指令步进而非源代码行（默认 false）

### gdb_finish
执行直到当前函数返回。

```python
gdb_finish(sessionId)
```

**使用场景**: 快速跳出当前函数

## 断点管理

### gdb_set_breakpoint
设置断点。

```python
gdb_set_breakpoint(sessionId, location, condition=None)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `location`: 断点位置
  - 地址: `"*0x555555555a10"` (注意前缀 `*`)
  - 函数名: `"main"`
  - 文件行号: `"file.c:42"`
- `condition` (可选): 断点条件，例如 `"x > 10"`

**示例**:
```python
# 地址断点
gdb_set_breakpoint(session_id, "*0x555555555a10")

# 函数断点
gdb_set_breakpoint(session_id, "main")

# 条件断点
gdb_set_breakpoint(session_id, "*0x555555555a10", "eax == 0")
```

**注意**: 删除和列出断点需要使用 `gdb_command`:
- 删除: `gdb_command(sessionId, "delete breakpoints N")` 或 `"delete breakpoints"` (删除所有)
- 列出: `gdb_command(sessionId, "info breakpoints")`

## 状态检查

### gdb_info_registers
显示寄存器值。

```python
gdb_info_registers(sessionId, register=None)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `register` (可选): 特定寄存器名称（如 "rax", "rsp"）

**示例**:
```python
# 显示所有寄存器
gdb_info_registers(session_id)

# 显示特定寄存器
gdb_info_registers(session_id, "rax")
```

### gdb_examine
检查内存内容。

```python
gdb_examine(sessionId, expression, format=None, count=None)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `expression`: 内存地址或表达式
- `format` (可选): 显示格式
  - `"x"`: 十六进制（默认）
  - `"i"`: 指令
  - `"s"`: 字符串
  - `"d"`: 十进制
- `count` (可选): 显示单元数量

**示例**:
```python
# 读取 16 字节（十六进制）
gdb_examine(session_id, "0x7fffffffde00", "x", 16)

# 反汇编 10 条指令
gdb_examine(session_id, "0x555555555a10", "i", 10)

# 读取字符串
gdb_examine(session_id, "0x555555555a10", "s")
```

**等价 GDB 命令**: `x/[count][format] <address>`

### gdb_backtrace
显示调用栈。

```python
gdb_backtrace(sessionId, full=False, limit=None)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `full` (可选): 是否显示每个帧的变量（默认 false）
- `limit` (可选): 最大显示帧数

**示例**:
```python
# 简洁调用栈
gdb_backtrace(session_id)

# 详细调用栈（包含变量）
gdb_backtrace(session_id, full=True)

# 限制帧数
gdb_backtrace(session_id, limit=5)
```

### gdb_print
计算并打印表达式值。

```python
gdb_print(sessionId, expression)
```

**参数**:
- `sessionId`: GDB 会话 ID
- `expression`: 要计算的表达式

**示例**:
```python
# 打印变量
gdb_print(session_id, "x")

# 计算表达式
gdb_print(session_id, "rax + rbx")

# 解引用指针
gdb_print(session_id, "*((int*)0x7fffffffde00)")
```

## 通用命令

### gdb_command
执行任意 GDB 命令。**最灵活的工具**。

```python
gdb_command(sessionId, command)
```

**常用命令**:

| 命令 | 用途 | 示例 |
|------|------|------|
| `file <binary>` | 加载程序 | `gdb_command(sid, "file /bin/ls")` |
| `starti` | 启动并停在入口点 | `gdb_command(sid, "starti")` |
| `info files` | 显示段地址（获取基地址） | `gdb_command(sid, "info files")` |
| `info proc mappings` | 显示内存映射 | `gdb_command(sid, "info proc mappings")` |
| `info breakpoints` | 列出所有断点 | `gdb_command(sid, "info breakpoints")` |
| `delete breakpoints [N]` | 删除断点 | `gdb_command(sid, "delete breakpoints")` |
| `x/Nbx <addr>` | 查看 N 字节内存 | `gdb_command(sid, "x/16bx $rsp")` |
| `x/Ni <addr>` | 反汇编 N 条指令 | `gdb_command(sid, "x/10i 0x401000")` |
| `print <expr>` | 计算表达式 | `gdb_command(sid, "print $rax + 1")` |
| `set $reg = value` | 修改寄存器 | `gdb_command(sid, "set $rax = 0")` |
| `run < input.txt` | 带输入运行 | `gdb_command(sid, "run < input.txt")` |
| `info locals` | 显示局部变量 | `gdb_command(sid, "info locals")` |
| `info args` | 显示函数参数 | `gdb_command(sid, "info args")` |
| `disas` | 反汇编当前函数 | `gdb_command(sid, "disas")` |

## 典型使用流程

### 完整调试会话

```python
# 1. 创建会话
session_id = gdb_start(workingDir="/tmp")

# 2. 加载程序（两种方式）

# 方式 A: 使用 gdb_load
gdb_load(session_id, "/path/to/binary", ["--arg1", "value1"])
gdb_command(session_id, "starti")

# 方式 B: 使用 gdb_command
gdb_command(session_id, "file /path/to/binary")
gdb_command(session_id, "starti")

# 3. 获取基地址（用于 ASLR 计算）
output = gdb_command(session_id, "info files")
# 从 output 解析基地址，例如: 0x555555554000

# 4. 设置断点
base_addr = 0x555555554000
offset = 0x12f0
gdb_set_breakpoint(session_id, f"*{base_addr + offset:x}")

# 5. 继续执行
gdb_continue(session_id)

# 6. 检查状态
gdb_info_registers(session_id)
gdb_examine(session_id, "0x7fffffffde00", "x", 64)
gdb_backtrace(session_id)

# 7. 单步调试
gdb_step(session_id)
gdb_next(session_id)

# 8. 清理
gdb_terminate(session_id)
```

### 附加到运行进程

```python
# 1. 创建会话并附加
session_id = gdb_start()
gdb_attach(session_id, 12345)  # PID 12345

# 2. 设置断点
gdb_set_breakpoint(session_id, "function_name")

# 3. 继续执行
gdb_continue(session_id)

# 4. 清理
gdb_command(session_id, "detach")  # 分离进程
gdb_terminate(session_id)
```

### 分析核心转储

```python
# 1. 创建会话
session_id = gdb_start()

# 2. 加载核心转储
gdb_load_core(session_id, "/path/to/binary", "/path/to/core")

# 3. 检查崩溃现场
gdb_backtrace(session_id, full=True)
gdb_info_registers(session_id)
gdb_print(session_id, "variable_name")

# 4. 清理
gdb_terminate(session_id)
```

## 工具参数说明

### sessionId
所有操作（除 `gdb_start` 和 `gdb_list_sessions`）都需要 sessionId。
- 由 `gdb_start` 返回
- 传递给所有后续操作
- 使用完毕后调用 `gdb_terminate` 清理

### location 格式
断点位置支持多种格式:

| 格式 | 示例 | 说明 |
|------|------|------|
| 绝对地址 | `"*0x555555555a10"` | 必须带 `*` 前缀 |
| 函数名 | `"main"` | 函数入口 |
| 文件:行号 | `"file.c:42"` | 源代码位置 |
| 偏移 | `"*0x401000+0x10"` | 地址 + 偏移 |
| 当前行 | `"*$pc"` | 当前程序计数器 |

### expression 格式
`gdb_examine` 和 `gdb_print` 支持的表达式:

| 表达式 | 说明 |
|--------|------|
| `0x7fffffffde00` | 绝对地址 |
| `$rsp` | 寄存器 |
| `$rsp + 16` | 寄存器运算 |
| `*(int*)0x...` | 内存解引用 |
| `array[0]` | 数组元素 |
| `struct->field` | 结构体字段 |

## 实战示例

### 示例 1: 调试运行中的 Nginx 进程

**场景**: 生产环境 Nginx worker 进程内存泄漏，需要调试但不重启服务

```python
# 1. 查找进程
# $ ps aux | grep nginx
# nginx   12345 ... nginx: worker process

# 2. 附加到运行进程
session_id = gdb_start()
gdb_attach(session_id, 12345)

# 3. 分析内存使用
gdb_command(session_id, "info proc mappings")  # 查看内存映射
gdb_command(session_id, "info address heap")    # 定位堆地址

# 4. 设置断点观察 malloc 调用
gdb_set_breakpoint(session_id, "malloc")
gdb_continue(session_id)

# 5. 每次断点命中检查分配大小
# 断点命中后
gdb_backtrace(session_id)  # 查看调用栈，定位泄漏源
gdb_print(session_id, "$rdi")  # malloc 的 size 参数

# 6. 分离进程（不终止 Nginx）
gdb_command(session_id, "detach")
gdb_terminate(session_id)
```

### 示例 2: 分析核心转储定位空指针解引用

**场景**: 生产环境程序崩溃，核心转储显示 SIGSEGV

```python
# 1. 加载核心转储
session_id = gdb_start()
gdb_load_core(
    session_id,
    "/usr/local/bin/myapp",
    "/var/lib/systemd/coredump/core.myapp.1001.deadbeef"
)

# 2. 查看崩溃位置
gdb_backtrace(session_id)
# 输出:
# #0  0x00000000004012ab in process_config (config=0x0) at config.c:156
# #1  0x00000000004010cd in main (argc=1, argv=0x7fffffffddf8) at main.c:42

# 3. 检查崩溃时的寄存器
gdb_info_registers(session_id, "rdi")
# 输出: rdi            0x0                 0

# 4. 查看崩溃代码附近的汇编
gdb_command(session_id, "x/10i $rip-0x20")
# 输出:
# 0x401295 <process_config+69>:  mov    rdi,QWORD PTR [rbp-0x18]
# 0x401299 <process_config+73>:  call   0x401050 <validate>
# 0x40129e <process_config+78>:  mov    rax,QWORD PTR [rdi]  ← 崩溃行

# 5. 验证: config 为 NULL，直接解引用导致崩溃
gdb_print(session_id, "config")
# 输出: $1 = (config_t *) 0x0

# 6. 返回调用者检查 config 初始化
gdb_command(session_id, "frame 1")  # 切换到 #1 帧
gdb_print(session_id, "config")
# 输出: $2 = (config_t *) 0x0
# → 调用者未初始化 config 参数

gdb_terminate(session_id)
```

### 示例 3: 使用 gdb_finish 分析递归函数

**场景**: 验证递归函数的返回值

```python
session_id = gdb_start()
gdb_load(session_id, "/path/to/program")
gdb_command(session_id, "starti")

# 设置断点在递归函数
gdb_set_breakpoint(session_id, "recursive factorial")
gdb_continue(session_id)

# 第一次调用: factorial(5)
gdb_print(session_id, "$rdi")  # 参数 n = 5

# 跳到函数返回
gdb_finish(session_id)
gdb_info_registers(session_id, "rax")  # 返回值 = 120 (5!)

# 继续到第二次递归调用
gdb_step(session_id)  # 进入 factorial(4)
gdb_print(session_id, "$rdi")  # n = 4

gdb_finish(session_id)
gdb_info_registers(session_id, "rax")  # 返回值 = 24 (4!)

gdb_terminate(session_id)
```

### 示例 4: 使用 gdb_print 进行复杂表达式求值

**场景**: 验证链表结构在内存中的布局

```python
# C 结构体:
# typedef struct node {
#     int value;
#     struct node* next;
# } node_t;

session_id = gdb_start()
gdb_load(session_id, "/path/to/program")
gdb_command(session_id, "starti")

# 假设 $rdi 指向链表头
gdb_print(session_id, "$rdi")  # 链表头指针
# 输出: $1 = (node_t *) 0x555555558000

# 查看第一个节点
gdb_print(session_id, "*((node_t*)$rdi)")
# 输出: $2 = {value = 10, next = 0x555555558010}

# 遍历链表
gdb_print(session_id, "((node_t*)$rdi)->value")
# 输出: $3 = 10

gdb_print(session_id, "((node_t*)$rdi)->next")
# 输出: $4 = (node_t *) 0x555555558010

# 计算链表长度
gdb_command(session_id, "set $len = 0")
gdb_command(session_id, "set $node = (node_t*)$rdi")
gdb_command(session_id, "while $node != 0")
gdb_command(session_id, "set $len = $len + 1")
gdb_command(session_id, "set $node = $node->next")
gdb_command(session_id, "end")
gdb_print(session_id, "$len")
# 输出: $5 = 5

gdb_terminate(session_id)
```

### 示例 5: 使用条件断点捕获特定条件

**场景**: 捕获缓冲区溢出时的特定输入

```python
session_id = gdb_start()
gdb_load(session_id, "/path/to/vulnerable_program")
gdb_command(session_id, "starti")

# 静态分析发现 strcpy 存在溢出风险
# 目标: 仅在输入长度 > 128 时触发断点

# 1. 找到 strcpy 地址
gdb_command(session_id, "print strcpy")
# 输出: $1 = {char *(char *, const char *)} 0x7ffff7a5e100 <strcpy>

# 2. 设置条件断点
gdb_set_breakpoint(
    session_id,
    "*0x7ffff7a5e100",
    "strlen((char*)$rsi) > 128"
)

# 3. 运行程序
gdb_command(session_id, "run < /tmp/large_input.txt")

# 4. 断点命中时检查
gdb_backtrace(session_id)
gdb_print(session_id, "strlen((char*)$rsi)")  # 源字符串长度
gdb_print(session_id, "$rdi")                 # 目标缓冲区地址

# 5. 验证溢出
gdb_command(session_id, "x/50bx $rdi")        # 查看缓冲区内容
gdb_step(session_id)
gdb_command(session_id, "x/50bx $rdi")        # 查看溢出后内容

gdb_terminate(session_id)
```

### 示例 6: 结合步进和表达式求值

**场景**: 分析复杂算法的中间值

```python
# C 代码:
# int calculate(int x, int y) {
#     int result = (x * x) + (2 * x * y) + (y * y);
#     return result;
# }

session_id = gdb_start()
gdb_load(session_id, "/path/to/program")
gdb_command(session_id, "starti")

gdb_set_breakpoint(session_id, "calculate")
gdb_continue(session_id)

# 断点命中时
gdb_print(session_id, "$rdi")  # x 参数
# 输出: $1 = 5

gdb_print(session_id, "$rsi")  # y 参数
# 输出: $2 = 3

# 单步执行验证每一步
gdb_step(session_id)
gdb_print(session_id, "result")  # 未初始化

gdb_step(session_id)
gdb_print(session_id, "result")
# 输出: $3 = 25  (x * x)

gdb_step(session_id)
gdb_print(session_id, "result")
# 输出: $4 = 55  (25 + 2*5*3)

gdb_step(session_id)
gdb_print(session_id, "result")
# 输出: $5 = 64  (55 + 3*3 = 25 + 30 + 9)

gdb_finish(session_id)
gdb_info_registers(session_id, "rax")
# 输出: rax            0x40                64

gdb_terminate(session_id)
```

### 示例 7: 调试多线程程序

**场景**: 竞态条件分析

```python
session_id = gdb_start()
gdb_load(session_id, "/path/to/threaded_program")

# 1. 设置断点
gdb_set_breakpoint(session_id, "critical_section")

# 2. 运行程序
gdb_command(session_id, "run")

# 3. 断点命中时查看线程
gdb_command(session_id, "info threads")
# 输出:
#   Id   Target Id         Frame
# * 1    Thread 0x7ffff7fc6700 (LWP 12345) "program" critical_section ()
#   2    Thread 0x7ffff77c5700 (LWP 12346) "program" 0x00007ffff7a4f128 in raise ()

# 4. 切换线程
gdb_command(session_id, "thread 2")

# 5. 查看该线程的栈
gdb_backtrace(session_id)

# 6. 检查共享变量
gdb_print(session_id, "shared_counter")

# 7. 继续执行观察竞态
gdb_continue(session_id)

gdb_terminate(session_id)
```

## 工具使用最佳实践

### gdb_print vs gdb_examine 选择

| 场景 | 推荐工具 | 原因 |
|------|---------|------|
| 查看已知类型的变量 | `gdb_print` | 自动处理类型和格式 |
| 检查指针解引用 | `gdb_print` | 理解指针类型 |
| 查看原始内存字节 | `gdb_examine` | 不需要类型信息 |
| 反汇编指令 | `gdb_examine(..., "i")` | 特化于指令 |
| 验证表达式 | `gdb_print` | 支持复杂表达式 |
| 搜索内存模式 | `gdb_command "find"` | 更强大 |

### 断点策略

| 断点类型 | 设置方法 | 使用场景 |
|---------|---------|---------|
| 函数断点 | `gdb_set_breakpoint(sid, "function")` | 已知函数名 |
| 地址断点 | `gdb_set_breakpoint(sid, "*0x...")` | 精确地址 |
| 条件断点 | `gdb_set_breakpoint(sid, loc, cond)` | 特定条件触发 |
| 临时断点 | `gdb_command(sid, "tbreak ...")` | 一次性断点 |
| 硬件断点 | `gdb_command(sid, "hbreak ...")` | 监视内存写入 |

### 性能优化

**使用 gdb_finish 而非手动步进**:
```python
# ❌ 慢: 函数有 1000 行代码
for _ in range(1000):
    gdb_step(session_id)

# ✅ 快: 直接跳到返回
gdb_finish(session_id)
```

**使用条件断点而非手动检查**:
```python
# ❌ 慢: 每次都手动检查
gdb_set_breakpoint(session_id, "loop")
gdb_continue(session_id)
# 手动检查 i == 100

# ✅ 快: 仅在条件满足时停止
gdb_set_breakpoint(session_id, "loop", "i == 100")
gdb_continue(session_id)
```

## 与旧 MCP 工具对比

| 旧工具名称 | 新工具名称 | 变化 |
|-----------|-----------|------|
| `create_session` | `gdb_start` | 重命名 |
| `close_session` | `gdb_terminate` | 重命名 |
| `get_session` / `get_all_sessions` | `gdb_list_sessions` | 简化 |
| `start_debugging` | `gdb_load` + 命令 | 拆分为加载和执行 |
| `continue_execution` | `gdb_continue` | 重命名 |
| `step_execution` | `gdb_step` | 重命名 |
| `next_execution` | `gdb_next` | 重命名 |
| `set_breakpoint` | `gdb_set_breakpoint` | 重命名 |
| `get_registers` | `gdb_info_registers` | 重命名 |
| `read_memory` | `gdb_examine` | 重命名，更灵活 |
| `get_stack_frames` | `gdb_backtrace` | 重命名 |
| `get_local_variables` | `gdb_command "info locals"` | 改用通用命令 |

**新增工具**:
- `gdb_attach` - 附加到运行进程
- `gdb_load_core` - 核心转储分析
- `gdb_finish` - 运行到函数返回
- `gdb_print` - 表达式求值
