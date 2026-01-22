# GDB MCP 工具参考

## 目录
- [会话管理](#会话管理)
- [调试控制](#调试控制)
- [断点管理](#断点管理)
- [状态检查](#状态检查)
- [通用命令](#通用命令)

## 会话管理

### create_session
创建新的 GDB 调试会话。

```python
create_session(gdb_path="gdb", working_dir="/path/to/dir")
```

**参数**:
- `gdb_path`: GDB 可执行文件路径（默认 "gdb"）
- `working_dir`: 工作目录

**返回**: `session_id` - 后续所有操作需要此 ID

### close_session
关闭 GDB 会话。**必须调用**以清理资源。

```python
close_session(session_id)
```

### get_session
获取会话状态信息。

```python
get_session(session_id)
```

### get_all_sessions
列出所有活动会话。

```python
get_all_sessions()
```

## 调试控制

### start_debugging
启动程序调试（等同于 `run`）。

```python
start_debugging(session_id, args="", input_file=None)
```

**参数**:
- `args`: 程序参数
- `input_file`: stdin 重定向文件

**注意**: 优先使用 `gdb_command "starti"` 以便在入口点停止。

### stop_debugging
停止当前调试。

```python
stop_debugging(session_id)
```

### continue_execution
继续执行直到下一个断点或程序结束。

```python
continue_execution(session_id)
```

### step_execution
单步执行，进入函数调用（step into）。

```python
step_execution(session_id)
```

### next_execution
单步执行，跳过函数调用（step over）。

```python
next_execution(session_id)
```

## 断点管理

### set_breakpoint
设置断点。

```python
set_breakpoint(session_id, location)
```

**参数**:
- `location`: 断点位置
  - 地址: `"*0x555555555a10"`
  - 函数名: `"main"`
  - 文件行号: `"file.c:42"`

### delete_breakpoint
删除断点。

```python
delete_breakpoint(session_id, breakpoint_id)
```

### get_breakpoints
列出所有断点。

```python
get_breakpoints(session_id)
```

**返回**: 断点列表，包含 ID、位置、状态

## 状态检查

### get_registers
获取所有寄存器值。

```python
get_registers(session_id)
```

**返回**: 寄存器名称和值的字典

### get_register_names
获取可用寄存器名称列表。

```python
get_register_names(session_id)
```

### read_memory
读取内存内容。

```python
read_memory(session_id, address, size)
```

**参数**:
- `address`: 起始地址（十六进制字符串或整数）
- `size`: 读取字节数

**返回**: 字节数据

### get_stack_frames
获取调用栈帧。

```python
get_stack_frames(session_id)
```

**返回**: 栈帧列表，包含函数名、地址、参数

### get_local_variables
获取当前帧的局部变量。

```python
get_local_variables(session_id)
```

## 通用命令

### gdb_command
执行任意 GDB 命令。**最灵活的工具**。

```python
gdb_command(session_id, command)
```

**常用命令**:

| 命令 | 用途 |
|------|------|
| `file <binary>` | 加载程序 |
| `starti` | 启动并停在入口点 |
| `info files` | 显示段地址（获取基地址） |
| `info proc mappings` | 显示内存映射 |
| `info registers` | 显示寄存器 |
| `x/Nbx <addr>` | 查看 N 字节内存 |
| `x/s <addr>` | 查看字符串 |
| `x/Ni <addr>` | 反汇编 N 条指令 |
| `print <expr>` | 计算表达式 |
| `set $reg = value` | 修改寄存器 |
| `break *<addr>` | 设置断点 |
| `run < input.txt` | 带输入运行 |

### gdb_print
计算并打印表达式（部分 MCP 实现可用）。

```python
gdb_print(session_id, expression)
```

等同于 `gdb_command(session_id, "print <expression>")`。

## 典型使用流程

```python
# 1. 创建会话
session_id = create_session(gdb_path="gdb", working_dir="/tmp")

# 2. 加载程序
gdb_command(session_id, "file /path/to/binary")

# 3. 启动（停在入口点）
gdb_command(session_id, "starti")

# 4. 获取基地址
output = gdb_command(session_id, "info files")
# 解析 output 获取基地址

# 5. 设置断点
set_breakpoint(session_id, "*0x5555555552f0")

# 6. 继续执行
continue_execution(session_id)

# 7. 检查状态
regs = get_registers(session_id)
mem = read_memory(session_id, "0x7fffffffde00", 64)

# 8. 清理
close_session(session_id)
```
