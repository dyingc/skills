---
name: gdb-dynamic-analysis
description: 使用 GDB MCP 服务器进行动态二进制分析。用于：(1) 验证静态分析假设，(2) 跟踪实际执行流程，(3) 在特定点检查内存和寄存器，(4) 观察运行时程序行为，(5) 调试二进制程序。当用户请求运行时验证、断点调试、内存检查、执行跟踪、或需要观察程序实际运行状态时触发此技能。
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
| 会话管理 | `create_session`, `close_session`, `get_session` |
| 执行控制 | `start_debugging`, `continue_execution`, `step_execution`, `next_execution` |
| 断点管理 | `set_breakpoint`, `delete_breakpoint`, `get_breakpoints` |
| 状态检查 | `get_registers`, `read_memory`, `get_stack_frames`, `get_local_variables` |
| 任意命令 | `gdb_command` (执行任意 GDB 命令) |

## 分析工作流

### 1. 会话启动
```
□ create_session: 创建 GDB 会话
□ gdb_command "file <binary>": 加载目标程序
□ gdb_command "starti": 启动程序（停在入口点）
□ gdb_command "info files": 获取基地址（用于 ASLR 计算）
```

### 2. 断点设置
```
□ 计算实际地址: 基地址 + 静态偏移
□ set_breakpoint 或 gdb_command "break *<addr>": 设置断点
□ get_breakpoints: 确认断点已设置
```

### 3. 执行与检查
```
□ continue_execution: 运行到断点
□ get_registers: 检查寄存器状态
□ read_memory / gdb_command "x/...": 检查内存
□ get_stack_frames: 查看调用栈
```

### 4. 清理
```
□ close_session: 关闭会话（必须）
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

从 **static-binary-analysis** 技能获取:
- 目标函数的偏移地址（通过 `decompile_function`）
- 反编译代码作为参考
- 交叉引用确定断点位置（通过 `get_xrefs_to`）

**验证后**: 将动态分析发现反馈到静态分析，添加注释记录实际运行时行为。

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
| 会话异常 | `close_session` 后重新创建；检查二进制路径和权限 |
| 内存读取失败 | `info proc mappings` 检查内存布局；确认地址已映射 |
| 脚本死锁 | 终止会话，重新开始；参见 [deadlock-prevention.md](references/deadlock-prevention.md) |
