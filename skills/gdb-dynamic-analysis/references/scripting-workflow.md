# GDB 脚本开发流程

## 目录
- [何时使用脚本](#何时使用脚本)
- [脚本开发流程](#脚本开发流程)
- [处理脚本失败](#处理脚本失败)
- [脚本模板](#脚本模板)

## 何时使用脚本

**适合使用脚本**:
- 交互式逐命令验证完成后
- 需要重复执行的分析流程
- 命令序列可预测且确定

**不适合使用脚本**:
- 初始探索/调试阶段
- 命令依赖运行时决策
- 执行路径不确定

## 脚本开发流程

### 阶段 1: 命令验证
- 通过 `gdb_command` 逐个执行每条 GDB 命令
- 验证输出符合预期
- 记录每条命令的执行时间
- **所有命令都通过后才进入下一阶段**

### 阶段 2: 序列验证
- 按预定顺序逐个执行完整命令序列
- 仍使用独立的 `gdb_command` 调用，检查每个结果
- 确保命令在预期顺序下正常工作

### 阶段 3: 脚本编写
- 将验证过的命令转换为 .gdb 脚本文件
- 添加注释说明每个步骤
- 添加日志: `set logging file <path>; set logging on`
- 添加环境设置: `set pagination off; set confirm off`

### 阶段 4: 脚本测试
- 通过 `gdb_command "source <script_path>"` 运行脚本
- 等待执行完成
- 检查日志文件是否有错误
- 验证输出符合预期

## 处理脚本失败

脚本失败或死锁时:
1. 立即终止 GDB 会话（MCP: `gdb_terminate` 或 `close_session`）
2. 创建新会话（**不要复用损坏的会话**）
3. 回退到交互式探索模式
4. 第二次尝试时更谨慎——彻底测试每条命令
5. 考虑简化脚本

## 脚本模板

### 基础模板
```gdb
# ========================================
# 环境设置
# ========================================
set pagination off
set confirm off
set logging file /tmp/gdb_analysis.log
set logging on

# ========================================
# 断点设置
# ========================================
break *0x5555555512f0
break *0x5555555513a0

# ========================================
# 执行
# ========================================
run < input.txt

# ========================================
# 第一个断点检查
# ========================================
echo [+] 到达第一个断点\n
x/s $rdi
info registers rax rbx

# ========================================
# 继续到下一个断点
# ========================================
continue

# ========================================
# 第二个断点检查
# ========================================
echo [+] 到达第二个断点\n
x/32bx $rsp
info registers

# ========================================
# 清理
# ========================================
set logging off
echo [+] 脚本执行完成\n
quit
```

### 带条件检查的模板
```gdb
set pagination off
set confirm off

break *0x555555555100

run < input.txt

# 检查程序是否仍在运行
if $_inferior == 0
  echo [!] 程序已退出\n
else
  echo [+] 程序运行中\n
  x/s $rdi
  info registers
end

quit
```

### 循环检查模板
```gdb
set pagination off
set confirm off

break *0x555555555200

run < input.txt

set $count = 0
while $count < 10
  if $_inferior == 0
    echo [!] 程序已退出\n
    loop_break
  end

  echo [+] 迭代次数:
  print $count

  x/s $rdi
  continue
  set $count = $count + 1
end

quit
```

## 注意事项

1. **始终在脚本开头设置环境**
   ```gdb
   set pagination off
   set confirm off
   ```

2. **使用日志记录输出**
   ```gdb
   set logging file /tmp/debug.log
   set logging on
   ```

3. **脚本结束时显式退出**
   ```gdb
   quit
   ```

4. **避免使用以下命令**（参见 [deadlock-prevention.md](deadlock-prevention.md)）
   - `until`
   - `finish`（除非已验证安全）
   - 无断点的 `continue`
