---
name: binary-analysis-orchestrator
description: Comprehensive binary analysis orchestrator that coordinates static, dynamic, and symbolic analysis techniques. Use this skill when the user asks to: (1) Analyze or reverse engineer a binary file, (2) Solve CTF challenges involving binaries, (3) Find vulnerabilities in binary programs, (4) Understand how a binary works, (5) Perform comprehensive security assessments. This skill determines the optimal analysis approach and coordinates the use of static-binary-analysis, gdb-dynamic-analysis, and angr-binary-analysis skills.
---

# Binary Analysis Orchestrator

## 核心行为

**语言**: 使用**简体中文**回复。代码、函数名、技术术语保持英文。

**角色**: 分析流程协调者，决定使用哪些工具并以何种顺序使用。

## 分析策略决策树

### 第一步：初始侦察（始终执行）

使用 **static-binary-analysis** 技能进行初步分析：

```
□ 识别二进制类型和架构
□ 检查安全保护（canary, NX, PIE, RELRO）
□ 提取字符串、导入函数、导出函数
□ 列出所有函数
□ 识别入口点和主要逻辑函数
```

**何时跳过**: 仅当用户明确要求动态调试或符号执行，且已经提供了详细的函数地址和逻辑信息。

### 第二步：选择主要分析方法

根据用户目标和发现，选择方法：

#### 场景 A：理解程序逻辑（最常见）

**用户意图**: "这个程序是做什么的？"、"分析这个二进制"

**方法**:
1. **static-binary-analysis**: 反编译关键函数
2. **gdb-dynamic-analysis** (可选): 验证复杂逻辑
3. 总结程序行为和关键算法

**示例**:
```
用户: "Analyze this binary"
→ 静态分析反编译 main()
→ 发现调用 check_password()
→ 反编译 check_password()
→ 发现 XOR 加密逻辑
→ 总结: "程序读取输入，XOR 加密后与目标比较"
```

#### 场景 B：查找漏洞

**用户意图**: "这个二进制有漏洞吗？"、"Find vulnerabilities"

**方法**:
1. **static-binary-analysis**: 识别危险函数调用
2. 检查用户输入到危险操作的数据流
3. **gdb-dynamic-analysis**: 验证漏洞可利用性
4. **angr-binary-analysis** (可选): 自动生成利用输入

**危险函数模式**:
- `gets`, `strcpy`, `sprintf` → 栈溢出
- `memcpy`, `malloc` 大小未验证 → 堆溢出
- 格式化字符串 `printf(user_input)` → 格式化字符串漏洞
- 整数溢出导致缓冲区过小 → 逻辑漏洞

#### 场景 C：解决 CTF 挑战

**用户意图**: "Solve this CTF challenge"、"获取 flag"

**判断标准**:

| 挑战类型 | 主要方法 | 辅助方法 |
|---------|---------|---------|
| 简单路径查找 | **angr-binary-analysis** | static (理解) |
| 需要特定格式输入 | **angr-binary-analysis** | static (提取格式) |
| 需要理解复杂逻辑 | **static-binary-analysis** → angr | - |
| 需要运行时状态 | **gdb-dynamic-analysis** | static (获取地址) |
| 动态密钥/随机值 | **gdb-dynamic-analysis** → angr | static (定位) |

**工作流**:
```
1. static: 快速侦察，识别输入类型和验证逻辑
2. 判断:
   - 标准输入/输出 + 简单检查 → angr
   - scanf/复杂输入 → angr (hook)
   - 静态链接 → angr (hook libc)
   - 运行时生成密钥 → gdb (提取) → angr
   - 极其复杂逻辑 → gdb (手动) 或 混合分析
3. 生成解决方案
```

#### 场景 D：验证假设

**用户意图**: "验证一下这个函数"、"确认这个偏移"

**方法**: **gdb-dynamic-analysis**
- 设置断点
- 单步执行
- 检查内存/寄存器
- 确认静态分析的推断

### 第三步：迭代深化分析

根据第二步的发现，可能需要：

**静态分析发现不确定**:
```
→ 使用 gdb 动态验证
→ 将发现注释回 Ghidra
```

**动态分析发现复杂控制流**:
```
→ 使用 angr 符号执行探索所有路径
→ 生成覆盖所有路径的测试用例
```

**符号执行失败（路径爆炸）**:
```
→ 回到静态分析，添加约束
→ 使用 gdb 手动探索关键路径
→ 结合两种方法
```

## 工作流示例

### 示例 1：简单 CTF 挑战

```
用户: "Solve this CTF binary"

1. static-binary-analysis:
   - 反编译 main()
   - 发现: 读取 16 字节，与固定值比较
   - 提取目标值

2. angr-binary-analysis:
   - 符号执行输入
   - 约束到成功路径
   - 输出: 正确输入

3. 验证:
   - 运行 binary，输入解
   - 确认获取 flag
```

### 示例 2：堆漏洞利用

```
用户: "Find vulnerabilities in this binary"

1. static-binary-analysis:
   - 识别 heap management 函数
   - 发现 malloc 大小可控
   - 交叉引用到用户输入

2. gdb-dynamic-analysis:
   - 断点在 malloc/strcpy
   - 运行测试输入
   - 验证堆溢出
   - 分析堆布局

3. 报告:
   - 漏洞类型：堆溢出
   - 触发条件：输入 > 128 字节
   - 影响范围：可覆盖下一个 chunk 的 metadata
```

### 示例 3：复杂逻辑 + 运行时密钥

```
用户: "Analyze this binary with runtime key generation"

1. static-binary-analysis:
   - 识别 keygen 函数
   - 识别加密函数
   - 交叉引用分析

2. gdb-dynamic-analysis:
   - 断点在 keygen 之后
   - 提取运行时生成的密钥
   - 跟踪加密过程

3. (可选) angr-binary-analysis:
   - 使用提取的密钥约束
   - 符号执行其余部分
   - 或直接使用密钥解密
```

## 工具选择优先级

| 任务 | 首选工具 | 次选工具 | 不推荐 |
|-----|---------|---------|--------|
| 初始侦察 | static | - | gdb/angr |
| 理解算法 | static | gdb (验证) | angr |
| 快速解 CTF | angr | static → angr | gdb |
| 漏洞挖掘 | static → gdb | - | angr |
| 调试崩溃 | gdb | static (上下文) | - |
| 路径探索 | angr | gdb | static |
| ASLR 绕过 | gdb (计算) | static (偏移) | - |

## 与子技能协作

### 使用 static-binary-analysis

**调用时机**: 总是第一步

**传递信息**:
- 如果用户有特定函数: "反编译 function_name"
- 如果查找漏洞: "检查危险函数调用"
- 如果需要字符串: "搜索包含 'password' 的字符串"

**提取信息**:
- 函数偏移地址（给 gdb）
- 反编译代码（给 angr 理解逻辑）
- 交叉引用（确定关键点）

### 使用 gdb-dynamic-analysis

**调用时机**:
- 验证静态分析发现
- 观察运行时行为
- 提取动态生成的值
- 调试崩溃或异常

**传递信息**:
- 目标函数偏移（从 static 获取）
- 预期的行为
- 需要检查的内存区域

**提取信息**:
- 实际执行的路径
- 运行时值（密钥、地址）
- 内存布局

### 使用 angr-binary-analysis

**调用时机**:
- CTF 挑战需要自动求解
- 需要探索所有可能路径
- 需要生成满足约束的输入

**传递信息**:
- 二进制路径
- 输入类型（stdin, 参数, 文件）
- 成功条件（输出字符串或地址）

**提取信息**:
- 正确的输入值
- 到达目标的路径约束

## 常见模式

### 模式 1: Static → Angr (CTF 快速求解)

```
1. static: 快速理解输入格式和检查逻辑
2. angr: 自动生成满足约束的输入
3. 验证并输出 flag
```

### 模式 2: Static → GDB → Static (迭代分析)

```
1. static: 发现可疑代码段
2. gdb: 运行时验证，添加注释
3. static: 重新审视，发现新线索
4. 重复直到理解完整逻辑
```

### 模式 3: GDB → Angr (动态辅助符号执行)

```
1. gdb: 提取运行时生成的值（密钥、随机数）
2. static: 定位使用这些值的函数
3. angr: 使用提取的值约束，自动求解剩余部分
```

## 关键决策点

### 需要切换工具的信号

**从 Static 切换到 GDB**:
- 反编译输出不确定或明显错误
- 控制流极其复杂（多个间接跳转）
- 需要观察实际内存布局
- 静态分析假设需要验证

**从 Static 切换到 Angr**:
- 识别出标准 CTF 模式（路径查找 + 输入验证）
- 需要逆向推导输入
- 逻辑清晰但手工计算复杂

**从 Angr 切换到 GDB**:
- 符号执行路径爆炸
- 需要运行时信息（ASLR, 动态链接）
- 约束过于复杂

**从 GDB 切换到 Static**:
- 发现新函数，需要理解上下文
- 需要找到所有调用点
- 需要全局视图

## 常见错误及避免

### 错误 1: 一上来就用 angr

**问题**: 符号执行可能路径爆炸或耗时过长

**正确**: 先用 static 快速侦察，判断是否适合 angr

### 错误 2: 忽视静态分析直接调试

**问题**: 不知道在哪里设置断点，盲目调试

**正确**: static 获取函数列表和偏移，有针对性调试

### 错误 3: 过度依赖单一工具

**问题**: 每个工具都有局限性

**正确**: 根据发现灵活切换，组合使用

## 总结

这个协调技能的核心价值：

1. **降低认知负担**: 不需要记忆每个工具的细节
2. **提高效率**: 选择最优路径，避免试错
3. **保证完整性**: 系统化覆盖所有分析角度
4. **灵活应变**: 根据发现动态调整策略

**记住**: 工具是手段，不是目的。目标是高效、准确地理解或解决二进制分析问题。
