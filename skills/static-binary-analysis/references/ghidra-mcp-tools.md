# Ghidra MCP 工具参考

## 目录
1. [代码分析工具](#代码分析工具)
2. [导航与搜索](#导航与搜索)
3. [交叉引用分析](#交叉引用分析)
4. [注释与重命名](#注释与重命名)
5. [类型修改](#类型修改)
6. [数据与字符串](#数据与字符串)
7. [程序结构](#程序结构)

---

## 代码分析工具

### decompile_function
反编译指定函数，返回C伪代码。
```
参数: name (函数名)
用途: 快速理解函数逻辑
注意: 输出可能误导，复杂循环/指针运算需验证汇编
```

### decompile_function_by_address
按地址反编译函数。
```
参数: address (十六进制地址，如 "0x401000")
用途: 当函数名未知或分析特定地址时使用
```

### disassemble_function
获取函数汇编代码（地址: 指令; 注释）。
```
参数: address (函数起始地址)
用途: 验证反编译结果，分析底层行为
最佳实践: 反编译输出可疑时必查
```

### get_current_function
获取用户当前选中的函数。
```
参数: 无
用途: 配合Ghidra GUI交互分析
```

### get_function_by_address
按地址获取函数信息。
```
参数: address
返回: 函数名、入口点等元数据
```

---

## 导航与搜索

### list_functions
列出程序所有函数。
```
参数: 无
用途: 获取函数全览，规划分析顺序
```

### list_methods
分页列出所有函数名。
```
参数: offset (默认0), limit (默认100)
用途: 大型二进制分页浏览
```

### search_functions_by_name
按名称子串搜索函数。
```
参数: query (搜索词), offset, limit
示例: query="main" 找所有含main的函数
用途: 快速定位目标函数
```

### get_current_address
获取用户当前选中的地址。
```
参数: 无
用途: 配合GUI定位分析点
```

---

## 交叉引用分析

### get_xrefs_to
获取到指定地址的所有引用。
```
参数: address, offset, limit
用途: 找谁调用了这个地址/函数
场景: 追踪危险函数调用者（如system, strcpy）
```

### get_xrefs_from
获取从指定地址发出的所有引用。
```
参数: address, offset, limit
用途: 找这个地址引用了什么
场景: 分析函数依赖关系
```

### get_function_xrefs
按函数名获取所有引用。
```
参数: name (函数名), offset, limit
用途: 比get_xrefs_to更便捷，直接用函数名
```

---

## 注释与重命名

### set_plate_comment
在 Listing 视图顶部添加板注释（最显眼）。
```
参数: address, comment
格式: "Claude suggests - [中文注释内容]"
用途: 函数级摘要、重要警告、安全提示、高层行为描述
删除: 传递空字符串 "" 移除现有注释
特点: Ghidra 中最显眼的注释类型，适合需要立即可见的信息
```

### set_decompiler_comment
在反编译伪代码视图添加注释。
```
参数: address, comment
格式: "Claude suggests - [中文注释内容]"
用途: 解释复杂逻辑/算法、记录变量使用/数据流、添加代码上下文
删除: 传递空字符串 "" 移除现有注释
位置: 伪代码视图中，作为前置注释显示
```

### set_disassembly_comment
在反汇编视图添加注释。
```
参数: address, comment
格式: "Claude suggests - [中文注释内容]"
用途: 解释单个指令行为、注意寄存器值/内存访问、记录底层实现
删除: 传递空字符串 "" 移除现有注释
位置: 反汇编视图中，显示在行尾 (EOL)
```

### 注释类型选择指南

根据信息层级和重要性选择注释类型：

| 工具 | 可见性 | 适用层级 | 典型用例 |
|------|--------|----------|----------|
| set_plate_comment | ⭐⭐⭐ 最高 | 函数级 | "处理用户输入的主函数，存在缓冲区溢出风险" |
| set_decompiler_comment | ⭐⭐ 中 | 代码块级 | "检查输入长度，超过 256 字节则返回错误" |
| set_disassembly_comment | ⭐ 低 | 指令级 | "MOV EAX, [EBP+8] - 加载第一个参数" |

**删除注释**: 所有三个注释工具都支持通过传递空字符串 "" 作为 comment 参数来删除现有注释。

### rename_function
重命名函数。
```
参数: old_name, new_name
警告: 仅在名称明显错误/误导时使用
前置: 必须先理解函数功能
```

### rename_function_by_address
按地址重命名函数。
```
参数: function_address, new_name
用途: 函数名未知时使用
```

### rename_variable
重命名函数内局部变量。
```
参数: function_name, old_name, new_name
警告: 谨慎操作，确认变量用途后再改
```

### rename_data
重命名数据标签。
```
参数: address, new_name
用途: 给全局变量/数据起有意义的名字
```

---

## 类型修改

### set_function_prototype
设置函数原型。
```
参数: function_address, prototype
示例: prototype="int foo(char *buf, int size)"
警告: 极度谨慎！影响所有调用点的反编译
建议: 优先用注释说明，用户明确要求时才修改
```

### set_local_variable_type
设置局部变量类型。
```
参数: function_address, variable_name, new_type
警告: 可能影响反编译输出
建议: 仅在类型明显错误且影响局部时修改
```

---

## 数据与字符串

### list_strings
列出程序中所有字符串。
```
参数: offset, limit, filter (可选过滤词)
用途: 找关键字符串（密码提示、错误信息、格式串）
技巧: 用filter参数缩小范围，如filter="password"
```

### list_data_items
列出数据标签及值。
```
参数: offset, limit
用途: 查看全局变量、常量定义
```

---

## 程序结构

### list_segments
列出内存段。
```
参数: offset, limit
用途: 了解程序内存布局（.text, .data, .bss等）
```

### list_imports
列出导入符号。
```
参数: offset, limit
用途: 识别外部依赖，找危险函数（gets, strcpy, system）
```

### list_exports
列出导出符号。
```
参数: offset, limit
用途: 找程序入口点、库导出函数
```

### list_namespaces
列出命名空间。
```
参数: offset, limit
用途: C++程序分析类结构
```

### list_classes
列出类/命名空间名。
```
参数: offset, limit
用途: 面向对象程序结构分析
```
