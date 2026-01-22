# 常见漏洞模式参考

## 目录
1. [栈缓冲区溢出](#栈缓冲区溢出)
2. [堆漏洞](#堆漏洞)
3. [格式化字符串](#格式化字符串)
4. [整数问题](#整数问题)
5. [Use-After-Free](#use-after-free)
6. [命令注入](#命令注入)
7. [竞态条件](#竞态条件)
8. [逻辑漏洞](#逻辑漏洞)

---

## 栈缓冲区溢出

### 危险函数
```c
gets()          // 无边界检查，必溢出
strcpy()        // 无长度限制
strcat()        // 同上
sprintf()       // 无长度限制
scanf("%s")     // 无长度限制
```

### 识别特征
- 栈上固定大小缓冲区 + 无边界检查的输入
- 反编译中看到 `char local_XX[N]` 配合危险函数
- 汇编中 `sub rsp, 0xXX` 配合直接写入

### 分析要点
```
1. 确认缓冲区大小: 查看栈帧布局
2. 确认输入来源: 用户可控?
3. 计算溢出距离: 到返回地址/canary的偏移
4. 检查保护: canary, NX, PIE
```

### Ghidra分析
```
- list_imports: 搜索危险函数
- get_function_xrefs: 追踪调用点
- disassemble_function: 确认栈布局
```

---

## 堆漏洞

### 常见类型
- **堆溢出**: 写入超过分配大小
- **Double Free**: 同一块内存释放两次
- **UAF**: 释放后继续使用
- **越界读写**: 数组索引未校验

### 识别特征
```c
// 堆溢出
malloc(size) 后 memcpy(ptr, src, larger_size)

// Double Free
free(ptr); ... free(ptr);

// 可疑模式
ptr = malloc(user_size);    // 用户控制大小
ptr[user_index] = value;    // 用户控制索引
```

### 分析要点
```
1. 追踪分配: malloc/calloc/realloc调用
2. 追踪释放: free调用，检查路径
3. 追踪使用: 指针解引用，检查释放后使用
4. 大小计算: 整数溢出可能导致小分配
```

---

## 格式化字符串

### 危险模式
```c
printf(user_input);         // 直接使用用户输入
fprintf(fp, user_input);
sprintf(buf, user_input);
snprintf(buf, n, user_input);
```

### 安全模式
```c
printf("%s", user_input);   // 安全
```

### 利用能力
- **信息泄露**: `%p%p%p` 泄露栈内容
- **任意读**: `%s` 配合栈上地址
- **任意写**: `%n` 写入已打印字符数
- **栈控制**: `%N$` 直接访问参数

### Ghidra分析
```
- list_strings: filter="%" 找格式串
- get_xrefs_to printf家族: 检查参数来源
- 反编译确认: 第一个参数是否用户可控
```

---

## 整数问题

### 溢出类型
```c
// 有符号溢出
int size = user_int + 100;  // 可能负数

// 无符号回绕
unsigned int a = 0xFFFFFFFF;
a + 1 == 0;

// 截断
int size = (short)user_int; // 高位丢失

// 符号扩展
int idx = (char)user_byte;  // 负数扩展
```

### 危险场景
```c
// 分配计算
size_t total = count * elem_size;  // 可能溢出
malloc(total);

// 边界检查绕过
if (idx < array_len) {     // idx为负数时通过
    array[idx] = val;      // 越界写
}
```

### 分析要点
```
1. 识别类型: 有符号/无符号，宽度
2. 追踪来源: 用户输入如何影响计算
3. 检查运算: 乘法/加法可能溢出
4. 检查转换: 类型转换可能截断/扩展
```

---

## Use-After-Free

### 模式
```c
free(obj);
// ... 其他代码，可能不清理指针 ...
obj->method();    // UAF
```

### 识别特征
- 指针释放后未置NULL
- 多个指针指向同一内存
- 错误路径中提前释放
- 回调函数中对象生命周期问题

### 分析要点
```
1. 追踪对象生命周期
2. 检查所有释放路径
3. 检查释放后的引用
4. 关注错误处理路径
```

---

## 命令注入

### 危险函数
```c
system(cmd);
popen(cmd, mode);
execl/execv/execve 系列
```

### 危险模式
```c
sprintf(cmd, "ls %s", user_input);
system(cmd);  // 用户可注入 ; rm -rf /
```

### Shell元字符
```
; | & $ ` ' " \ < > ( ) { } [ ] ! ~ * ?
```

### 分析要点
```
1. 找命令执行函数
2. 追踪参数来源
3. 检查是否有过滤/转义
4. 检查环境变量影响
```

---

## 竞态条件

### 常见类型
- **TOCTOU**: 检查时与使用时状态变化
- **信号处理**: 信号中断导致不一致
- **多线程**: 共享数据无同步

### TOCTOU示例
```c
if (access(file, W_OK) == 0) {  // 检查
    // 攻击窗口: 文件可能被替换
    fd = open(file, O_WRONLY);   // 使用
}
```

### 分析要点
```
1. 识别检查-使用序列
2. 评估时间窗口
3. 检查锁/同步机制
4. 文件操作注意符号链接
```

---

## 逻辑漏洞

### 认证绕过
```c
if (check_password(input)) {
    authenticated = 1;
}
// 忘记else分支，authenticated可能未初始化
```

### 权限检查缺失
```c
void admin_action() {
    // 缺少 if (!is_admin()) return;
    do_sensitive_operation();
}
```

### 状态机错误
```c
// 状态转换缺少验证
current_state = new_state;  // 任意状态跳转
```

### 分析要点
```
1. 绘制程序流程图
2. 检查所有分支路径
3. 验证状态转换合法性
4. 检查错误处理是否完整
```

---

## 快速检查清单

### 初始分析
```
□ list_imports: 找危险函数
□ list_strings: filter敏感词（password, admin, secret）
□ list_exports: 确认入口点
```

### 深入分析
```
□ 危险函数xrefs: 追踪所有调用
□ 输入处理函数: main, read, recv, fgets等
□ 边界检查: 数组访问、内存操作
□ 类型转换: 符号/大小变化
```

### 漏洞确认
```
□ 反编译 + 汇编对比
□ 追踪数据流: 从输入到危险操作
□ 计算具体值: 溢出点、偏移量
□ 考虑保护机制: canary, ASLR, NX
```
