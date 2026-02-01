# 格式化字符串漏洞
printf 系列函数使用不当导致的漏洞。
- 危险用法：printf(user_input) 而不是 printf("%s", user_input)
- 利用：读取栈内容、任意地址写
- 常用格式符：%p（泄露地址）、%n（写入）、%s（读字符串）
