# ASLR 和 PIE
Address Space Layout Randomization (ASLR) 和 Position Independent Executable (PIE) 是地址随机化保护机制。
- ASLR: 每次运行时随机化栈、堆、库的基地址
- PIE: 随机化程序代码段的基地址
绕过方法：信息泄露获取真实地址
