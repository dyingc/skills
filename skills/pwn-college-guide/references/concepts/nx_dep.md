# NX/DEP
No-Execute (NX) 或 Data Execution Prevention (DEP) 标记栈和堆为不可执行。
- 防止直接执行注入的 shellcode
- 绕过方法：ROP、ret2libc、ret2syscall
- 检查：checksec 或 readelf -l binary | grep GNU_STACK
