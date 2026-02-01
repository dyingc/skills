# 堆利用基础
堆是动态分配的内存区域，通过 malloc/free 管理。
- 常见漏洞：UAF、Double Free、Heap Overflow
- 堆管理器：ptmalloc2（glibc）
- 数据结构：bins、chunks、tcache
