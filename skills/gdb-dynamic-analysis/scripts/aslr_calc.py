#!/usr/bin/env python3
"""
ASLR 地址计算工具

计算运行时实际地址: 实际地址 = 基地址 + 静态偏移

用法:
    python aslr_calc.py <base_addr> <offset>
    python aslr_calc.py <base_addr> <offset1> <offset2> ...

示例:
    # 单个偏移
    python aslr_calc.py 0x555555554000 0x12f0
    # 输出: 0x5555555552f0

    # 多个偏移
    python aslr_calc.py 0x555555554000 0x12f0 0x1a10 0x1b20
    # 输出:
    # 0x12f0 -> 0x5555555552f0
    # 0x1a10 -> 0x555555555a10
    # 0x1b20 -> 0x555555555b20
"""

import sys


def parse_addr(addr_str: str) -> int:
    """解析地址字符串（支持 0x 前缀和纯数字）"""
    addr_str = addr_str.strip()
    if addr_str.startswith("0x") or addr_str.startswith("0X"):
        return int(addr_str, 16)
    # 如果包含 a-f 字符，视为十六进制
    if any(c in addr_str.lower() for c in "abcdef"):
        return int(addr_str, 16)
    # 否则尝试十六进制，失败则十进制
    try:
        return int(addr_str, 16)
    except ValueError:
        return int(addr_str)


def main():
    if len(sys.argv) < 3:
        print("用法: python aslr_calc.py <base_addr> <offset> [offset2 ...]")
        print("示例: python aslr_calc.py 0x555555554000 0x12f0")
        sys.exit(1)

    try:
        base_addr = parse_addr(sys.argv[1])
    except ValueError:
        print(f"错误: 无效的基地址 '{sys.argv[1]}'")
        sys.exit(1)

    offsets = sys.argv[2:]

    if len(offsets) == 1:
        # 单个偏移，简洁输出
        try:
            offset = parse_addr(offsets[0])
            result = base_addr + offset
            print(f"0x{result:x}")
        except ValueError:
            print(f"错误: 无效的偏移 '{offsets[0]}'")
            sys.exit(1)
    else:
        # 多个偏移，详细输出
        for offset_str in offsets:
            try:
                offset = parse_addr(offset_str)
                result = base_addr + offset
                print(f"0x{offset:x} -> 0x{result:x}")
            except ValueError:
                print(f"0x{offset_str} -> 错误: 无效的偏移")


if __name__ == "__main__":
    main()
