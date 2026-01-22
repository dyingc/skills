#!/usr/bin/env python3
"""
测试输入生成工具

生成用于动态分析的测试输入文件。

用法:
    python create_input.py <type> [options]

类型:
    pattern  - 生成模式字符串（用于定位溢出偏移）
    padding  - 生成填充数据
    payload  - 生成带地址的 payload

示例:
    # 生成 100 字节模式字符串
    python create_input.py pattern -n 100 -o input.txt

    # 生成 64 字节 'A' 填充
    python create_input.py padding -n 64 -c A -o input.txt

    # 生成填充 + 地址的 payload
    python create_input.py payload -n 64 -a 0x401234 -o input.txt

    # 查找模式偏移
    python create_input.py pattern --find "Ab3A"
"""

import sys
import struct
import argparse


def generate_pattern(length: int) -> bytes:
    """
    生成循环模式字符串（用于定位溢出偏移）

    模式格式: Aa0Aa1Aa2...Ab0Ab1...Ba0Ba1...
    每4字节唯一，可用于精确定位覆盖位置
    """
    pattern = []
    for upper in range(ord("A"), ord("Z") + 1):
        for lower in range(ord("a"), ord("z") + 1):
            for digit in range(ord("0"), ord("9") + 1):
                if len(pattern) >= length:
                    return bytes(pattern[:length])
                pattern.append(upper)
                if len(pattern) >= length:
                    return bytes(pattern[:length])
                pattern.append(lower)
                if len(pattern) >= length:
                    return bytes(pattern[:length])
                pattern.append(digit)
                if len(pattern) >= length:
                    return bytes(pattern[:length])
                pattern.append(upper)
    return bytes(pattern[:length])


def find_pattern_offset(pattern_bytes: bytes) -> int:
    """查找模式在完整模式中的偏移"""
    full_pattern = generate_pattern(20280)  # 最大模式长度
    try:
        return full_pattern.index(pattern_bytes)
    except ValueError:
        return -1


def generate_padding(length: int, char: str = "A") -> bytes:
    """生成填充数据"""
    return (char.encode() * length)[:length]


def generate_payload(padding_len: int, address: int, endian: str = "little") -> bytes:
    """生成填充 + 地址的 payload"""
    padding = generate_padding(padding_len)
    if endian == "little":
        addr_bytes = struct.pack("<Q", address)
    else:
        addr_bytes = struct.pack(">Q", address)
    return padding + addr_bytes


def main():
    parser = argparse.ArgumentParser(
        description="测试输入生成工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python create_input.py pattern -n 100 -o input.txt
  python create_input.py padding -n 64 -c A -o input.txt
  python create_input.py payload -n 64 -a 0x401234 -o input.txt
  python create_input.py pattern --find "Ab3A"
        """,
    )

    subparsers = parser.add_subparsers(dest="type", help="输入类型")

    # pattern 子命令
    pattern_parser = subparsers.add_parser("pattern", help="生成模式字符串")
    pattern_parser.add_argument("-n", "--length", type=int, default=100, help="长度（字节）")
    pattern_parser.add_argument("-o", "--output", help="输出文件（默认 stdout）")
    pattern_parser.add_argument("--find", help="查找模式偏移")

    # padding 子命令
    padding_parser = subparsers.add_parser("padding", help="生成填充数据")
    padding_parser.add_argument("-n", "--length", type=int, required=True, help="长度（字节）")
    padding_parser.add_argument("-c", "--char", default="A", help="填充字符（默认 A）")
    padding_parser.add_argument("-o", "--output", help="输出文件（默认 stdout）")

    # payload 子命令
    payload_parser = subparsers.add_parser("payload", help="生成 payload")
    payload_parser.add_argument("-n", "--padding", type=int, required=True, help="填充长度")
    payload_parser.add_argument("-a", "--address", required=True, help="目标地址（如 0x401234）")
    payload_parser.add_argument("-e", "--endian", choices=["little", "big"], default="little", help="字节序")
    payload_parser.add_argument("-o", "--output", help="输出文件（默认 stdout）")

    args = parser.parse_args()

    if not args.type:
        parser.print_help()
        sys.exit(1)

    # 处理各类型
    if args.type == "pattern":
        if args.find:
            # 查找模式偏移
            pattern_bytes = args.find.encode()
            offset = find_pattern_offset(pattern_bytes)
            if offset >= 0:
                print(f"模式 '{args.find}' 偏移: {offset} (0x{offset:x})")
            else:
                print(f"未找到模式 '{args.find}'")
            return

        data = generate_pattern(args.length)

    elif args.type == "padding":
        data = generate_padding(args.length, args.char)

    elif args.type == "payload":
        addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address)
        data = generate_payload(args.padding, addr, args.endian)

    # 输出
    if args.output:
        with open(args.output, "wb") as f:
            f.write(data)
        print(f"已写入 {len(data)} 字节到 {args.output}")
    else:
        # 输出到 stdout
        sys.stdout.buffer.write(data)
        if sys.stdout.isatty():
            print()  # 终端时换行


if __name__ == "__main__":
    main()
