#!/usr/bin/env python3
"""
在二进制文件中搜索字节模式或字符串。
使用 rafind2 进行快速搜索。

用法:
  python search_bytes.py <binary> --hex <pattern>     # 搜索十六进制
  python search_bytes.py <binary> --string <pattern>  # 搜索字符串
  python search_bytes.py <binary> --regex <pattern>   # 正则搜索
"""

import subprocess
import sys
import argparse


def search_hex(binary: str, pattern: str) -> str:
    """搜索十六进制模式"""
    # 移除可能的空格和0x前缀
    pattern = pattern.replace(" ", "").replace("0x", "").lower()

    try:
        cmd = ["rafind2", "-x", pattern, binary]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        if not output.strip():
            return f"未找到模式: {pattern}"
        return f"十六进制 '{pattern}' 找到于:\n{output}"
    except subprocess.CalledProcessError:
        return f"搜索失败"
    except FileNotFoundError:
        return "错误: rafind2 未安装"


def search_string(binary: str, pattern: str, wide: bool = False) -> str:
    """搜索字符串"""
    try:
        flag = "-S" if wide else "-s"
        cmd = ["rafind2", flag, pattern, binary]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        if not output.strip():
            return f"未找到字符串: {pattern}"
        string_type = "宽字符串" if wide else "字符串"
        return f"{string_type} '{pattern}' 找到于:\n{output}"
    except subprocess.CalledProcessError:
        return f"搜索失败"
    except FileNotFoundError:
        return "错误: rafind2 未安装"


def search_regex(binary: str, pattern: str) -> str:
    """正则表达式搜索"""
    try:
        cmd = ["rafind2", "-e", pattern, binary]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        if not output.strip():
            return f"未找到匹配: {pattern}"
        return f"正则 '{pattern}' 匹配于:\n{output}"
    except subprocess.CalledProcessError:
        return f"搜索失败"
    except FileNotFoundError:
        return "错误: rafind2 未安装"


def main():
    parser = argparse.ArgumentParser(description="在二进制中搜索模式")
    parser.add_argument("binary", help="目标二进制文件")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hex", "-x", help="搜索十六进制模式 (如 'deadbeef')")
    group.add_argument("--string", "-s", help="搜索 ASCII 字符串")
    group.add_argument("--wide", "-w", help="搜索宽字符串 (UTF-16)")
    group.add_argument("--regex", "-e", help="正则表达式搜索")

    args = parser.parse_args()

    if args.hex:
        print(search_hex(args.binary, args.hex))
    elif args.string:
        print(search_string(args.binary, args.string, wide=False))
    elif args.wide:
        print(search_string(args.binary, args.wide, wide=True))
    elif args.regex:
        print(search_regex(args.binary, args.regex))


if __name__ == "__main__":
    main()
