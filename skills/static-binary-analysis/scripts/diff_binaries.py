#!/usr/bin/env python3
"""
对比两个二进制文件的差异。
使用 radiff2 进行智能代码块对比。

用法: python diff_binaries.py <binary1> <binary2> [--function <name>]
"""

import subprocess
import sys
import argparse


def diff_binaries(bin1: str, bin2: str, function: str = None) -> str:
    """对比两个二进制文件"""
    try:
        if function:
            # 对比特定函数
            cmd = ["radiff2", "-g", function, bin1, bin2]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            return f"函数 {function} 的图形对比 (DOT 格式):\n{output}"
        else:
            # 代码块级对比
            cmd = ["radiff2", "-c", bin1, bin2]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)

            if not output.strip():
                return "两个二进制文件相同（代码块级别）"

            # 统计信息
            stats_cmd = ["radiff2", "-s", bin1, bin2]
            stats = subprocess.check_output(stats_cmd, stderr=subprocess.DEVNULL, text=True)

            return f"代码块差异:\n{output}\n\n统计信息:\n{stats}"

    except subprocess.CalledProcessError as e:
        return f"错误: radiff2 执行失败: {e}"
    except FileNotFoundError:
        return "错误: radiff2 未安装或不在 PATH 中"


def main():
    parser = argparse.ArgumentParser(description="对比两个二进制文件")
    parser.add_argument("binary1", help="第一个二进制文件")
    parser.add_argument("binary2", help="第二个二进制文件")
    parser.add_argument("--function", "-f", help="对比特定函数（输出 DOT 格式）")

    args = parser.parse_args()

    result = diff_binaries(args.binary1, args.binary2, args.function)
    print(result)


if __name__ == "__main__":
    main()
