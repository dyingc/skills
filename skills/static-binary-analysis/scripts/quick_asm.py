#!/usr/bin/env python3
"""
快速汇编/反汇编工具。
使用 rasm2 进行单条指令操作。

用法:
  python quick_asm.py --disasm <hex>           # 反汇编
  python quick_asm.py --asm <instructions>     # 汇编
  python quick_asm.py --arch <arch> --bits <bits> ...  # 指定架构
"""

import subprocess
import sys
import argparse


def disassemble(hex_code: str, arch: str = "x86", bits: int = 64) -> str:
    """反汇编十六进制代码"""
    # 清理输入
    hex_code = hex_code.replace(" ", "").replace("0x", "").replace("\\x", "")

    try:
        cmd = ["rasm2", "-a", arch, "-b", str(bits), "-d", hex_code]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return f"反汇编失败: {e}"
    except FileNotFoundError:
        return "错误: rasm2 未安装"


def assemble(instructions: str, arch: str = "x86", bits: int = 64) -> str:
    """汇编指令到机器码"""
    try:
        cmd = ["rasm2", "-a", arch, "-b", str(bits), instructions]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        hex_output = output.strip()

        # 格式化输出
        formatted = " ".join(hex_output[i:i+2] for i in range(0, len(hex_output), 2))
        c_array = ", ".join(f"0x{hex_output[i:i+2]}" for i in range(0, len(hex_output), 2))

        return f"原始: {hex_output}\n格式化: {formatted}\nC数组: {{ {c_array} }}"
    except subprocess.CalledProcessError as e:
        return f"汇编失败: {e}"
    except FileNotFoundError:
        return "错误: rasm2 未安装"


def list_archs() -> str:
    """列出支持的架构"""
    try:
        cmd = ["rasm2", "-L"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return output
    except subprocess.CalledProcessError:
        return "获取架构列表失败"
    except FileNotFoundError:
        return "错误: rasm2 未安装"


def main():
    parser = argparse.ArgumentParser(description="快速汇编/反汇编")
    parser.add_argument("--arch", "-a", default="x86", help="架构 (默认: x86)")
    parser.add_argument("--bits", "-b", type=int, default=64, help="位数 (默认: 64)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--disasm", "-d", help="反汇编十六进制")
    group.add_argument("--asm", "-s", help="汇编指令")
    group.add_argument("--list-archs", "-L", action="store_true", help="列出支持的架构")

    args = parser.parse_args()

    if args.list_archs:
        print(list_archs())
    elif args.disasm:
        print(f"[{args.arch} {args.bits}位] 反汇编: {args.disasm}")
        print(disassemble(args.disasm, args.arch, args.bits))
    elif args.asm:
        print(f"[{args.arch} {args.bits}位] 汇编: {args.asm}")
        print(assemble(args.asm, args.arch, args.bits))


if __name__ == "__main__":
    main()
