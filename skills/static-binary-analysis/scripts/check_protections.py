#!/usr/bin/env python3
"""
检查二进制文件的安全保护机制。
使用 rabin2 获取 RELRO, Stack Canary, NX, PIE 等信息。

用法: python check_protections.py <binary>
"""

import subprocess
import sys
import json
import re


def check_protections(binary_path: str) -> dict:
    """检查二进制保护机制"""
    result = {
        "binary": binary_path,
        "arch": None,
        "bits": None,
        "canary": False,
        "nx": False,
        "pie": False,
        "relro": "none",
        "stripped": False,
        "static": False,
    }

    try:
        # 获取二进制信息
        output = subprocess.check_output(
            ["rabin2", "-I", binary_path],
            stderr=subprocess.DEVNULL,
            text=True
        )

        for line in output.strip().split("\n"):
            line = line.strip()
            if line.startswith("arch"):
                result["arch"] = line.split()[-1]
            elif line.startswith("bits"):
                result["bits"] = int(line.split()[-1])
            elif line.startswith("canary"):
                result["canary"] = "true" in line.lower()
            elif line.startswith("nx"):
                result["nx"] = "true" in line.lower()
            elif line.startswith("pic"):
                result["pie"] = "true" in line.lower()
            elif line.startswith("relro"):
                relro_val = line.split()[-1].lower()
                if "full" in relro_val:
                    result["relro"] = "full"
                elif "partial" in relro_val:
                    result["relro"] = "partial"
            elif line.startswith("stripped"):
                result["stripped"] = "true" in line.lower()
            elif line.startswith("static"):
                result["static"] = "true" in line.lower()

    except subprocess.CalledProcessError as e:
        print(f"错误: rabin2 执行失败: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("错误: rabin2 未安装或不在 PATH 中", file=sys.stderr)
        sys.exit(1)

    return result


def format_output(info: dict) -> str:
    """格式化输出"""
    lines = [
        f"文件: {info['binary']}",
        f"架构: {info['arch']} ({info['bits']}位)",
        "",
        "保护机制:",
        f"  Stack Canary: {'✓ 启用' if info['canary'] else '✗ 未启用'}",
        f"  NX (不可执行栈): {'✓ 启用' if info['nx'] else '✗ 未启用'}",
        f"  PIE (位置无关): {'✓ 启用' if info['pie'] else '✗ 未启用'}",
        f"  RELRO: {info['relro'].upper()}",
        "",
        f"符号表: {'已剥离' if info['stripped'] else '保留'}",
        f"链接方式: {'静态' if info['static'] else '动态'}",
    ]
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <binary>")
        sys.exit(1)

    binary_path = sys.argv[1]
    info = check_protections(binary_path)

    # 输出人类可读格式
    print(format_output(info))
    print()

    # 同时输出 JSON 便于程序处理
    print("JSON 格式:")
    print(json.dumps(info, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
