#!/usr/bin/env python3
"""
Paper Tutor dependency checker.

Checks whether required Python packages are available for script execution.
Optionally installs missing packages from requirements.txt when explicitly asked.

Usage:
    python check_dependencies.py
    python check_dependencies.py --install-missing
"""

from __future__ import annotations

import argparse
import importlib
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple


REQUIRED_IMPORTS: List[Tuple[str, str]] = [
    ("pymupdf", "PyMuPDF (package: pymupdf)"),
    ("PIL", "Pillow (package: Pillow)"),
    ("imagehash", "imagehash"),
]


def check_dependencies() -> Tuple[List[str], List[Tuple[str, str]]]:
    """Return (installed_display_names, missing_imports)."""
    installed: List[str] = []
    missing: List[Tuple[str, str]] = []

    for import_name, display_name in REQUIRED_IMPORTS:
        try:
            importlib.import_module(import_name)
            installed.append(display_name)
        except ModuleNotFoundError:
            missing.append((import_name, display_name))

    return installed, missing


def install_requirements(requirements_path: Path) -> int:
    """Install dependencies from requirements file using current Python executable."""
    cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_path)]
    print("Installing dependencies:")
    print("  " + " ".join(cmd))
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Paper Tutor script dependencies and optionally install missing packages."
    )
    parser.add_argument(
        "--install-missing",
        action="store_true",
        help="Install missing packages using requirements.txt.",
    )
    args = parser.parse_args()

    requirements_path = Path(__file__).resolve().parent / "requirements.txt"
    if not requirements_path.exists():
        print(f"ERROR: requirements file not found: {requirements_path}")
        return 2

    print("Checking Paper Tutor Python dependencies...")
    installed, missing = check_dependencies()

    if installed:
        print("Installed:")
        for name in installed:
            print(f"  - {name}")

    if not missing:
        print("All required dependencies are available.")
        return 0

    print("Missing:")
    for _, name in missing:
        print(f"  - {name}")

    if not args.install_missing:
        print("\nDependency check failed.")
        print("Ask user permission before installing packages.")
        print("Install command:")
        print(f"  {sys.executable} -m pip install -r {requirements_path}")
        return 1

    install_rc = install_requirements(requirements_path)
    if install_rc != 0:
        print(f"ERROR: pip install failed with exit code {install_rc}.")
        return install_rc

    _, missing_after_install = check_dependencies()
    if missing_after_install:
        print("ERROR: Some dependencies are still missing after installation:")
        for _, name in missing_after_install:
            print(f"  - {name}")
        return 3

    print("Dependencies installed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
