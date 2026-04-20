#!/usr/bin/env python3
"""
Paper Tutor dependency checker.

Checks whether:
    1. The active Python interpreter is a version PyMuPDF supports.
    2. Required Python packages import cleanly at runtime.
    3. PyMuPDF itself meets the minimum version used by extract_figures.py.

Optionally installs missing packages from requirements.txt when explicitly asked.

The Python-version guard exists because PyMuPDF tracks CPython release pace
conservatively — e.g. a freshly released CPython (like 3.14) often lacks
PyMuPDF wheels for weeks after launch, and `pip install pymupdf` fails with a
confusing "Could not build wheels" error on an interpreter that is simply too
new. A clear up-front message saves the user a debugging cycle.

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
from typing import List, Optional, Tuple


# PyMuPDF compatibility window. Lower bound is what extract_figures.py was
# authored against; upper bound is exclusive — any Python major.minor strictly
# less than this is known-good. Bump UPPER when a new CPython has confirmed
# PyMuPDF wheel coverage on pypi.
PY_VERSION_MIN = (3, 10)
PY_VERSION_UPPER_EXCLUSIVE = (3, 14)

PYMUPDF_MIN_VERSION = (1, 23, 0)

REQUIRED_IMPORTS: List[Tuple[str, str]] = [
    ("pymupdf", "PyMuPDF (package: pymupdf)"),
    ("PIL", "Pillow (package: Pillow)"),
    ("imagehash", "imagehash"),
]


def _parse_version(s: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for tok in s.split("."):
        num = ""
        for ch in tok:
            if ch.isdigit():
                num += ch
            else:
                break
        if not num:
            break
        parts.append(int(num))
    return tuple(parts)


def check_python_version() -> Optional[str]:
    """Return an error message if the Python version is incompatible."""
    cur = sys.version_info[:2]
    if cur < PY_VERSION_MIN:
        return (
            f"Python {cur[0]}.{cur[1]} is too old for Paper Tutor. "
            f"PyMuPDF requires Python >= {PY_VERSION_MIN[0]}.{PY_VERSION_MIN[1]}."
        )
    if cur >= PY_VERSION_UPPER_EXCLUSIVE:
        return (
            f"Python {cur[0]}.{cur[1]} is not yet supported by PyMuPDF wheels. "
            f"Paper Tutor supports Python < {PY_VERSION_UPPER_EXCLUSIVE[0]}."
            f"{PY_VERSION_UPPER_EXCLUSIVE[1]}. "
            f"Install a supported interpreter (e.g. `brew install python@3.12` on "
            f"macOS, or `python3.12 -m venv` to create a matching venv) and re-run "
            f"from that interpreter."
        )
    return None


def check_pymupdf_version() -> Optional[str]:
    """Return an error message if pymupdf is installed but too old."""
    try:
        mod = importlib.import_module("pymupdf")
    except ModuleNotFoundError:
        return None  # import-level check will catch this
    raw = getattr(mod, "__version__", None) or getattr(mod, "VersionBind", None) or ""
    ver = _parse_version(str(raw))
    if not ver:
        return None
    if ver < PYMUPDF_MIN_VERSION:
        need = ".".join(str(v) for v in PYMUPDF_MIN_VERSION)
        got = ".".join(str(v) for v in ver)
        return (
            f"PyMuPDF {got} is older than the required {need}. "
            f"Run: {sys.executable} -m pip install --upgrade pymupdf"
        )
    return None


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

    # 1. Python interpreter version — this must pass before packages can even
    # be installed, because `pip install pymupdf` will fail with an opaque
    # wheel-build error on an unsupported interpreter (e.g. CPython 3.14).
    py_err = check_python_version()
    if py_err:
        print(f"ERROR: {py_err}")
        print(f"  Current interpreter: {sys.executable}")
        print(f"  Current Python:      {sys.version.splitlines()[0]}")
        return 4

    installed, missing = check_dependencies()

    if installed:
        print("Installed:")
        for name in installed:
            print(f"  - {name}")

    if not missing:
        # Packages are present — also verify pymupdf version.
        pymupdf_err = check_pymupdf_version()
        if pymupdf_err:
            print(f"ERROR: {pymupdf_err}")
            return 5
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

    pymupdf_err = check_pymupdf_version()
    if pymupdf_err:
        print(f"ERROR: {pymupdf_err}")
        return 5

    print("Dependencies installed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
