#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox Builder Packager
Generates steelfox_builder.exe — graphical payload construction interface.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

# Always work from the project directory, regardless of the CWD
ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

ICON    = ROOT / "steelfox" / "assets" / "logo-steel-fox-icon.ico"
VERSION = ROOT / "version_builder.txt"
OUTPUT  = "steelfox_builder"
SCRIPT  = "builder.py"


def build_builder_executable() -> None:
    """Compiles builder.py into a GUI executable without a console via PyInstaller."""
    if not (ROOT / SCRIPT).exists():
        sys.exit(f"[ERROR] Script not found: {ROOT / SCRIPT}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",       # no console window
        "--noconfirm",
        "--clean",
        "--name", OUTPUT,
        "--collect-all", "steelfox",
        "--hidden-import", "PIL",
        "--hidden-import", "PIL._imagingtk",
    ]
    if ICON.exists():
        cmd += ["--icon", str(ICON)]
    if VERSION.exists():
        cmd += ["--version-file", str(VERSION)]
    cmd.append(SCRIPT)

    print(f"[*] Building: {OUTPUT}.exe ...")
    result = subprocess.run(cmd)

    if result.returncode != 0:
        sys.exit(f"[ERROR] PyInstaller failed (code {result.returncode}).")

    exe_src = ROOT / "dist" / f"{OUTPUT}.exe"
    exe_dst = ROOT / f"{OUTPUT}.exe"

    if not exe_src.exists():
        sys.exit(f"[ERROR] Expected executable not found: {exe_src}")

    shutil.move(str(exe_src), str(exe_dst))
    print(f"[+] Executable created: {exe_dst}")

    # Cleanup PyInstaller artifacts
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    shutil.rmtree(ROOT / "dist",  ignore_errors=True)
    spec = ROOT / f"{OUTPUT}.spec"
    if spec.exists():
        spec.unlink()

    print("[+] Cleanup complete.")


if __name__ == "__main__":
    build_builder_executable()