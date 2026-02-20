#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox Builder Packager
Génère steelfox_builder.exe — interface graphique de construction de payload.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

# Toujours travailler depuis le répertoire du projet, quel que soit le CWD
ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

ICON   = ROOT / "steelfox" / "assets" / "logo-steel-fox-icon.ico"
OUTPUT = "steelfox_builder"
SCRIPT = "builder.py"


def build_builder_executable() -> None:
    """Compile builder.py en exécutable GUI sans console via PyInstaller."""
    if not (ROOT / SCRIPT).exists():
        sys.exit(f"[ERREUR] Script introuvable : {ROOT / SCRIPT}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",       # pas de fenêtre console
        "--noconfirm",
        "--clean",
        "--name", OUTPUT,
        "--collect-all", "steelfox",
        "--hidden-import", "PIL",
        "--hidden-import", "PIL._imagingtk",
    ]
    if ICON.exists():
        cmd += ["--icon", str(ICON)]
    cmd.append(SCRIPT)

    print(f"[*] Build : {OUTPUT}.exe …")
    result = subprocess.run(cmd)

    if result.returncode != 0:
        sys.exit(f"[ERREUR] PyInstaller a échoué (code {result.returncode}).")

    exe_src = ROOT / "dist" / f"{OUTPUT}.exe"
    exe_dst = ROOT / f"{OUTPUT}.exe"

    if not exe_src.exists():
        sys.exit(f"[ERREUR] Exécutable attendu introuvable : {exe_src}")

    shutil.move(str(exe_src), str(exe_dst))
    print(f"[+] Exécutable créé : {exe_dst}")

    # Nettoyage des artéfacts PyInstaller
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    shutil.rmtree(ROOT / "dist",  ignore_errors=True)
    spec = ROOT / f"{OUTPUT}.spec"
    if spec.exists():
        spec.unlink()

    print("[+] Nettoyage terminé.")


if __name__ == "__main__":
    build_builder_executable()