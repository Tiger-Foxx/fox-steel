#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox Console Mode Packager
Creates a stealthy console executable.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def build_console_executable():
    """Build the console executable with stealth capabilities."""
    
    # Use PyInstaller to create a single file executable
    cmd = [
        sys.executable, '-m', 'pyinstaller',
        '--onefile',
        '--name', 'steelfox_console',
        '--icon', 'steelfox/assets/logo-steel-fox-icon.ico',
        'steelfox.py'
    ]
    
    print("Building console executable...")
    subprocess.run(cmd, check=True)
    
    # Move to root
    exe_path = Path('dist/steelfox_console.exe')
    if exe_path.exists():
        shutil.move(str(exe_path), 'steelfox_console.exe')
        print("Console executable created: steelfox_console.exe")
        
        # Clean up
        shutil.rmtree('build', ignore_errors=True)
        shutil.rmtree('dist', ignore_errors=True)
        os.remove('steelfox_console.spec')
    else:
        print("Failed to create executable")

if __name__ == "__main__":
    build_console_executable()