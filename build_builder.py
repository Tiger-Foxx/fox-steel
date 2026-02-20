#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox Builder Packager
Creates the builder executable.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def build_builder_executable():
    """Build the builder executable."""
    
    # Use PyInstaller to create a single file executable
    cmd = [
        sys.executable, '-m', 'pyinstaller',
        '--onefile',
        '--windowed',  # No console for GUI
        '--name', 'steelfox_builder',
        '--icon', 'steelfox/assets/logo-steel-fox-icon.ico',
        'builder.py'
    ]
    
    print("Building builder executable...")
    subprocess.run(cmd, check=True)
    
    # Move to root
    exe_path = Path('dist/steelfox_builder.exe')
    if exe_path.exists():
        shutil.move(str(exe_path), 'steelfox_builder.exe')
        print("Builder executable created: steelfox_builder.exe")
        
        # Clean up
        shutil.rmtree('build', ignore_errors=True)
        shutil.rmtree('dist', ignore_errors=True)
        os.remove('steelfox_builder.spec')
    else:
        print("Failed to create executable")

if __name__ == "__main__":
    build_builder_executable()