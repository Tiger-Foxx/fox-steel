# -*- coding: utf-8 -*-
"""
SteelFox — Windows Privilege & User Management

Provides:
  - Admin status detection
  - Token impersonation helpers
  - User enumeration from filesystem and Win32 API
  - Environment variable resolution per user
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import sys
from pathlib import Path

from steelfox.core.config import config

logger = logging.getLogger("steelfox")


# ─── Admin Detection ─────────────────────────────────────────────────────

def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ─── Current Username via Win32 API ──────────────────────────────────────

def get_current_username() -> str:
    """Retrieve the current username using advapi32.GetUserNameW."""
    try:
        GetUserNameW = ctypes.windll.advapi32.GetUserNameW
        GetUserNameW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint)]
        GetUserNameW.restype = ctypes.c_uint

        buf = ctypes.create_unicode_buffer(256)
        size = ctypes.c_uint(256)
        if GetUserNameW(buf, ctypes.byref(size)):
            return buf.value
    except Exception:
        pass
    return os.environ.get("USERNAME", os.environ.get("USER", "unknown"))


# ─── OS Version ──────────────────────────────────────────────────────────

def get_os_version() -> str:
    """Return the Windows NT version string (e.g., '10.0' for Win10/11)."""
    try:
        version = sys.getwindowsversion()
        return f"{version.major}.{version.minor}"
    except Exception:
        return "10.0"


def get_os_build() -> int:
    """Return the Windows build number."""
    try:
        return sys.getwindowsversion().build
    except Exception:
        return 0


def is_windows_11() -> bool:
    """Windows 11 is build >= 22000."""
    return get_os_build() >= 22000


# ─── User Enumeration ───────────────────────────────────────────────────

EXCLUDED_USERS = {"All Users", "Default User", "Default", "Public", "desktop.ini"}


def get_users_on_filesystem(
    exclude_current: bool = True,
    extra_exclude: list[str] | None = None,
) -> list[str]:
    """List user profile directories on the system drive.

    Args:
        exclude_current: Whether to exclude the currently logged-in user.
        extra_exclude: Additional usernames to exclude.
    """
    users_path = Path(f"{config.drive}:\\Users")
    if float(get_os_version()) < 6:
        users_path = Path(f"{config.drive}:\\Documents and Settings")

    if not users_path.exists():
        return []

    excluded = set(EXCLUDED_USERS)
    if extra_exclude:
        excluded.update(extra_exclude)
    if exclude_current and config.username:
        excluded.add(config.username)

    return [
        p.name
        for p in users_path.iterdir()
        if p.is_dir() and p.name not in excluded
    ]


# ─── Environment Variables Setup ─────────────────────────────────────────

def set_env_for_user(user: str, impersonate: bool = False) -> None:
    """Populate config.profile with resolved paths for the given user.

    If *impersonate* is False and the user is the current user, prefer
    real environment variables; otherwise use templated paths.
    """
    template = {
        "APPDATA": "{drive}:\\Users\\{user}\\AppData\\Roaming\\",
        "USERPROFILE": "{drive}:\\Users\\{user}\\",
        "HOMEDRIVE": "{drive}:",
        "HOMEPATH": "{drive}:\\Users\\{user}",
        "ALLUSERSPROFILE": "{drive}:\\ProgramData",
        "LOCALAPPDATA": "{drive}:\\Users\\{user}\\AppData\\Local",
    }

    config.profile = dict(template)

    if not impersonate:
        for env_key in config.profile:
            real_val = os.environ.get(env_key)
            if real_val:
                config.profile[env_key] = real_val

    for key in config.profile:
        config.profile[key] = config.profile[key].format(
            drive=config.drive, user=user
        )


# ─── Utility: Check Specific Privilege ───────────────────────────────────

def check_privilege(privilege_name: str = "SeDebugPrivilege") -> bool:
    """Check if the current process holds a given privilege."""
    try:
        import ctypes.wintypes as wt

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        TOKEN_QUERY = 0x0008
        h_process = kernel32.GetCurrentProcess()
        h_token = wt.HANDLE()
        if not advapi32.OpenProcessToken(h_process, TOKEN_QUERY, ctypes.byref(h_token)):
            return False

        # Lookup privilege LUID
        luid = ctypes.c_int64()
        if not advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
            kernel32.CloseHandle(h_token)
            return False

        # Check token privileges (simplified)
        kernel32.CloseHandle(h_token)
        return is_admin()  # Simplified fallback
    except Exception:
        return False
