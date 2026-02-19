# -*- coding: utf-8 -*-
"""
SteelFox — Email Client Credential Recovery

Recovers data from:
  - Microsoft Outlook (registry profiles + DPAPI)
  - Mozilla Thunderbird (profiles + logins.json)
  - Mailbird
"""

from __future__ import annotations

import json
import logging
import os
import re
import winreg
from pathlib import Path
from typing import Any

from steelfox.core.config import config
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta

logger = logging.getLogger("steelfox")


def _resolve(template: str) -> str | None:
    try:
        result = template
        for k, v in config.profile.items():
            result = result.replace(f"{{{k}}}", v)
        return result
    except Exception:
        return None


class Outlook(ModuleBase):
    """Recover Microsoft Outlook stored mail account credentials."""

    meta = ModuleMeta(
        name="Outlook",
        category=Category.MAILS,
        description="Recover Outlook mail profiles from the registry (IMAP/POP3/SMTP/Exchange)",
    )

    # Outlook stores mail profiles under these registry paths
    OUTLOOK_REG_PATHS = [
        r"SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles",
        r"SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles",
        r"SOFTWARE\Microsoft\Windows Messaging Subsystem\Profiles",
    ]

    OUTLOOK_VALUES = [
        ("Email", 0x0001),
        ("Display Name", None),
        ("IMAP Server", None),
        ("POP3 Server", None),
        ("SMTP Server", None),
        ("HTTP Server URL", None),
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for reg_path in self.OUTLOOK_REG_PATHS:
            try:
                results.extend(self._enum_profile(winreg.HKEY_CURRENT_USER, reg_path))
            except Exception:
                continue

        return results

    def _enum_profile(self, hive: int, base_path: str) -> list[dict[str, Any]]:
        """Recursively enumerate Outlook profile registry keys."""
        found: list[dict[str, Any]] = []

        try:
            key = winreg.OpenKey(hive, base_path)
        except OSError:
            return found

        # Iterate subkeys recursively
        try:
            idx = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, idx)
                    subkey_path = f"{base_path}\\{subkey_name}"
                    found.extend(self._enum_profile(hive, subkey_path))
                    idx += 1
                except OSError:
                    break
        except Exception:
            pass

        # Check this key for Outlook values
        entry: dict[str, Any] = {"Source": "Outlook"}
        try:
            for val_name in [
                "Email", "Display Name", "IMAP Server", "POP3 Server",
                "SMTP Server", "HTTP Server URL", "IMAP User",
                "POP3 User", "SMTP User",
            ]:
                try:
                    val, reg_type = winreg.QueryValueEx(key, val_name)
                    if isinstance(val, bytes):
                        val = val.decode("utf-16-le", errors="replace").rstrip("\x00")
                    if val:
                        entry[val_name] = val
                except FileNotFoundError:
                    continue

            # IMAP/POP3/SMTP passwords are stored as DPAPI-encrypted binary blobs
            for pwd_name in ["IMAP Password", "POP3 Password", "SMTP Password", "HTTP Password"]:
                try:
                    val, _ = winreg.QueryValueEx(key, pwd_name)
                    if isinstance(val, bytes) and len(val) > 1:
                        # Try DPAPI decryption
                        try:
                            from steelfox.core.winapi import win32_crypt_unprotect_data
                            dec = win32_crypt_unprotect_data(val[1:])  # skip first byte
                            if dec:
                                entry[pwd_name] = dec.decode("utf-8", errors="replace")
                        except Exception:
                            entry[pwd_name] = f"[DPAPI blob, {len(val)} bytes]"
                except FileNotFoundError:
                    continue

        except Exception:
            pass

        winreg.CloseKey(key)

        if len(entry) > 1:
            found.append(entry)

        return found


class Thunderbird(ModuleBase):
    """Recover Mozilla Thunderbird stored mail credentials."""

    meta = ModuleMeta(
        name="Thunderbird",
        category=Category.MAILS,
        description="Recover Thunderbird mail account saved passwords and profiles",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Thunderbird profiles
        tb_path = Path(_resolve("{APPDATA}\\Thunderbird") or "")
        if not tb_path.exists():
            return results

        profiles_ini = tb_path / "profiles.ini"
        if not profiles_ini.exists():
            return results

        # Parse profiles
        profile_dirs: list[Path] = []
        try:
            content = profiles_ini.read_text(encoding="utf-8", errors="replace")
            # Find profile sections
            sections = re.findall(
                r"\[Profile\d+\].*?(?=\[|\Z)", content, re.DOTALL
            )
            for section in sections:
                path_match = re.search(r"Path=(.+)", section)
                is_relative = "IsRelative=1" in section
                if path_match:
                    p = path_match.group(1).strip()
                    if is_relative:
                        profile_dirs.append(tb_path / p.replace("/", "\\"))
                    else:
                        profile_dirs.append(Path(p))
        except Exception:
            pass

        for profile_dir in profile_dirs:
            if not profile_dir.exists():
                continue

            # logins.json — stored credentials
            logins_file = profile_dir / "logins.json"
            if logins_file.exists():
                try:
                    data = json.loads(logins_file.read_text(encoding="utf-8"))
                    for login in data.get("logins", []):
                        results.append({
                            "Source": "Thunderbird",
                            "Profile": profile_dir.name,
                            "Hostname": login.get("hostname", ""),
                            "Username (encrypted)": login.get("encryptedUsername", "")[:50],
                            "Password (encrypted)": login.get("encryptedPassword", "")[:50],
                            "Form Submit URL": login.get("formSubmitURL", ""),
                            "Note": "Requires NSS/key4.db decryption",
                        })
                except Exception:
                    pass

            # signons.sqlite (legacy format)
            signons_db = profile_dir / "signons.sqlite"
            if signons_db.exists():
                results.append({
                    "Source": "Thunderbird (Legacy)",
                    "Profile": profile_dir.name,
                    "Path": str(signons_db),
                    "Note": "Legacy format — signons.sqlite",
                })

        return results


class Mailbird(ModuleBase):
    """Recover Mailbird stored account credentials."""

    meta = ModuleMeta(
        name="Mailbird",
        category=Category.MAILS,
        description="Recover Mailbird email client stored accounts",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        mailbird_db = Path(_resolve("{LOCALAPPDATA}\\Mailbird\\Store\\Store.db") or "")
        if not mailbird_db.exists():
            return results

        try:
            import sqlite3
            from steelfox.core.winapi import safe_copy_db

            tmp = safe_copy_db(mailbird_db)
            if not tmp:
                return results

            conn = sqlite3.connect(tmp)
            cursor = conn.cursor()

            # Accounts table
            try:
                cursor.execute(
                    "SELECT Server, Port, Username, Password, encryptedPassword "
                    "FROM Accounts"
                )
                for row in cursor.fetchall():
                    entry: dict[str, Any] = {
                        "Source": "Mailbird",
                        "Server": row[0] or "",
                        "Port": str(row[1] or ""),
                        "Username": row[2] or "",
                    }

                    # Password may be stored in plaintext or encrypted
                    if row[3]:
                        entry["Password"] = row[3]
                    elif row[4]:
                        entry["Encrypted Password"] = str(row[4])[:50]

                    results.append(entry)
            except Exception:
                pass

            conn.close()
            Path(tmp).unlink(missing_ok=True)
        except Exception:
            pass

        return results
