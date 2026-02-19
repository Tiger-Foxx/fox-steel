# -*- coding: utf-8 -*-
"""
SteelFox — Cloud Service Token & Configuration Recovery

Recovers data from:
  - OneDrive (business & personal)
  - Google Drive / Google Chrome sync tokens
  - Dropbox
  - Mega
  - iCloud for Windows
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
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


class OneDrive(ModuleBase):
    """Recover Microsoft OneDrive configuration and account data."""

    meta = ModuleMeta(
        name="OneDrive",
        category=Category.CLOUD,
        description="Recover OneDrive account info, sync settings, and business configs",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # --- Registry keys ---
        reg_paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\OneDrive\Accounts\Personal"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\OneDrive\Accounts\Business1"),
        ]

        for hive, key_path in reg_paths:
            try:
                key = winreg.OpenKey(hive, key_path)
                entry: dict[str, Any] = {"Source": "OneDrive"}

                for val_name in [
                    "UserEmail", "UserName", "UserFolder",
                    "cid", "ServiceEndpointUri", "SPOLastUpdate",
                ]:
                    try:
                        val, _ = winreg.QueryValueEx(key, val_name)
                        entry[val_name] = str(val)
                    except FileNotFoundError:
                        continue

                winreg.CloseKey(key)

                if len(entry) > 1:
                    results.append(entry)
            except Exception:
                continue

        # --- settings.dat sqlite (OneDrive internal db) ---
        od_path = Path(_resolve("{LOCALAPPDATA}\\Microsoft\\OneDrive\\settings") or "")
        if od_path.exists():
            for db_file in od_path.rglob("*.dat"):
                try:
                    if db_file.stat().st_size > 0:
                        results.append({
                            "Source": "OneDrive (Settings DB)",
                            "Path": str(db_file),
                            "Size": f"{db_file.stat().st_size:,} bytes",
                        })
                except Exception:
                    continue

        return results


class GoogleDrive(ModuleBase):
    """Recover Google Drive for Desktop tokens and configuration."""

    meta = ModuleMeta(
        name="Google Drive",
        category=Category.CLOUD,
        description="Recover Google Drive for Desktop account info and sync tokens",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Google Drive for Desktop
        gd_path = Path(_resolve("{LOCALAPPDATA}\\Google\\DriveFS") or "")
        if gd_path.exists():
            # Each sub-directory under DriveFS is an account
            for account_dir in gd_path.iterdir():
                if not account_dir.is_dir():
                    continue

                entry: dict[str, Any] = {
                    "Source": "Google Drive for Desktop",
                    "Account Folder": account_dir.name,
                }

                # account_db
                account_db = account_dir / "account_db"
                if account_db.exists():
                    try:
                        conn = sqlite3.connect(str(account_db))
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        )
                        tables = [row[0] for row in cursor.fetchall()]
                        entry["Tables"] = ", ".join(tables)

                        # Try to get account info
                        for table in tables:
                            try:
                                cursor.execute(f"SELECT * FROM [{table}] LIMIT 5")
                                rows = cursor.fetchall()
                                if rows:
                                    desc = [d[0] for d in cursor.description]
                                    for row in rows:
                                        row_data = dict(zip(desc, row))
                                        for k, v in row_data.items():
                                            if isinstance(v, str) and "@" in v:
                                                entry["Email"] = v
                                                break
                            except Exception:
                                continue

                        conn.close()
                    except Exception:
                        pass

                results.append(entry)

        # Legacy Google Backup and Sync
        legacy_path = Path(_resolve("{LOCALAPPDATA}\\Google\\Drive") or "")
        if legacy_path.exists():
            user_default = legacy_path / "user_default"
            if user_default.exists():
                results.append({
                    "Source": "Google Backup and Sync (Legacy)",
                    "Path": str(user_default),
                })

        return results


class Dropbox(ModuleBase):
    """Recover Dropbox configuration and tokens."""

    meta = ModuleMeta(
        name="Dropbox",
        category=Category.CLOUD,
        description="Recover Dropbox account info, sync paths, and host keys",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        db_path = Path(_resolve("{APPDATA}\\Dropbox") or "")
        if not db_path.exists():
            db_path = Path(_resolve("{LOCALAPPDATA}\\Dropbox") or "")

        if not db_path.exists():
            return results

        # info.json — primary config
        info_json = db_path / "info.json"
        if info_json.exists():
            try:
                data = json.loads(info_json.read_text(encoding="utf-8"))
                for account_type in ("personal", "business"):
                    if account_type in data:
                        acc = data[account_type]
                        results.append({
                            "Source": "Dropbox",
                            "Account Type": account_type.title(),
                            "Path": acc.get("path", ""),
                            "Host": str(acc.get("host", "")),
                            "Is Team": str(acc.get("is_team", False)),
                        })
            except Exception:
                pass

        # host.db — encoded host ID
        host_db = db_path / "host.db"
        if host_db.exists():
            try:
                import base64
                lines = host_db.read_bytes().split(b"\n")
                if len(lines) >= 2:
                    host_id = lines[0].strip()
                    dropbox_path = base64.b64decode(lines[1].strip()).decode(
                        "utf-8", errors="replace"
                    )
                    results.append({
                        "Source": "Dropbox (host.db)",
                        "Host ID": host_id.decode("utf-8", errors="replace"),
                        "Dropbox Path": dropbox_path,
                    })
            except Exception:
                pass

        # instance_db — SQLite database with keys
        for db_file in db_path.rglob("*.db"):
            if "instance" in db_file.name.lower():
                results.append({
                    "Source": "Dropbox (Instance DB)",
                    "Path": str(db_file),
                    "Size": f"{db_file.stat().st_size:,} bytes",
                })

        # config.dbx — encrypted config, note its location
        config_dbx = db_path / "config.dbx"
        if config_dbx.exists():
            results.append({
                "Source": "Dropbox (Config)",
                "Path": str(config_dbx),
                "Size": f"{config_dbx.stat().st_size:,} bytes",
                "Note": "SQLite DB encrypted with DPAPI (requires user context)",
            })

        return results


class Mega(ModuleBase):
    """Recover MEGA cloud storage configuration."""

    meta = ModuleMeta(
        name="MEGA",
        category=Category.CLOUD,
        description="Recover MEGA sync client configuration and cached credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        mega_path = Path(_resolve("{LOCALAPPDATA}\\Mega Limited\\MEGAsync") or "")
        if not mega_path.exists():
            return results

        # MEGAsync.cfg
        cfg_file = mega_path / "MEGAsync.cfg"
        if cfg_file.exists():
            try:
                content = cfg_file.read_text(encoding="utf-8", errors="replace")
                entry: dict[str, Any] = {"Source": "MEGA"}

                email_match = re.search(r"email\s*=\s*(.+)", content)
                if email_match:
                    entry["Email"] = email_match.group(1).strip()

                session_match = re.search(r"session\s*=\s*(.+)", content)
                if session_match:
                    entry["Session"] = session_match.group(1).strip()[:64] + "..."

                sync_match = re.search(r"syncName0Folder\s*=\s*(.+)", content)
                if sync_match:
                    entry["Sync Folder"] = sync_match.group(1).strip()

                if len(entry) > 1:
                    results.append(entry)
            except Exception:
                pass

        # SQLite databases
        for db in mega_path.rglob("*.db"):
            results.append({
                "Source": "MEGA (Database)",
                "Path": str(db),
                "Size": f"{db.stat().st_size:,} bytes",
            })

        return results
