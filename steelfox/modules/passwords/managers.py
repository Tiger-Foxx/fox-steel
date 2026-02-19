# -*- coding: utf-8 -*-
"""
SteelFox — Password Manager Configuration & Data Recovery

Recovers data from:
  - KeePass (configuration, recent databases, key file paths)
  - Bitwarden (desktop vault location + session data)
  - 1Password (local vault metadata)
  - LastPass (cached vault data from browser extension stores)
"""

from __future__ import annotations

import json
import logging
import os
import re
import winreg
import xml.etree.ElementTree as ET
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


class KeePass(ModuleBase):
    """Recover KeePass configuration, recent databases, and key file references."""

    meta = ModuleMeta(
        name="KeePass",
        category=Category.PASSWORDS,
        description="Recover KeePass config, recent .kdbx databases, trigger exports, and key files",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # KeePass.config.xml — user config
        config_paths = [
            Path(_resolve("{APPDATA}\\KeePass\\KeePass.config.xml") or ""),
        ]

        # Also check installation dir
        for install_path in [
            "C:\\Program Files\\KeePass Password Safe 2",
            "C:\\Program Files (x86)\\KeePass Password Safe 2",
        ]:
            p = Path(install_path) / "KeePass.config.xml"
            if p.exists():
                config_paths.append(p)

        for config_file in config_paths:
            if not config_file.exists():
                continue

            try:
                tree = ET.parse(str(config_file))
                root = tree.getroot()

                # Recent databases (ConnectionInfo/Path)
                for item in root.iter("ConnectionInfo"):
                    path_elem = item.find("Path")
                    if path_elem is not None and path_elem.text:
                        entry: dict[str, Any] = {
                            "Source": "KeePass",
                            "Type": "Recent Database",
                            "Database Path": path_elem.text,
                        }

                        # Key file?
                        key_src = item.find("KeyFilePath")
                        if key_src is not None and key_src.text:
                            entry["Key File"] = key_src.text

                        # Credentials saved?
                        cred_save = item.find("CredSaveMode")
                        if cred_save is not None and cred_save.text:
                            entry["Credential Save Mode"] = cred_save.text

                        results.append(entry)

                # Check for triggers (potential export-on-open)
                for trigger in root.iter("Trigger"):
                    name_elem = trigger.find("Name")
                    enabled = trigger.find("Enabled")
                    if name_elem is not None:
                        results.append({
                            "Source": "KeePass (Trigger)",
                            "Trigger Name": name_elem.text or "Unnamed",
                            "Enabled": (enabled.text if enabled is not None else "?"),
                        })

            except Exception as e:
                logger.debug("KeePass config parse error: %s", e)

        # Look for .kdbx files in common locations
        search_dirs = [
            Path(_resolve("{USERPROFILE}\\Documents") or ""),
            Path(_resolve("{USERPROFILE}\\Desktop") or ""),
            Path(_resolve("{USERPROFILE}\\Downloads") or ""),
        ]

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            for kdbx in search_dir.rglob("*.kdbx"):
                results.append({
                    "Source": "KeePass",
                    "Type": "Database File Found",
                    "Path": str(kdbx),
                    "Size": f"{kdbx.stat().st_size:,} bytes",
                })

        return results


class Bitwarden(ModuleBase):
    """Recover Bitwarden Desktop cached vault data."""

    meta = ModuleMeta(
        name="Bitwarden",
        category=Category.PASSWORDS,
        description="Recover Bitwarden desktop vault location, session keys, and cached data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        bw_path = Path(_resolve("{APPDATA}\\Bitwarden") or "")
        if not bw_path.exists():
            return results

        # data.json — main vault cache
        data_json = bw_path / "data.json"
        if data_json.exists():
            try:
                data = json.loads(data_json.read_text(encoding="utf-8"))

                entry: dict[str, Any] = {"Source": "Bitwarden"}

                # Account email
                if "userEmail" in data:
                    entry["Email"] = data["userEmail"]
                if "userId" in data:
                    entry["User ID"] = data["userId"]

                # Vault format
                if "encKey" in data:
                    entry["Encrypted Key"] = data["encKey"][:64] + "..."
                if "keyHash" in data:
                    entry["Key Hash"] = data["keyHash"][:64] + "..."

                # Environment
                env = data.get("environmentUrls", {})
                if env:
                    entry["Server"] = env.get("base", "cloud")

                # Count cached items
                ciphers = data.get("ciphers_" + data.get("userId", ""), {})
                if ciphers:
                    entry["Cached Entries"] = str(len(ciphers))

                results.append(entry)
            except Exception:
                pass

        # Local storage / leveldb
        ls_path = bw_path / "Local Storage" / "leveldb"
        if ls_path.exists():
            results.append({
                "Source": "Bitwarden (Cache)",
                "Path": str(ls_path),
                "Note": "LevelDB local storage — may contain session data",
            })

        return results


class OnePassword(ModuleBase):
    """Recover 1Password local vault metadata."""

    meta = ModuleMeta(
        name="1Password",
        category=Category.PASSWORDS,
        description="Recover 1Password local vault metadata and account info",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # 1Password 7+
        op_paths = [
            Path(_resolve("{LOCALAPPDATA}\\1Password\\data") or ""),
            Path(_resolve("{LOCALAPPDATA}\\1password\\data") or ""),
            Path(_resolve("{APPDATA}\\1Password") or ""),
        ]

        for op_path in op_paths:
            if not op_path.exists():
                continue

            for db in op_path.rglob("*.sqlite"):
                results.append({
                    "Source": "1Password",
                    "Type": "Vault Database",
                    "Path": str(db),
                    "Size": f"{db.stat().st_size:,} bytes",
                })

            for f in op_path.rglob("*.json"):
                if "account" in f.name.lower():
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        results.append({
                            "Source": "1Password",
                            "Type": "Account Info",
                            "Email": data.get("email", data.get("userEmail", "")),
                            "Server": data.get("url", data.get("server", "")),
                        })
                    except Exception:
                        pass

        # 1Password CLI
        op_cli_config = Path(_resolve("{APPDATA}\\op") or "")
        if op_cli_config.exists():
            for cfg in op_cli_config.rglob("config"):
                results.append({
                    "Source": "1Password CLI",
                    "Path": str(cfg),
                })

        return results


class LastPass(ModuleBase):
    """Recover LastPass cached vault data from browser extension stores."""

    meta = ModuleMeta(
        name="LastPass",
        category=Category.PASSWORDS,
        description="Recover LastPass extension cached vault and account data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # LastPass stores data in browser extension local storage
        # Check AppData for standalone app
        lp_path = Path(_resolve("{APPDATA}\\LastPass") or "")
        if lp_path.exists():
            for f in lp_path.rglob("*"):
                if f.is_file() and f.suffix in (".dat", ".sht", ".bco"):
                    results.append({
                        "Source": "LastPass",
                        "Type": "Data File",
                        "Path": str(f),
                        "Size": f"{f.stat().st_size:,} bytes",
                    })

        # Also check LocalAppData
        lp_local = Path(_resolve("{LOCALAPPDATA}\\LastPass") or "")
        if lp_local.exists():
            for f in lp_local.rglob("*"):
                if f.is_file():
                    results.append({
                        "Source": "LastPass (Local)",
                        "Path": str(f),
                    })

        # Chrome extension local storage
        chrome_ext = Path(
            _resolve("{LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\Local Extension Settings") or ""
        )
        if chrome_ext.exists():
            # LastPass extension ID: hdokiejnpimakedhajhdlcegeplioahd
            lp_ext = chrome_ext / "hdokiejnpimakedhajhdlcegeplioahd"
            if lp_ext.exists():
                results.append({
                    "Source": "LastPass (Chrome Extension)",
                    "Path": str(lp_ext),
                    "Note": "LevelDB — may contain cached vault entries",
                })

        return results
