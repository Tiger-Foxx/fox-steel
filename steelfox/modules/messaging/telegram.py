# -*- coding: utf-8 -*-
"""
SteelFox — Telegram Desktop Session Recovery

Recovers Telegram Desktop session data:
  - tdata folder contents (session keys)
  - Account identification
  - Session file locations

Note: Telegram encrypts session data with a local passcode.
Without the passcode, we can identify that sessions exist but
cannot decrypt the actual auth key.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from steelfox.core.config import config
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta

logger = logging.getLogger("steelfox")


TELEGRAM_PATHS = [
    "{APPDATA}\\Telegram Desktop\\tdata",
    "{APPDATA}\\Telegram Desktop UWP\\tdata",
]


class Telegram(ModuleBase):
    """Recovery module for Telegram Desktop session data."""

    meta = ModuleMeta(
        name="Telegram",
        category=Category.MESSAGING,
        description="Identify Telegram Desktop sessions and recover session file locations",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for tmpl in TELEGRAM_PATHS:
            tdata_path = self._resolve_path(tmpl)
            if not tdata_path or not Path(tdata_path).exists():
                continue

            tdata = Path(tdata_path)

            # Look for key_data file (session encryption key)
            key_data = tdata / "key_datas"
            if not key_data.exists():
                key_data = tdata / "key_data"

            if key_data.exists():
                results.append({
                    "Source": "Telegram Desktop",
                    "Type": "Session Key File",
                    "Path": str(key_data),
                    "Size": f"{key_data.stat().st_size} bytes",
                })

            # Look for session directories (D877F783D5D3EF8C, etc.)
            for item in tdata.iterdir():
                if item.is_dir() and len(item.name) == 16:
                    # This is likely a session/account directory
                    map_file = item / "map0"
                    map_file_s = item / "maps"
                    session_size = sum(
                        f.stat().st_size for f in item.rglob("*") if f.is_file()
                    )
                    results.append({
                        "Source": "Telegram Desktop",
                        "Type": "Session Directory",
                        "Account ID": item.name,
                        "Path": str(item),
                        "Session Data Size": f"{session_size} bytes",
                        "Has Map": str(map_file.exists() or map_file_s.exists()),
                    })

            # Check for settings file
            settings_file = tdata / "settings0"
            if not settings_file.exists():
                settings_file = tdata / "settings1"
            if settings_file.exists():
                results.append({
                    "Source": "Telegram Desktop",
                    "Type": "Settings File",
                    "Path": str(settings_file),
                    "Size": f"{settings_file.stat().st_size} bytes",
                })

        return results

    @staticmethod
    def _resolve_path(template: str) -> str | None:
        try:
            result = template
            for key, value in config.profile.items():
                result = result.replace(f"{{{key}}}", value)
            return result
        except Exception:
            return None
