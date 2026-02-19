# -*- coding: utf-8 -*-
"""
SteelFox — Global Configuration & Runtime State

Centralizes all runtime constants, paths, and shared state used across
the entire framework. Replaces the old mutable class-level approach with
a cleaner dataclass + singleton pattern.
"""

from __future__ import annotations

import os
import random
import string
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _random_filename(min_len: int = 6, max_len: int = 12) -> str:
    """Generate a random lowercase filename for temp hive storage."""
    length = random.randint(min_len, max_len)
    return "".join(random.choices(string.ascii_lowercase, k=length))


@dataclass
class SteelFoxConfig:
    """Singleton-style runtime configuration for SteelFox."""

    # ─── Identity ────────────────────────────────────────────────────────
    APP_NAME: str = "SteelFox"
    VERSION: str = "1.0.0"
    CODENAME: str = "Fox"
    AUTHOR: str = "Fox"
    PYTHON_MIN: str = "3.10"

    # ─── Output ──────────────────────────────────────────────────────────
    output_dir: str = "."
    output_format: str = "html"               # "json" | "txt" | "html" | "all"
    quiet_mode: bool = False
    stealth_mode: bool = False                # hide console window, no output
    verbosity: int = 0                        # 0 = progress bar, 1 = verbose, 2 = debug
    total_modules: int = 0                    # populated before scan for progress bar
    timestamp: str = field(default_factory=lambda: time.strftime("%Y%m%d_%H%M%S"))

    # ─── Runtime State ───────────────────────────────────────────────────
    username: str = ""
    drive: str = "C"
    is_admin: bool = False
    is_current_user: bool = False
    user_password: str | None = None

    # ─── Result Accumulation ─────────────────────────────────────────────
    nb_credentials_found: int = 0
    credentials_found: list[dict[str, Any]] = field(default_factory=list)
    stdout_result: list[dict[str, Any]] = field(default_factory=list)
    final_results: dict[str, Any] = field(default_factory=dict)
    modules_registry: dict[str, Any] = field(default_factory=dict)

    # ─── DPAPI / Windows Internals ───────────────────────────────────────
    user_dpapi: Any = None
    system_dpapi: Any = None
    lsa_secrets: Any = None
    pypykatz_result: dict = field(default_factory=dict)
    dpapi_cache: dict = field(default_factory=dict)
    keepass: dict = field(default_factory=dict)

    # ─── Hive Temp Paths (randomized) ────────────────────────────────────
    hives: dict[str, str] = field(default_factory=lambda: {
        "sam": os.path.join(tempfile.gettempdir(), _random_filename()),
        "security": os.path.join(tempfile.gettempdir(), _random_filename()),
        "system": os.path.join(tempfile.gettempdir(), _random_filename()),
    })

    # ─── Deferred Execution Queues ───────────────────────────────────────
    module_to_exec_at_end: dict[str, list] = field(
        default_factory=lambda: {"winapi": [], "dpapi": []}
    )

    # ─── User Profile Paths (templated) ──────────────────────────────────
    profile: dict[str, str] = field(default_factory=lambda: {
        "APPDATA": "{drive}:\\Users\\{user}\\AppData\\Roaming\\",
        "USERPROFILE": "{drive}:\\Users\\{user}\\",
        "HOMEDRIVE": "{drive}:",
        "HOMEPATH": "{drive}:\\Users\\{user}",
        "ALLUSERSPROFILE": "{drive}:\\ProgramData",
        "LOCALAPPDATA": "{drive}:\\Users\\{user}\\AppData\\Local",
    })

    # ─── StandardOutput reference (set at runtime) ───────────────────────
    st: Any = None

    # ─── Convenience Properties ──────────────────────────────────────────
    @property
    def file_name_results(self) -> str:
        return f"steelfox_report_{self.timestamp}"

    @property
    def appdata(self) -> str:
        return self.profile.get("APPDATA", "")

    @property
    def localappdata(self) -> str:
        return self.profile.get("LOCALAPPDATA", "")

    @property
    def userprofile(self) -> str:
        return self.profile.get("USERPROFILE", "")

    def resolve_profile(self, user: str | None = None) -> None:
        """Fill in {drive} and {user} placeholders for every profile path."""
        u = user or self.username
        for key in self.profile:
            self.profile[key] = self.profile[key].format(drive=self.drive, user=u)

    def reset_results(self) -> None:
        """Clear per-user result accumulators."""
        self.credentials_found.clear()
        self.final_results.clear()
        self.module_to_exec_at_end = {"winapi": [], "dpapi": []}

    # ─── Banner ──────────────────────────────────────────────────────────
    @property
    def BANNER(self) -> str:  # type: ignore[override]
        here = Path(__file__).parent.parent.parent  # project root
        art_file = here / "ascii-art.txt"
        fox = ""
        if art_file.exists():
            try:
                fox = art_file.read_text(encoding="utf-8")
            except Exception:
                pass
        title = (
            "\n"
            "    ███████╗████████╗███████╗███████╗██╗     ███████╗ ██████╗ ██╗  ██╗\n"
            "    ██╔════╝╚══██╔══╝██╔════╝██╔════╝██║     ██╔════╝██╔═══██╗╚██╗██╔╝\n"
            "    ███████╗   ██║   █████╗  █████╗  ██║     █████╗  ██║   ██║ ╚███╔╝ \n"
            "    ╚════██║   ██║   ██╔══╝  ██╔══╝  ██║     ██╔══╝  ██║   ██║ ██╔██╗ \n"
            "    ███████║   ██║   ███████╗███████╗███████╗██║     ╚██████╔╝██╔╝ ██╗\n"
            "    ╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝\n"
        )
        return fox + title


# ─── Global Singleton ────────────────────────────────────────────────────
config = SteelFoxConfig()
