# -*- coding: utf-8 -*-
"""
SteelFox — Base Module Class

Every recovery/reconnaissance module inherits from `ModuleBase`.
This provides a uniform interface for:
  - metadata (name, category, description, admin requirement, etc.)
  - execution (`run()` method)
  - output reporting
  - error handling
"""

from __future__ import annotations

import logging
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("steelfox")


class Category(str, Enum):
    """All supported module categories."""
    BROWSERS = "browsers"
    MESSAGING = "messaging"
    MAILS = "mails"
    PASSWORDS = "passwords"
    CLOUD = "cloud"
    GAMING = "gaming"
    DEVTOOLS = "devtools"
    NETWORK = "network"
    SYSADMIN = "sysadmin"
    DATABASES = "databases"
    WINDOWS = "windows"
    RECONNAISSANCE = "reconnaissance"


@dataclass
class ModuleMeta:
    """Metadata descriptor for a SteelFox module."""
    name: str
    category: Category
    description: str = ""
    admin_required: bool = False
    dpapi_used: bool = False
    winapi_used: bool = False
    registry_used: bool = False
    only_current_user: bool = False
    system_module: bool = False
    platforms: list[str] = field(default_factory=lambda: ["windows"])


class ModuleBase(ABC):
    """Abstract base class for all SteelFox recovery / recon modules."""

    # Subclasses MUST define meta as a class-level ModuleMeta
    meta: ModuleMeta

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "meta") or cls.meta is None:
            # Allow abstract intermediaries without meta
            if not getattr(cls, "__abstractmethods__", None):
                raise TypeError(
                    f"Module {cls.__name__} must define a 'meta' attribute "
                    f"of type ModuleMeta."
                )

    # ─── Core Interface ──────────────────────────────────────────────
    @abstractmethod
    def run(self) -> list[dict[str, Any]]:
        """Execute the module logic and return a list of credential dicts.

        Each dict should contain at least:
            - "URL" or "Application": source of the credential
            - "Login" / "Username": the identity
            - "Password" / "Token" / "Key": the secret

        Return an empty list if nothing was found.
        """
        ...

    # ─── Safe Execution Wrapper ──────────────────────────────────────
    def execute(self) -> tuple[bool, str, list[dict[str, Any]]]:
        """Run the module with exception handling.

        Returns:
            (success: bool, module_name: str, results: list[dict])
        """
        name = self.meta.name
        try:
            results = self.run() or []
            return True, name, results
        except Exception:
            logger.debug("Module %s failed:\n%s", name, traceback.format_exc())
            return False, name, []

    # ─── Utilities for Subclasses ────────────────────────────────────
    @staticmethod
    def _make_credential(
        source: str,
        username: str = "",
        password: str = "",
        url: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Helper to build a standardized credential dictionary."""
        cred: dict[str, Any] = {
            "Source": source,
        }
        if url:
            cred["URL"] = url
        if username:
            cred["Username"] = username
        if password:
            cred["Password"] = password
        if extra:
            cred.update(extra)
        return cred

    def __repr__(self) -> str:
        return f"<Module: {self.meta.name} [{self.meta.category.value}]>"
