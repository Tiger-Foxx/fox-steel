# -*- coding: utf-8 -*-
"""
SteelFox — Dynamic Module Loader

Scans the `steelfox.modules` package tree, discovers every class that
inherits from `ModuleBase`, and builds a registry organised by category.
This replaces the old hard-coded `get_modules_names()` list approach
with a fully automatic plug-and-play system.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from typing import Any

from steelfox.core.module_base import Category, ModuleBase

logger = logging.getLogger("steelfox")

# ─── Module Registry (populated once at startup) ─────────────────────────
_module_classes: list[type[ModuleBase]] = []
_modules_by_category: dict[str, list[type[ModuleBase]]] = {}
_loaded: bool = False


def _discover_modules() -> None:
    """Walk the `steelfox.modules` package and import every sub-module."""
    global _loaded
    if _loaded:
        return

    import steelfox.modules as modules_pkg

    for importer, modname, ispkg in pkgutil.walk_packages(
        path=modules_pkg.__path__,
        prefix=modules_pkg.__name__ + ".",
    ):
        try:
            module = importlib.import_module(modname)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not import %s: %s", modname, exc)
            continue

        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, ModuleBase)
                and obj is not ModuleBase
                and hasattr(obj, "meta")
                and obj.meta is not None
            ):
                _module_classes.append(obj)
                cat = obj.meta.category.value
                _modules_by_category.setdefault(cat, []).append(obj)

    _loaded = True
    logger.info(
        "Discovered %d modules across %d categories.",
        len(_module_classes),
        len(_modules_by_category),
    )


def get_all_module_classes() -> list[type[ModuleBase]]:
    """Return every discovered module class."""
    _discover_modules()
    return list(_module_classes)


def get_modules_by_category(category: str | Category | None = None) -> dict[str, list[type[ModuleBase]]]:
    """Return {category_name: [ModuleClass, ...]} mapping.

    If *category* is given, return only that subset.
    """
    _discover_modules()
    if category is None:
        return dict(_modules_by_category)

    key = category.value if isinstance(category, Category) else category
    return {key: _modules_by_category.get(key, [])}


def get_categories() -> list[str]:
    """Return sorted list of all categories that contain at least one module."""
    _discover_modules()
    return sorted(_modules_by_category.keys())


def instantiate_modules(
    category: str | Category | None = None,
) -> list[ModuleBase]:
    """Create fresh instances of every discovered module (optionally filtered)."""
    _discover_modules()
    classes = (
        _modules_by_category.get(
            category.value if isinstance(category, Category) else category, []
        )
        if category
        else _module_classes
    )
    instances: list[ModuleBase] = []
    for cls in classes:
        try:
            instances.append(cls())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not instantiate %s: %s", cls.__name__, exc)
    return instances


def module_summary() -> dict[str, int]:
    """Return {category: count} summary of loaded modules."""
    _discover_modules()
    return {cat: len(mods) for cat, mods in sorted(_modules_by_category.items())}
