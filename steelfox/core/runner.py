# -*- coding: utf-8 -*-
"""
SteelFox — Execution Runner

Orchestrates the full scan lifecycle:
  1. Admin detection and system module execution (if privileged)
  2. Current user credential recovery
  3. Other user enumeration & impersonation (if admin)
  4. Deferred DPAPI / WinAPI module execution
  5. Report generation

This is the main "engine" of SteelFox.
"""

from __future__ import annotations

import logging
import time
import traceback
from typing import Any, Generator

from steelfox.core.config import config
from steelfox.core.module_base import ModuleBase
from steelfox.core.module_loader import (
    get_categories,
    get_modules_by_category,
    instantiate_modules,
)
from steelfox.core.output import StandardOutput, print_debug, write_reports
from steelfox.core.privileges import (
    get_current_username,
    get_users_on_filesystem,
    is_admin,
    set_env_for_user,
)

logger = logging.getLogger("steelfox")


# ─── Types ───────────────────────────────────────────────────────────────
ScanResult = tuple[bool, str, list[dict[str, Any]]]


# ─── Module Execution ────────────────────────────────────────────────────

def _run_single_module(module: ModuleBase) -> Generator[ScanResult, None, None]:
    """Execute a single module, yielding its result."""
    name = module.meta.name
    try:
        if config.st:
            config.st.title_info(name)
        results = module.run() or []
        if config.st:
            config.st.print_output(name, results)

        # Accumulate results into final_results for report generation
        if results:
            config.nb_credentials_found += len(results)
            cat_key = module.meta.category.value
            if cat_key not in config.final_results:
                config.final_results[cat_key] = {}
            if name not in config.final_results[cat_key]:
                config.final_results[cat_key][name] = []
            config.final_results[cat_key][name].extend(results)

        yield True, name, results
    except Exception:
        error_msg = traceback.format_exc()
        print_debug("DEBUG", f"Module {name} failed:\n{error_msg}")
        yield False, name, []


def _run_module_set(
    modules: list[ModuleBase],
    system_mode: bool = False,
) -> Generator[ScanResult, None, None]:
    """Run a filtered set of modules, deferring DPAPI/WinAPI ones."""
    for mod in modules:
        meta = mod.meta

        # Skip registry-dependent modules when not the current user
        if not config.is_current_user:
            if meta.registry_used or meta.only_current_user:
                continue

        # System vs non-system separation
        if system_mode != meta.system_module:
            continue

        # Defer WinAPI modules
        if meta.winapi_used:
            config.module_to_exec_at_end["winapi"].append(mod)
            continue

        # Defer DPAPI modules
        if meta.dpapi_used:
            config.module_to_exec_at_end["dpapi"].append(mod)
            continue

        yield from _run_single_module(mod)


def _run_deferred_modules() -> Generator[ScanResult, None, None]:
    """Execute modules that were deferred (WinAPI / DPAPI)."""
    # WinAPI modules (only for current user)
    if config.is_current_user:
        for mod in config.module_to_exec_at_end.get("winapi", []):
            yield from _run_single_module(mod)

    # DPAPI modules
    for mod in config.module_to_exec_at_end.get("dpapi", []):
        yield from _run_single_module(mod)


# ─── Category Execution ─────────────────────────────────────────────────

def run_category(
    category: str = "all",
    system_mode: bool = False,
) -> Generator[ScanResult, None, None]:
    """Execute all modules in one or all categories."""
    config.module_to_exec_at_end = {"winapi": [], "dpapi": []}

    if category == "all":
        modules = instantiate_modules()
    else:
        modules = instantiate_modules(category=category)

    # Sort modules: non-deferred first
    yield from _run_module_set(modules, system_mode=system_mode)

    # Run deferred modules
    if not system_mode:
        yield from _run_deferred_modules()


# ─── Main Scan Entry Point ──────────────────────────────────────────────

def run_steelfox(
    category: str = "all",
    password: str | None = None,
    output_dir: str = ".",
    output_format: str | None = None,
) -> Generator[tuple[str, Any], None, None]:
    """Full SteelFox scan lifecycle.

    Yields tuples of:
        ("User", username) — when switching to a new user context
        (success, module_name, results) — per-module results

    After the generator is exhausted, reports are written if configured.
    """
    # ─── Setup ───────────────────────────────────────────────────────
    if password:
        config.user_password = password
    if output_format:
        config.output_format = output_format
    if output_dir:
        config.output_dir = output_dir

    if not config.st:
        config.st = StandardOutput()

    config.is_admin = is_admin()
    config.st.print_banner()

    # ─── Phase 1: System Modules (admin only) ────────────────────────
    if config.is_admin:
        logger.info("Running with administrator privileges — system modules enabled.")
        config.username = "SYSTEM"
        config.final_results = {"User": "SYSTEM"}
        config.is_current_user = False

        if config.st:
            config.st.print_user("SYSTEM")
        yield "User", "SYSTEM"

        try:
            for result in run_category(category, system_mode=True):
                yield result
        except Exception:
            print_debug("WARNING", traceback.format_exc())

        config.stdout_result.append(config.final_results)

    # ─── Phase 2: Current User ───────────────────────────────────────
    config.is_current_user = True
    config.username = get_current_username()

    if not config.username.endswith("$"):
        config.final_results = {"User": config.username}
        config.st.print_user(config.username)
        yield "User", config.username

        set_env_for_user(config.username, impersonate=False)

        for result in run_category(category):
            yield result

        config.stdout_result.append(config.final_results)

    # ─── Phase 3: Other Users (admin only, filesystem walk) ──────────
    if config.is_admin:
        config.is_current_user = False
        other_users = get_users_on_filesystem(exclude_current=True)

        for user in other_users:
            set_env_for_user(user, impersonate=True)
            config.username = user
            config.final_results = {"User": user}
            config.st.print_user(user)
            yield "User", user

            for result in run_category(category):
                yield result

            config.stdout_result.append(config.final_results)

    # ─── Phase 4: Reports ────────────────────────────────────────────
    config.st.print_footer()

    paths: list[str] = []
    if config.output_format:
        paths = write_reports(config.stdout_result, config.output_dir)
        for p in paths:
            logger.info("Report saved: %s", p)
        if config.st:
            config.st.print_report_path(paths)
