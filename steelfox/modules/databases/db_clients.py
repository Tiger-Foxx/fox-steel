# -*- coding: utf-8 -*-
"""
SteelFox — Database Client Credential Recovery

Recovers data from:
  - MySQL Workbench
  - DBeaver
  - HeidiSQL
  - pgAdmin (PostgreSQL)
  - DBVisualizer
  - Robomongo / Robo 3T (MongoDB)
  - Redis Desktop Manager
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import winreg
import xml.etree.ElementTree as ET
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


class MySQLWorkbench(ModuleBase):
    """Recover MySQL Workbench stored connections."""

    meta = ModuleMeta(
        name="MySQL Workbench",
        category=Category.DATABASES,
        description="Recover MySQL Workbench stored server connections",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        wb_path = Path(_resolve("{APPDATA}\\MySQL\\Workbench") or "")
        if not wb_path.exists():
            return results

        connections_file = wb_path / "connections.xml"
        if not connections_file.exists():
            return results

        try:
            tree = ET.parse(str(connections_file))
            root = tree.getroot()

            for conn in root.iter("value"):
                if conn.get("type") != "object" or "db.mgmt.Connection" not in conn.get(
                    "struct-name", ""
                ):
                    continue

                entry: dict[str, Any] = {"Source": "MySQL Workbench"}

                for param in conn.iter("value"):
                    key = param.get("key", "")
                    if key == "name":
                        entry["Connection Name"] = param.text or ""
                    elif key == "hostName":
                        entry["Host"] = param.text or ""
                    elif key == "port":
                        entry["Port"] = param.text or "3306"
                    elif key == "userName":
                        entry["Username"] = param.text or ""
                    elif key == "schema":
                        entry["Database"] = param.text or ""

                if entry.get("Host") or entry.get("Username"):
                    results.append(entry)

        except Exception as e:
            logger.debug("MySQL Workbench parse failed: %s", e)

        return results


class DBeaver(ModuleBase):
    """Recover DBeaver stored database credentials."""

    meta = ModuleMeta(
        name="DBeaver",
        category=Category.DATABASES,
        description="Recover DBeaver saved connections and credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        dbeaver_paths = [
            Path(_resolve("{APPDATA}\\DBeaverData\\workspace6\\General\\.dbeaver") or ""),
            Path(_resolve("{APPDATA}\\DBeaverData\\workspace6\\.dbeaver") or ""),
        ]

        for dbeaver_path in dbeaver_paths:
            if not dbeaver_path.exists():
                continue

            # data-sources.json — connection definitions
            ds_file = dbeaver_path / "data-sources.json"
            if ds_file.exists():
                try:
                    data = json.loads(ds_file.read_text(encoding="utf-8"))
                    connections = data.get("connections", {})

                    for conn_id, conn_data in connections.items():
                        config_data = conn_data.get("configuration", {})
                        entry: dict[str, Any] = {
                            "Source": "DBeaver",
                            "Connection ID": conn_id,
                            "Name": conn_data.get("name", ""),
                            "Driver": conn_data.get("driver", ""),
                            "URL": config_data.get("url", ""),
                            "Host": config_data.get("host", ""),
                            "Port": str(config_data.get("port", "")),
                            "Database": config_data.get("database", ""),
                            "Username": config_data.get("user", ""),
                        }
                        results.append(entry)
                except Exception:
                    pass

            # credentials-config.json — encrypted passwords
            creds_file = dbeaver_path / "credentials-config.json"
            if creds_file.exists():
                try:
                    creds_raw = creds_file.read_bytes()
                    # DBeaver uses a simple XOR cipher with a static key
                    # babb4a9f-7295-11d1-a5e2-0007e4c92c6b
                    dec = self._decrypt_dbeaver(creds_raw)
                    if dec:
                        creds_data = json.loads(dec)
                        for conn_id, cred_info in creds_data.items():
                            for existing in results:
                                if existing.get("Connection ID") == conn_id:
                                    existing["Password"] = cred_info.get(
                                        "#connection", {}
                                    ).get("password", "")
                                    break
                except Exception as e:
                    logger.debug("DBeaver credential decrypt failed: %s", e)

        return results

    @staticmethod
    def _decrypt_dbeaver(data: bytes) -> str | None:
        """Decrypt DBeaver credentials (static AES key)."""
        try:
            from Crypto.Cipher import AES

            # DBeaver's static encryption key (derived from their UUID)
            key = bytes([
                0xBA, 0xBB, 0x4A, 0x9F, 0x72, 0x95, 0x11, 0xD1,
                0xA5, 0xE2, 0x00, 0x07, 0xE4, 0xC9, 0x2C, 0x6B,
            ])
            iv = bytes([0] * 16)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(data)

            # Remove PKCS7 padding
            pad_len = decrypted[-1]
            if 0 < pad_len <= 16:
                decrypted = decrypted[:-pad_len]

            return decrypted.decode("utf-8")
        except Exception:
            return None


class HeidiSQL(ModuleBase):
    """Recover HeidiSQL stored server credentials."""

    meta = ModuleMeta(
        name="HeidiSQL",
        category=Category.DATABASES,
        description="Recover HeidiSQL stored server connections and passwords",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\HeidiSQL\Servers",
            )

            idx = 0
            while True:
                try:
                    server_name = winreg.EnumKey(key, idx)
                    server_key = winreg.OpenKey(key, server_name)

                    entry: dict[str, Any] = {
                        "Source": "HeidiSQL",
                        "Server Name": server_name,
                    }

                    for val_name in ["Host", "Port", "User", "Password", "Database"]:
                        try:
                            val, _ = winreg.QueryValueEx(server_key, val_name)
                            if val_name == "Password" and val:
                                # HeidiSQL uses a simple shift cipher
                                entry["Password"] = self._decrypt_heidi(str(val))
                            else:
                                entry[val_name] = str(val)
                        except FileNotFoundError:
                            continue

                    winreg.CloseKey(server_key)
                    results.append(entry)
                    idx += 1
                except OSError:
                    break

            winreg.CloseKey(key)
        except Exception:
            pass

        return results

    @staticmethod
    def _decrypt_heidi(hex_str: str) -> str:
        """Decrypt HeidiSQL's simple password encoding."""
        try:
            result = []
            shift = int(hex_str[-1])  # last char is the shift value
            hex_data = hex_str[:-1]
            for i in range(0, len(hex_data), 2):
                val = int(hex_data[i : i + 2], 16) - shift
                result.append(chr(val))
            return "".join(result)
        except Exception:
            return hex_str


class PgAdmin(ModuleBase):
    """Recover pgAdmin 4 stored PostgreSQL connections."""

    meta = ModuleMeta(
        name="pgAdmin 4",
        category=Category.DATABASES,
        description="Recover pgAdmin 4 stored PostgreSQL server connections",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        pgadmin_path = Path(
            _resolve("{APPDATA}\\pgAdmin\\pgadmin4") or ""
        )
        if not pgadmin_path.exists():
            pgadmin_path = Path(_resolve("{APPDATA}\\pgAdmin") or "")

        if not pgadmin_path.exists():
            return results

        # servers.json
        servers_file = pgadmin_path / "servers.json"
        # Also check pgadmin4.db (SQLite)
        pgadmin_db = pgadmin_path / "pgadmin4.db"

        if servers_file.exists():
            try:
                data = json.loads(servers_file.read_text(encoding="utf-8"))
                servers = data.get("Servers", data)
                if isinstance(servers, dict):
                    for srv_id, srv in servers.items():
                        results.append({
                            "Source": "pgAdmin 4",
                            "Name": srv.get("Name", ""),
                            "Host": srv.get("Host", ""),
                            "Port": str(srv.get("Port", 5432)),
                            "Username": srv.get("Username", ""),
                            "Database": srv.get("MaintenanceDB", ""),
                            "SSL Mode": srv.get("SSLMode", ""),
                        })
            except Exception:
                pass

        if pgadmin_db.exists():
            try:
                import sqlite3

                conn = sqlite3.connect(str(pgadmin_db))
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                tables = [r[0] for r in cursor.fetchall()]

                if "server" in tables:
                    cursor.execute("SELECT * FROM server")
                    cols = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        data = dict(zip(cols, row))
                        results.append({
                            "Source": "pgAdmin 4 (DB)",
                            "Name": data.get("name", ""),
                            "Host": data.get("host", ""),
                            "Port": str(data.get("port", 5432)),
                            "Username": data.get("username", ""),
                        })

                conn.close()
            except Exception:
                pass

        return results


class Robomongo(ModuleBase):
    """Recover Robo 3T / Robomongo MongoDB stored credentials."""

    meta = ModuleMeta(
        name="Robo 3T",
        category=Category.DATABASES,
        description="Recover Robo 3T (Robomongo) MongoDB stored connections",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        paths = [
            Path(_resolve("{USERPROFILE}\\.3T\\robo-3t") or ""),
            Path(_resolve("{USERPROFILE}\\.3T\\robomongo") or ""),
        ]

        for base_path in paths:
            if not base_path.exists():
                continue

            for version_dir in base_path.iterdir():
                if not version_dir.is_dir():
                    continue

                robo_json = version_dir / "robo3t.json"
                if not robo_json.exists():
                    robo_json = version_dir / "robomongo.json"

                if not robo_json.exists():
                    continue

                try:
                    data = json.loads(robo_json.read_text(encoding="utf-8"))
                    for conn in data.get("connections", []):
                        creds = conn.get("credentials", [{}])
                        for cred in creds:
                            results.append({
                                "Source": "Robo 3T",
                                "Connection": conn.get("connectionName", ""),
                                "Host": conn.get("serverHost", ""),
                                "Port": str(conn.get("serverPort", 27017)),
                                "Database": cred.get("databaseName", ""),
                                "Username": cred.get("userName", ""),
                                "Password": cred.get("userPassword", ""),
                            })
                except Exception:
                    pass

        return results
