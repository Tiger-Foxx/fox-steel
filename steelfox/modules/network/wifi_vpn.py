# -*- coding: utf-8 -*-
"""
SteelFox — WiFi Password Recovery

Recovers saved WiFi network credentials using:
  - `netsh wlan show profiles` + `netsh wlan show profile name=X key=clear`
  - Works on Windows 10/11
  - Requires administrator privileges for WPA/WPA2 key retrieval
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any

from steelfox.core.module_base import Category, ModuleBase, ModuleMeta
from steelfox.core.privileges import is_admin


def _decode_cmd_output(raw: bytes) -> str:
    """Decode subprocess output trying OEM codepage before UTF-8."""
    for enc in ("utf-8", "cp850", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")

logger = logging.getLogger("steelfox")


class WiFi(ModuleBase):
    """Recovery module for saved WiFi network passwords."""

    meta = ModuleMeta(
        name="WiFi Networks",
        category=Category.NETWORK,
        description="Recover saved WiFi network passwords using netsh",
        admin_required=False,  # Can list profiles without admin, but keys need admin
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Get list of all WiFi profiles
        profiles = self._get_wifi_profiles()
        if not profiles:
            return results

        for profile_name in profiles:
            info = self._get_profile_details(profile_name)
            if info:
                results.append(info)

        return results

    @staticmethod
    def _get_wifi_profiles() -> list[str]:
        """List all saved WiFi profile names."""
        try:
            output = _decode_cmd_output(subprocess.check_output(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=False,
                stderr=subprocess.DEVNULL,
                timeout=15,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            ))

            profiles = []
            for line in output.splitlines():
                if ":" in line:
                    # Handle both English and French locales
                    match = re.search(r":\s*(.+)$", line)
                    if match:
                        name = match.group(1).strip()
                        if name and name not in ("", " "):
                            profiles.append(name)
            return profiles
        except Exception as e:
            logger.debug("Failed to list WiFi profiles: %s", e)
            return []

    @staticmethod
    def _get_profile_details(profile_name: str) -> dict[str, Any] | None:
        """Get detailed information about a WiFi profile, including the key."""
        try:
            output = _decode_cmd_output(subprocess.check_output(
                ["netsh", "wlan", "show", "profile", f"name={profile_name}", "key=clear"],
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=0x08000000,
            ))

            info: dict[str, Any] = {
                "Source": "WiFi",
                "SSID": profile_name,
                "Password": "",
                "Authentication": "",
                "Cipher": "",
                "Security Type": "",
                "Connection Mode": "",
            }

            for line in output.splitlines():
                line_clean = line.strip()

                # Password / Key Content (English + French + other locales)
                if re.search(r"Key Content|Contenu de la cl|Schl.sselinhalt|Contenido de la clave", line_clean, re.IGNORECASE):
                    match = re.search(r":\s*(.+)$", line_clean)
                    if match:
                        info["Password"] = match.group(1).strip()

                # Authentication
                elif re.search(r"Authentication|Authentification|Authentifizierung", line_clean, re.IGNORECASE):
                    match = re.search(r":\s*(.+)$", line_clean)
                    if match:
                        info["Authentication"] = match.group(1).strip()

                # Cipher
                elif re.search(r"Cipher|Chiffrement|Verschl", line_clean, re.IGNORECASE):
                    match = re.search(r":\s*(.+)$", line_clean)
                    if match:
                        info["Cipher"] = match.group(1).strip()

                # Security type
                elif re.search(r"Security key|Cl. de s.curit|Sicherheitsschl", line_clean, re.IGNORECASE):
                    match = re.search(r":\s*(.+)$", line_clean)
                    if match:
                        info["Security Type"] = match.group(1).strip()

                # Connection mode
                elif re.search(r"Connection mode|Mode de connexion", line_clean, re.IGNORECASE):
                    match = re.search(r":\s*(.+)$", line_clean)
                    if match:
                        info["Connection Mode"] = match.group(1).strip()

            return info if info["SSID"] else None

        except Exception as e:
            logger.debug("Failed to get WiFi profile details for '%s': %s", profile_name, e)
            return None


# ═══════════════════════════════════════════════════════════════════════════
# VPN Client Credential Recovery
# ═══════════════════════════════════════════════════════════════════════════

class OpenVPN(ModuleBase):
    """Recover OpenVPN configuration files and embedded credentials."""

    meta = ModuleMeta(
        name="OpenVPN",
        category=Category.NETWORK,
        description="Recover OpenVPN profiles, certificates, and stored credentials",
    )

    OPENVPN_PATHS = [
        "{USERPROFILE}\\OpenVPN\\config",
        "{APPDATA}\\OpenVPN\\config",
        "C:\\Program Files\\OpenVPN\\config",
        "C:\\Program Files (x86)\\OpenVPN\\config",
        "{LOCALAPPDATA}\\OpenVPN Connect\\profiles",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        from steelfox.core.config import config as cfg
        for tmpl in self.OPENVPN_PATHS:
            try:
                path = tmpl
                for k, v in cfg.profile.items():
                    path = path.replace(f"{{{k}}}", v)
            except Exception:
                continue

            from pathlib import Path
            base = Path(path)
            if not base.exists():
                continue

            for ovpn_file in base.rglob("*.ovpn"):
                info = self._parse_ovpn(ovpn_file)
                if info:
                    results.append(info)

            for conf_file in base.rglob("*.conf"):
                info = self._parse_ovpn(conf_file)
                if info:
                    results.append(info)

        return results

    @staticmethod
    def _parse_ovpn(filepath) -> dict[str, Any] | None:
        """Parse an OpenVPN config file for credentials and server info."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            info: dict[str, Any] = {
                "Source": "OpenVPN",
                "Config File": str(filepath),
                "Server": "",
                "Port": "",
                "Protocol": "",
                "Auth User File": "",
            }

            for line in content.splitlines():
                line = line.strip()
                if line.startswith("remote "):
                    parts = line.split()
                    if len(parts) >= 2:
                        info["Server"] = parts[1]
                    if len(parts) >= 3:
                        info["Port"] = parts[2]
                elif line.startswith("proto "):
                    info["Protocol"] = line.split(None, 1)[1]
                elif line.startswith("auth-user-pass"):
                    parts = line.split(None, 1)
                    if len(parts) > 1:
                        info["Auth User File"] = parts[1]

            # Check for embedded credentials in auth-user-pass file
            if info["Auth User File"]:
                auth_file = filepath.parent / info["Auth User File"]
                if auth_file.exists():
                    try:
                        lines = auth_file.read_text().strip().splitlines()
                        if len(lines) >= 2:
                            info["Username"] = lines[0].strip()
                            info["Password"] = lines[1].strip()
                    except Exception:
                        pass

            return info if info["Server"] else None
        except Exception:
            return None


class NordVPN(ModuleBase):
    """Recover NordVPN stored credentials."""

    meta = ModuleMeta(
        name="NordVPN",
        category=Category.NETWORK,
        description="Recover NordVPN stored user credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        from pathlib import Path
        from steelfox.core.config import config as cfg

        nord_paths = [
            Path(cfg.profile.get("LOCALAPPDATA", "")) / "NordVPN",
            Path(cfg.profile.get("APPDATA", "")) / "NordVPN",
        ]

        for base in nord_paths:
            if not base.exists():
                continue

            # NordVPN stores credentials in user.config XML files
            for config_file in base.rglob("user.config"):
                try:
                    content = config_file.read_text(encoding="utf-8", errors="replace")
                    # Extract username/password from XML config
                    import re
                    username_match = re.search(
                        r"<setting name=\"Username\".*?<value>(.*?)</value>",
                        content, re.DOTALL
                    )
                    password_match = re.search(
                        r"<setting name=\"Password\".*?<value>(.*?)</value>",
                        content, re.DOTALL
                    )

                    if username_match or password_match:
                        results.append(self._make_credential(
                            source="NordVPN",
                            username=username_match.group(1) if username_match else "",
                            password=password_match.group(1) if password_match else "",
                        ))
                except Exception:
                    continue

            # Also check for NordVPN SQLite databases
            for db in base.rglob("*.db"):
                results.append({
                    "Source": "NordVPN",
                    "Type": "Database",
                    "Path": str(db),
                })

        return results


class ProtonVPN(ModuleBase):
    """Recover ProtonVPN stored configuration."""

    meta = ModuleMeta(
        name="ProtonVPN",
        category=Category.NETWORK,
        description="Recover ProtonVPN configuration and profile data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        from pathlib import Path
        from steelfox.core.config import config as cfg
        import json

        proton_paths = [
            Path(cfg.profile.get("LOCALAPPDATA", "")) / "ProtonVPN",
            Path(cfg.profile.get("APPDATA", "")) / "ProtonVPN",
        ]

        for base in proton_paths:
            if not base.exists():
                continue

            # ProtonVPN stores config in JSON/XML files
            for json_file in base.rglob("*.json"):
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        for key in data:
                            if any(kw in key.lower() for kw in ["user", "pass", "token", "auth", "credential"]):
                                results.append({
                                    "Source": "ProtonVPN",
                                    "Type": f"Config: {key}",
                                    "Value": str(data[key])[:200],
                                    "File": str(json_file),
                                })
                except Exception:
                    continue

            for ovpn in base.rglob("*.ovpn"):
                results.append({
                    "Source": "ProtonVPN",
                    "Type": "OpenVPN Profile",
                    "Path": str(ovpn),
                })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# WireGuard
# ═══════════════════════════════════════════════════════════════════════════

class WireGuard(ModuleBase):
    """Recover WireGuard VPN tunnel configurations (private keys in cleartext)."""

    meta = ModuleMeta(
        name="WireGuard",
        category=Category.NETWORK,
        description="Recover WireGuard tunnel configs with private keys (stored in cleartext)",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        from pathlib import Path

        # WireGuard stores configs in Program Files
        wg_paths = [
            Path(r"C:\Program Files\WireGuard\Data\Configurations"),
            Path(r"C:\Windows\System32\config\systemprofile\AppData\Local\WireGuard\Configurations"),
        ]

        for wg_dir in wg_paths:
            if not wg_dir.exists():
                continue

            for conf in wg_dir.glob("*.conf*"):
                try:
                    content = conf.read_text(encoding="utf-8", errors="replace")
                    entry: dict[str, Any] = {
                        "Source": "WireGuard",
                        "Config File": str(conf),
                    }

                    for line in content.splitlines():
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip()
                            if key == "PrivateKey":
                                entry["Private Key"] = val
                            elif key == "Address":
                                entry["Address"] = val
                            elif key == "DNS":
                                entry["DNS"] = val
                            elif key == "Endpoint":
                                entry["Endpoint"] = val
                            elif key == "PublicKey":
                                entry["Peer Public Key"] = val
                            elif key == "PresharedKey":
                                entry["Preshared Key"] = val
                            elif key == "AllowedIPs":
                                entry["Allowed IPs"] = val

                    results.append(entry)
                except PermissionError:
                    results.append({
                        "Source": "WireGuard",
                        "Config File": str(conf),
                        "Note": "Access denied — likely need SYSTEM privileges",
                    })
                except Exception:
                    continue

        # Also check user-accessible wg configs
        from steelfox.core.config import config as cfg
        user_wg = Path(cfg.profile.get("LOCALAPPDATA", "")) / "WireGuard" / "Configurations"
        if user_wg.exists():
            for conf in user_wg.glob("*.conf*"):
                try:
                    content = conf.read_text(encoding="utf-8", errors="replace")
                    entry = {"Source": "WireGuard (User)", "Config File": str(conf)}
                    for line in content.splitlines():
                        line = line.strip()
                        if "=" in line and not line.startswith("#") and "privatekey" in line.lower():
                            _, val = line.split("=", 1)
                            entry["Private Key"] = val.strip()
                    results.append(entry)
                except Exception:
                    continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Cisco AnyConnect
# ═══════════════════════════════════════════════════════════════════════════

class CiscoAnyConnect(ModuleBase):
    """Recover Cisco AnyConnect VPN profiles and connection history."""

    meta = ModuleMeta(
        name="Cisco AnyConnect",
        category=Category.NETWORK,
        description="Recover Cisco AnyConnect VPN profiles, recent connections, and certificates",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        from pathlib import Path
        import xml.etree.ElementTree as ET

        anyconnect_paths = [
            Path(r"C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client"),
            Path(r"C:\ProgramData\Cisco\Cisco Secure Client"),
        ]

        for ac_path in anyconnect_paths:
            if not ac_path.exists():
                continue

            # Profile XML files
            profile_dir = ac_path / "profile"
            if profile_dir.exists():
                for xml_file in profile_dir.rglob("*.xml"):
                    try:
                        tree = ET.parse(str(xml_file))
                        root = tree.getroot()

                        # Remove namespace for easier parsing
                        ns = ""
                        if root.tag.startswith("{"):
                            ns = root.tag.split("}")[0] + "}"

                        for host in root.iter(f"{ns}HostEntry"):
                            name = host.find(f"{ns}HostName")
                            addr = host.find(f"{ns}HostAddress")
                            results.append({
                                "Source": "Cisco AnyConnect",
                                "Type": "VPN Profile",
                                "Host": name.text if name is not None else "",
                                "Address": addr.text if addr is not None else "",
                                "Profile": str(xml_file),
                            })
                    except Exception:
                        continue

            # Preferences with recent connections
            prefs_file = ac_path / "preferences.xml"
            if prefs_file.exists():
                try:
                    tree = ET.parse(str(prefs_file))
                    root = tree.getroot()
                    for host in root.iter("DefaultHostName"):
                        if host.text:
                            results.append({
                                "Source": "Cisco AnyConnect",
                                "Type": "Recent Connection",
                                "Host": host.text,
                            })
                    for user in root.iter("DefaultUser"):
                        if user.text:
                            results.append({
                                "Source": "Cisco AnyConnect",
                                "Type": "Last Username",
                                "Username": user.text,
                            })
                except Exception:
                    pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# FortiClient VPN
# ═══════════════════════════════════════════════════════════════════════════

class FortiClientVPN(ModuleBase):
    """Recover FortiClient VPN stored credentials."""

    meta = ModuleMeta(
        name="FortiClient VPN",
        category=Category.NETWORK,
        description="Recover FortiClient SSL VPN tunnel credentials from the registry",
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        import winreg

        reg_paths = [
            r"SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels",
            r"SOFTWARE\FortiClient\Sslvpn\Tunnels",
        ]

        for reg_path in reg_paths:
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    tunnels_key = winreg.OpenKey(hive, reg_path)
                    idx = 0
                    while True:
                        try:
                            tunnel_name = winreg.EnumKey(tunnels_key, idx)
                            tunnel_key = winreg.OpenKey(tunnels_key, tunnel_name)

                            entry: dict[str, Any] = {
                                "Source": "FortiClient VPN",
                                "Tunnel": tunnel_name,
                            }

                            for val_name in ["Server", "ServerCert", "userName", "DATA1", "DATA2", "DATA3"]:
                                try:
                                    val, _ = winreg.QueryValueEx(tunnel_key, val_name)
                                    if val_name == "DATA3" and isinstance(val, str) and val:
                                        # DATA3 contains the encrypted password
                                        entry["Encrypted Password"] = val[:64] + "..."
                                    elif val_name == "Server":
                                        entry["Server"] = str(val)
                                    elif val_name == "userName":
                                        entry["Username"] = str(val)
                                    elif val:
                                        entry[val_name] = str(val)[:100]
                                except FileNotFoundError:
                                    continue

                            winreg.CloseKey(tunnel_key)
                            results.append(entry)
                            idx += 1
                        except OSError:
                            break

                    winreg.CloseKey(tunnels_key)
                except Exception:
                    continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# GlobalProtect (Palo Alto)
# ═══════════════════════════════════════════════════════════════════════════

class GlobalProtect(ModuleBase):
    """Recover GlobalProtect VPN configuration and credentials."""

    meta = ModuleMeta(
        name="GlobalProtect VPN",
        category=Category.NETWORK,
        description="Recover Palo Alto GlobalProtect VPN portals, credentials, and certificates",
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        import winreg
        from pathlib import Path
        from steelfox.core.config import config as cfg

        # Registry
        reg_paths = [
            r"SOFTWARE\Palo Alto Networks\GlobalProtect\PanSetup",
            r"SOFTWARE\Palo Alto Networks\GlobalProtect\Settings",
        ]

        for reg_path in reg_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                entry: dict[str, Any] = {"Source": "GlobalProtect"}
                idx = 0
                while True:
                    try:
                        val_name, val, _ = winreg.EnumValue(key, idx)
                        if val:
                            entry[val_name] = str(val)[:200]
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                if len(entry) > 1:
                    results.append(entry)
            except Exception:
                continue

        # Config files
        gp_paths = [
            Path(cfg.profile.get("LOCALAPPDATA", "")) / "Palo Alto Networks" / "GlobalProtect",
            Path(r"C:\ProgramData\Palo Alto Networks\GlobalProtect"),
        ]

        for gp_path in gp_paths:
            if not gp_path.exists():
                continue
            for xml_file in gp_path.rglob("*.xml"):
                results.append({
                    "Source": "GlobalProtect",
                    "Type": "Config File",
                    "Path": str(xml_file),
                    "Size": f"{xml_file.stat().st_size:,} bytes",
                })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Tailscale
# ═══════════════════════════════════════════════════════════════════════════

class Tailscale(ModuleBase):
    """Recover Tailscale VPN node identity and configuration."""

    meta = ModuleMeta(
        name="Tailscale",
        category=Category.NETWORK,
        description="Recover Tailscale node identity, auth keys, and network state",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        import winreg
        from pathlib import Path
        import json
        from steelfox.core.config import config as cfg

        # Registry
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Tailscale IPN")
            entry: dict[str, Any] = {"Source": "Tailscale"}
            idx = 0
            while True:
                try:
                    val_name, val, _ = winreg.EnumValue(key, idx)
                    entry[val_name] = str(val)[:200]
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            if len(entry) > 1:
                results.append(entry)
        except Exception:
            pass

        # LocalState
        ts_paths = [
            Path(cfg.profile.get("LOCALAPPDATA", "")) / "Tailscale",
            Path(r"C:\ProgramData\Tailscale"),
        ]

        for ts_path in ts_paths:
            if not ts_path.exists():
                continue
            for f in ts_path.rglob("*.json"):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        for key_name in ("AuthKey", "NodeKey", "PrivateNodeKey", "MachineKey"):
                            if key_name in data:
                                results.append({
                                    "Source": "Tailscale",
                                    "Type": key_name,
                                    "Value": str(data[key_name])[:100],
                                })
                except Exception:
                    continue

        return results
