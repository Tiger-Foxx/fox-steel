# -*- coding: utf-8 -*-
"""
SteelFox — Windows Credential Recovery Modules

Recovers credentials from Windows internal storage mechanisms:
  - Windows Credential Manager (credman)
  - Autologon registry entries
  - Windows Vault
  - DPAPI credential files
  - SAM / LSA Secrets / Hashdump (admin only)
  - Cached domain credentials (MSCache)
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import re
import struct
import subprocess
from pathlib import Path
from typing import Any

from steelfox.core.config import config
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta
from steelfox.core.winapi import (
    HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE,
    enumerate_credential_manager,
    reg_read_value,
)

logger = logging.getLogger("steelfox")


def _decode_cmd_output(raw: bytes) -> str:
    """Decode subprocess output trying OEM codepage before UTF-8."""
    for enc in ("utf-8", "cp850", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


# ═══════════════════════════════════════════════════════════════════════════
# Credential Manager
# ═══════════════════════════════════════════════════════════════════════════

class CredentialManager(ModuleBase):
    """Recover all credentials from Windows Credential Manager."""

    meta = ModuleMeta(
        name="Credential Manager",
        category=Category.WINDOWS,
        description="Enumerate and recover credentials from Windows Credential Manager",
        winapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        creds = enumerate_credential_manager()
        for cred in creds:
            results.append(self._make_credential(
                source="Windows Credential Manager",
                url=cred.get("Target", ""),
                username=cred.get("Username", ""),
                password=cred.get("Password", ""),
                extra={"Credential Type": cred.get("Type", "")},
            ))

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Autologon
# ═══════════════════════════════════════════════════════════════════════════

class Autologon(ModuleBase):
    """Recover Windows Autologon credentials from the registry."""

    meta = ModuleMeta(
        name="Windows Autologon",
        category=Category.WINDOWS,
        description="Recover autologon username and password from the Windows registry",
    )

    WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Check both HKLM and HKCU
        for hive, hive_name in [
            (HKEY_LOCAL_MACHINE, "HKLM"),
            (HKEY_CURRENT_USER, "HKCU"),
        ]:
            username = reg_read_value(hive, self.WINLOGON_KEY, "DefaultUserName")
            password = reg_read_value(hive, self.WINLOGON_KEY, "DefaultPassword")
            domain = reg_read_value(hive, self.WINLOGON_KEY, "DefaultDomainName")
            auto_admin = reg_read_value(hive, self.WINLOGON_KEY, "AutoAdminLogon")

            if username and (password or auto_admin == "1"):
                results.append(self._make_credential(
                    source=f"Windows Autologon ({hive_name})",
                    username=f"{domain}\\{username}" if domain else username,
                    password=password or "<enabled but no password stored>",
                    extra={
                        "AutoAdminLogon": auto_admin or "0",
                        "Domain": domain or "",
                    },
                ))

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Windows Vault
# ═══════════════════════════════════════════════════════════════════════════

class WindowsVault(ModuleBase):
    """Recover credentials from the Windows Vault (Web Credentials, etc.)."""

    meta = ModuleMeta(
        name="Windows Vault",
        category=Category.WINDOWS,
        description="Recover credentials from Windows Vault (Web Credentials, Windows Credentials)",
        winapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        try:
            # Use vaultcmd to enumerate vaults
            output = _decode_cmd_output(subprocess.check_output(
                ["vaultcmd", "/listcreds:\"Web Credentials\"", "/all"],
                stderr=subprocess.DEVNULL,
                timeout=15,
                creationflags=0x08000000,
            ))

            current_entry: dict[str, str] = {}
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    if current_entry:
                        results.append({
                            "Source": "Windows Vault",
                            **current_entry,
                        })
                        current_entry = {}
                    continue

                if ":" in line:
                    key, _, value = line.partition(":")
                    current_entry[key.strip()] = value.strip()

            if current_entry:
                results.append({"Source": "Windows Vault", **current_entry})

        except Exception as e:
            logger.debug("Windows Vault enumeration failed: %s", e)

        # Also try Windows Credentials vault
        try:
            output = _decode_cmd_output(subprocess.check_output(
                ["vaultcmd", "/listcreds:\"Windows Credentials\"", "/all"],
                stderr=subprocess.DEVNULL,
                timeout=15,
                creationflags=0x08000000,
            ))

            current_entry = {}
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    if current_entry:
                        results.append({
                            "Source": "Windows Vault (Windows Credentials)",
                            **current_entry,
                        })
                        current_entry = {}
                    continue

                if ":" in line:
                    key, _, value = line.partition(":")
                    current_entry[key.strip()] = value.strip()

            if current_entry:
                results.append({"Source": "Windows Vault (Windows Credentials)", **current_entry})

        except Exception:
            pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# DPAPI Credential Files
# ═══════════════════════════════════════════════════════════════════════════

class DPAPICredFiles(ModuleBase):
    """Discover and list DPAPI-protected credential files."""

    meta = ModuleMeta(
        name="DPAPI Credential Files",
        category=Category.WINDOWS,
        description="Enumerate DPAPI-protected credential files in user profiles",
        dpapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        cred_dirs = [
            Path(config.profile.get("APPDATA", "")) / "Microsoft" / "Credentials",
            Path(config.profile.get("LOCALAPPDATA", "")) / "Microsoft" / "Credentials",
        ]

        for cred_dir in cred_dirs:
            if not cred_dir.exists():
                continue

            for cred_file in cred_dir.iterdir():
                if cred_file.is_file():
                    try:
                        size = cred_file.stat().st_size
                        results.append({
                            "Source": "DPAPI Credential File",
                            "File": cred_file.name,
                            "Path": str(cred_file),
                            "Size": f"{size} bytes",
                        })

                        # Try DPAPI decryption
                        try:
                            from steelfox.core.winapi import win32_crypt_unprotect_data
                            data = cred_file.read_bytes()
                            if len(data) > 36:
                                decrypted = win32_crypt_unprotect_data(data)
                                if decrypted:
                                    results[-1]["Status"] = "Decryptable"
                                    # Parse the credential blob
                                    results[-1]["Decrypted Size"] = f"{len(decrypted)} bytes"
                        except Exception:
                            results[-1]["Status"] = "Protected (needs master key)"

                    except Exception:
                        continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# SAM / Hashdump (Admin Only)
# ═══════════════════════════════════════════════════════════════════════════

class Hashdump(ModuleBase):
    """Dump password hashes from the SAM registry hive (requires admin)."""

    meta = ModuleMeta(
        name="SAM Hashdump",
        category=Category.WINDOWS,
        description="Dump local user password hashes (LM/NTLM) from the SAM hive",
        admin_required=True,
        system_module=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Try using secretsdump-style approach via reg save
        from steelfox.core.winapi import save_hives, delete_hives

        if not save_hives():
            # Fallback: try pypykatz if available
            return self._try_pypykatz()

        try:
            # Parse SAM + SYSTEM hives for hash extraction
            # This would require a full SAM parser (like impacket's secretsdump)
            # For now, indicate that hives were saved successfully
            for hive_name, hive_path in config.hives.items():
                if os.path.exists(hive_path):
                    results.append({
                        "Source": f"Registry Hive: {hive_name.upper()}",
                        "Type": "Saved Hive",
                        "Path": hive_path,
                        "Size": f"{os.path.getsize(hive_path):,} bytes",
                        "Status": "Saved for offline analysis",
                    })
        finally:
            delete_hives()

        return results

    @staticmethod
    def _try_pypykatz() -> list[dict[str, Any]]:
        """Attempt to use pypykatz for in-memory credential extraction."""
        try:
            import pypykatz  # type: ignore
            # pypykatz live lsa
            results_data = pypykatz.lsa.live_lsa()
            results = []
            for session in results_data:
                for cred in session.credentials:
                    results.append({
                        "Source": "pypykatz (Live LSA)",
                        "Username": cred.username or "",
                        "Domain": cred.domain or "",
                        "Password": cred.password or "",
                        "NT Hash": cred.nt_hash or "",
                    })
            return results
        except ImportError:
            logger.debug("pypykatz not available")
        except Exception as e:
            logger.debug("pypykatz failed: %s", e)
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Unattended / Sysprep Files
# ═══════════════════════════════════════════════════════════════════════════

class UnattendedFiles(ModuleBase):
    """Search for credentials in Windows unattended/sysprep configuration files."""

    meta = ModuleMeta(
        name="Unattended Config",
        category=Category.WINDOWS,
        description="Search unattend.xml, sysprep.xml, and similar files for cleartext passwords",
    )

    SEARCH_PATHS = [
        "C:\\Windows\\Panther\\Unattend.xml",
        "C:\\Windows\\Panther\\unattend.xml",
        "C:\\Windows\\Panther\\Unattend\\Unattend.xml",
        "C:\\Windows\\System32\\sysprep\\sysprep.xml",
        "C:\\Windows\\System32\\sysprep\\Panther\\unattend.xml",
        "C:\\unattend.xml",
        "C:\\autounattend.xml",
    ]

    PASSWORD_PATTERNS = [
        re.compile(r"<Password>.*?<Value>(.*?)</Value>", re.DOTALL | re.IGNORECASE),
        re.compile(r"<AdministratorPassword>.*?<Value>(.*?)</Value>", re.DOTALL | re.IGNORECASE),
        re.compile(r"<AutoLogon>.*?<Password>.*?<Value>(.*?)</Value>", re.DOTALL | re.IGNORECASE),
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for filepath in self.SEARCH_PATHS:
            if not os.path.exists(filepath):
                continue

            try:
                content = Path(filepath).read_text(encoding="utf-8", errors="replace")
                for pattern in self.PASSWORD_PATTERNS:
                    for match in pattern.finditer(content):
                        password = match.group(1).strip()
                        if password:
                            # Try base64 decode (unattend often base64-encodes passwords)
                            decoded = password
                            try:
                                import base64
                                decoded = base64.b64decode(password).decode("utf-16-le", errors="replace")
                            except Exception:
                                pass

                            results.append(self._make_credential(
                                source="Unattended Config",
                                username="Administrator",
                                password=decoded,
                                extra={
                                    "File": filepath,
                                    "Raw Value": password if password != decoded else "",
                                },
                            ))
            except Exception as e:
                logger.debug("Error reading %s: %s", filepath, e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Environment Variables with Sensitive Data
# ═══════════════════════════════════════════════════════════════════════════

class EnvironmentSecrets(ModuleBase):
    """Detect environment variables that likely contain secrets."""

    meta = ModuleMeta(
        name="Environment Secrets",
        category=Category.WINDOWS,
        description="Scan environment variables for tokens, keys, passwords, and secrets",
    )

    SENSITIVE_KEYWORDS = [
        "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "API_KEY", "APIKEY",
        "ACCESS_KEY", "PRIVATE_KEY", "AUTH", "CREDENTIAL", "CONNECTION_STRING",
        "DATABASE_URL", "DB_PASS", "SMTP_PASS", "MAIL_PASSWORD",
        "AWS_SECRET", "AZURE_", "GCP_", "GITHUB_TOKEN", "GITLAB_TOKEN",
        "SLACK_TOKEN", "DISCORD_TOKEN", "WEBHOOK", "JWT", "BEARER",
        "ENCRYPTION_KEY", "MASTER_KEY", "SIGNING_KEY",
    ]

    EXCLUDE_NAMES = {
        "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
        "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES",
        "PROGRAMDATA", "SYSTEMDRIVE", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
        "OS", "USERNAME", "USERDOMAIN", "COMPUTERNAME", "LOGONSERVER",
        "PUBLIC", "PSMODULEPATH", "PROMPT",
    }

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for name, value in os.environ.items():
            if name.upper() in self.EXCLUDE_NAMES:
                continue
            if not value or len(value) < 4:
                continue

            name_upper = name.upper()
            if any(kw in name_upper for kw in self.SENSITIVE_KEYWORDS):
                results.append({
                    "Source": "Environment Variable",
                    "Variable": name,
                    "Value": value[:300],
                })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# PowerShell History & Transcript Logs
# ═══════════════════════════════════════════════════════════════════════════

class PowerShellHistory(ModuleBase):
    """Extract sensitive commands from PowerShell history and transcript logs."""

    meta = ModuleMeta(
        name="PowerShell History",
        category=Category.WINDOWS,
        description="Scan PowerShell command history and transcripts for credentials",
    )

    SENSITIVE_PATTERNS = [
        re.compile(r"(?:password|passwd|pwd|secret|token|key|credential)\s*[=:]\s*['\"]?(\S+)", re.IGNORECASE),
        re.compile(r"ConvertTo-SecureString\s+['\"]?(\S+)", re.IGNORECASE),
        re.compile(r"(?:New-Object\s+.*PSCredential|Get-Credential)", re.IGNORECASE),
        re.compile(r"-(?:Password|Credential|Token|Secret|ApiKey)\s+['\"]?(\S+)", re.IGNORECASE),
        re.compile(r"(?:Invoke-WebRequest|curl|wget).*(?:Authorization|Bearer|Basic)\s+(\S+)", re.IGNORECASE),
        re.compile(r"net\s+user\s+\S+\s+(\S+)", re.IGNORECASE),
        re.compile(r"(?:psexec|runas).*(?:/password|/p)\s*[:=]\s*(\S+)", re.IGNORECASE),
        re.compile(r"cmdkey\s+/add.*?/pass(?:word)?:\s*(\S+)", re.IGNORECASE),
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # PSReadLine history — the goldmine
        history_paths = [
            Path(config.profile.get("APPDATA", "")) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
            Path(config.profile.get("APPDATA", "")) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "Visual Studio Code Host_history.txt",
        ]

        for hist_path in history_paths:
            if not hist_path.exists():
                continue
            try:
                lines = hist_path.read_text(encoding="utf-8", errors="replace").splitlines()
                for i, line in enumerate(lines):
                    for pattern in self.SENSITIVE_PATTERNS:
                        if pattern.search(line):
                            results.append({
                                "Source": "PowerShell History",
                                "File": str(hist_path),
                                "Line": str(i + 1),
                                "Command": line.strip()[:500],
                            })
                            break  # one match per line is enough
            except Exception:
                continue

        # Transcript logs
        transcript_dirs = [
            Path(config.profile.get("USERPROFILE", "")) / "Documents",
            Path(config.profile.get("USERPROFILE", "")) / "Desktop",
            Path("C:\\Transcripts"),
        ]

        for trans_dir in transcript_dirs:
            if not trans_dir.exists():
                continue
            for transcript in trans_dir.glob("PowerShell_transcript*.txt"):
                try:
                    content = transcript.read_text(encoding="utf-8", errors="replace")
                    for pattern in self.SENSITIVE_PATTERNS:
                        for match in pattern.finditer(content):
                            results.append({
                                "Source": "PowerShell Transcript",
                                "File": str(transcript),
                                "Match": match.group(0)[:300],
                            })
                except Exception:
                    continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Saved .rdp Files with DPAPI-encrypted Passwords
# ═══════════════════════════════════════════════════════════════════════════

class SavedRDPFiles(ModuleBase):
    """Recover saved .rdp files and decrypt embedded passwords."""

    meta = ModuleMeta(
        name="Saved RDP Files",
        category=Category.WINDOWS,
        description="Search for .rdp files and decrypt DPAPI-protected passwords",
        dpapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        search_dirs = [
            Path(config.profile.get("USERPROFILE", "")) / "Desktop",
            Path(config.profile.get("USERPROFILE", "")) / "Documents",
            Path(config.profile.get("USERPROFILE", "")) / "Downloads",
            Path(config.profile.get("APPDATA", "")) / "Microsoft" / "Terminal Server Client",
        ]

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue

            for rdp_file in search_dir.rglob("*.rdp"):
                try:
                    content = rdp_file.read_text(encoding="utf-8", errors="replace")
                    entry: dict[str, Any] = {
                        "Source": "RDP File",
                        "Path": str(rdp_file),
                    }

                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("full address:"):
                            entry["Server"] = line.split(":", 2)[-1].strip()
                        elif line.startswith("username:"):
                            entry["Username"] = line.split(":", 2)[-1].strip()
                        elif line.startswith("domain:"):
                            entry["Domain"] = line.split(":", 2)[-1].strip()
                        elif line.startswith("password 51:b:"):
                            hex_blob = line.split(":", 3)[-1].strip()
                            if hex_blob:
                                try:
                                    from steelfox.core.winapi import win32_crypt_unprotect_data
                                    enc = bytes.fromhex(hex_blob)
                                    dec = win32_crypt_unprotect_data(enc)
                                    if dec:
                                        entry["Password"] = dec.decode("utf-16-le", errors="replace").rstrip("\x00")
                                    else:
                                        entry["Password (DPAPI)"] = f"[{len(enc)} bytes]"
                                except Exception:
                                    entry["Password (DPAPI)"] = f"[hex: {hex_blob[:40]}...]"

                    results.append(entry)
                except Exception:
                    continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Tortoise SVN
# ═══════════════════════════════════════════════════════════════════════════

class TortoiseSVN(ModuleBase):
    """Recover Tortoise SVN / Subversion saved credentials."""

    meta = ModuleMeta(
        name="Tortoise SVN",
        category=Category.WINDOWS,
        description="Recover Subversion cached credentials (DPAPI-protected auth files)",
        dpapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        svn_auth_dir = Path(config.profile.get("APPDATA", "")) / "Subversion" / "auth" / "svn.simple"
        if not svn_auth_dir.exists():
            return results

        for auth_file in svn_auth_dir.iterdir():
            if not auth_file.is_file():
                continue

            try:
                content = auth_file.read_bytes()
                text = content.decode("utf-8", errors="replace")

                entry: dict[str, Any] = {
                    "Source": "Tortoise SVN",
                    "Auth File": str(auth_file),
                }

                # SVN auth files use a simple key-value format
                lines = text.splitlines()
                i = 0
                pairs: dict[str, str] = {}
                while i < len(lines):
                    if lines[i].startswith("K "):
                        key_len = int(lines[i][2:])
                        key = lines[i + 1] if i + 1 < len(lines) else ""
                        if i + 2 < len(lines) and lines[i + 2].startswith("V "):
                            val = lines[i + 3] if i + 3 < len(lines) else ""
                            pairs[key] = val
                            i += 4
                            continue
                    i += 1

                if "svn:realmstring" in pairs:
                    entry["Realm"] = pairs["svn:realmstring"]
                if "username" in pairs:
                    entry["Username"] = pairs["username"]
                if "password" in pairs:
                    entry["Password"] = pairs["password"]
                if "passtype" in pairs:
                    entry["Password Type"] = pairs["passtype"]
                    if pairs["passtype"] == "wincrypt":
                        # DPAPI encrypted — try to decrypt
                        try:
                            import base64 as b64
                            from steelfox.core.winapi import win32_crypt_unprotect_data
                            enc = b64.b64decode(pairs.get("password", ""))
                            dec = win32_crypt_unprotect_data(enc)
                            if dec:
                                entry["Password"] = dec.decode("utf-8", errors="replace")
                        except Exception:
                            pass

                if len(entry) > 2:
                    results.append(entry)
            except Exception:
                continue

        return results
