# -*- coding: utf-8 -*-
"""
SteelFox — System Reconnaissance Module

Collects comprehensive system information for security auditing:
  - Hardware info (CPU, RAM, GPU, disks, BIOS)
  - OS details (version, build, architecture, install date)
  - Network configuration (interfaces, IPs, DNS, routing)
  - Installed software
  - Running processes
  - Startup programs
  - User accounts and groups
  - Installed Windows updates
  - Environment variables
  - Security software (antivirus, firewall)
  - Scheduled tasks
  - Active network connections
  - Shared folders
  - Recent files & USB history

This module does NOT require admin privileges for most information,
but some details (other users, security software) benefit from elevation.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
import winreg
from datetime import datetime
from pathlib import Path
from typing import Any

from steelfox.core.config import config
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta
from steelfox.core.privileges import is_admin, get_os_build, is_windows_11

logger = logging.getLogger("steelfox")


def _run_cmd(cmd: str | list[str], timeout: int = 30) -> str:
    """Execute a command and return stdout, handling Windows codepage properly."""
    try:
        # First try with OEM codepage (what cmd.exe actually uses)
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            shell=isinstance(cmd, str),
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        raw = result.stdout
        if not raw:
            return ""

        # Try UTF-8 first, then OEM codepage, then latin-1 as fallback
        for enc in ("utf-8", "cp850", "cp1252", "latin-1"):
            try:
                return raw.decode(enc).strip()
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _run_wmic(query: str) -> str:
    """Run a WMIC query (deprecated but still works on Win10/11)."""
    return _run_cmd(f"wmic {query}")


def _run_powershell(script: str, timeout: int = 30) -> str:
    """Run a PowerShell one-liner."""
    return _run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


# ═══════════════════════════════════════════════════════════════════════════
# System Information
# ═══════════════════════════════════════════════════════════════════════════

class SystemInfo(ModuleBase):
    """Collect comprehensive system information."""

    meta = ModuleMeta(
        name="System Information",
        category=Category.RECONNAISSANCE,
        description="Collect hardware, OS, and system configuration details",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # ── OS Information ──
        os_info = self._get_os_info()
        if os_info:
            results.append(os_info)

        # ── Hardware ──
        hw_info = self._get_hardware_info()
        if hw_info:
            results.append(hw_info)

        # ── GPU ──
        gpu_info = self._get_gpu_info()
        if gpu_info:
            results.extend(gpu_info)

        # ── Disk Drives ──
        disk_info = self._get_disk_info()
        if disk_info:
            results.extend(disk_info)

        # ── BIOS ──
        bios_info = self._get_bios_info()
        if bios_info:
            results.append(bios_info)

        return results

    def _get_os_info(self) -> dict[str, Any]:
        build = get_os_build()
        return {
            "Source": "System Recon — OS",
            "OS": platform.system(),
            "OS Version": platform.version(),
            "Build Number": str(build),
            "Windows 11": str(is_windows_11()),
            "Architecture": platform.machine(),
            "Platform": platform.platform(),
            "Hostname": socket.gethostname(),
            "FQDN": socket.getfqdn(),
            "Username": os.environ.get("USERNAME", ""),
            "Domain": os.environ.get("USERDOMAIN", ""),
            "System Directory": os.environ.get("SYSTEMROOT", ""),
            "Temp Directory": os.environ.get("TEMP", ""),
            "System Locale": _run_powershell("(Get-Culture).Name") or "unknown",
            "Timezone": _run_powershell("(Get-TimeZone).DisplayName") or "unknown",
            "Install Date": self._get_install_date(),
            "Last Boot": _run_powershell(
                "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')"
            ) or "unknown",
            "Is Admin": str(is_admin()),
        }

    @staticmethod
    def _get_install_date() -> str:
        try:
            output = _run_powershell(
                "(Get-CimInstance Win32_OperatingSystem).InstallDate.ToString('yyyy-MM-dd HH:mm:ss')"
            )
            return output or "unknown"
        except Exception:
            return "unknown"

    @staticmethod
    def _get_hardware_info() -> dict[str, Any]:
        try:
            cpu = _run_powershell(
                "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name"
            )
            cpu_cores = _run_powershell(
                "(Get-CimInstance Win32_Processor | Select-Object -First 1).NumberOfCores"
            )
            cpu_threads = _run_powershell(
                "(Get-CimInstance Win32_Processor | Select-Object -First 1).NumberOfLogicalProcessors"
            )
            ram_bytes = _run_powershell(
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"
            )
            manufacturer = _run_powershell(
                "(Get-CimInstance Win32_ComputerSystem).Manufacturer"
            )
            model = _run_powershell(
                "(Get-CimInstance Win32_ComputerSystem).Model"
            )
            serial = _run_powershell(
                "(Get-CimInstance Win32_BIOS).SerialNumber"
            )

            ram_gb = ""
            if ram_bytes and ram_bytes.isdigit():
                ram_gb = f"{int(ram_bytes) / (1024**3):.1f} GB"

            return {
                "Source": "System Recon — Hardware",
                "CPU": cpu or "unknown",
                "CPU Cores": cpu_cores or "unknown",
                "CPU Threads": cpu_threads or "unknown",
                "RAM": ram_gb or "unknown",
                "Manufacturer": manufacturer or "unknown",
                "Model": model or "unknown",
                "Serial Number": serial or "unknown",
            }
        except Exception:
            return {}

    @staticmethod
    def _get_gpu_info() -> list[dict[str, Any]]:
        try:
            output = _run_powershell(
                "Get-CimInstance Win32_VideoController | "
                "Select-Object Name, AdapterRAM, DriverVersion, VideoProcessor | "
                "ConvertTo-Json"
            )
            if not output:
                return []

            import json
            gpus = json.loads(output)
            if isinstance(gpus, dict):
                gpus = [gpus]

            results = []
            for gpu in gpus:
                vram = gpu.get("AdapterRAM", 0)
                vram_str = f"{vram / (1024**3):.1f} GB" if vram else "unknown"
                results.append({
                    "Source": "System Recon — GPU",
                    "GPU": gpu.get("Name", "unknown"),
                    "VRAM": vram_str,
                    "Driver Version": gpu.get("DriverVersion", "unknown"),
                    "Video Processor": gpu.get("VideoProcessor", ""),
                })
            return results
        except Exception:
            return []

    @staticmethod
    def _get_disk_info() -> list[dict[str, Any]]:
        try:
            output = _run_powershell(
                "Get-CimInstance Win32_LogicalDisk | "
                "Where-Object {$_.DriveType -eq 3} | "
                "Select-Object DeviceID, Size, FreeSpace, FileSystem, VolumeName | "
                "ConvertTo-Json"
            )
            if not output:
                return []

            import json
            disks = json.loads(output)
            if isinstance(disks, dict):
                disks = [disks]

            results = []
            for disk in disks:
                total = disk.get("Size", 0)
                free = disk.get("FreeSpace", 0)
                results.append({
                    "Source": "System Recon — Disk",
                    "Drive": disk.get("DeviceID", ""),
                    "Label": disk.get("VolumeName", ""),
                    "File System": disk.get("FileSystem", ""),
                    "Total": f"{total / (1024**3):.1f} GB" if total else "unknown",
                    "Free": f"{free / (1024**3):.1f} GB" if free else "unknown",
                    "Used %": f"{((total - free) / total * 100):.1f}%" if total else "unknown",
                })
            return results
        except Exception:
            return []

    @staticmethod
    def _get_bios_info() -> dict[str, Any]:
        try:
            output = _run_powershell(
                "Get-CimInstance Win32_BIOS | "
                "Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber | "
                "ConvertTo-Json"
            )
            if not output:
                return {}

            import json
            bios = json.loads(output)
            return {
                "Source": "System Recon — BIOS",
                "Manufacturer": bios.get("Manufacturer", ""),
                "Version": bios.get("SMBIOSBIOSVersion", ""),
                "Serial": bios.get("SerialNumber", ""),
            }
        except Exception:
            return {}


# ═══════════════════════════════════════════════════════════════════════════
# Network Reconnaissance
# ═══════════════════════════════════════════════════════════════════════════

class NetworkRecon(ModuleBase):
    """Collect detailed network configuration and active connections."""

    meta = ModuleMeta(
        name="Network Reconnaissance",
        category=Category.RECONNAISSANCE,
        description="Collect network interfaces, IP configuration, DNS, ARP, active connections",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Network interfaces
        results.extend(self._get_interfaces())

        # DNS configuration
        dns_info = self._get_dns_config()
        if dns_info:
            results.append(dns_info)

        # Active connections
        results.extend(self._get_active_connections())

        # ARP table
        arp_info = self._get_arp_table()
        if arp_info:
            results.append(arp_info)

        # Shared folders
        results.extend(self._get_shares())

        return results

    @staticmethod
    def _get_interfaces() -> list[dict[str, Any]]:
        try:
            output = _run_powershell(
                "Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | "
                "Select-Object InterfaceAlias, IPAddress, PrefixLength | "
                "ConvertTo-Json"
            )
            if not output:
                return []

            import json
            ifaces = json.loads(output)
            if isinstance(ifaces, dict):
                ifaces = [ifaces]

            results = []
            for iface in ifaces:
                results.append({
                    "Source": "Network Recon — Interface",
                    "Interface": iface.get("InterfaceAlias", ""),
                    "IP Address": iface.get("IPAddress", ""),
                    "Prefix Length": str(iface.get("PrefixLength", "")),
                })

            # Add MAC addresses
            mac_output = _run_powershell(
                "Get-NetAdapter | Select-Object Name, MacAddress, Status, LinkSpeed | ConvertTo-Json"
            )
            if mac_output:
                adapters = json.loads(mac_output)
                if isinstance(adapters, dict):
                    adapters = [adapters]
                for adapter in adapters:
                    results.append({
                        "Source": "Network Recon — Adapter",
                        "Name": adapter.get("Name", ""),
                        "MAC Address": adapter.get("MacAddress", ""),
                        "Status": adapter.get("Status", ""),
                        "Speed": adapter.get("LinkSpeed", ""),
                    })

            return results
        except Exception:
            return []

    @staticmethod
    def _get_dns_config() -> dict[str, Any] | None:
        try:
            output = _run_powershell(
                "Get-DnsClientServerAddress -AddressFamily IPv4 | "
                "Where-Object {$_.ServerAddresses} | "
                "Select-Object InterfaceAlias, ServerAddresses | "
                "ConvertTo-Json"
            )
            if not output:
                return None

            import json
            dns_data = json.loads(output)
            if isinstance(dns_data, dict):
                dns_data = [dns_data]

            dns_servers = []
            for entry in dns_data:
                iface = entry.get("InterfaceAlias", "")
                servers = entry.get("ServerAddresses", [])
                if servers:
                    dns_servers.append(f"{iface}: {', '.join(servers)}")

            return {
                "Source": "Network Recon — DNS",
                "DNS Servers": " | ".join(dns_servers),
                "Hostname": socket.gethostname(),
                "FQDN": socket.getfqdn(),
            }
        except Exception:
            return None

    @staticmethod
    def _get_active_connections() -> list[dict[str, Any]]:
        """Get active TCP connections (similar to netstat)."""
        try:
            output = _run_powershell(
                "Get-NetTCPConnection -State Established | "
                "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | "
                "Sort-Object RemoteAddress | "
                "ConvertTo-Json"
            )
            if not output:
                return []

            import json
            connections = json.loads(output)
            if isinstance(connections, dict):
                connections = [connections]

            results = []
            for conn in connections[:50]:  # Limit to 50
                pid = conn.get("OwningProcess", 0)
                proc_name = ""
                try:
                    proc_name = _run_powershell(
                        f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"
                    )
                except Exception:
                    pass

                results.append({
                    "Source": "Network Recon — Connection",
                    "Local": f"{conn.get('LocalAddress', '')}:{conn.get('LocalPort', '')}",
                    "Remote": f"{conn.get('RemoteAddress', '')}:{conn.get('RemotePort', '')}",
                    "PID": str(pid),
                    "Process": proc_name,
                })

            return results
        except Exception:
            return []

    @staticmethod
    def _get_arp_table() -> dict[str, Any] | None:
        try:
            output = _run_cmd("arp -a")
            if output:
                return {
                    "Source": "Network Recon — ARP Table",
                    "ARP Entries": output[:2000],
                }
        except Exception:
            pass
        return None

    @staticmethod
    def _get_shares() -> list[dict[str, Any]]:
        try:
            output = _run_powershell(
                "Get-SmbShare | Select-Object Name, Path, Description | ConvertTo-Json"
            )
            if not output:
                return []

            import json
            shares = json.loads(output)
            if isinstance(shares, dict):
                shares = [shares]

            return [
                {
                    "Source": "Network Recon — Share",
                    "Share Name": s.get("Name", ""),
                    "Path": s.get("Path", ""),
                    "Description": s.get("Description", ""),
                }
                for s in shares
            ]
        except Exception:
            return []


# ═══════════════════════════════════════════════════════════════════════════
# Software & Process Enumeration
# ═══════════════════════════════════════════════════════════════════════════

class InstalledSoftware(ModuleBase):
    """Enumerate all installed software on the system."""

    meta = ModuleMeta(
        name="Installed Software",
        category=Category.RECONNAISSANCE,
        description="List all installed applications with versions and publishers",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Registry-based enumeration (more reliable than WMI)
        for hive_key in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive_key)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)

                        name = self._reg_val(subkey, "DisplayName")
                        if not name:
                            continue

                        version = self._reg_val(subkey, "DisplayVersion")
                        publisher = self._reg_val(subkey, "Publisher")
                        install_date = self._reg_val(subkey, "InstallDate")
                        install_loc = self._reg_val(subkey, "InstallLocation")

                        results.append({
                            "Source": "Recon — Installed Software",
                            "Name": name,
                            "Version": version or "",
                            "Publisher": publisher or "",
                            "Install Date": install_date or "",
                            "Install Location": install_loc or "",
                        })

                        winreg.CloseKey(subkey)
                    except Exception:
                        continue
                winreg.CloseKey(key)
            except Exception:
                continue

        return results

    @staticmethod
    def _reg_val(key, name: str) -> str:
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value)
        except Exception:
            return ""


class RunningProcesses(ModuleBase):
    """Enumerate running processes with details."""

    meta = ModuleMeta(
        name="Running Processes",
        category=Category.RECONNAISSANCE,
        description="List all running processes with PID, path, and memory usage",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        try:
            output = _run_powershell(
                "Get-Process | Select-Object Id, ProcessName, Path, "
                "@{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB,1)}} | "
                "Sort-Object MemoryMB -Descending | "
                "ConvertTo-Json",
                timeout=30,
            )
            if not output:
                return results

            import json
            processes = json.loads(output)
            if isinstance(processes, dict):
                processes = [processes]

            for proc in processes[:100]:  # Top 100 by memory
                results.append({
                    "Source": "Recon — Process",
                    "PID": str(proc.get("Id", "")),
                    "Name": proc.get("ProcessName", ""),
                    "Path": proc.get("Path", "") or "",
                    "Memory (MB)": str(proc.get("MemoryMB", "")),
                })

        except Exception as e:
            logger.debug("Process enumeration failed: %s", e)

        return results


class SecuritySoftware(ModuleBase):
    """Detect installed security software (antivirus, firewall, EDR)."""

    meta = ModuleMeta(
        name="Security Software",
        category=Category.RECONNAISSANCE,
        description="Detect antivirus, firewall, and endpoint security products",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Windows Security Center (WMI)
        for product_type in ["AntiVirusProduct", "AntiSpywareProduct", "FirewallProduct"]:
            try:
                output = _run_powershell(
                    f"Get-CimInstance -Namespace 'root/SecurityCenter2' "
                    f"-ClassName {product_type} | "
                    f"Select-Object displayName, productState, instanceGuid, pathToSignedProductExe | "
                    f"ConvertTo-Json"
                )
                if not output:
                    continue

                import json
                products = json.loads(output)
                if isinstance(products, dict):
                    products = [products]

                for product in products:
                    state = product.get("productState", 0)
                    results.append({
                        "Source": f"Security — {product_type}",
                        "Name": product.get("displayName", "unknown"),
                        "State": self._decode_product_state(state),
                        "Path": product.get("pathToSignedProductExe", ""),
                        "GUID": product.get("instanceGuid", ""),
                    })
            except Exception:
                continue

        # Check Windows Defender status
        try:
            defender_output = _run_powershell(
                "Get-MpComputerStatus | Select-Object "
                "AntivirusEnabled, RealTimeProtectionEnabled, "
                "AntivirusSignatureLastUpdated, AMServiceEnabled | "
                "ConvertTo-Json"
            )
            if defender_output:
                import json
                defender = json.loads(defender_output)
                results.append({
                    "Source": "Security — Windows Defender",
                    "Antivirus Enabled": str(defender.get("AntivirusEnabled", "")),
                    "Real-Time Protection": str(defender.get("RealTimeProtectionEnabled", "")),
                    "Signatures Updated": str(defender.get("AntivirusSignatureLastUpdated", "")),
                    "AM Service": str(defender.get("AMServiceEnabled", "")),
                })
        except Exception:
            pass

        # Check Windows Firewall
        try:
            fw_output = _run_powershell(
                "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
            )
            if fw_output:
                import json
                profiles = json.loads(fw_output)
                if isinstance(profiles, dict):
                    profiles = [profiles]
                for profile in profiles:
                    results.append({
                        "Source": "Security — Windows Firewall",
                        "Profile": profile.get("Name", ""),
                        "Enabled": str(profile.get("Enabled", "")),
                    })
        except Exception:
            pass

        return results

    @staticmethod
    def _decode_product_state(state: int) -> str:
        """Decode WMI product state bitmask."""
        if state == 0:
            return "Unknown"
        # Byte 1: product state, Byte 2: scanner state, Byte 3: definition state
        hex_state = f"{state:06x}"
        scanner = hex_state[2:4]
        definitions = hex_state[4:6]

        status_parts = []
        if scanner == "10":
            status_parts.append("Enabled")
        elif scanner == "11":
            status_parts.append("Snoozed")
        else:
            status_parts.append("Disabled")

        if definitions == "00":
            status_parts.append("Up-to-date")
        else:
            status_parts.append("Out-of-date")

        return ", ".join(status_parts)


class StartupPrograms(ModuleBase):
    """Enumerate programs that run at startup."""

    meta = ModuleMeta(
        name="Startup Programs",
        category=Category.RECONNAISSANCE,
        description="List programs configured to run at Windows startup",
    )

    STARTUP_REG_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Registry entries
        for hive, key_path in self.STARTUP_REG_KEYS:
            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                for i in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        results.append({
                            "Source": "Recon — Startup",
                            "Name": name,
                            "Command": str(value),
                            "Location": f"{hive_name}\\{key_path}",
                            "Type": "Registry",
                        })
                    except Exception:
                        continue
                winreg.CloseKey(key)
            except Exception:
                continue

        # Startup folders
        startup_folders = [
            Path(config.profile.get("APPDATA", ""))
            / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        ]

        for folder in startup_folders:
            if folder.exists():
                for item in folder.iterdir():
                    if item.is_file() and item.suffix.lower() in (".lnk", ".bat", ".cmd", ".exe", ".vbs"):
                        results.append({
                            "Source": "Recon — Startup",
                            "Name": item.name,
                            "Path": str(item),
                            "Type": "Startup Folder",
                        })

        # Scheduled tasks (brief)
        try:
            output = _run_powershell(
                "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | "
                "Select-Object TaskName, TaskPath -First 30 | ConvertTo-Json"
            )
            if output:
                import json
                tasks = json.loads(output)
                if isinstance(tasks, dict):
                    tasks = [tasks]
                for task in tasks:
                    results.append({
                        "Source": "Recon — Scheduled Task",
                        "Task Name": task.get("TaskName", ""),
                        "Task Path": task.get("TaskPath", ""),
                        "Type": "Scheduled Task",
                    })
        except Exception:
            pass

        return results


class USBHistory(ModuleBase):
    """Recover USB device connection history."""

    meta = ModuleMeta(
        name="USB History",
        category=Category.RECONNAISSANCE,
        description="Enumerate previously connected USB storage devices",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
            )
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    device_name = winreg.EnumKey(key, i)
                    device_key = winreg.OpenKey(key, device_name)

                    for j in range(winreg.QueryInfoKey(device_key)[0]):
                        try:
                            serial = winreg.EnumKey(device_key, j)
                            serial_key = winreg.OpenKey(device_key, serial)

                            friendly_name = ""
                            try:
                                friendly_name, _ = winreg.QueryValueEx(serial_key, "FriendlyName")
                            except Exception:
                                pass

                            results.append({
                                "Source": "Recon — USB Device",
                                "Device": device_name,
                                "Serial": serial,
                                "Name": friendly_name or device_name,
                            })

                            winreg.CloseKey(serial_key)
                        except Exception:
                            continue

                    winreg.CloseKey(device_key)
                except Exception:
                    continue
            winreg.CloseKey(key)
        except Exception as e:
            logger.debug("USB history enumeration failed: %s", e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Clipboard Content
# ═══════════════════════════════════════════════════════════════════════════

class ClipboardContent(ModuleBase):
    """Capture current clipboard text content using Win32 API."""

    meta = ModuleMeta(
        name="Clipboard",
        category=Category.RECONNAISSANCE,
        description="Capture current clipboard text content",
        winapi_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            CF_TEXT = 1
            CF_UNICODETEXT = 13

            if not user32.OpenClipboard(None):
                return results

            try:
                # Try Unicode first
                for cf in (CF_UNICODETEXT, CF_TEXT):
                    handle = user32.GetClipboardData(cf)
                    if handle:
                        ptr = kernel32.GlobalLock(handle)
                        if ptr:
                            try:
                                if cf == CF_UNICODETEXT:
                                    text = ctypes.wstring_at(ptr)
                                else:
                                    text = ctypes.string_at(ptr).decode("utf-8", errors="replace")

                                if text and text.strip():
                                    results.append({
                                        "Source": "Recon — Clipboard",
                                        "Content": text[:2000],
                                        "Length": str(len(text)),
                                    })
                                break
                            finally:
                                kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()
        except Exception as e:
            logger.debug("Clipboard capture failed: %s", e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# RDP Connection History
# ═══════════════════════════════════════════════════════════════════════════

class RDPHistory(ModuleBase):
    """Recover recent RDP connection history from registry."""

    meta = ModuleMeta(
        name="RDP History",
        category=Category.RECONNAISSANCE,
        description="Recover recent RDP connections, servers, and usernames from registry",
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Terminal Server Client — Servers
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Terminal Server Client\Servers",
            )
            i = 0
            while True:
                try:
                    server_name = winreg.EnumKey(key, i)
                    entry: dict[str, Any] = {
                        "Source": "Recon — RDP History",
                        "Server": server_name,
                    }

                    try:
                        srv_key = winreg.OpenKey(key, server_name)
                        username, _ = winreg.QueryValueEx(srv_key, "UsernameHint")
                        entry["Username Hint"] = username
                        winreg.CloseKey(srv_key)
                    except Exception:
                        pass

                    results.append(entry)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

        # Default connection settings
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Terminal Server Client\Default",
            )
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if name.startswith("MRU"):
                        results.append({
                            "Source": "Recon — RDP Default MRU",
                            "Entry": name,
                            "Server": str(value),
                        })
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# User Groups & Privileges
# ═══════════════════════════════════════════════════════════════════════════

class UserPrivileges(ModuleBase):
    """Enumerate current user groups and privileges."""

    meta = ModuleMeta(
        name="User Privileges",
        category=Category.RECONNAISSANCE,
        description="Enumerate current user, groups, and token privileges",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # whoami /all
        output = _run_cmd("whoami /all", timeout=10)
        if output:
            results.append({
                "Source": "Recon — User Info",
                "Type": "whoami /all",
                "Output": output[:3000],
            })

        # net localgroup administrators
        output = _run_cmd("net localgroup Administrators", timeout=10)
        if output:
            results.append({
                "Source": "Recon — Local Admins",
                "Output": output[:1500],
            })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Recent Files
# ═══════════════════════════════════════════════════════════════════════════

class RecentFiles(ModuleBase):
    """List recently accessed files from Windows Recent folder."""

    meta = ModuleMeta(
        name="Recent Files",
        category=Category.RECONNAISSANCE,
        description="List recently accessed files from Windows Recent folder",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        recent_dir = Path(config.profile.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
        if not recent_dir.exists():
            return results

        try:
            files = sorted(
                recent_dir.iterdir(),
                key=lambda p: p.stat().st_mtime if p.is_file() else 0,
                reverse=True,
            )
            for f in files[:100]:
                if f.is_file():
                    try:
                        mtime = datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                    except Exception:
                        mtime = ""
                    results.append({
                        "Source": "Recon — Recent File",
                        "Name": f.name,
                        "Modified": mtime,
                    })
        except Exception as e:
            logger.debug("Recent files enumeration failed: %s", e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Scheduled Tasks with Credentials
# ═══════════════════════════════════════════════════════════════════════════

class ScheduledTasks(ModuleBase):
    """Enumerate scheduled tasks — some run under specific user accounts."""

    meta = ModuleMeta(
        name="Scheduled Tasks",
        category=Category.RECONNAISSANCE,
        description="Enumerate scheduled tasks, authors, and run-as accounts",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        output = _run_cmd(
            'schtasks /query /fo CSV /v',
            timeout=30,
        )
        if not output:
            return results

        lines = output.splitlines()
        if len(lines) < 2:
            return results

        # Parse CSV-like output
        header = lines[0].replace('"', '').split(',')
        # Find key column indices
        col_map: dict[str, int] = {}
        key_columns = ["TaskName", "Next Run Time", "Status", "Run As User", "Author", "Task To Run"]
        for i, col in enumerate(header):
            for kc in key_columns:
                if kc.lower() in col.lower():
                    col_map[kc] = i
                    break

        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.replace('"', '').split(',')
            task_name = parts[col_map.get("TaskName", 0)] if col_map.get("TaskName", 0) < len(parts) else ""

            # Skip system noise
            if any(skip in task_name for skip in ["\\Microsoft\\Windows\\", "\\Microsoft\\Office\\"]):
                continue

            run_as = parts[col_map.get("Run As User", 0)] if col_map.get("Run As User", 0) < len(parts) else ""
            author = parts[col_map.get("Author", 0)] if col_map.get("Author", 0) < len(parts) else ""
            command = parts[col_map.get("Task To Run", 0)] if col_map.get("Task To Run", 0) < len(parts) else ""

            if task_name:
                entry: dict[str, Any] = {
                    "Source": "Recon — Scheduled Task",
                    "Task": task_name,
                }
                if run_as:
                    entry["Run As"] = run_as
                if author:
                    entry["Author"] = author
                if command:
                    entry["Command"] = command[:300]
                results.append(entry)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Active Network Connections
# ═══════════════════════════════════════════════════════════════════════════

class ActiveConnections(ModuleBase):
    """Enumerate active network connections (netstat-style)."""

    meta = ModuleMeta(
        name="Active Connections",
        category=Category.RECONNAISSANCE,
        description="Enumerate active TCP/UDP network connections and listening ports",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        output = _run_cmd("netstat -ano", timeout=15)
        if not output:
            return results

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Active") or line.startswith("Proto"):
                continue

            parts = line.split()
            if len(parts) >= 4:
                proto = parts[0]
                local = parts[1]
                remote = parts[2]
                state = parts[3] if len(parts) > 3 and not parts[3].isdigit() else ""
                pid = parts[-1] if parts[-1].isdigit() else ""

                # Skip loopback noise
                if remote.startswith("0.0.0.0:") or remote == "*:*":
                    if state not in ("LISTENING", "LISTEN"):
                        continue

                results.append({
                    "Source": "Recon — Network Connection",
                    "Protocol": proto,
                    "Local": local,
                    "Remote": remote,
                    "State": state,
                    "PID": pid,
                })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Shared Folders
# ═══════════════════════════════════════════════════════════════════════════

class SharedFolders(ModuleBase):
    """Enumerate network shared folders."""

    meta = ModuleMeta(
        name="Shared Folders",
        category=Category.RECONNAISSANCE,
        description="Enumerate local network shared folders and permissions",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        output = _run_cmd("net share", timeout=10)
        if not output:
            return results

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Share name") or line.startswith("----") or line.startswith("The command"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 2:
                share_name = parts[0]
                resource = parts[1] if len(parts) >= 2 else ""
                remark = parts[2] if len(parts) >= 3 else ""

                results.append({
                    "Source": "Recon — Network Share",
                    "Share": share_name,
                    "Resource": resource,
                    "Remark": remark,
                })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Windows Defender Exclusions
# ═══════════════════════════════════════════════════════════════════════════

class DefenderExclusions(ModuleBase):
    """Enumerate Windows Defender exclusions — useful for hiding payloads."""

    meta = ModuleMeta(
        name="Defender Exclusions",
        category=Category.RECONNAISSANCE,
        description="Enumerate Windows Defender exclusion paths, extensions, and processes",
        registry_used=True,
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        exclusion_keys = {
            "Paths": r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            "Extensions": r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
            "Processes": r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        }

        for excl_type, reg_path in exclusion_keys.items():
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    key = winreg.OpenKey(hive, reg_path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            results.append({
                                "Source": "Recon — Defender Exclusion",
                                "Type": excl_type,
                                "Value": name,
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Saved WiFi Profiles Summary (Quick)
# ═══════════════════════════════════════════════════════════════════════════

class SavedWiFiProfiles(ModuleBase):
    """Quick enumeration of all saved WiFi profile names."""

    meta = ModuleMeta(
        name="WiFi Profiles List",
        category=Category.RECONNAISSANCE,
        description="Quick list of all saved WiFi profile names on the system",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        output = _run_cmd("netsh wlan show profiles", timeout=10)
        if not output:
            return results

        for line in output.splitlines():
            if ":" in line and ("All User Profile" in line or "Profil" in line):
                profile_name = line.split(":", 1)[1].strip()
                if profile_name:
                    results.append({
                        "Source": "Recon — WiFi Profile",
                        "Profile": profile_name,
                    })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Hosts File
# ═══════════════════════════════════════════════════════════════════════════

class HostsFile(ModuleBase):
    """Read hosts file entries — can reveal internal infrastructure or tampered DNS."""

    meta = ModuleMeta(
        name="Hosts File",
        category=Category.RECONNAISSANCE,
        description="Read non-default hosts file entries (can reveal infrastructure or DNS tampering)",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        hosts_path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
        if not hosts_path.exists():
            return results

        try:
            content = hosts_path.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    hostnames = " ".join(parts[1:])
                    # Skip standard loopback entries
                    if ip == "127.0.0.1" and hostnames == "localhost":
                        continue
                    if ip == "::1" and hostnames == "localhost":
                        continue
                    results.append({
                        "Source": "Recon — Hosts File",
                        "IP": ip,
                        "Hostnames": hostnames,
                    })
        except Exception as e:
            logger.debug("Hosts file read failed: %s", e)

        return results
