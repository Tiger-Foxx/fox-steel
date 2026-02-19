# -*- coding: utf-8 -*-
"""
SteelFox — Cryptocurrency Wallet Discovery & Data Recovery

Detects and recovers data from:
  - Exodus (wallet seed vault)
  - Electrum (wallet files)
  - Atomic Wallet
  - Coinomi
  - Wasabi Wallet
  - MetaMask (Chromium extension LevelDB)
  - Brave Wallet
  - Phantom (Solana)
  - Bitcoin Core / Litecoin / Dogecoin (wallet.dat)
  - Ethereum Keystore
  - Zcash
"""

from __future__ import annotations

import json
import logging
import os
import re
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
# Exodus Wallet
# ═══════════════════════════════════════════════════════════════════════════

class ExodusWallet(ModuleBase):
    """Recover Exodus wallet vault and seed data."""

    meta = ModuleMeta(
        name="Exodus Wallet",
        category=Category.GAMING,
        description="Recover Exodus wallet files (encrypted vault, seed, passphrase JSON)",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        exodus_dirs = [
            _resolve("{APPDATA}\\Exodus"),
            _resolve("{APPDATA}\\exodus"),
        ]

        for dir_str in exodus_dirs:
            if not dir_str:
                continue
            base = Path(dir_str)
            if not base.exists():
                continue

            # exodus.wallet directory
            wallet_dir = base / "exodus.wallet"
            if wallet_dir.exists():
                for wallet_file in wallet_dir.iterdir():
                    if wallet_file.is_file():
                        entry: dict[str, Any] = {
                            "Source": "Exodus Wallet",
                            "File": wallet_file.name,
                            "Path": str(wallet_file),
                            "Size": str(wallet_file.stat().st_size),
                        }

                        # Try to read seed/passphrase files
                        if wallet_file.suffix == ".json" or wallet_file.suffix == ".seco":
                            try:
                                content = wallet_file.read_text(encoding="utf-8", errors="replace")[:2000]
                                if wallet_file.suffix == ".json":
                                    data = json.loads(content)
                                    if isinstance(data, dict):
                                        for k in data:
                                            if any(kw in k.lower() for kw in ["seed", "mnemonic", "key", "passphrase"]):
                                                entry["Key"] = k
                                                entry["Value (encrypted)"] = str(data[k])[:200]
                            except Exception:
                                pass

                        results.append(entry)

            # Backup directory
            backup_dir = base / "backups"
            if backup_dir.exists():
                for backup in backup_dir.rglob("*"):
                    if backup.is_file():
                        results.append({
                            "Source": "Exodus Wallet (Backup)",
                            "Path": str(backup),
                            "Size": str(backup.stat().st_size),
                        })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Electrum Wallet
# ═══════════════════════════════════════════════════════════════════════════

class ElectrumWallet(ModuleBase):
    """Recover Electrum Bitcoin wallet files."""

    meta = ModuleMeta(
        name="Electrum Wallet",
        category=Category.GAMING,
        description="Recover Electrum wallet files, recent servers, and config",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        electrum_dirs = [
            _resolve("{APPDATA}\\Electrum"),
            _resolve("{APPDATA}\\Electrum-LTC"),
            _resolve("{APPDATA}\\Electrum-DASH"),
        ]

        for dir_str in electrum_dirs:
            if not dir_str:
                continue
            base = Path(dir_str)
            if not base.exists():
                continue

            # Wallet files in wallets/
            wallets_dir = base / "wallets"
            if wallets_dir.exists():
                for wallet_file in wallets_dir.iterdir():
                    if not wallet_file.is_file():
                        continue
                    try:
                        content = wallet_file.read_text(encoding="utf-8", errors="replace")[:5000]
                        data = json.loads(content)

                        entry: dict[str, Any] = {
                            "Source": f"Electrum ({base.name})",
                            "Wallet File": str(wallet_file),
                            "Wallet Type": data.get("wallet_type", ""),
                        }

                        # Seed — may be encrypted or cleartext
                        if "seed" in data:
                            entry["Seed (encrypted)"] = str(data["seed"])[:200]
                        if "keystore" in data:
                            ks = data["keystore"]
                            if isinstance(ks, dict):
                                entry["Keystore Type"] = ks.get("type", "")
                                if "seed" in ks:
                                    entry["Keystore Seed"] = str(ks["seed"])[:200]
                                if "xpub" in ks:
                                    entry["XPUB"] = ks["xpub"]
                                if "xprv" in ks:
                                    entry["XPRV (encrypted)"] = str(ks["xprv"])[:200]

                        results.append(entry)
                    except json.JSONDecodeError:
                        # Binary wallet or non-JSON
                        results.append({
                            "Source": f"Electrum ({base.name})",
                            "Wallet File": str(wallet_file),
                            "Size": str(wallet_file.stat().st_size),
                            "Format": "Binary/Encrypted",
                        })
                    except Exception:
                        continue

            # Config file
            config_file = base / "config"
            if config_file.exists():
                try:
                    data = json.loads(config_file.read_text(encoding="utf-8", errors="replace"))
                    if "recent_servers" in data:
                        results.append({
                            "Source": f"Electrum ({base.name})",
                            "Recent Servers": ", ".join(str(s) for s in data["recent_servers"][:5]),
                        })
                except Exception:
                    pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Atomic Wallet
# ═══════════════════════════════════════════════════════════════════════════

class AtomicWallet(ModuleBase):
    """Recover Atomic Wallet encrypted vault."""

    meta = ModuleMeta(
        name="Atomic Wallet",
        category=Category.GAMING,
        description="Recover Atomic Wallet encrypted vault and account data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        atomic_dir = _resolve("{APPDATA}\\atomic")
        if not atomic_dir:
            return results

        base = Path(atomic_dir)
        if not base.exists():
            return results

        # Local Storage
        ls = base / "Local Storage" / "leveldb"
        if ls.exists():
            for ldb in ls.glob("*.ldb"):
                try:
                    content = ldb.read_bytes()
                    # Look for mnemonic / encrypted seed
                    if b"mnemonic" in content or b"encrypted" in content or b"seed" in content:
                        results.append({
                            "Source": "Atomic Wallet",
                            "Type": "LevelDB (contains encrypted data)",
                            "Path": str(ldb),
                            "Size": str(ldb.stat().st_size),
                        })
                except Exception:
                    continue

        # Wallet files
        for json_file in base.rglob("*.json"):
            try:
                content = json_file.read_text(encoding="utf-8", errors="replace")[:3000]
                if any(kw in content.lower() for kw in ["mnemonic", "encrypted", "vault", "keystore", "seed"]):
                    results.append({
                        "Source": "Atomic Wallet",
                        "File": str(json_file),
                        "Size": str(json_file.stat().st_size),
                        "Type": "Wallet Config",
                    })
            except Exception:
                continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Coinomi Wallet
# ═══════════════════════════════════════════════════════════════════════════

class CoinomiWallet(ModuleBase):
    """Recover Coinomi wallet files."""

    meta = ModuleMeta(
        name="Coinomi Wallet",
        category=Category.GAMING,
        description="Recover Coinomi wallet encrypted data and configuration",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        coinomi_dirs = [
            _resolve("{LOCALAPPDATA}\\Coinomi\\Coinomi\\wallets"),
            _resolve("{APPDATA}\\Coinomi\\Coinomi\\wallets"),
        ]

        for dir_str in coinomi_dirs:
            if not dir_str:
                continue
            wallets_dir = Path(dir_str)
            if not wallets_dir.exists():
                continue

            for wallet_file in wallets_dir.iterdir():
                if wallet_file.is_file():
                    results.append({
                        "Source": "Coinomi Wallet",
                        "File": wallet_file.name,
                        "Path": str(wallet_file),
                        "Size": str(wallet_file.stat().st_size),
                    })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Bitcoin Core & Core-Based Altcoins (wallet.dat)
# ═══════════════════════════════════════════════════════════════════════════

class BitcoinCoreWallets(ModuleBase):
    """Discover Bitcoin Core and altcoin wallet.dat files."""

    meta = ModuleMeta(
        name="Bitcoin Core Wallets",
        category=Category.GAMING,
        description="Discover wallet.dat files for Bitcoin Core, Litecoin, Dogecoin, Zcash, etc.",
    )

    COIN_DIRS: list[tuple[str, str]] = [
        ("Bitcoin", "{APPDATA}\\Bitcoin"),
        ("Litecoin", "{APPDATA}\\Litecoin"),
        ("Dogecoin", "{APPDATA}\\Dogecoin"),
        ("Zcash", "{APPDATA}\\Zcash"),
        ("Dash", "{APPDATA}\\DashCore"),
        ("Bitcoin Cash", "{APPDATA}\\Bitcoin Cash Node"),
        ("Monero", "{APPDATA}\\bitmonero"),
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for coin_name, path_template in self.COIN_DIRS:
            dir_str = _resolve(path_template)
            if not dir_str:
                continue
            base = Path(dir_str)
            if not base.exists():
                continue

            # wallet.dat in root
            wallet_dat = base / "wallet.dat"
            if wallet_dat.exists():
                results.append({
                    "Source": f"{coin_name} Core",
                    "File": "wallet.dat",
                    "Path": str(wallet_dat),
                    "Size": str(wallet_dat.stat().st_size),
                })

            # Additional wallets in wallets/ subdirectory (Bitcoin Core 0.16+)
            wallets_dir = base / "wallets"
            if wallets_dir.exists():
                for item in wallets_dir.iterdir():
                    if item.is_dir():
                        wd = item / "wallet.dat"
                        if wd.exists():
                            results.append({
                                "Source": f"{coin_name} Core",
                                "Wallet Name": item.name,
                                "Path": str(wd),
                                "Size": str(wd.stat().st_size),
                            })
                    elif item.name == "wallet.dat":
                        results.append({
                            "Source": f"{coin_name} Core",
                            "File": item.name,
                            "Path": str(item),
                            "Size": str(item.stat().st_size),
                        })

            # bitcoin.conf — can contain rpcuser/rpcpassword
            conf_file = base / f"{coin_name.lower().replace(' ', '')}.conf"
            if not conf_file.exists():
                # Try common names
                for name in [f"{coin_name.lower()}.conf", f"{base.name.lower()}.conf"]:
                    candidate = base / name
                    if candidate.exists():
                        conf_file = candidate
                        break

            if conf_file.exists():
                try:
                    content = conf_file.read_text(encoding="utf-8", errors="replace")
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("#") or "=" not in line:
                            continue
                        key = line.split("=", 1)[0].strip().lower()
                        if key in ("rpcuser", "rpcpassword", "rpcauth"):
                            results.append({
                                "Source": f"{coin_name} Core",
                                "Config": line.strip(),
                            })
                except Exception:
                    pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Ethereum Keystore Files
# ═══════════════════════════════════════════════════════════════════════════

class EthereumKeystore(ModuleBase):
    """Discover Ethereum keystore (UTC--) files."""

    meta = ModuleMeta(
        name="Ethereum Keystore",
        category=Category.GAMING,
        description="Discover Ethereum keystore files (encrypted private keys)",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        keystore_dirs = [
            _resolve("{APPDATA}\\Ethereum\\keystore"),
            _resolve("{APPDATA}\\Ethereum Wallet\\keystore"),
            # Geth default
            Path(os.path.expanduser("~")) / ".ethereum" / "keystore",
        ]

        for ks_dir in keystore_dirs:
            if ks_dir is None:
                continue
            ks_path = Path(ks_dir) if not isinstance(ks_dir, Path) else ks_dir
            if not ks_path.exists():
                continue

            for ks_file in ks_path.iterdir():
                if not ks_file.is_file():
                    continue
                try:
                    data = json.loads(ks_file.read_text(encoding="utf-8", errors="replace"))
                    results.append({
                        "Source": "Ethereum Keystore",
                        "Address": data.get("address", ""),
                        "File": ks_file.name,
                        "Path": str(ks_file),
                        "Cipher": data.get("crypto", {}).get("cipher", ""),
                        "KDF": data.get("crypto", {}).get("kdf", ""),
                    })
                except Exception:
                    # Non-JSON keystore or binary
                    if ks_file.name.startswith("UTC--"):
                        results.append({
                            "Source": "Ethereum Keystore",
                            "File": ks_file.name,
                            "Path": str(ks_file),
                        })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# MetaMask / Browser Extension Wallets (Chromium LevelDB)
# ═══════════════════════════════════════════════════════════════════════════

class MetaMaskWallet(ModuleBase):
    """Recover MetaMask vault data from Chromium extension storage."""

    meta = ModuleMeta(
        name="MetaMask",
        category=Category.GAMING,
        description="Recover MetaMask encrypted vault from browser extension LevelDB",
    )

    # Extension IDs for MetaMask in various browsers
    METAMASK_IDS = [
        "nkbihfbeogaeaoehlefnkodbefgpgknn",  # Chrome MetaMask
        "ejbalbakoplchlghecdalmeeeajnimhm",  # Edge MetaMask (legacy)
    ]

    BROWSER_EXTENSION_PATHS = [
        "{LOCALAPPDATA}\\Google\\Chrome\\User Data",
        "{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data",
        "{LOCALAPPDATA}\\Microsoft\\Edge\\User Data",
        "{LOCALAPPDATA}\\Vivaldi\\User Data",
        "{APPDATA}\\Opera Software\\Opera Stable",
        "{APPDATA}\\Opera Software\\Opera GX Stable",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for path_tmpl in self.BROWSER_EXTENSION_PATHS:
            dir_str = _resolve(path_tmpl)
            if not dir_str:
                continue
            base = Path(dir_str)
            if not base.exists():
                continue

            # Check Default + Profile N
            profile_dirs = []
            default = base / "Default"
            if default.exists():
                profile_dirs.append(default)
            for item in base.iterdir():
                if item.is_dir() and item.name.startswith("Profile "):
                    profile_dirs.append(item)
            if (base / "Login Data").exists():
                profile_dirs.append(base)

            for profile in profile_dirs:
                for ext_id in self.METAMASK_IDS:
                    # IndexedDB location
                    idb_path = profile / "IndexedDB" / f"chrome-extension_{ext_id}_0.indexeddb.leveldb"
                    if idb_path.exists():
                        vault_data = self._extract_vault_from_leveldb(idb_path)
                        if vault_data:
                            results.append({
                                "Source": "MetaMask",
                                "Browser Profile": str(profile),
                                "Extension ID": ext_id,
                                "Vault (encrypted)": vault_data[:500],
                            })
                        else:
                            results.append({
                                "Source": "MetaMask",
                                "Browser Profile": str(profile),
                                "Extension ID": ext_id,
                                "LevelDB Path": str(idb_path),
                                "Status": "Vault DB exists — extraction requires additional parsing",
                            })

                    # Local Extension Settings (older MetaMask)
                    les_path = profile / "Local Extension Settings" / ext_id
                    if les_path.exists():
                        vault_data = self._extract_vault_from_leveldb(les_path)
                        if vault_data:
                            results.append({
                                "Source": "MetaMask (Local Storage)",
                                "Browser Profile": str(profile),
                                "Extension ID": ext_id,
                                "Vault (encrypted)": vault_data[:500],
                            })

        return results

    @staticmethod
    def _extract_vault_from_leveldb(ldb_dir: Path) -> str:
        """Try to extract MetaMask vault JSON from LevelDB .ldb and .log files."""
        vault_pattern = re.compile(rb'"vault"\s*:\s*"\{.*?\}"', re.DOTALL)
        data_pattern = re.compile(rb'"data"\s*:\s*"[A-Za-z0-9+/=]+"')

        for ldb_file in list(ldb_dir.glob("*.ldb")) + list(ldb_dir.glob("*.log")):
            try:
                content = ldb_file.read_bytes()

                # Try to find the vault JSON
                match = vault_pattern.search(content)
                if match:
                    return match.group(0).decode("utf-8", errors="replace")

                # Fallback: look for encrypted data blob
                match = data_pattern.search(content)
                if match:
                    return match.group(0).decode("utf-8", errors="replace")
            except Exception:
                continue

        return ""


# ═══════════════════════════════════════════════════════════════════════════
# Brave Wallet (built-in crypto wallet)
# ═══════════════════════════════════════════════════════════════════════════

class BraveWallet(ModuleBase):
    """Recover Brave browser built-in wallet data."""

    meta = ModuleMeta(
        name="Brave Wallet",
        category=Category.GAMING,
        description="Recover Brave browser built-in crypto wallet encrypted data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        brave_dir = _resolve("{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data")
        if not brave_dir:
            return results
        base = Path(brave_dir)
        if not base.exists():
            return results

        profile_dirs = []
        default = base / "Default"
        if default.exists():
            profile_dirs.append(default)
        for item in base.iterdir():
            if item.is_dir() and item.name.startswith("Profile "):
                profile_dirs.append(item)

        for profile in profile_dirs:
            # Brave Wallet uses Preferences JSON
            prefs_file = profile / "Preferences"
            if not prefs_file.exists():
                continue
            try:
                prefs = json.loads(prefs_file.read_text(encoding="utf-8", errors="replace"))
                brave_wallet = prefs.get("brave", {}).get("wallet", {})
                if brave_wallet:
                    entry: dict[str, Any] = {
                        "Source": "Brave Wallet",
                        "Profile": profile.name,
                    }

                    # Encrypted mnemonic
                    enc_mnemonic = brave_wallet.get("encrypted_mnemonic", "")
                    if enc_mnemonic:
                        entry["Encrypted Mnemonic"] = str(enc_mnemonic)[:200]

                    # Selected networks / accounts
                    if "selected_networks" in brave_wallet:
                        entry["Networks"] = str(brave_wallet["selected_networks"])[:200]

                    if "keyrings" in brave_wallet:
                        entry["Keyrings"] = str(list(brave_wallet["keyrings"].keys()))[:200]

                    if len(entry) > 2:
                        results.append(entry)
            except Exception:
                continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Wasabi Wallet
# ═══════════════════════════════════════════════════════════════════════════

class WasabiWallet(ModuleBase):
    """Recover Wasabi Wallet files (Bitcoin privacy wallet)."""

    meta = ModuleMeta(
        name="Wasabi Wallet",
        category=Category.GAMING,
        description="Recover Wasabi Wallet encrypted files and configuration",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        wasabi_dir = _resolve("{APPDATA}\\WalletWasabi\\Client")
        if not wasabi_dir:
            return results
        base = Path(wasabi_dir)
        if not base.exists():
            return results

        # Wallet files
        wallets_dir = base / "Wallets"
        if wallets_dir.exists():
            for wallet_file in wallets_dir.iterdir():
                if wallet_file.is_file() and wallet_file.suffix == ".json":
                    try:
                        data = json.loads(wallet_file.read_text(encoding="utf-8", errors="replace"))
                        results.append({
                            "Source": "Wasabi Wallet",
                            "Wallet": wallet_file.name,
                            "Path": str(wallet_file),
                            "Encrypted Secret": str(data.get("EncryptedSecret", ""))[:200],
                            "Chain Code": str(data.get("ChainCode", ""))[:100],
                            "ExtPubKey": str(data.get("ExtPubKey", ""))[:100],
                        })
                    except Exception:
                        results.append({
                            "Source": "Wasabi Wallet",
                            "Wallet": wallet_file.name,
                            "Path": str(wallet_file),
                        })

        return results
