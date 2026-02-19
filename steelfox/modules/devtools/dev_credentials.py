# -*- coding: utf-8 -*-
"""
SteelFox — Developer Tools Credential Recovery

Recovers credentials, tokens, and keys from:
  - Git (credentials, global config)
  - SSH keys (~/.ssh/)
  - VS Code (stored secrets, settings)
  - Docker (config.json with registry auth)
  - AWS CLI (credentials & config)
  - Azure CLI (tokens)
  - NPM (.npmrc tokens)
  - JetBrains IDEs (stored credentials)
  - WSL (Windows Subsystem for Linux)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from configparser import ConfigParser
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
# Git Credentials
# ═══════════════════════════════════════════════════════════════════════════

class GitCredentials(ModuleBase):
    """Recover Git stored credentials, tokens, and configuration.

    Sources:
      - .git-credentials (plaintext store)
      - .gitconfig (user info + credential helper config)
      - Git Credential Manager for Windows (Windows Credential Manager entries)
      - GitHub CLI tokens (~/.config/gh/hosts.yml)
      - GitHub Desktop tokens (%APPDATA%/GitHub Desktop)
      - GitHub Copilot tokens (VS Code extension globalStorage)
      - Git credential-cache / credential-store
      - System-level Git config
    """

    meta = ModuleMeta(
        name="Git",
        category=Category.DEVTOOLS,
        description="Recover Git credentials, tokens, Copilot auth, and global configuration",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        userprofile = config.profile.get("USERPROFILE", "")
        appdata = config.profile.get("APPDATA", "")
        localappdata = config.profile.get("LOCALAPPDATA", "")

        # ── 1. .git-credentials (plaintext credential store) ─────────
        for cred_path in [
            Path(userprofile) / ".git-credentials",
            Path(userprofile) / ".git-credentials-store",
        ]:
            if cred_path.exists():
                try:
                    for line in cred_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if "://" in line:
                            match = re.match(r"(https?)://([^:]+):([^@]+)@(.+)", line)
                            if match:
                                results.append(self._make_credential(
                                    source="Git Credentials File",
                                    url=f"{match.group(1)}://{match.group(4)}",
                                    username=match.group(2),
                                    password=match.group(3),
                                ))
                except Exception as e:
                    logger.debug("Git credentials parse failed: %s", e)

        # ── 2. .gitconfig (user info + credential helpers) ───────────
        for gitconfig_path in [
            Path(userprofile) / ".gitconfig",
            Path(os.environ.get("ProgramFiles", "")) / "Git" / "etc" / "gitconfig",
            Path(os.environ.get("ProgramFiles(x86)", "")) / "Git" / "etc" / "gitconfig",
            Path(localappdata) / "Programs" / "Git" / "etc" / "gitconfig",
        ]:
            if gitconfig_path.exists():
                try:
                    content = gitconfig_path.read_text(encoding="utf-8", errors="replace")
                    cp = ConfigParser()
                    cp.read_string(content)

                    user_name = cp.get("user", "name", fallback="")
                    user_email = cp.get("user", "email", fallback="")
                    cred_helper = cp.get("credential", "helper", fallback="")

                    if user_name or user_email or cred_helper:
                        results.append({
                            "Source": "Git Config",
                            "Path": str(gitconfig_path),
                            "User Name": user_name,
                            "Email": user_email,
                            "Credential Helper": cred_helper,
                        })

                    # Extract any URL-specific credential blocks
                    for section in cp.sections():
                        if section.startswith("credential"):
                            helper = cp.get(section, "helper", fallback="")
                            url = section.replace("credential", "").strip().strip('"').strip("'")
                            if helper or url:
                                results.append({
                                    "Source": "Git Config (credential block)",
                                    "Path": str(gitconfig_path),
                                    "URL Pattern": url or "(default)",
                                    "Helper": helper,
                                })
                except Exception:
                    pass

        # ── 3. Windows Credential Manager — Git entries ──────────────
        try:
            from steelfox.core.winapi import enumerate_credential_manager
            for cred in enumerate_credential_manager():
                target = cred.get("Target", "").lower()
                # Match git-related credential entries
                if any(kw in target for kw in [
                    "git:", "github", "gitlab", "bitbucket", "azure",
                    "vsts", "dev.azure", "copilot",
                ]):
                    token_type = "Token"
                    pw = cred.get("Password", "")
                    if pw.startswith("gho_"):
                        token_type = "GitHub OAuth Token"
                    elif pw.startswith("ghp_"):
                        token_type = "GitHub Personal Access Token"
                    elif pw.startswith("ghu_"):
                        token_type = "GitHub User-to-Server Token"
                    elif pw.startswith("ghs_"):
                        token_type = "GitHub Server-to-Server Token"
                    elif pw.startswith("github_pat_"):
                        token_type = "GitHub Fine-grained PAT"
                    elif pw.startswith("glpat-"):
                        token_type = "GitLab Personal Access Token"

                    results.append(self._make_credential(
                        source="Git Credential Manager (Windows)",
                        url=cred.get("Target", ""),
                        username=cred.get("Username", ""),
                        password=pw,
                        extra={"Token Type": token_type},
                    ))
        except Exception as e:
            logger.debug("Git Credential Manager enum failed: %s", e)

        # ── 4. GitHub Copilot tokens (VS Code extension) ────────────
        for vscode_variant in ["Code", "Code - Insiders", "VSCodium"]:
            copilot_dirs = [
                Path(appdata) / vscode_variant / "User" / "globalStorage" / "github.copilot",
                Path(appdata) / vscode_variant / "User" / "globalStorage" / "github.copilot-chat",
            ]
            for copilot_dir in copilot_dirs:
                if not copilot_dir.exists():
                    continue
                # Check for hosts.json / token files
                for token_file in copilot_dir.iterdir():
                    if not token_file.is_file():
                        continue
                    try:
                        content = token_file.read_text(encoding="utf-8", errors="replace")
                        # Try JSON parse
                        if content.strip().startswith("{"):
                            data = json.loads(content)
                            for key, val in data.items():
                                if isinstance(val, str) and (
                                    val.startswith("gho_") or val.startswith("ghu_") or
                                    val.startswith("ghp_") or val.startswith("tid=") or
                                    "token" in key.lower()
                                ):
                                    results.append(self._make_credential(
                                        source="GitHub Copilot (VS Code)",
                                        url="github.com/copilot",
                                        username=key,
                                        password=val,
                                    ))
                        # Raw token search in non-JSON files
                        else:
                            for token_match in re.finditer(
                                r"(gho_[A-Za-z0-9_]{20,}|ghu_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9_]{20,})",
                                content,
                            ):
                                results.append(self._make_credential(
                                    source="GitHub Copilot (VS Code)",
                                    url="github.com/copilot",
                                    username="copilot-token",
                                    password=token_match.group(1),
                                ))
                    except Exception:
                        pass

            # Also check the VS Code state.vscdb for Copilot keys
            state_db = Path(appdata) / vscode_variant / "User" / "globalStorage" / "state.vscdb"
            if state_db.exists():
                try:
                    from steelfox.core.winapi import safe_copy_db, query_db
                    tmp_db = safe_copy_db(state_db)
                    if tmp_db:
                        rows = query_db(tmp_db, "SELECT key, value FROM ItemTable")
                        for key, value in rows:
                            key_lower = str(key).lower()
                            if any(kw in key_lower for kw in [
                                "copilot", "github.auth", "github.copilot",
                                "github-enterprise", "vscode.github.authentication",
                            ]):
                                val_str = str(value) if value else ""
                                # Try to parse JSON token values
                                if val_str.strip().startswith(("{", "[")):
                                    try:
                                        parsed = json.loads(val_str)
                                        results.append({
                                            "Source": f"VS Code State DB ({vscode_variant})",
                                            "Key": str(key),
                                            "Data": parsed if isinstance(parsed, dict) else str(parsed)[:500],
                                        })
                                    except json.JSONDecodeError:
                                        results.append({
                                            "Source": f"VS Code State DB ({vscode_variant})",
                                            "Key": str(key),
                                            "Value": val_str[:500],
                                        })
                                elif val_str:
                                    results.append({
                                        "Source": f"VS Code State DB ({vscode_variant})",
                                        "Key": str(key),
                                        "Value": val_str[:500],
                                    })
                        try:
                            os.unlink(tmp_db)
                        except OSError:
                            pass
                except Exception as e:
                    logger.debug("VS Code state DB query failed: %s", e)

        # ── 5. GitHub CLI token (~/.config/gh/hosts.yml) ─────────────
        gh_hosts = Path(appdata) / "GitHub CLI" / "hosts.yml"
        if not gh_hosts.exists():
            gh_hosts = Path(userprofile) / ".config" / "gh" / "hosts.yml"
        if gh_hosts.exists():
            try:
                content = gh_hosts.read_text(encoding="utf-8", errors="replace")
                # Simple YAML-like parsing (avoid external dependency)
                current_host = ""
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.endswith(":") and not stripped.startswith("-"):
                        current_host = stripped.rstrip(":")
                    elif "oauth_token:" in stripped:
                        token = stripped.split("oauth_token:", 1)[1].strip()
                        results.append(self._make_credential(
                            source="GitHub CLI (gh)",
                            url=current_host or "github.com",
                            username="oauth_token",
                            password=token,
                        ))
                    elif "token:" in stripped:
                        token = stripped.split("token:", 1)[1].strip()
                        results.append(self._make_credential(
                            source="GitHub CLI (gh)",
                            url=current_host or "github.com",
                            username="token",
                            password=token,
                        ))
            except Exception as e:
                logger.debug("GitHub CLI hosts.yml parse failed: %s", e)

        # ── 6. GitHub Desktop tokens ─────────────────────────────────
        gh_desktop = Path(appdata) / "GitHub Desktop"
        if gh_desktop.exists():
            # Look for auth tokens in IndexedDB / localStorage
            for local_storage in gh_desktop.rglob("Local Storage/leveldb/*.log"):
                try:
                    content = local_storage.read_bytes()
                    for token_match in re.finditer(
                        rb"(gho_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9_]{20,})", content
                    ):
                        results.append(self._make_credential(
                            source="GitHub Desktop",
                            url="github.com",
                            username="desktop-token",
                            password=token_match.group(1).decode("ascii", errors="replace"),
                        ))
                except Exception:
                    pass

            # GitHub Desktop Electron cookie store
            cookies_db = gh_desktop / "Cookies"
            if cookies_db.exists():
                try:
                    from steelfox.core.winapi import safe_copy_db, query_db
                    tmp = safe_copy_db(cookies_db)
                    if tmp:
                        rows = query_db(tmp, (
                            "SELECT host_key, name, encrypted_value "
                            "FROM cookies WHERE host_key LIKE '%github%'"
                        ))
                        for host, name, enc_val in rows:
                            results.append({
                                "Source": "GitHub Desktop Cookie",
                                "Host": host,
                                "Cookie Name": name,
                                "Note": f"Encrypted ({len(enc_val)} bytes)" if enc_val else "Empty",
                            })
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass
                except Exception:
                    pass

        # ── 7. Credential cache/store file (non-default locations) ───
        # Some users store credentials in custom paths via git-credential-store
        for xdg_path in [
            Path(userprofile) / ".config" / "git" / "credentials",
            Path(localappdata) / "git" / "credentials",
        ]:
            if xdg_path.exists():
                try:
                    for line in xdg_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if "://" in line:
                            match = re.match(r"(https?)://([^:]+):([^@]+)@(.+)", line)
                            if match:
                                results.append(self._make_credential(
                                    source="Git Credential Store (XDG)",
                                    url=f"{match.group(1)}://{match.group(4)}",
                                    username=match.group(2),
                                    password=match.group(3),
                                ))
                except Exception:
                    pass

        # ── 8. Scan for tokens in known token patterns across home ───
        # Look for GitHub/GitLab tokens in common dot files
        token_patterns = [
            (r"GITHUB_TOKEN[=: ]+['\"]?([A-Za-z0-9_]{20,})['\"]?", "GITHUB_TOKEN"),
            (r"GH_TOKEN[=: ]+['\"]?([A-Za-z0-9_]{20,})['\"]?", "GH_TOKEN"),
            (r"GITLAB_TOKEN[=: ]+['\"]?([A-Za-z0-9_-]{20,})['\"]?", "GITLAB_TOKEN"),
            (r"(ghp_[A-Za-z0-9]{36,})", "GitHub PAT"),
            (r"(gho_[A-Za-z0-9]{36,})", "GitHub OAuth"),
            (r"(glpat-[A-Za-z0-9_-]{20,})", "GitLab PAT"),
        ]
        token_files = [
            Path(userprofile) / ".bashrc",
            Path(userprofile) / ".bash_profile",
            Path(userprofile) / ".profile",
            Path(userprofile) / ".zshrc",
            Path(userprofile) / ".env",
            Path(userprofile) / ".npmrc",
        ]
        seen_tokens: set[str] = set()
        for tf in token_files:
            if tf.exists():
                try:
                    content = tf.read_text(encoding="utf-8", errors="replace")
                    for pattern, label in token_patterns:
                        for m in re.finditer(pattern, content):
                            token_val = m.group(1)
                            if token_val not in seen_tokens:
                                seen_tokens.add(token_val)
                                results.append(self._make_credential(
                                    source=f"Dotfile ({tf.name})",
                                    url=label,
                                    username=label,
                                    password=token_val,
                                ))
                except Exception:
                    pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# SSH Keys
# ═══════════════════════════════════════════════════════════════════════════

class SSHKeys(ModuleBase):
    """Discover and catalog SSH private keys."""

    meta = ModuleMeta(
        name="SSH Keys",
        category=Category.DEVTOOLS,
        description="Discover SSH private keys, known hosts, and SSH config",
    )

    KEY_FILE_PATTERNS = [
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        "id_rsa_*", "id_ed25519_*", "*.pem", "*.key",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        ssh_dir = Path(config.profile.get("USERPROFILE", "")) / ".ssh"
        if not ssh_dir.exists():
            return results

        for item in ssh_dir.iterdir():
            if item.is_file():
                try:
                    content = item.read_text(encoding="utf-8", errors="replace")

                    if "PRIVATE KEY" in content:
                        # Determine key type and encryption status
                        encrypted = "ENCRYPTED" in content
                        key_type = "Unknown"
                        if "RSA" in content:
                            key_type = "RSA"
                        elif "ED25519" in content:
                            key_type = "Ed25519"
                        elif "ECDSA" in content:
                            key_type = "ECDSA"
                        elif "DSA" in content:
                            key_type = "DSA"
                        elif "OPENSSH" in content:
                            key_type = "OpenSSH"

                        results.append({
                            "Source": "SSH Private Key",
                            "File": item.name,
                            "Path": str(item),
                            "Key Type": key_type,
                            "Encrypted": str(encrypted),
                            "Size": f"{item.stat().st_size} bytes",
                            "Private Key": content,
                        })

                    elif item.name == "known_hosts":
                        line_count = len(content.splitlines())
                        results.append({
                            "Source": "SSH Known Hosts",
                            "Path": str(item),
                            "Entries": str(line_count),
                        })

                    elif item.name == "config":
                        # Parse SSH config for host definitions
                        hosts = re.findall(
                            r"Host\s+(\S+)", content, re.MULTILINE
                        )
                        results.append({
                            "Source": "SSH Config",
                            "Path": str(item),
                            "Configured Hosts": ", ".join(hosts) if hosts else "none",
                        })

                    elif item.name == "authorized_keys":
                        line_count = len([l for l in content.splitlines() if l.strip()])
                        results.append({
                            "Source": "SSH Authorized Keys",
                            "Path": str(item),
                            "Keys": str(line_count),
                        })

                except Exception:
                    continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Docker
# ═══════════════════════════════════════════════════════════════════════════

class Docker(ModuleBase):
    """Recover Docker registry authentication tokens."""

    meta = ModuleMeta(
        name="Docker",
        category=Category.DEVTOOLS,
        description="Recover Docker registry credentials from config.json",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        docker_config = Path(config.profile.get("USERPROFILE", "")) / ".docker" / "config.json"
        if not docker_config.exists():
            return results

        try:
            data = json.loads(docker_config.read_text(encoding="utf-8"))
            auths = data.get("auths", {})

            for registry, auth_data in auths.items():
                auth = auth_data.get("auth", "")
                if auth:
                    try:
                        decoded = base64.b64decode(auth).decode("utf-8")
                        if ":" in decoded:
                            username, password = decoded.split(":", 1)
                            results.append(self._make_credential(
                                source="Docker Registry",
                                url=registry,
                                username=username,
                                password=password,
                            ))
                    except Exception:
                        results.append(self._make_credential(
                            source="Docker Registry",
                            url=registry,
                            username="<encoded>",
                            password=auth,
                        ))

            # Credential helpers
            cred_store = data.get("credsStore", "")
            if cred_store:
                results.append({
                    "Source": "Docker",
                    "Type": "Credential Store",
                    "Helper": cred_store,
                })

        except Exception as e:
            logger.debug("Docker config parse failed: %s", e)

        return results


# ═══════════════════════════════════════════════════════════════════════════
# AWS CLI
# ═══════════════════════════════════════════════════════════════════════════

class AWSCredentials(ModuleBase):
    """Recover AWS CLI credentials and configuration."""

    meta = ModuleMeta(
        name="AWS CLI",
        category=Category.DEVTOOLS,
        description="Recover AWS CLI access keys, secrets, and profile configuration",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        aws_dir = Path(config.profile.get("USERPROFILE", "")) / ".aws"
        if not aws_dir.exists():
            return results

        # credentials file
        creds_file = aws_dir / "credentials"
        if creds_file.exists():
            try:
                cp = ConfigParser()
                cp.read(str(creds_file), encoding="utf-8")

                for section in cp.sections():
                    access_key = cp.get(section, "aws_access_key_id", fallback="")
                    secret_key = cp.get(section, "aws_secret_access_key", fallback="")
                    session_token = cp.get(section, "aws_session_token", fallback="")

                    if access_key or secret_key:
                        entry = self._make_credential(
                            source="AWS CLI",
                            username=f"Profile: {section}",
                            password=secret_key,
                            extra={
                                "Access Key ID": access_key,
                                "Profile": section,
                            },
                        )
                        if session_token:
                            entry["Session Token"] = session_token[:40] + "..."
                        results.append(entry)
            except Exception as e:
                logger.debug("AWS credentials parse failed: %s", e)

        # config file
        config_file = aws_dir / "config"
        if config_file.exists():
            try:
                cp = ConfigParser()
                cp.read(str(config_file), encoding="utf-8")
                for section in cp.sections():
                    region = cp.get(section, "region", fallback="")
                    output = cp.get(section, "output", fallback="")
                    role_arn = cp.get(section, "role_arn", fallback="")
                    if region or role_arn:
                        results.append({
                            "Source": "AWS Config",
                            "Profile": section.replace("profile ", ""),
                            "Region": region,
                            "Output": output,
                            "Role ARN": role_arn,
                        })
            except Exception:
                pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Azure CLI
# ═══════════════════════════════════════════════════════════════════════════

class AzureCLI(ModuleBase):
    """Recover Azure CLI tokens and profile data."""

    meta = ModuleMeta(
        name="Azure CLI",
        category=Category.DEVTOOLS,
        description="Recover Azure CLI access tokens, subscriptions, and profile data",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        azure_dir = Path(config.profile.get("USERPROFILE", "")) / ".azure"
        if not azure_dir.exists():
            return results

        # Access tokens
        tokens_file = azure_dir / "accessTokens.json"
        if tokens_file.exists():
            try:
                tokens = json.loads(tokens_file.read_text(encoding="utf-8"))
                if isinstance(tokens, list):
                    for token in tokens:
                        results.append(self._make_credential(
                            source="Azure CLI",
                            username=token.get("userId", ""),
                            password=token.get("accessToken", "")[:60] + "..." if token.get("accessToken") else "",
                            extra={
                                "Tenant": token.get("authority", ""),
                                "Resource": token.get("resource", ""),
                                "Token Type": token.get("tokenType", ""),
                            },
                        ))
            except Exception:
                pass

        # Azure profile
        profile_file = azure_dir / "azureProfile.json"
        if profile_file.exists():
            try:
                # Remove BOM if present
                content = profile_file.read_bytes()
                if content.startswith(b"\xef\xbb\xbf"):
                    content = content[3:]
                profile = json.loads(content)
                for sub in profile.get("subscriptions", []):
                    results.append({
                        "Source": "Azure Profile",
                        "Subscription": sub.get("name", ""),
                        "Subscription ID": sub.get("id", ""),
                        "Tenant ID": sub.get("tenantId", ""),
                        "State": sub.get("state", ""),
                        "User": sub.get("user", {}).get("name", ""),
                    })
            except Exception:
                pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# NPM
# ═══════════════════════════════════════════════════════════════════════════

class NPMTokens(ModuleBase):
    """Recover NPM registry authentication tokens."""

    meta = ModuleMeta(
        name="NPM",
        category=Category.DEVTOOLS,
        description="Recover NPM registry tokens from .npmrc files",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        npmrc_locations = [
            Path(config.profile.get("USERPROFILE", "")) / ".npmrc",
            Path(config.profile.get("APPDATA", "")) / "npm" / "etc" / "npmrc",
        ]

        for npmrc in npmrc_locations:
            if not npmrc.exists():
                continue

            try:
                content = npmrc.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    line = line.strip()
                    if "_authToken=" in line or "_auth=" in line:
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            key, token = parts
                            registry = key.replace("_authToken", "").replace("_auth", "").strip(":/")
                            results.append(self._make_credential(
                                source="NPM",
                                url=registry or "default registry",
                                username="NPM Token",
                                password=token,
                            ))
            except Exception:
                pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# VS Code
# ═══════════════════════════════════════════════════════════════════════════

class VSCode(ModuleBase):
    """Recover VS Code stored secrets, extension tokens, and session data."""

    meta = ModuleMeta(
        name="VS Code",
        category=Category.DEVTOOLS,
        description="Recover VS Code stored settings, workspace history, extension credentials, and auth tokens",
    )

    # Keys in state.vscdb that may contain secrets / tokens / sessions
    _INTERESTING_KEYS = [
        "github", "gitlab", "azure", "copilot", "auth", "token",
        "secret", "credential", "session", "account", "password",
        "apikey", "api_key", "access_token", "refresh_token",
        "microsoft", "vscode.github", "gitlens", "remote",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for vscode_variant in ["Code", "Code - Insiders", "VSCodium"]:
            vscode_dir = Path(config.profile.get("APPDATA", "")) / vscode_variant
            if not vscode_dir.exists():
                continue

            label = f"VS Code ({vscode_variant})" if vscode_variant != "Code" else "VS Code"

            # ── Recent workspaces and files ──────────────────────────
            storage_file = vscode_dir / "User" / "globalStorage" / "storage.json"
            if not storage_file.exists():
                storage_file = vscode_dir / "storage.json"

            if storage_file.exists():
                try:
                    data = json.loads(storage_file.read_text(encoding="utf-8", errors="replace"))
                    recent = data.get("openedPathsList", {})
                    if isinstance(recent, dict):
                        workspaces = recent.get("workspaces3", [])
                        if workspaces:
                            results.append({
                                "Source": label,
                                "Type": "Recent Workspaces",
                                "Count": str(len(workspaces)),
                                "Workspaces": ", ".join(str(w) for w in workspaces[:10]),
                            })
                except Exception:
                    pass

            # ── State database — extract auth tokens & secrets ───────
            state_db = vscode_dir / "User" / "globalStorage" / "state.vscdb"
            if state_db.exists():
                try:
                    from steelfox.core.winapi import safe_copy_db, query_db
                    tmp_db = safe_copy_db(state_db)
                    if tmp_db:
                        rows = query_db(tmp_db, "SELECT key, value FROM ItemTable")
                        for key, value in rows:
                            key_str = str(key).lower()
                            if any(kw in key_str for kw in self._INTERESTING_KEYS):
                                val_str = str(value) if value else ""
                                if not val_str or val_str == "None":
                                    continue

                                entry: dict[str, Any] = {
                                    "Source": label,
                                    "Type": "State DB Entry",
                                    "Key": str(key),
                                }

                                # Try JSON parse for structured data
                                if val_str.strip().startswith(("{", "[")):
                                    try:
                                        parsed = json.loads(val_str)
                                        # For dicts, include key fields inline
                                        if isinstance(parsed, dict):
                                            entry["Data"] = {
                                                k: (v if len(str(v)) < 200 else str(v)[:200] + "...")
                                                for k, v in parsed.items()
                                            }
                                        else:
                                            entry["Data"] = str(parsed)[:500]
                                    except json.JSONDecodeError:
                                        entry["Value"] = val_str[:500]
                                else:
                                    entry["Value"] = val_str[:500]

                                results.append(entry)

                        try:
                            os.unlink(tmp_db)
                        except OSError:
                            pass
                except Exception as e:
                    logger.debug("VS Code state DB query failed: %s", e)

            # ── Extension globalStorage — scan for token files ───────
            global_storage = vscode_dir / "User" / "globalStorage"
            if global_storage.exists():
                for ext_dir in global_storage.iterdir():
                    if not ext_dir.is_dir():
                        continue
                    ext_name = ext_dir.name.lower()
                    if any(kw in ext_name for kw in ["github", "gitlab", "azure", "auth", "copilot"]):
                        for f in ext_dir.iterdir():
                            if f.is_file() and f.suffix in (".json", ".yml", ".yaml", ".txt", ".token", ""):
                                try:
                                    content = f.read_text(encoding="utf-8", errors="replace")
                                    if len(content) > 5000:
                                        content = content[:5000] + "..."
                                    if content.strip():
                                        results.append({
                                            "Source": label,
                                            "Type": f"Extension Data ({ext_dir.name})",
                                            "File": f.name,
                                            "Content": content[:500],
                                        })
                                except Exception:
                                    pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# JetBrains IDEs (IntelliJ, PyCharm, WebStorm, GoLand, PhpStorm, Rider, etc.)
# ═══════════════════════════════════════════════════════════════════════════

class JetBrainsIDEs(ModuleBase):
    """Recover JetBrains IDE stored credentials, database passwords, and deployment configs."""

    meta = ModuleMeta(
        name="JetBrains IDEs",
        category=Category.DEVTOOLS,
        description="Recover JetBrains stored credentials (DB passwords, remote hosts, tokens)",
    )

    IDE_PREFIXES = [
        "IntelliJIdea", "PyCharm", "WebStorm", "PhpStorm", "GoLand",
        "Rider", "CLion", "DataGrip", "RubyMine", "AppCode",
        "AndroidStudio",
    ]

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        jb_base = Path(_resolve("{APPDATA}\\JetBrains") or "")
        if not jb_base.exists():
            return results

        for ide_dir in jb_base.iterdir():
            if not ide_dir.is_dir():
                continue

            ide_name = ide_dir.name

            # --- recentProjects.xml — recent projects ---
            recent = ide_dir / "options" / "recentProjects.xml"
            if recent.exists():
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(str(recent))
                    for entry in tree.iter("entry"):
                        key = entry.get("key", "")
                        if key and ("$USER_HOME$" in key or ":" in key):
                            results.append({
                                "Source": f"JetBrains ({ide_name})",
                                "Type": "Recent Project",
                                "Path": key.replace("$USER_HOME$", "~"),
                            })
                except Exception:
                    pass

            # --- security.xml — stored credentials (DPAPI on Windows) ---
            security = ide_dir / "options" / "security.xml"
            if security.exists():
                results.append({
                    "Source": f"JetBrains ({ide_name})",
                    "Type": "Credentials Store (security.xml)",
                    "Path": str(security),
                    "Note": "Contains DPAPI-encrypted credentials for DB, SSH, deployments",
                })

            # --- Database credentials in dataSources.xml ---
            ds_files = list(ide_dir.rglob("dataSources*.xml"))
            for ds in ds_files:
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(str(ds))
                    for data_source in tree.iter("data-source"):
                        name = data_source.get("name", "")
                        entry: dict[str, Any] = {
                            "Source": f"JetBrains ({ide_name})",
                            "Type": "Database Connection",
                            "Name": name,
                        }
                        url = data_source.find(".//jdbc-url")
                        if url is not None and url.text:
                            entry["JDBC URL"] = url.text
                        user = data_source.find(".//user-name")
                        if user is not None and user.text:
                            entry["Username"] = user.text
                        driver = data_source.find(".//jdbc-driver")
                        if driver is not None and driver.text:
                            entry["Driver"] = driver.text
                        results.append(entry)
                except Exception:
                    continue

            # --- Deployment configs (SSH/FTP credentials) ---
            for deployment_file in ide_dir.rglob("deployment.xml"):
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(str(deployment_file))
                    for server in tree.iter("serverData"):
                        mapping = server.find(".//fileTransfer")
                        if mapping is not None:
                            entry = {
                                "Source": f"JetBrains ({ide_name})",
                                "Type": "Deployment Server",
                                "Host": mapping.get("host", ""),
                                "Port": mapping.get("port", ""),
                                "Username": mapping.get("username", ""),
                                "Root Path": mapping.get("rootPath", ""),
                            }
                            results.append(entry)
                except Exception:
                    continue

            # --- sshConfigs.xml ---
            ssh_config = ide_dir / "options" / "sshConfigs.xml"
            if ssh_config.exists():
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(str(ssh_config))
                    for cfg in tree.iter("sshConfig"):
                        results.append({
                            "Source": f"JetBrains ({ide_name})",
                            "Type": "SSH Configuration",
                            "Host": cfg.get("host", ""),
                            "Port": cfg.get("port", "22"),
                            "Username": cfg.get("username", ""),
                            "Auth Type": cfg.get("authType", ""),
                            "Key Path": cfg.get("keyPath", ""),
                        })
                except Exception:
                    pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Postman
# ═══════════════════════════════════════════════════════════════════════════

class Postman(ModuleBase):
    """Recover Postman API keys, auth tokens, and environment variables."""

    meta = ModuleMeta(
        name="Postman",
        category=Category.DEVTOOLS,
        description="Recover Postman stored API keys, Bearer tokens, and environment secrets",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        postman_dir = Path(_resolve("{APPDATA}\\Postman") or "")
        if not postman_dir.exists():
            return results

        # Environment files
        for env_file in postman_dir.rglob("*.postman_environment.json"):
            try:
                data = json.loads(env_file.read_text(encoding="utf-8"))
                for var in data.get("values", []):
                    key = var.get("key", "")
                    value = var.get("value", "")
                    if value and any(kw in key.lower() for kw in [
                        "token", "key", "secret", "password", "auth", "api",
                        "bearer", "credential",
                    ]):
                        results.append({
                            "Source": "Postman",
                            "Environment": data.get("name", ""),
                            "Variable": key,
                            "Value": str(value)[:200],
                        })
            except Exception:
                continue

        # Collection files with auth
        for col_file in postman_dir.rglob("*.postman_collection.json"):
            try:
                data = json.loads(col_file.read_text(encoding="utf-8"))
                col_name = data.get("info", {}).get("name", col_file.stem)
                self._extract_auth(data, col_name, results)
            except Exception:
                continue

        # Globals
        for global_file in postman_dir.rglob("*.postman_globals.json"):
            try:
                data = json.loads(global_file.read_text(encoding="utf-8"))
                for var in data.get("values", []):
                    key = var.get("key", "")
                    value = var.get("value", "")
                    if value:
                        results.append({
                            "Source": "Postman (Globals)",
                            "Variable": key,
                            "Value": str(value)[:200],
                        })
            except Exception:
                continue

        return results

    def _extract_auth(self, obj: dict, name: str, results: list) -> None:
        """Recursively extract auth data from Postman collections."""
        auth = obj.get("auth", {})
        if auth:
            auth_type = auth.get("type", "")
            for auth_item in auth.get(auth_type, []):
                if isinstance(auth_item, dict):
                    key = auth_item.get("key", "")
                    value = auth_item.get("value", "")
                    if value and key in ("token", "password", "key", "secret", "username"):
                        results.append({
                            "Source": "Postman",
                            "Collection": name,
                            "Auth Type": auth_type,
                            key: str(value)[:200],
                        })

        # Recurse into items
        for item in obj.get("item", []):
            if isinstance(item, dict):
                self._extract_auth(item, name, results)


# ═══════════════════════════════════════════════════════════════════════════
# Insomnia
# ═══════════════════════════════════════════════════════════════════════════

class Insomnia(ModuleBase):
    """Recover Insomnia REST client stored API credentials."""

    meta = ModuleMeta(
        name="Insomnia",
        category=Category.DEVTOOLS,
        description="Recover Insomnia API client stored authentication and environment secrets",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        insomnia_dir = Path(_resolve("{APPDATA}\\Insomnia") or "")
        if not insomnia_dir.exists():
            return results

        for json_file in insomnia_dir.rglob("insomnia.*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                resources = data.get("resources", [])
                for resource in resources:
                    r_type = resource.get("_type", "")

                    # Environment variables
                    if r_type == "environment":
                        env_data = resource.get("data", {})
                        for key, value in env_data.items():
                            if value and any(kw in key.lower() for kw in [
                                "token", "key", "secret", "password", "auth", "api",
                            ]):
                                results.append({
                                    "Source": "Insomnia",
                                    "Environment": resource.get("name", ""),
                                    "Variable": key,
                                    "Value": str(value)[:200],
                                })

                    # Request auth
                    elif r_type == "request":
                        auth = resource.get("authentication", {})
                        if auth and auth.get("type"):
                            for k, v in auth.items():
                                if v and k in ("token", "password", "username", "key"):
                                    results.append({
                                        "Source": "Insomnia",
                                        "Request": resource.get("name", ""),
                                        "Auth Type": auth.get("type", ""),
                                        k: str(v)[:200],
                                    })
            except Exception:
                continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Google Cloud SDK (gcloud)
# ═══════════════════════════════════════════════════════════════════════════

class GCPCredentials(ModuleBase):
    """Recover Google Cloud SDK credentials and service account keys."""

    meta = ModuleMeta(
        name="GCP / gcloud",
        category=Category.DEVTOOLS,
        description="Recover GCP access tokens, service account keys, and project configs",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        gcloud_dir = Path(_resolve("{APPDATA}\\gcloud") or "")
        if not gcloud_dir.exists():
            return results

        # credentials.db (SQLite)
        creds_db = gcloud_dir / "credentials.db"
        if creds_db.exists():
            try:
                import sqlite3
                conn = sqlite3.connect(str(creds_db))
                cursor = conn.cursor()
                cursor.execute("SELECT account_id, value FROM credentials")
                for row in cursor.fetchall():
                    try:
                        cred_data = json.loads(row[1])
                        results.append({
                            "Source": "GCP (gcloud)",
                            "Account": row[0],
                            "Type": cred_data.get("type", ""),
                            "Client ID": cred_data.get("client_id", "")[:50],
                            "Token URI": cred_data.get("token_uri", ""),
                        })
                    except Exception:
                        results.append({
                            "Source": "GCP (gcloud)",
                            "Account": row[0],
                            "Raw": str(row[1])[:200],
                        })
                conn.close()
            except Exception:
                pass

        # application_default_credentials.json
        adc = gcloud_dir / "application_default_credentials.json"
        if adc.exists():
            try:
                data = json.loads(adc.read_text(encoding="utf-8"))
                results.append({
                    "Source": "GCP (Application Default Credentials)",
                    "Type": data.get("type", ""),
                    "Client ID": data.get("client_id", "")[:50],
                    "Project": data.get("quota_project_id", ""),
                })
            except Exception:
                pass

        # properties (config)
        props = gcloud_dir / "properties"
        if props.exists():
            try:
                cp = ConfigParser()
                cp.read(str(props), encoding="utf-8")
                if cp.has_option("core", "project"):
                    results.append({
                        "Source": "GCP (gcloud config)",
                        "Default Project": cp.get("core", "project"),
                        "Account": cp.get("core", "account", fallback=""),
                        "Region": cp.get("compute", "region", fallback=""),
                    })
            except Exception:
                pass

        # Service account key files in common locations
        for sa_file in gcloud_dir.rglob("*-key.json"):
            try:
                data = json.loads(sa_file.read_text(encoding="utf-8"))
                if data.get("type") == "service_account":
                    results.append({
                        "Source": "GCP (Service Account Key)",
                        "Email": data.get("client_email", ""),
                        "Project": data.get("project_id", ""),
                        "Key ID": data.get("private_key_id", "")[:20],
                        "Path": str(sa_file),
                    })
            except Exception:
                continue

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Kubernetes (kubectl)
# ═══════════════════════════════════════════════════════════════════════════

class KubernetesConfig(ModuleBase):
    """Recover Kubernetes kubectl configuration (clusters, users, tokens)."""

    meta = ModuleMeta(
        name="Kubernetes (kubectl)",
        category=Category.DEVTOOLS,
        description="Recover kubectl clusters, users, tokens, and certificates from kubeconfig",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        kubeconfig = Path(_resolve("{USERPROFILE}\\.kube\\config") or "")
        if not kubeconfig.exists():
            return results

        try:
            # kubeconfig is YAML but we avoid adding a dependency — parse simple patterns
            content = kubeconfig.read_text(encoding="utf-8", errors="replace")

            # Extract clusters
            for match in re.finditer(
                r"- cluster:.*?name:\s*(\S+)", content, re.DOTALL
            ):
                results.append({
                    "Source": "Kubernetes",
                    "Type": "Cluster",
                    "Name": match.group(1),
                })

            # Extract users with tokens
            for match in re.finditer(
                r"- name:\s*(\S+)\s+user:.*?token:\s*(\S+)", content, re.DOTALL
            ):
                results.append({
                    "Source": "Kubernetes",
                    "Type": "User Token",
                    "User": match.group(1),
                    "Token": match.group(2)[:50] + "...",
                })

            # Extract certificate data
            for match in re.finditer(
                r"client-certificate-data:\s*(\S+)", content
            ):
                results.append({
                    "Source": "Kubernetes",
                    "Type": "Client Certificate (base64)",
                    "Length": f"{len(match.group(1))} chars",
                })

            for match in re.finditer(
                r"client-key-data:\s*(\S+)", content
            ):
                results.append({
                    "Source": "Kubernetes",
                    "Type": "Client Key (base64)",
                    "Length": f"{len(match.group(1))} chars",
                })

            # Context info
            current = re.search(r"current-context:\s*(\S+)", content)
            if current:
                results.append({
                    "Source": "Kubernetes",
                    "Type": "Current Context",
                    "Context": current.group(1),
                })

        except Exception:
            pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# GitHub CLI (gh)
# ═══════════════════════════════════════════════════════════════════════════

class GitHubCLI(ModuleBase):
    """Recover GitHub CLI OAuth tokens."""

    meta = ModuleMeta(
        name="GitHub CLI",
        category=Category.DEVTOOLS,
        description="Recover GitHub CLI (gh) OAuth tokens from hosts.yml",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        gh_dir = Path(_resolve("{APPDATA}\\GitHub CLI") or "")
        if not gh_dir.exists():
            return results

        hosts_file = gh_dir / "hosts.yml"
        if not hosts_file.exists():
            return results

        try:
            content = hosts_file.read_text(encoding="utf-8")
            # Simple YAML parsing for oauth_token lines
            current_host = ""
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.endswith(":") and not stripped.startswith("-"):
                    current_host = stripped.rstrip(":")
                elif "oauth_token:" in stripped:
                    token = stripped.split(":", 1)[1].strip()
                    results.append({
                        "Source": "GitHub CLI",
                        "Host": current_host,
                        "OAuth Token": token,
                    })
                elif "user:" in stripped:
                    user = stripped.split(":", 1)[1].strip()
                    results.append({
                        "Source": "GitHub CLI",
                        "Host": current_host,
                        "Username": user,
                    })
        except Exception:
            pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Terraform
# ═══════════════════════════════════════════════════════════════════════════

class Terraform(ModuleBase):
    """Recover Terraform CLI credentials and state secrets."""

    meta = ModuleMeta(
        name="Terraform",
        category=Category.DEVTOOLS,
        description="Recover Terraform Cloud/Enterprise tokens from credentials.tfrc.json",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # credentials.tfrc.json
        tf_dir = Path(_resolve("{APPDATA}\\terraform.d") or "")
        creds_file = tf_dir / "credentials.tfrc.json"
        if creds_file.exists():
            try:
                data = json.loads(creds_file.read_text(encoding="utf-8"))
                credentials = data.get("credentials", {})
                for host, cred in credentials.items():
                    results.append({
                        "Source": "Terraform",
                        "Host": host,
                        "Token": cred.get("token", "")[:64] + "...",
                    })
            except Exception:
                pass

        # Also check USERPROFILE
        alt_creds = Path(_resolve("{USERPROFILE}\\.terraform.d\\credentials.tfrc.json") or "")
        if alt_creds.exists() and alt_creds != creds_file:
            try:
                data = json.loads(alt_creds.read_text(encoding="utf-8"))
                for host, cred in data.get("credentials", {}).items():
                    results.append({
                        "Source": "Terraform",
                        "Host": host,
                        "Token": cred.get("token", "")[:64] + "...",
                    })
            except Exception:
                pass

        # .terraform directories with state (search common project locations)
        docs = Path(_resolve("{USERPROFILE}\\Documents") or "")
        if docs.exists():
            for tfstate in docs.rglob("*.tfstate"):
                if tfstate.stat().st_size > 0:
                    results.append({
                        "Source": "Terraform (State File)",
                        "Path": str(tfstate),
                        "Size": f"{tfstate.stat().st_size:,} bytes",
                        "Note": "May contain secrets in outputs/resources",
                    })

        return results


# ═══════════════════════════════════════════════════════════════════════════
# Maven, Composer (PHP), PyPI, NuGet, ngrok, Helm
# ═══════════════════════════════════════════════════════════════════════════

class MavenCredentials(ModuleBase):
    """Recover Maven repository credentials from settings.xml."""

    meta = ModuleMeta(
        name="Maven",
        category=Category.DEVTOOLS,
        description="Recover Maven repository usernames, passwords, and master password",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        import xml.etree.ElementTree as ET

        m2_dir = Path(_resolve("{USERPROFILE}\\.m2") or "")
        settings_file = m2_dir / "settings.xml"
        if settings_file.exists():
            try:
                tree = ET.parse(str(settings_file))
                root = tree.getroot()
                # Remove namespace
                ns = ""
                if root.tag.startswith("{"):
                    ns = root.tag.split("}")[0] + "}"

                for server in root.iter(f"{ns}server"):
                    srv_id = server.find(f"{ns}id")
                    username = server.find(f"{ns}username")
                    password = server.find(f"{ns}password")
                    results.append({
                        "Source": "Maven",
                        "Server ID": srv_id.text if srv_id is not None else "",
                        "Username": username.text if username is not None else "",
                        "Password": password.text if password is not None else "",
                    })
            except Exception:
                pass

        # settings-security.xml (master password)
        security_file = m2_dir / "settings-security.xml"
        if security_file.exists():
            try:
                tree = ET.parse(str(security_file))
                root = tree.getroot()
                ns = ""
                if root.tag.startswith("{"):
                    ns = root.tag.split("}")[0] + "}"
                master = root.find(f"{ns}master")
                if master is not None and master.text:
                    results.append({
                        "Source": "Maven (Master Password)",
                        "Encrypted Master": master.text,
                    })
            except Exception:
                pass

        return results


class ComposerCredentials(ModuleBase):
    """Recover PHP Composer registry tokens and credentials."""

    meta = ModuleMeta(
        name="Composer (PHP)",
        category=Category.DEVTOOLS,
        description="Recover PHP Composer private registry tokens and HTTP Basic credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Composer home
        composer_home = os.environ.get("COMPOSER_HOME", "")
        if not composer_home:
            composer_home = str(Path(_resolve("{APPDATA}\\Composer") or ""))

        auth_file = Path(composer_home) / "auth.json"
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))

                # HTTP Basic auth
                for host, cred in data.get("http-basic", {}).items():
                    results.append({
                        "Source": "Composer",
                        "Host": host,
                        "Username": cred.get("username", ""),
                        "Password": cred.get("password", ""),
                    })

                # Bearer tokens
                for host, cred in data.get("bearer", {}).items():
                    results.append({
                        "Source": "Composer",
                        "Host": host,
                        "Bearer Token": cred.get("token", str(cred))[:100],
                    })

                # GitHub/GitLab/Bitbucket tokens
                for token_type in ["github-oauth", "gitlab-oauth", "gitlab-token", "bitbucket-oauth"]:
                    for host, token in data.get(token_type, {}).items():
                        results.append({
                            "Source": "Composer",
                            "Type": token_type,
                            "Host": host,
                            "Token": str(token)[:100],
                        })
            except Exception:
                pass

        return results


class PyPICredentials(ModuleBase):
    """Recover PyPI publishing tokens from .pypirc."""

    meta = ModuleMeta(
        name="PyPI (.pypirc)",
        category=Category.DEVTOOLS,
        description="Recover PyPI/TestPyPI publishing tokens and credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        pypirc = Path(_resolve("{USERPROFILE}\\.pypirc") or "")
        if not pypirc.exists():
            return results

        try:
            cp = ConfigParser()
            cp.read(str(pypirc), encoding="utf-8")

            for section in cp.sections():
                if section == "distutils":
                    continue
                entry: dict[str, Any] = {
                    "Source": "PyPI",
                    "Repository": section,
                }
                for key in ["repository", "username", "password"]:
                    if cp.has_option(section, key):
                        entry[key.title()] = cp.get(section, key)

                if entry.get("Username") or entry.get("Password"):
                    results.append(entry)
        except Exception:
            pass

        return results


class NuGetCredentials(ModuleBase):
    """Recover NuGet API keys and feed credentials."""

    meta = ModuleMeta(
        name="NuGet",
        category=Category.DEVTOOLS,
        description="Recover NuGet API keys and private feed credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        import xml.etree.ElementTree as ET

        nuget_config = Path(_resolve("{APPDATA}\\NuGet\\NuGet.Config") or "")
        if not nuget_config.exists():
            return results

        try:
            tree = ET.parse(str(nuget_config))
            root = tree.getroot()

            # Package source credentials
            creds_section = root.find("packageSourceCredentials")
            if creds_section is not None:
                for source in creds_section:
                    entry: dict[str, Any] = {
                        "Source": "NuGet",
                        "Feed": source.tag,
                    }
                    for add in source.iter("add"):
                        key = add.get("key", "")
                        val = add.get("value", "")
                        if key and val:
                            entry[key] = val
                    results.append(entry)

            # API keys
            api_keys = root.find("apikeys")
            if api_keys is not None:
                for add in api_keys.iter("add"):
                    results.append({
                        "Source": "NuGet (API Key)",
                        "Feed": add.get("key", ""),
                        "Encrypted Key": add.get("value", "")[:80],
                    })

        except Exception:
            pass

        return results


class NgrokCredentials(ModuleBase):
    """Recover ngrok auth tokens."""

    meta = ModuleMeta(
        name="ngrok",
        category=Category.DEVTOOLS,
        description="Recover ngrok auth tokens from configuration file",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        ngrok_paths = [
            Path(_resolve("{USERPROFILE}\\.ngrok2\\ngrok.yml") or ""),
            Path(_resolve("{LOCALAPPDATA}\\ngrok\\ngrok.yml") or ""),
        ]

        for ngrok_config in ngrok_paths:
            if not ngrok_config.exists():
                continue
            try:
                content = ngrok_config.read_text(encoding="utf-8")
                for line in content.splitlines():
                    if "authtoken:" in line:
                        token = line.split(":", 1)[1].strip()
                        results.append({
                            "Source": "ngrok",
                            "Auth Token": token,
                            "Path": str(ngrok_config),
                        })
                    elif "api_key:" in line:
                        key = line.split(":", 1)[1].strip()
                        results.append({
                            "Source": "ngrok",
                            "API Key": key,
                        })
            except Exception:
                continue

        return results


class HelmCredentials(ModuleBase):
    """Recover Helm repository credentials."""

    meta = ModuleMeta(
        name="Helm",
        category=Category.DEVTOOLS,
        description="Recover Helm chart repository credentials",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        helm_dir = Path(_resolve("{APPDATA}\\helm") or "")
        repo_file = helm_dir / "repositories.yaml"
        if not repo_file.exists():
            return results

        try:
            content = repo_file.read_text(encoding="utf-8")
            # Simple YAML parsing
            current_repo: dict[str, Any] = {}
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("- name:"):
                    if current_repo and (current_repo.get("Username") or current_repo.get("Password")):
                        results.append(current_repo)
                    current_repo = {
                        "Source": "Helm",
                        "Repo": stripped.split(":", 1)[1].strip(),
                    }
                elif "username:" in stripped and current_repo:
                    current_repo["Username"] = stripped.split(":", 1)[1].strip()
                elif "password:" in stripped and current_repo:
                    current_repo["Password"] = stripped.split(":", 1)[1].strip()
                elif "url:" in stripped and current_repo:
                    current_repo["URL"] = stripped.split(":", 1)[1].strip()

            if current_repo and (current_repo.get("Username") or current_repo.get("Password")):
                results.append(current_repo)
        except Exception:
            pass

        return results


class HashiCorpVault(ModuleBase):
    """Recover HashiCorp Vault CLI tokens."""

    meta = ModuleMeta(
        name="HashiCorp Vault",
        category=Category.DEVTOOLS,
        description="Recover HashiCorp Vault CLI token from .vault-token file",
    )

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        vault_token = Path(_resolve("{USERPROFILE}\\.vault-token") or "")
        if vault_token.exists():
            try:
                token = vault_token.read_text(encoding="utf-8").strip()
                if token:
                    results.append({
                        "Source": "HashiCorp Vault",
                        "Token": token,
                        "Path": str(vault_token),
                    })
            except Exception:
                pass

        return results
