# Changelog

All notable changes to the **SteelFox** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-02-23

### Changed

- Translated all French comments, docstrings, and console messages to English across `builder.py`, `build_builder.py`, and `build_console.py`.
- Added `setup.py` for `pip install .` support with optional extras (`[builder]`, `[linux]`, `[all]`).
- Added `steelfox_cli.py` entry point for `console_scripts`.
- Comprehensive README rewrite with improved structure, Linux usage guide, roadmap, and contributing section.
- Bumped version to 1.3.1 across all version files and config.

## [1.3.0] - 2026-02-20

### Added

- **Builder CLI** (`builder_cli.py`): Headless command-line payload builder for Linux/CI use.
- **GitHub Actions CI/CD** pipeline: Automatic release builds on tag push.
- Windows VERSIONINFO metadata for all executables.

## [1.2.0] - 2026-02-19

### Added

- **New Core Architecture**: Complete rewrite of the execution engine for better modularity and speed.
- **Stealth Mode (`--stealth`)**:
  - Console window hiding via Win32 API.
  - Silent execution path with no standard output.
- **Advanced Reporting**:
  - New "Jet Black" HTML report template with dashboard view.
  - Interactive search and filtering in reports.
  - Copy-to-clipboard functionality for credentials.
  - Sensitive data masking in reports (click-to-reveal).
- **UX Improvements**:
  - Real-time progress bar with percentage and current module display.
  - Unified CLI argument parsing.
- **Module enhancements**:
  - Improved Chrome/Edge cookie decryption stability.
  - Better handling of large output data sets.

### Changed

- Renamed project from _LaZagne_ to **SteelFox**.
- Default output format is now HTML (previously required flags).
- Console output is now UTF-8 forced to handle special characters in usernames/passwords correctly.

### Security

- Added memory cleanup routines for sensitive strings (where possible in Python).
- Removed deprecated cryptographic libraries in favor of modern implementations.

## [1.0.0] - 2024-01-15 (Legacy)

### Added

- Initial fork from the original LaZagne project.
- Basic refactoring of the directory structure.
