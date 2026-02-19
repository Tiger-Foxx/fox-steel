# Changelog

All notable changes to the **SteelFox** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-19

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
- Renamed project from *LaZagne* to **SteelFox**.
- Default output format is now HTML (previously required flags).
- Console output is now UTF-8 forced to handle special characters in usernames/passwords correctly.

### Security
- Added memory cleanup routines for sensitive strings (where possible in Python).
- removed deprecated cryptographic libraries in favor of modern implementations.

## [1.0.0] - 2024-01-15 (Legacy)

### Added
- Initial fork from the original LaZagne project.
- Basic refactoring of the directory structure.
