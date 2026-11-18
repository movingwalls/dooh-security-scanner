# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/); versions follow [Semantic Versioning](https://semver.org/).
Per-release notes are in [docs/releases/](docs/releases/).

## [1.0.0-rc1] - 2026-11-18 (release candidate)

### Fixed
- 5 templates that did not load (`detect-ssh-service`, `ssh-open`, `open-vnc-interface`,
  `exposed-adb-detection`, `huidu-hdplayer-port-detect`): truncated file, `status: success`,
  port lists written as `22, 2222`.
- Templates that matched ordinary web servers: `samsung-vxt-detect` (either condition matched),
  `novastar-taurus-favicon` (reversed `negative` matcher), `novastar-config-exposure` (matched any
  page containing "sn"), `novastar-default-login` (treated `"success":false` as a login).
- ADB handshake was malformed (wrong length, checksum and magic); real devices ignored it.
- A template that failed to load was reported as PASS. The scanner now validates templates first
  and reports **ERROR** (exit code 3) instead.
- Command injection: each line of `targets.txt` used to be written into `scanner.bat` and run.
  Nuclei is now started once with an argument list, and targets are validated first.
- Discovery picked up multicast addresses, VPN/virtual adapters and assumed a /24. It now uses the
  real subnet, skips virtual adapters, shows the network and asks before probing.
- Findings were lost: results are now saved as `results.jsonl`, `report.txt` and `report.json`
  with the matched URL/port and evidence.
- Hard-coded `C:\Users\...` paths; the scanner now runs on Windows, macOS and Linux.

### Added
- **Automatic Nuclei install**: if Nuclei is not found, the scanner offers to download the pinned release
  (v3.4.10) from ProjectDiscovery's official GitHub page for the user's platform, verifies a SHA-256 checksum
  compiled into the scanner (HTTPS only, nothing extracted if it does not match) and caches it per user.
  `--install-nuclei`, `--offline`.
- **Single-jar use**: templates are packaged in the jar and extracted automatically.
- `report.html` (self-contained, escaped) next to `report.txt` / `report.json`.
- Ctrl+C stops the Nuclei process; warning when the Nuclei version differs from the tested one.
- Docs: `docs/FIXING-FINDINGS.md`, `docs/LEGAL.md`, `docs/ARCHITECTURE.md`, `docs/TESTING.md`; Code of Conduct,
  issue and pull request templates, Dependabot, third-party licence notice.
- Windows release bundle: native `.exe` with its own Java runtime, bundled `nuclei.exe` and templates.

### Changed
- **Licence changed from GPL-3.0 to Apache-2.0** (permissive, patent grant; compatible with Nuclei's MIT licence
  and lets the templates be contributed back to ProjectDiscovery).
- Security reports go through GitHub private vulnerability reporting or security@movingwalls.com.
- Default-password checks only run with `--intrusive` (templates tagged `intrusive`).
- Report status is PASS / REVIEW / FAIL, with a recommended fix per finding, and no longer prints a
  blanket "close inbound WAN ports" message.
- Templates are grouped by platform folder, carry `remediation` text and an OWASP IoT mapping, and
  use `movingwalls` as author.
- Added Maven build, unit tests, template lint tests and CI.

### Removed
- Developer leftovers: `scanner.bat`, `config.txt`, `targets.txt`, `discovered_ips.txt`, Eclipse files.

[1.0.0-rc1]: https://github.com/movingwalls/dooh-security-scanner/releases/tag/v1.0.0-rc1
