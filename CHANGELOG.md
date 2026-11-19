# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/); versions follow [Semantic Versioning](https://semver.org/).
Per-release notes are in [docs/releases/](docs/releases/).

## [1.0.0-rc3] - 2026-11-19 (release candidate)

### Added
- Nuclei is now downloaded as the **latest** release for the machine's OS and CPU (verified against the SHA-256
  published with that release), falling back to the tested version if the lookup fails. New `--nuclei-version`
  option; `--install-nuclei` updates to the latest. Downloads retry on connection failures and timeouts.
- `scripts/platform-test.sh`: target-machine test (auto-download, template validation, false-positive check,
  fresh-machine run). CI runs it on Linux x64/arm64, macOS Intel/Apple Silicon and Windows, and the release workflow
  publishes nothing unless all of them pass.

### Changed
- Self-contained bundles (own Java runtime, pinned Nuclei, templates) are now published for every mainstream
  platform, each built and smoke-tested natively: `windows-x64`, `linux-x64`, `linux-arm64`, `macos-x64`
  (Intel) and `macos-arm64` (Apple Silicon). Linux/macOS bundles are `.tar.gz`; Windows stays `.zip`.
  The Windows asset is renamed `...-windows.zip` -> `...-windows-x64.zip`.
- CI now builds and smoke-tests the bundle on all five platforms on every change, using the same
  `scripts/build-bundle.sh` as the release.

## [1.0.0-rc2] - 2026-11-19 (release candidate)

### Added
- The single jar is published as its own release asset (`dooh-security-scanner-<version>.jar` plus `.sha256`),
  in addition to the two zips.

## [1.0.0-rc1] - 2026-11-18 (release candidate)

### Added
- Double-click launchers `dooh-security-scanner-easy.bat` (scan `targets.txt`) and
  `dooh-security-scanner-discover-easy.bat` (LAN discovery), plus pass-through `dooh-security-scanner.bat`,
  updated to the new single-command CLI and shipped in both zips.

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
- Scans stalled for minutes because Nuclei waited on an open stdin pipe; the scanner now gives it no stdin.
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

[1.0.0-rc3]: https://github.com/movingwalls/dooh-security-scanner/releases/tag/v1.0.0-rc3
[1.0.0-rc2]: https://github.com/movingwalls/dooh-security-scanner/releases/tag/v1.0.0-rc2
[1.0.0-rc1]: https://github.com/movingwalls/dooh-security-scanner/releases/tag/v1.0.0-rc1
