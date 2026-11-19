# Testing and device verification

## Automated (every push, see `.github/workflows/ci.yml`)
- `mvn verify`: unit tests, template lint (truncated files, `status: success`, spaced port lists, placeholder authors,
  intrusive tagging, ADB handshake bytes), installer checksum tests, HTML-escaping tests.
- `PlantedBinaryTest` and `TemplateStoreTest`: the real scanner is run with a `nuclei` planted in the working folder, a tampered
  cache entry and a relative `PATH` entry (none may run), and tampered or extra templates are restored from the jar.
- `scripts/platform-test.sh` on Linux x64/arm64, macOS Intel/Apple Silicon and Windows: installs Nuclei (tested and latest),
  runs `nuclei -validate -t templates`, runs the false-positive check below (Linux/macOS), and scans from a fresh machine.
- `scripts/build-bundle.sh` on the same five platforms: builds the self-contained bundle and checks that it runs offline with
  its own, trusted Nuclei.
- `scripts/false-positive-check.sh`: a plain web server that looks like a home router must come back PASS.

## Real-device verification (required before removing the "release candidate" label)
Run the scanner against each device below, once with default settings and once with `--intrusive` where noted,
and record the result. Use test devices you own.

| Device | Expected | Verified (date / tester / firmware) |
|---|---|---|
| NovaStar TB40 / Taurus player (web panel on 80/8000) | REVIEW (panel) | |
| NovaStar player with default password (`--intrusive`) | FAIL (default login) | |
| Colorlight C-Series | REVIEW (console) | |
| Huidu HD-C16 / C36 | REVIEW (web UI / ports) | |
| XiXun Y-Series | REVIEW | |
| Android player with ADB over network enabled | FAIL (ADB) | |
| Android player with ADB disabled | PASS | |
| Windows player with RDP on | REVIEW (RDP) | |
| Linux player with VNC / Telnet on | FAIL | |
| Ordinary home router / IP camera | PASS | |

Record any wrong result as a "Bug report / false result" issue.
