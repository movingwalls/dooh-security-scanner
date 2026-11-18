# Testing and device verification

## Automated (every push, see `.github/workflows/ci.yml`)
- `mvn verify`: unit tests, template lint (truncated files, `status: success`, spaced port lists, placeholder authors,
  intrusive tagging, ADB handshake bytes), installer checksum tests, HTML-escaping tests.
- `nuclei -validate -t templates` with the pinned Nuclei version.
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
