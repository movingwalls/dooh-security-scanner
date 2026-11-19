# Design and developer notes

## Flow
```
targets (-t file | -h list | --discover)
   -> TargetParser      validate + expand (IPv4, CIDR /22-/32, host names; reject everything else)
   -> locate templates  ./templates, else packaged in the jar (extracted to ~/.dooh-security-scanner/templates/<ver>)
   -> locate Nuclei     --nuclei, next to the jar, ~/.dooh-security-scanner/nuclei/<ver>, PATH,
                        else offer to download the pinned release (SHA-256 verified)
   -> confirm           authorisation prompt (--yes to skip)
   -> nuclei -validate  any template that fails to load => ERROR (exit 3), never PASS
   -> nuclei -l targets.txt -t templates -rate-limit 10 -c 5 -timeout 4 -silent -nc -ni -duc -jsonl -o results.jsonl
                        (+ -etags intrusive unless --intrusive)
   -> DOOHReportPrinter results.jsonl -> report.txt / report.json / report.html
```

## Classes
| Class | Role |
|---|---|
| `DOOHSecurityScanner` | CLI, orchestration, exit codes |
| `TargetParser` | input validation; the only gate for what reaches Nuclei |
| `NucleiInstaller` | downloads the latest Nuclei for this OS/CPU from the official GitHub release, verified against that release's published SHA-256; falls back to the tested version with compiled-in checksums |
| `TemplateStore` | extracts the templates packaged in the jar |
| `LocalArpScanner` | optional LAN discovery (real subnet, no VPN/virtual adapters, no multicast) |
| `DOOHReportPrinter` | PASS/REVIEW/FAIL classification and text/JSON/HTML output |
| `Json` | tiny JSON reader/writer (no third-party dependencies) |

## Security properties
- Nuclei is started with an argument list, never through a shell; targets are written to a list file.
- Only this project's templates are loaded (`-t <dir>`), never Nuclei's general exploit library.
- `intrusive`-tagged templates (anything sending credentials) are excluded unless `--intrusive`.
- Downloads: HTTPS only, pinned version, SHA-256 compiled into the code, verified before extraction,
  only the Nuclei executable is extracted.
- HTML report escapes all device-supplied text and has a no-script content-security-policy.

## Status model
`FAIL` = at least one medium/high/critical finding; `REVIEW` = only info/low findings (a panel or service is
reachable and should be checked); `PASS` = no finding; `ERROR` = the run was unreliable, no verdict given.
Exit codes: 0 no FAIL, 1 FAIL present, 2 usage/invalid targets, 3 ERROR.

## Updating the tested Nuclei version
The scanner downloads the *latest* Nuclei by default; `NucleiInstaller.VERSION` is the version it is tested with, the
fallback when the latest cannot be looked up, and the one bundled in the release packages.
1. Read the official `nuclei_<ver>_checksums.txt` from the release page.
2. Update `NucleiInstaller.VERSION` and the `SHA256` table (the release workflow and `scripts/build-bundle.sh` read them from there).
3. Run `scripts/platform-test.sh` (CI does this on every platform) to check the templates against both the new and the latest Nuclei.

Trust note: for the latest version the checksum comes from the same GitHub release as the download, so it protects against corrupted or
tampered downloads in transit, not against a compromised release. Use `--nuclei-version <tested>` for the compiled-in checksums.
