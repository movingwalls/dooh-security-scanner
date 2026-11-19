# Design and developer notes

## Flow
```
targets (-t file | -h list | --discover)
   -> TargetParser      validate + expand (IPv4, CIDR /22-/32, host names; reject everything else)
   -> locate templates  --templates <dir>, else the templates packaged in the jar, extracted to
                        ~/.dooh-security-scanner/templates/<ver> and re-checked against the jar on every run
                        (the current folder is never searched)
   -> locate Nuclei     --nuclei <path> (run as given, with a warning if unofficial), else only an official build
                        (SHA-256 checked) next to the jar, in ~/.dooh-security-scanner/nuclei/<ver> or on an absolute
                        PATH entry; else offer to download the tested release (SHA-256 verified)
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
| `NucleiInstaller` | downloads the tested Nuclei for this OS/CPU from the official GitHub release, verified against compiled-in SHA-256 values (archive and executable); optionally the latest release; decides which Nuclei is trusted to run |
| `TemplateStore` | extracts the templates packaged in the jar and re-verifies the extracted copy against the jar on every run |
| `LocalArpScanner` | optional LAN discovery (real subnet, no VPN/virtual adapters, no multicast) |
| `DOOHReportPrinter` | PASS/REVIEW/FAIL classification and text/JSON/HTML output |
| `Json` | tiny JSON reader/writer (no third-party dependencies) |

## Security properties
- Nuclei is started with an argument list, never through a shell; targets are written to a list file.
- Only this project's templates are loaded (`-t <dir>`), never Nuclei's general exploit library.
- `intrusive`-tagged templates (anything sending credentials) are excluded unless `--intrusive`.
- Downloads: HTTPS only, tested version by default, SHA-256 of the archive and of the extracted executable compiled into the
  code, verified before anything is kept; only the Nuclei executable is extracted.
- The current folder is never searched for Nuclei or templates; see "Which Nuclei is run" below.
- HTML report escapes all device-supplied text and has a no-script content-security-policy.

## Status model
`FAIL` = at least one medium/high/critical finding; `REVIEW` = only info/low findings (a panel or service is
reachable and should be checked); `PASS` = no finding; `ERROR` = the run was unreliable, no verdict given.
Exit codes: 0 no FAIL, 1 FAIL present, 2 usage/invalid targets, 3 ERROR.

## Which Nuclei is run
Without `--nuclei`, candidates are looked up only in: the folder of the jar, the per-user cache, and absolute `PATH`
entries. The current folder and relative `PATH` entries are never searched. A candidate runs only if its SHA-256 equals
`NucleiInstaller.BINARY_SHA256` for this platform (the official build), or it is in the cache and matches the hash
recorded when the scanner installed it (used for `--nuclei-version latest`; this detects later modification but, being
recorded locally, is not a signature). Others are skipped with a notice. `--nuclei <path>` runs exactly that file.
`PlantedBinaryTest` runs the real scanner with planted and tampered binaries to prove this.

## Updating the tested Nuclei version
`NucleiInstaller.VERSION` is the version the scanner is tested with, installs by default, and bundles in the release packages.
1. Read the official `nuclei_<ver>_checksums.txt` from the release page.
2. Update `VERSION`, the `SHA256` table (archives) and the `BINARY_SHA256` table (SHA-256 of the extracted `nuclei` / `nuclei.exe`
   of each archive). The release workflow and `scripts/build-bundle.sh` read them from there.
3. Run `scripts/platform-test.sh` (CI does this on every platform); it checks the templates against both the tested and the latest Nuclei.
