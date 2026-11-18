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
| `NucleiInstaller` | pinned-version, checksum-verified download from the official GitHub release |
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

## Updating the pinned Nuclei version
1. Read the official `nuclei_<ver>_checksums.txt` from the release page.
2. Update `NucleiInstaller.VERSION` and the `SHA256` table, the `env:` values in `.github/workflows/*.yml`, and the README.
3. Run `nuclei -validate -t templates` and the false-positive check with the new version.

## Template conventions
See [CONTRIBUTING.md](../CONTRIBUTING.md). Every template has an `info.remediation`, a `metadata.owasp-iot`
mapping and a vendor-specific matcher; credential-sending templates carry the `intrusive` tag.

## Not included (by design)
- No generic "HTTP 200" detection template: it matches every web server.
- No network discovery engine beyond the optional local-LAN helper; owners supply their own targets.
- No cloud service or telemetry.
