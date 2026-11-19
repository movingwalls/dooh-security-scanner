# DOOH Security Scanner

A free, open-source **perimeter check for digital out-of-home (DOOH) screens**. Give it a list of IP
addresses; it checks them for exposed management interfaces and risky services (open ADB, Telnet, VNC, RDP,
NovaStar / Colorlight / Huidu / XiXun panels, ...) and reports **PASS**, **REVIEW** or **FAIL** for each one,
with the evidence and a recommended fix. It is built on [Nuclei](https://github.com/projectdiscovery/nuclei)
and runs entirely on your own machine: no scan data is sent anywhere.

> **Release candidate (1.0.0-rc2).** Static checks and unit tests pass; the vendor checks are being verified
> against real devices (see [docs/TESTING.md](docs/TESTING.md)). Treat PASS as "none of these checks matched",
> not as proof that a screen is secure.

## Authorised use only

Only scan IP addresses and devices that **you own or are explicitly authorised, in writing, to test**.
Unauthorised scanning may be illegal. The scanner asks you to confirm this before every run. See
[docs/LEGAL.md](docs/LEGAL.md). Moving Walls is not affiliated with any of the device vendors named here.

## Quick start

Pick the download for your computer from the **Releases** page. Each one includes everything: the scanner,
its own Java runtime (nothing to install), Nuclei (the tested version) and the templates.

| Your computer | Download |
|---|---|
| Windows 10/11, Intel/AMD (also runs on Windows-on-ARM through its built-in emulation) | `dooh-security-scanner-<version>-windows-x64.zip` |
| Linux, Intel/AMD (x86-64) | `dooh-security-scanner-<version>-linux-x64.tar.gz` |
| Linux, ARM (64-bit: Raspberry Pi 4/5, AWS Graviton, ...) | `dooh-security-scanner-<version>-linux-arm64.tar.gz` |
| Mac, Intel | `dooh-security-scanner-<version>-macos-x64.tar.gz` |
| Mac, Apple Silicon (M1 and later) | `dooh-security-scanner-<version>-macos-arm64.tar.gz` |

Not sure which one? On Linux/macOS run `uname -m`: `x86_64` means x64, `arm64` or `aarch64` means arm64.

**Windows**

1. Extract the zip. If your antivirus blocks `nuclei.exe` (security tools are often flagged), add it to the
   antivirus exception/allowlist.
2. Copy `targets.example.txt` to `targets.txt` and list your addresses, one per line.
3. Open Command Prompt or PowerShell in the extracted folder and run `dooh-security-scanner.exe -t targets.txt`.

Prefer double-clicking? Use `dooh-security-scanner-easy.bat` (scans `targets.txt`; creates it from the example
on first run) or `dooh-security-scanner-discover-easy.bat` (finds devices on your own network first).

**Linux and macOS**

```
tar -xzf dooh-security-scanner-<version>-<platform>.tar.gz
cd dooh-security-scanner-<version>
cp targets.example.txt targets.txt        # then edit it
./dooh-security-scanner -t targets.txt
```

On **macOS**, a downloaded app is quarantined by Gatekeeper because these builds are not signed with an Apple
developer certificate. Clear that once after extracting, then run as above:

```
xattr -dr com.apple.quarantine dooh-security-scanner-<version>
```

Verify every download first with the `.sha256` file next to it (`certutil -hashfile <file> SHA256` on Windows,
`shasum -a 256 -c <file>.sha256` on Linux/macOS).

## Any other system: the single jar

The scanner is plain Java, so it runs anywhere Java 17+ does (any OS, any CPU), for example 32-bit ARM or
Windows-on-ARM with an ARM Java.
Download `dooh-security-scanner-<version>.zip` (or just `dooh-security-scanner-<version>.jar` from the same
Releases page), install **Java 17+**, then:

```
java -jar dooh-security-scanner.jar -t targets.txt     # use the downloaded jar's file name
```

You do **not** need to install Nuclei or copy the templates yourself:

- **Nuclei is downloaded automatically** the first time it is needed, after you approve it. The scanner picks the
  build for your OS and CPU and fetches the **latest** release from ProjectDiscovery's official GitHub page. It checks
  the download against the SHA-256 checksum published with that release (the download is discarded if it does not
  match) and stores it in `~/.dooh-security-scanner/` (on Windows: `C:\Users\<you>\.dooh-security-scanner\`).
  If GitHub's "latest" cannot be looked up, it falls back to the tested version (`v3.4.10`, whose checksums are
  built into the scanner). Use `--yes` to approve in scripts, `--offline` to forbid downloads,
  `--install-nuclei` to fetch (or update to) the latest now, or `--nuclei-version 3.4.10` for an exact version.
  If you prefer, put your own Nuclei next to the jar, on `PATH`, or pass `--nuclei <path>`.
- **The templates are packaged inside the jar** and extracted automatically. A `templates/` folder next to the
  jar (or `--templates <dir>`) takes precedence, which is handy for testing your own templates.

## Using it

```
java -jar dooh-security-scanner.jar -t targets.txt                    targets from a file
java -jar dooh-security-scanner.jar -h 203.0.113.10,203.0.113.0/28    targets on the command line
java -jar dooh-security-scanner.jar --discover                        find devices on your own LAN first
```

Targets are IPv4 addresses, CIDR blocks from /22 to /32, or host names, one per line (`#` for comments).
Anything else is rejected before anything runs.

| Option | Meaning |
|---|---|
| `-t, --targets <file>` | targets file |
| `-h, --hosts <list>` | comma-separated targets |
| `--discover` | find devices on the local network (shows the network, asks to confirm) |
| `--intrusive` | also try vendor default passwords. **Only with the owner's written consent** |
| `--templates <dir>`, `--nuclei <path>`, `--out <dir>` | locations |
| `--install-nuclei` | download and verify the latest Nuclei (updates a cached older one), then exit |
| `--nuclei-version <v>` | `latest` (default) or an exact version such as `3.4.10` for downloads |
| `--offline` | never download anything |
| `-y, --yes` | skip prompts (you confirm you are authorised, and approve the Nuclei download) |
| `--version`, `--help` | version and usage |

### Safety limits

Nuclei is started once for all targets with fixed, conservative settings (`-rate-limit 10 -c 5 -timeout 4`)
so low-power LED controllers and cellular links are not overloaded. Only this project's templates are loaded,
never Nuclei's general web-exploit library. Targets are validated and never passed through a shell.

## Reading the results

```
[PASS]   203.0.113.10  -  No exposed DOOH management interfaces found
[FAIL]   203.0.113.11  -  1 finding(s), highest: CRITICAL
           - CRITICAL: Android Debug Bridge (ADB) - Unauthenticated Connection Accepted
             Evidence: 203.0.113.11:5555
             Fix: Disable "ADB over network" ... and block inbound TCP 5555 ...
```

| Status | Meaning |
|---|---|
| **PASS** | none of this tool's checks matched |
| **REVIEW** | a panel or service answered (info/low severity); check whether it should be reachable |
| **FAIL** | a medium, high or critical finding, such as open ADB, Telnet or VNC |
| **ERROR** | a template failed to load or Nuclei failed. **A PASS is never shown for a run that did not complete** |

Each run saves `report.txt`, `report.html`, `report.json` and the raw `results.jsonl` in `scans/<timestamp>/`.
Exit codes: `0` no FAIL, `1` at least one FAIL, `2` bad usage or invalid targets, `3` ERROR.

A finding means the service answered **from where you scanned**. Scanned from inside your own network, it does
not by itself prove the port is reachable from the internet: check your router's port-forwards, or scan from
outside. **What to do about each finding: [docs/FIXING-FINDINGS.md](docs/FIXING-FINDINGS.md).**
Findings map to the [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/) via the `owasp-iot`
field in each template.

## What it checks

| Folder | Checks |
|---|---|
| `templates/android/` | Android Debug Bridge (ADB) on TCP 5555: reachable, and accepting connections without authorisation |
| `templates/led-controllers/` | NovaStar Taurus / VNNOX / player service, Colorlight C-Series, Huidu HDPlayer, XiXun Y-Series: exposed web panels and control ports; NovaStar default login (intrusive only) |
| `templates/linux/` | SSH (22, 2222), Telnet (23) and VNC (5900) reachable |
| `templates/windows/` | RDP (3389) reachable |
| `templates/samsung/` | Samsung VXT interface reachable |

## What it does **not** cover

- It does not look for devices on the internet and never scans beyond the addresses you give it
  (`--discover` only looks at your own local network, after you confirm).
- It does not test firmware versions or known CVEs, CMS servers (Xibo, MagicINFO, SuperSign), LG webOS,
  BrightSign, SMB, WinRM, Docker, UPnP, SNMP, RTSP cameras or 4G/LTE router settings.
- It does not exploit anything. Default-password checks are **off** unless you pass `--intrusive`.
- It is not a security audit or certification.

## Build from source

```
mvn verify                       # compile, unit tests, template lint -> target/dooh-security-scanner.jar
scripts/false-positive-check.sh  # a plain web server must PASS (needs python3, root for port 80)
```

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Releases are made by pushing a `v*` tag
(`git tag v1.0.0 && git push origin v1.0.0`); GitHub Actions builds, tests, and publishes the portable zip, the jar and a
self-contained bundle for each of Windows x64, Linux x64/arm64 and macOS x64/arm64, with checksums. Tags containing a `-` (such as `v1.0.0-rc1`) are published as pre-releases.

## Contributing, security, licence

- [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [CHANGELOG.md](CHANGELOG.md)
- Found a vulnerability? [SECURITY.md](SECURITY.md) (private reporting)
- Licensed under the [Apache License 2.0](LICENSE). Third-party notices: [NOTICE](NOTICE),
  [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
