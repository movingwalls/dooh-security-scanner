# Security policy

## Reporting a vulnerability

Please report problems in this tool, its templates or its documentation **privately**:

1. Preferred: use **GitHub's "Report a vulnerability"** button on this repository's *Security* tab
   (private vulnerability reporting).
2. Or email **security@movingwalls.com**.

Include the version, what you did and what you saw. Please do not open a public issue for a vulnerability.
We aim to acknowledge reports within 5 working days and to publish a fix and advisory once it is available.

Supported versions: the latest release.

## Known vulnerability in earlier release candidates (fixed in 1.0.0-rc3)
**1.0.0-rc1 and 1.0.0-rc2 must not be used.** Without `--nuclei`, they ran any `nuclei` / `nuclei.exe` found in the folder
the scanner was started from, and loaded a `templates/` folder there. A file planted in a folder the user ran the scanner
from (for example Downloads) could therefore be executed with the user's rights. 1.0.0-rc3 never searches the current folder,
runs only a Nuclei whose SHA-256 matches the official build (checked on every run) and re-verifies its templates against the
jar on every run. Upgrade to 1.0.0-rc3 or later.

## Responsible use

This tool is for checking **your own** screens and networks. Only scan IP addresses and devices that you
own or are explicitly authorised, in writing, to test. The `--intrusive` option attempts vendor default
passwords and must only be used with the device owner's consent. Unauthorised scanning may be illegal.
See [docs/LEGAL.md](docs/LEGAL.md).

## If the tool shows that someone else's screen is exposed

Tell the owner or operator responsibly. Do not log in to, change or take over devices you do not own.
