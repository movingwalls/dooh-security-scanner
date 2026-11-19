# Authorised use and disclaimer

## Authorised use
You may run this tool only against IP addresses, networks and devices that:
- you own, **or**
- you have explicit, written permission from the owner to test.

Scanning systems without permission may be a criminal offence in your country (for example under computer
misuse or cybercrime laws). The `--intrusive` option tries vendor default passwords; use it only with the
owner's written consent, because repeated failed logins can lock accounts or trigger alarms.

The scanner asks you to confirm authorisation before every run. In scripts, `--yes` means *you* confirm it.

## Safety limits
The scanner is deliberately gentle (rate limit 10, 5 concurrent checks, 4-second timeout, only this project's
templates). Even so, scanning can disturb fragile devices. Test during a maintenance window for critical screens.

## No warranty
This software is provided "as is" under the Apache License 2.0, without warranties of any kind. A **PASS** means
only that none of this tool's checks matched. It is not a security audit or certification, and does not cover
firmware vulnerabilities, CMS flaws or physical security. Moving Walls is not liable for damage or loss arising
from use or misuse of the tool.

## Not affiliated
Moving Walls is not affiliated with NovaStar, Colorlight, Huidu, XiXun, Samsung, Google or ProjectDiscovery.
Product names are trademarks of their owners and are used only to say what a check detects.

## Privacy
The scanner runs on your machine. Results stay on your machine in the `scans/` folder. The only network
traffic apart from the scan itself is the optional one-time download of Nuclei from GitHub, which you approve (the self-contained
bundles already include it; `--nuclei-version latest` also asks GitHub which release is the newest).
Moving Walls does not receive any scan data.
