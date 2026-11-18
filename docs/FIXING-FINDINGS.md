# What to do when a check fails

A finding means the service answered **from where you scanned**. First work out whether you scanned from
inside your own network or from the internet:

- Scanned from **outside** your network (e.g. a phone hotspot or cloud server) and it answered: the device
  is exposed to the internet. Fix it now.
- Scanned from **inside** your network: the device is reachable on your LAN. That is only an internet
  exposure if your router forwards the port. Check your router's port-forwarding / UPnP / DMZ settings, and
  re-scan from outside to confirm.

## General hardening for any DOOH site
1. **No inbound ports.** Screens should poll your CMS outbound over HTTPS. Remove every port-forward to a
   player or controller.
2. **Change every default password** on players, LED controllers, routers and CMS accounts.
3. **Turn off services you do not use**: ADB over network, Telnet, VNC, RDP, web consoles.
4. **Management only over VPN** or from a fixed, allow-listed address.
5. **Update firmware** on 4G/LTE routers, controllers and players.
6. **Separate** the screen network from office/guest networks.

## By finding

| Finding | Why it matters | Fix |
|---|---|---|
| ADB reachable / unauthenticated (TCP 5555) | Anyone can run commands and install apps on the player | Disable "ADB over network"; block TCP 5555 |
| Telnet (23) | Clear-text login, favourite target of IoT botnets | Disable Telnet, use SSH; block TCP 23 |
| VNC (5900) | Often no/weak password: full screen control | Block 5900; set a strong password; use a VPN |
| RDP (3389) | Common route into Windows players | Block 3389; use VPN + NLA + strong passwords |
| SSH (22/2222) | Fine when restricted; risky with default passwords | Restrict to VPN/management IPs; keys, not passwords |
| NovaStar / Colorlight / Huidu / XiXun panels or ports | Management interface of the LED controller is reachable | Do not forward their ports; reach them only on the LAN/VPN; change default passwords |
| NovaStar default login (`--intrusive` only) | The device accepted a vendor default password | Change the password immediately; keep the panel off the internet |
| Samsung VXT interface | Management interface reachable | Restrict to the management network; update firmware |

Each finding in the report also prints a specific **Fix** line from the template that matched.

## After fixing
Re-run the scanner. For internet exposure, run it from outside your network.
