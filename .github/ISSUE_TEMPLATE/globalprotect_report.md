---
name: GlobalProtect report
about: Tell us how Palo Alto GlobalProtect (experimental) works, or does not work, with your gateway
title: "GlobalProtect: "
labels: globalprotect
---

<!-- Palo Alto GlobalProtect support is experimental: it has only been tested against openconnect's own test server, so a report from a real gateway helps a lot, whether it worked or not. Security problem? Please do not file it here. See SECURITY.md for private reporting. -->

**Did it work?**
Yes / No / Partly (for example, connected but some networks were not reachable). What happened:

**Environment**
- PassTunnel version (at the bottom of Settings → General):
- macOS version, or Linux distribution and `openconnect --version` (GlobalProtect needs 9.11 or later on Linux):
- Installed from: release / Homebrew / built from source

**Portal and gateways**
- Does the portal address also work as the gateway (one host), or does the portal name other gateways? How many?
- Profile settings: Gateway (empty, or set), Skip portal (on / off), TLS only (on / off)

**Sign-in**
- Where is the one-time code asked: portal / gateway / both
- Does the portal use an override cookie (sign-in to gateways without password or code)? Unknown is fine.
- One-time code: generated (TOTP) / ask each time / none; delivery: with the password / separately

**Tunnel**
- ESP (UDP) or TLS only: which one was used, if the log shows it
- Did the gateway ask for a host information report (HIP)? PassTunnel never sends one and shows a notice. Did access seem limited?

**Log**
Relevant lines from **Show Log** or `passtunnel log <id>`. PassTunnel already masks cookies and codes.
Replace host names, user names, IP addresses and anything else you would not post publicly (use names like `vpn.example.com` and `alice`).
Never paste passwords, TOTP secrets, `otpauth://` links or private keys.

```
```
