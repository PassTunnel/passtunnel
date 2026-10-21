# Changelog

All notable changes to PassTunnel. Versions follow Semantic Versioning.
`scripts/release.sh` uses the section of the version it releases as the release notes (GitHub
release and the update window), so write it for users.

## [1.0.0] - Unreleased

The first public release.

### One-time codes

- **One-time codes filled in for you.** TOTP secrets are kept in the macOS Keychain; PassTunnel
  sends the current code with your password when you connect, and waits for a fresh code when the
  current one is about to expire.
- **Code format templates:** append, prepend, `password:code`, `password,code` or any custom
  template, or send the code separately (OpenVPN static challenge, FortiGate OTP field).
- **Authenticator-style main window** with live codes, a countdown ring and copy on click.
- **QR import** from a screenshot, an image file or the clipboard; Base32 secrets and
  `otpauth://` links work too.
- **Optional auto-type** of the current code with a global shortcut.

### VPN client

- **OpenVPN and FortiGate SSL VPN**, using signed copies of `openvpn` and `openfortivpn` bundled in
  the app.
- **Privileged helper** registered through macOS's own `SMAppService` and approved once: no admin
  password at every connect and no sudoers rule. It only runs the tools inside the app, with
  sanitized configurations.
- **Menu bar** badges per pinned or active profile, with five color palettes and alerts for
  unexpected drops.
- **Stays connected:** auto-reconnect with backoff, health checks, reconnect after wake and a
  reminder before a session limit runs out.
- **Several VPNs at once**, and a check that refuses to start a full tunnel over another VPN.
- **Shareable `.passtunnel` profiles** without passwords, secrets or user names.

### More

- **Optional Touch ID protection** for your codes and secrets.
- **Command-line tool** `passtunnel` with the same features as the app, `--json` output and shell
  completions.
- **Automatic updates** (signed with EdDSA, checked before installing); the helper updates itself
  after an app update as soon as no VPN connection is active.
- **English and Turkish** user interface.
