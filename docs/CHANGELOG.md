# Changelog

All notable changes to PassTunnel. Versions follow Semantic Versioning.
`scripts/release.sh` uses the section of the version it releases as the release notes (GitHub
release and the update window), so write it for users.

## [1.0.1] - 2026-10-21

### Security

- **Confirmations are bound to the server.** With Confirm with Touch ID, the prompt names the server,
  and a confirmation only counts for the server settings the profile had at that moment. If they
  change, PassTunnel asks again, and an automatic reconnect does not happen: a notification asks you
  to connect and confirm yourself. The helper starts only the exact OpenVPN configuration the app
  checked. When an OpenVPN configuration lists several servers, the prompt names the first and how
  many others there are.
- **The VPN tools run only after their loaded code is checked.** The helper starts `openvpn` and
  `openfortivpn` suspended and lets them run only once the code the system actually loaded carries
  PassTunnel's signature and is the exact build this version was released with.
- **The VPN tools and their libraries run from a root-owned copy.** The helper copies `openvpn`,
  `openfortivpn` and their libraries (OpenSSL, LZO, LZ4, pkcs11-helper) out of the app, checks that
  every copy is the exact build this version was released with, and runs them from there, so
  changing or renaming the app bundle afterwards changes nothing that runs as root.
- **The bundled OpenSSL ignores Homebrew files on your Mac.** No configuration, providers or engines
  are loaded from Homebrew paths, and certificates are checked against the system's CA bundle
  (FortiGate too).
- **The helper is never replaced silently by another copy.** It updates itself only from the copy in
  `/Applications` and only to a newer helper. Replacing it on request from the command line asks you
  first, and installing an older helper over a newer one shows a warning.
- **Signed update feed.** The update feed itself must be signed, and updates are checked before they
  are unpacked.
- **Keychain items are replaced, never updated in place,** so a value is never written into an item
  another app created. A new profile no longer picks up items left behind under its ID, and a
  replaced Touch ID key record is refused.
- **Credentials stay out of configuration files.** A user name and password embedded in an imported
  `.ovpn` move to the profile and the Keychain. Shared profiles no longer contain embedded sign-in or
  proxy credentials, and importing a shared profile drops someone else's sign-in.
- **Copied codes are cleared after 30 seconds,** stay on this Mac (no Universal Clipboard) and are
  hidden from clipboard managers, in the app and with `passtunnel code -c`.
- **The OpenVPN configuration check** now rejects backslash escapes that OpenVPN itself refuses, and a
  backslash at the end of a line.
- **A Keychain write that fails keeps the previous value,** and an OpenVPN profile whose
  configuration cannot be read no longer connects without the configuration check.
- The `passtunnel debug drop` test command is no longer part of release builds.

### Changed

- `brew uninstall --zap --cask passtunnel` also deletes PassTunnel's Keychain items.
- `openvpn`, `openfortivpn` and their libraries are bundled only in pinned versions.
- A copy of PassTunnel outside `/Applications` (for example in `~/Applications`) no longer updates
  the helper automatically, and `passtunnel helper install` / `update` are refused by it. Move the
  app to `/Applications`, or install and update the helper in the app (Settings → Helper).
- Legacy PKCS#12 files encrypted with RC2 can no longer be loaded: OpenSSL's legacy module is never
  loaded. Re-export them with modern encryption (see the FAQ in the README).

## [1.0.0] - 2026-10-21

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

- **Confirm with Touch ID** per profile: off, before connecting, or before connecting and showing
  codes. Secrets are then encrypted with a Secure Enclave key that only Touch ID or your Mac
  password unlocks.
- **Command-line tool** `passtunnel` with the same features as the app, `--json` output and shell
  completions.
- **Automatic updates** (signed with EdDSA, checked before installing); the helper updates itself
  after an app update as soon as no VPN connection is active.
- **English and Turkish** user interface.
