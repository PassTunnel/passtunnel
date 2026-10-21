# PassTunnel app & CLI specification

Companion to ARCHITECTURE.md (core, helper, storage). This document is the spec for the
`PassTunnel` executable target: SwiftUI app, menu bar, onboarding, CLI, and `ConnectionManager`.

Product promise: **you never type a one-time code again.** Every screen should make the live
code and "connect with it filled in" the obvious thing.

## Process model

One binary, two modes:
- **GUI**: launched as an app (no arguments, or `-psn_…`). SwiftUI `App` with a main `Window`,
  a `MenuBarExtra`, and a `Settings` scene. Dock icon shown while a window is open; when the last
  window closes the app keeps running in the menu bar (`NSApp.setActivationPolicy(.accessory)`),
  and opening the main window from the menu bar switches back to `.regular`.
- **CLI**: when invoked as `passtunnel` (argv[0] basename) or with a first argument that is a known
  command. The app installs the symlink `/usr/local/bin/passtunnel` (or `~/.local/bin` if not
  writable, with a hint to add it to PATH) from Settings → General → "Install command-line tool".
- Single instance for GUI (`NSRunningApplication` check → activate the existing one and exit).
- Resources: use `Bundle.main` (never `Bundle.module`, it crashes in a signed .app).

## ConnectionManager (Core, `Sources/PassTunnelCore/ConnectionManager.swift`)

`@MainActor final class ConnectionManager: ObservableObject`
- `@Published private(set) var states: [String: ConnectionState]` and `lastError: [String: String]`.
- Polls every 3 s while the app runs (and immediately after wake, after any action). OpenVPN state
  from `ManagementSocket` (unix socket in the profile dir); Forti from helper `status` + log parsing.
  Apply results with a monotonically increasing sequence number so stale polls never overwrite newer
  state.
- `connect(_ id:, given: [CredentialField: String]) async throws`:
  1. read profile; check `Secrets.has` for keychain password / TOTP secret → precise error if missing
  2. TOTP: if fewer than 8 s remain in the window, or this window's code was already sent (by the app
     or the CLI, `profiles/<id>/.last-otp`), wait for the next one ("Waiting for a fresh code…",
     at most one window, not counted against the timeout; `disconnect` ends the wait at once)
  3. `OTPComposer.compose` → helper `startOpenVPN` / `startForti`
  4. wait until connected (timeout 60 s OpenVPN, 120 s Forti); on auth failure read the log tail and throw
     `PTError.authFailed(details)`; on timeout stop the process.
- `disconnect(_ id:)` → helper `stop`; marks the profile *user-stopped* so it is not treated as a drop.
- Drop detection: only `connected → disconnected` with no action in flight and not user-stopped.
  Then: notification (if enabled) and, if `profile.autoReconnect && profile.unattended` and secrets
  exist, reconnect with backoff 5 s / 15 s / 45 s (generation counter; any manual action cancels).
- Health: every 30 s for connected profiles with `healthHost`; 2 consecutive failures → "connected
  but unreachable" (amber) + one notification per outage; if auto-reconnect, one forced reconnect per
  outage. Success clears the outage.
- Wake (`NSWorkspace.didWakeNotification`): poll after 4 s, health-check, reconnect eligible profiles
  that were connected before sleep.
- Session limit: notification `sessionNotifyMin` before `sessionLimitMin` elapses (once per session).

## Main window (authenticator-style)

Sidebar-less single list, one row per profile (drag to reorder → `order`):
```
[icon/badge]  Acme VPN                    482 913  ◔ 23 s   [ Connect ]
              OpenVPN · alice · connected 1 h 12 m · 10.8.0.6        ⋯
```
- The live code (if the profile has TOTP) is large, monospaced, grouped 3+3; a circular countdown
  ring; click copies it (toast "Copied"). Hidden behind "•••" when `Preferences.hideCodes`.
- Primary button: Connect / Disconnect / Cancel (while connecting). If the profile needs input
  (`needs`), Connect opens a compact sheet asking only those fields, with the TOTP pre-filled when
  available.
- Status line colors: green connected, amber connecting/degraded, secondary disconnected; red error
  with the reason (tooltip shows log tail, "Show log" link).
- Row menu (⋯): Edit…, Copy code, Copy password + code (uses the composition template), Share…
  (export `.passtunnel`), Show log, Pin to menu bar, Make default, Delete…
- Toolbar: "+" menu → New OpenVPN…, New FortiGate…, Import .ovpn…, Import shared profile…, Add
  code from QR…; search field when > 6 profiles.
- Empty state: big call to action "Add your first VPN" with the three import options.
- Drag & drop onto the window: `.ovpn`, `.conf`, `.passtunnel`, or an image containing a QR code.

## Profile editor (sheet)

Sections (only relevant rows visible — hide, don't disable):
1. **General**: name, type (read-only after creation), icon picker (SF Symbols grid ~24 curated),
   badge letter, menu-bar style (letter / icon / both) with live preview, pin.
2. **Connection**: OpenVPN → config file (choose / replace, shows remote host); Forti → host, port,
   trusted cert (with "Fetch fingerprint" that reads the server cert SHA-256 via a TLS handshake and
   asks to confirm), DNS / routes toggles. Session limit, health host with "Test", auto-reconnect
   (disabled with explanation when not unattended).
3. **Sign-in**: username (empty = ask), password: Keychain / ask / none (cert only; OpenVPN only).
4. **One-time code** (the hero section): mode none / TOTP / ask.
   - TOTP: "Scan QR…" (image file, clipboard image, or drag & drop; Vision `VNDetectBarcodesRequest`;
     `otpauth://` → secret + digits + period + algorithm), or paste secret / otpauth URI; live preview of
     the generated code so the user can compare with their phone; advanced: digits, period, algorithm.
   - Delivery: Combined / Separate. Combined → template picker: "Append (password + code)", "Prepend",
     "Password:code", "Password,code", "Custom…" (text field, validated with `OTPComposer.validate`,
     shows an example with fake values `secret` / `123456` → e.g. `secret123456`).
   Secrets are written to the Keychain only on Save; fields show "Saved in Keychain ✓".

Save of an existing profile writes only the fields changed in the sheet (`ProfileMerge`: diff against the
profile as it was when the sheet opened, applied with `ProfileStore.update`), so changes made meanwhile by
the CLI, reordering or a connect are kept.

## Auto-type (optional, off by default)

Preferences → "Type the code for me": a global hotkey (default ⌃⌥C) types the current code of the
default (or chosen) profile into the focused field using `CGEvent` keyboard events. Requires
Accessibility permission — request it only when the user enables the feature, with an explanation and a
button to open the right System Settings pane. Also a menu-bar action "Type code".

## Menu bar (`MenuBarExtra`, `.menu` style)

Title: lock symbol (optional) + one badge per *visible* profile (pinned, or connecting/connected, or
dropped-until-seen), colored by state with the selected palette. Menu: per profile — name + status,
Connect/Disconnect, Copy code; then Open PassTunnel (⌘O), Settings… (⌘,), Quit.

## Settings (`Settings` scene, tabs)

- **General**: launch at login (`SMAppService.mainApp`), show in Dock, install CLI, appearance,
  badge palette (pastel / vivid / soft / candy / earth — the menu bar colors for connected /
  connecting / disconnected), show lock symbol, hide codes.
- **Notifications**: unexpected drop, session-limit (minutes before), health.
- **Shortcuts**: enable global hotkeys (default off): ⌃⌥V connect/disconnect default profile,
  ⌃⌥C type/copy code.
- **Helper**: status (enabled / needs approval / not installed) with Install / Open Login Items / Remove;
  bundled tool versions; "Show licenses" (Resources/licenses).
- **Updates**: Sparkle (check automatically, check now). Feed URL on GitHub Releases (appcast.xml).
- **About**: version, GitHub link, license (MIT).

`Preferences` (Core) gets: `badgePalette` (string enum above), `appearance` (system/light/dark),
`showLock`, `hideCodes`, `showInDock`, `notifyOnDrop`, `notifyHealth`, `sessionNotifyMin`,
`hotkeys`, `autoType`, `defaultProfile`.

## Launch at login

`LoginItem` (Core) wraps `SMAppService.mainApp` (status: enabled / needs approval / disabled / unavailable).
Never registered without the user's choice: onboarding step 3 offers "Start PassTunnel at login" (default on)
and Settings → General has the toggle. A login launch (`keyAELaunchedAsLogInItem` or `--background`) starts in the
menu bar only; manual launches open the main window.

## Onboarding (first launch, 3 steps)

1. Welcome — what PassTunnel does (one sentence + illustration with a live fake code).
2. Install the helper — explain why (VPN tools need root; PassTunnel only runs its own signed copies),
   button → `HelperInstaller.register()`; if "requires approval", show the Login Items button and poll
   status until enabled.
3. Add your first VPN — the same three import options as the empty state.

## CLI (`passtunnel`)

Parity with the app; output in the user's language; `--json` where marked.
```
passtunnel                                   status of all profiles (= status)
passtunnel status [ID] [--json]
passtunnel connect|disconnect|toggle [ID]    ID default: default profile; asks on TTY for `needs`
passtunnel disconnect --all
passtunnel connect [ID] --force              even if another VPN already takes all traffic
passtunnel code [ID] [-c|--copy] [--json]    live code + seconds left
passtunnel list [--json] / show ID / set ID key=value…   (keys as in the editor)
passtunnel add NAME --type openvpn|forti / import FILE [--name N] / export ID [-o FILE] / rm ID
passtunnel secret ID password|totp           reads from TTY (no echo) or stdin; totp accepts base32 or otpauth://
passtunnel default ID / pin ID / unpin ID
passtunnel log ID [-f]
passtunnel helper status|install|uninstall
passtunnel completion zsh|bash|fish
```
Exit codes: 0 ok, 1 error, 2 usage, 3 not connected (status of a single profile).

`helper install|uninstall` are carried out by the app: SMAppService refuses registrations from a
process started in Terminal ("Operation not permitted"), so the CLI never calls it. It posts
`HelperHandoff.notification` to a running app, or opens its own app bundle with `--install-helper` /
`--uninstall-helper`; the app shows Settings → Helper, starts the registration (removal asks for
confirmation there), and the CLI waits for the new status and prints it. `helper status` stays local.

The app and the CLI share the files and the Keychain. The app never acts on a cached profile:
connect, copy code, copy password + code and auto-type re-read the stored profile and Keychain item
first, and single-field changes (pin, order, remembered user name) go through `ProfileStore.update`
(read-modify-write). It reloads on `ProfilesWatcher` (FSEvents on the support directory, debounced;
`vpn.log`, the management socket, markers and temp files are ignored), on `ProfileChangeSignal` (posted by the
CLI after commands that change profiles or secrets), when it becomes active, and every 5 s.

## Localization

English source strings; Turkish in `Sources/PassTunnel/Resources/Localizable.xcstrings`
(build-app.sh compiles it into the bundle). All user-facing strings (app, CLI, core errors, helper
client errors) must have Turkish translations.

- Lookups use `Bundle.main` (Core included), so the language is the user's `Locale.preferredLanguages`
  (or the per-app language in System Settings). The CLI follows the same rule; started through the
  `passtunnel` symlink it re-executes the binary inside the app so `Bundle.main` is the app bundle.
  `-AppleLanguages '(tr)'` works for both and is ignored by the CLI parser.
- SwiftPM does not sync the catalog: add new keys by hand. `LocalizationTests` fails when a localized
  literal in the sources is missing from the catalog, lacks a Turkish value, or changes placeholders.
- `PASSTUNNEL_RENDER_LANG=tr` renders the `PASSTUNNEL_RENDER` screenshots in Turkish.

## Content rules

No company or customer names and no real hostnames — examples use Acme, vpn.example.com, alice.
