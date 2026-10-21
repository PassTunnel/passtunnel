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
  0. "Confirm with Touch ID" (`Profile.requireAuth`, see below): when a secret the connect uses is stored
     encrypted and not unlocked, `vault.unlock` asks (Touch ID / Mac password) before anything starts;
     a cancel throws `PTError.userConfirmationCancelled` (no helper call, no `lastError`), a failure is
     recorded in `lastError` like any connect failure. Not asked when the profile is already
     connecting or connected.
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
  Automatic and health-forced reconnects never prompt (`interactive: false`): they use the decrypted
  secrets the manager keeps for a session it connected (dropped, overwritten, on user disconnect, final
  reconnect failure or when the profile is forgotten) or the reuse window; otherwise they fail with
  `PTError.confirmationRequired` (not retried; "Could not reconnect" with a Connect action), e.g. for a
  session the CLI started.
- Health: every 30 s for connected profiles with `healthHost`; 2 consecutive failures → "connected
  but unreachable" (amber) + one notification per outage; if auto-reconnect, one forced reconnect per
  outage. Success clears the outage.
- Wake (`NSWorkspace.didWakeNotification`): poll after 4 s, health-check, reconnect eligible profiles
  that were connected before sleep. Sleep ends the reuse window (`vault.reset()`). A profile whose
  connect needs a confirmation (`vault.requiresConfirmation`) is not reconnected and nobody is prompted
  out of the blue: the event `droppedWhileAsleep` becomes the notification "“Acme VPN” disconnected
  while the Mac was asleep." / "Click to reconnect." (shown even with drop notifications off, as it
  replaces the automatic reconnect); clicking it or its Connect action runs `AppModel.connect`, which asks.
- Disconnect never asks.
- Session limit: notification `sessionNotifyMin` before `sessionLimitMin` elapses (once per session).

## Main window (authenticator-style)

Sidebar-less single list, one row per profile (drag to reorder → `order`):
```
[icon/badge]  Acme VPN                    482 913  ◔ 23 s   [ Connect ]
              OpenVPN · alice · connected 1 h 12 m · 10.8.0.6        ⋯
```
- The live code (if the profile has TOTP) is large, monospaced, grouped 3+3; a circular countdown
  ring; click copies it (toast "Copied"). Hidden behind "•••" when `Preferences.hideCodes`.
  When the TOTP secret is stored encrypted ("Confirm with Touch ID": `always`, or `connect` without a saved
  password) and not unlocked, the code is "••• •••" with a lock instead of the ring; click asks
  (`AppModel.revealCode`) and the code shows for the reuse window. Copy code, Copy password + code,
  ⌘C, the menu bar's Copy Code and auto-type ask first in the same way (`whenUnlocked`); a cancel does
  nothing, a failure shows an alert.
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
   **Confirm with Touch ID** (`requireAuth`, picker `editor.requireAuth`: Off / Before connecting /
   Before connecting and showing codes; named "Confirm with your password" on a Mac without Touch ID,
   `ConfirmationWording`, where `LAContext.biometryType == .none`), shown only when the profile uses a stored secret
   (`usesStoredSecrets`), disabled with a hint on a Mac without a Secure Enclave. The hint says what is
   encrypted. Save of an existing profile first runs `vault.applyProtection(from: original, to: edited)`:
   turning it on encrypts without a prompt; lowering it asks (a cancel keeps the sheet open, nothing
   saved). New and changed secrets are written with `vault.store` (encrypted when protected). An
   encrypted saved TOTP secret shows "••• •••" with **Show** (`editor.revealCode`) instead of the live code.
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
default (or chosen) profile into the focused field using `CGEvent` keyboard events. An encrypted TOTP
secret asks first; typing starts 0.4 s after the prompt closes so the focus is back in the field. Requires
Accessibility permission — request it only when the user enables the feature, with an explanation and a
button to open the right System Settings pane. Also a menu-bar action "Type code".

## Menu bar (`MenuBarExtra`, `.menu` style)

Title: lock symbol (optional) + one badge per *visible* profile (pinned, or connecting/connected, or
dropped-until-seen), colored by state with the selected palette. Menu: per profile — name + status,
Connect/Disconnect, Copy code; then Open PassTunnel (⌘O), Settings… (⌘,), Quit.

## Settings (`Settings` scene, tabs)

- **General**: launch at login (`SMAppService.mainApp`), show in Dock, install CLI, appearance,
  badge palette (pastel / vivid / soft / candy / earth — the menu bar colors for connected /
  connecting / disconnected), show lock symbol, hide codes; **Security**: "Ask again after" 1 / 5 / 15
  minutes (`authReuseMinutes`, `settings.authReuse`): how long one confirmation unlocks a profile.
- **Notifications**: unexpected drop, session-limit (minutes before), health.
- **Shortcuts**: enable global hotkeys (default off): ⌃⌥V connect/disconnect default profile,
  ⌃⌥C type/copy code.
- **Helper**: status (enabled / needs approval / not installed / needs an update / updating) with Install /
  Update / Open Login Items / Remove;
  bundled tool versions; "Show licenses" (Resources/licenses).
- **Updates**: Sparkle 2 (`AppUpdater`, `SPUStandardUpdaterController`): "Check for updates
  automatically" (Sparkle's own setting, default on via `SUEnableAutomaticChecks`; Sparkle checks once
  a day), current version, last check date, **Check Now**; the app menu has "Check for Updates…".
  `SUAutomaticallyUpdate` is false: an update is installed when the user clicks Install. Feed:
  `https://github.com/<GITHUB_REPO>/releases/latest/download/appcast.xml` (`SUFeedURL`, stamped by
  build-app.sh from scripts/release.env), signed with EdDSA (`SUPublicEDKey`). The app is not
  sandboxed, so Sparkle's installer launcher XPC service is off (`SUEnableInstallerLauncherService`
  false). The updater starts in `PassTunnelApp.init` only, so the CLI and the screenshot renderer
  never start it; unbundled runs show the tab disabled. A scheduled update in the menu-bar-only state
  switches to a regular app (Dock icon) without taking focus. Releases: docs/RELEASING.md.
- **About**: version, GitHub link, license (MIT).

`Preferences` (Core) gets: `badgePalette` (string enum above), `appearance` (system/light/dark),
`showLock`, `hideCodes`, `showInDock`, `notifyOnDrop`, `notifyHealth`, `sessionNotifyMin`,
`hotkeys`, `autoType`, `defaultProfile`, `authReuseMinutes`.

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
passtunnel debug drop ID                     test hook, not in help or completion (see below)
```
Exit codes: 0 ok, 1 error, 2 usage, 3 not connected (status of a single profile).

"Confirm with Touch ID" in the CLI (its own process, so its own reuse window: in practice it asks every
time): `connect` and `toggle` (when connecting) unlock after the other-VPN check and before asking for
credentials; `code` decrypts an encrypted TOTP secret; `set ID require_auth=off|connect|always`
(alias `auth`) runs `vault.applyProtection` before saving (turning it on encrypts without a prompt,
lowering it asks); `secret` writes encrypted when the profile protects that secret; `show` says
"saved in Keychain, encrypted (Touch ID)" (`--json`: `password_encrypted`, `totp_encrypted`). A
cancelled prompt prints "Cancelled." and exits 1; when no prompt can be shown (over SSH:
`notInteractive` / `systemCancel`), the Touch ID lockout or a Mac without a login password, it prints why
and exits 1. Nothing is ever done without the decrypt. `disconnect` never asks.

`debug drop ID` (test hook, `DebugDrop`) makes a connected OpenVPN profile drop as if the server ended
the session, so drop notifications and auto-reconnect can be tried for real: OpenVPN gets
`signal SIGTERM` over its management interface and exits, and the profile is *not* marked user-stopped.
OpenVPN serves one management client at a time and the app holds it, so the CLI posts
`DebugDrop.notification` (object: the profile ID; distributed notifications stay within the user's
login session) and the app sends the command over its own connection
(`ConnectionManager.simulateDrop` → `ManagementQuerying.send`); without a running app the CLI sends it
itself. The CLI then waits up to 15 s for the profile to leave "connected".

`connect` runs the other-VPN check (`ConnectionManager.checkCanStart`) before it prints
"Connecting …" or asks for credentials. On a terminal it prints each connecting phase once and only
forward (`ConnectionManager.PhaseProgress`: a session followed from another process is polled, so its
phases can arrive out of order); without one it prints only "Waiting for a fresh code (N s)…"
(`ConnectionManager.codeWaitUntil`).

`helper install|uninstall` are carried out by the app: SMAppService refuses registrations from a
process started in Terminal ("Operation not permitted"), so the CLI never calls it. It posts
`HelperHandoff.notification` to a running app, or opens its own app bundle with `--install-helper` /
`--uninstall-helper`; the app shows Settings → Helper, starts the registration (removal asks for
confirmation there), and the CLI waits for the new status and prints it. `helper status` stays local.
When the helper is enabled but outdated (another protocol or build), `helper install` hands off
`--update-helper` (`HelperHandoff.update`) instead: the app runs the same update as Settings → Helper →
Update Helper (active connections stop), and the CLI waits up to 60 s for the helper to report the
current protocol and build. An `install` hand-off that finds an outdated helper updates it too.

The app and the CLI share the files and the Keychain. The app never acts on a cached profile:
connect, copy code, copy password + code and auto-type re-read the stored profile and Keychain item
first, and single-field changes (pin, order, remembered user name) go through `ProfileStore.update`
(read-modify-write). It reloads on `ProfilesWatcher` (FSEvents on the support directory, debounced;
`vpn.log`, the management socket, markers and temp files are ignored), on `ProfileChangeSignal` (posted by the
CLI after commands that change profiles or secrets), when it becomes active, and every 5 s.

## Accessibility

Every control has a localized accessibility label (text buttons get it from their title; icon-only
controls, the live code and the row's primary button set `.accessibilityLabel` on the control itself —
a label set inside a button's label with `children: .ignore` can leave the button nameless). SwiftUI
exposes it as `AXDescription` (read by VoiceOver and `AXUIElementCopyAttributeValue`), never as
`AXTitle`, and does not list it in `AXAttributeNames`, so System Events shows `name` as missing value.
For UI automation, key controls carry stable, unlocalized `.accessibilityIdentifier`s (`AXIdentifier`):
`profile.<id>`, `profile.<id>.primary`, `profile.<id>.more`, `profile.<id>.code`, `main.add`,
`helper.install|update|loginItems|remove|licenses`, `onboarding.back|continue|done|installHelper|loginItems`,
`editor.cancel|save|requireAuth|revealCode`, `settings.authReuse`. While the screen is locked, accessibility clients see no windows at all (the
window server still lists them).

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
- `PASSTUNNEL_RENDER_LANG=tr` renders the `PASSTUNNEL_RENDER` screenshots in Turkish (from a bundle
  with the compiled `tr.lproj`, e.g. the app `build-app.sh` makes). Renders include `main-code-locked`
  (`AppModel.previewLockedCodes`; no Secure Enclave key is made) and `editor/editor-require-auth`.

## Content rules

No company or customer names and no real hostnames — examples use Acme, vpn.example.com, alice.
