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
- Opened files (`.passtunnel`, below) arrive as Apple events to the GUI only: CLI mode returns
  before `NSApplication` starts, and the app never treats its arguments as files to open.
- Resources: use `Bundle.main` (never `Bundle.module`, it crashes in a signed .app).

## ConnectionManager (Core, `Sources/PassTunnelCore/ConnectionManager.swift`)

`@MainActor final class ConnectionManager: ObservableObject`
- `@Published private(set) var states: [String: ConnectionState]` and `lastError: [String: String]`.
- Polls every 3 s while the app runs (and immediately after wake, after any action). OpenVPN state
  from `ManagementSocket` (unix socket in the helper's run directory); Forti from helper `status` + log parsing.
  Every poll (and `AppModel.reload`) also runs `revalidateDestinations` (see step 0 below).
  Apply results with a monotonically increasing sequence number so stale polls never overwrite newer
  state.
- `connect(_ id:, given: [CredentialField: String]) async throws`:
  0. "Confirm with Touch ID" (`Profile.requireAuth`, see below): when a secret the connect uses is stored
     encrypted and not unlocked, `vault.unlock` asks (Touch ID / Mac password) before anything starts;
     a cancel throws `PTError.userConfirmationCancelled` (no helper call, no `lastError`), a failure is
     recorded in `lastError` like any connect failure. Not asked when the profile is already
     connecting or connected. The prompt names the server (`UserPresenceAction.reason(name, host:)`:
     "connect to “Acme VPN” (vpn.example.com)"). Decrypted values are bound to the profile's
     `ProfileDestination` (fingerprint of `config.ovpn`, or Forti host, port and trusted cert) when the
     user confirms; values confirmed for another destination are dropped first
     (`vault.forgetUnlessBound`), so a changed server always asks again.
  1. read profile; check `Secrets.has` for keychain password / TOTP secret → precise error if missing
  2. TOTP: if this window's code was already sent (by the app or the CLI, `profiles/<id>/.last-otp`),
     always wait for the next one, whatever the setting below (a server rejects a reused code); with
     `Preferences.waitForFreshCode` (Settings → "Wait for a fresh code", default on), also when 5 s or
     less remain in the window (`Preferences.freshCodeSeconds`). "Waiting for a fresh code…", at most
     one window, not counted against the timeout; `disconnect` ends the wait at once. The setting is
     read from `config.json` at every connect: the app, the CLI and `passtunnel mcp` follow the same one
  3. `OTPComposer.compose` → helper `startOpenVPN` (with `configSHA256` of the `config.ovpn` read for the
     destination; a `config.ovpn` the app cannot read fails the connect with `missingConfig` before any
     secret is read; a helper reply `config_changed` → `DestinationChangedError`, not retried) / `startForti`
  4. wait until connected (timeout 60 s OpenVPN, 120 s Forti); on auth failure read the log tail and throw
     `PTError.authFailed(details)`; on timeout stop the process. When the tool exits or the time is up,
     the log decides (`VPNLog.verdict`): a name that did not resolve is `PTError.hostNotFound`, a server
     that never answered (refused, timed out, no route, no TLS answer; or nothing at all in time after the
     tool tried) `PTError.serverUnreachable` with the tool's reason, else `connectFailed` / `connectTimeout`.
  5. any failure is kept typed in `failures[id]` (`ConnectionFailure`: kind, the server's reply, the tool's
     reason, whether the sign-in reached the server — the TLS session came up — and whether a code went
     with it and with how many seconds left, tries); a cancelled attempt too, though it sets no
     `lastError`. When the sign-in never reached the server, the `.last-otp` record this attempt wrote is
     put back as it was (unless another process wrote one since; never after a cancel, whose tool may still
     be on its way), so the next connect does not wait for a fresh code. A rejected sign-in is never retried (decision D-7): neither by an automatic reconnect nor
     by a health-forced one.
  6. clock check (decision D-16): after a FortiGate rejected a sign-in this manager sent, it asks the
     gateway for its time in the background (`ServerClock.gateway`: one `HEAD /` over TLS to host:port,
     accepted when the certificate's SHA-256 is the profile's trusted certificate or the system trusts it
     (no network fetch for that), as openfortivpn decides; no credentials or cookies; the `Date` header
     against the middle of the exchange; 5 s at most). The result (`ClockOffset`) goes to
     `clockOffsets[id]`, to `profiles/<id>/clock.json` (0600; `lastClock` reads it for other processes)
     and to `failures[id].clock` if that failure is still the last one. `clockCheckFinished(id)` waits for
     it (`AutomationService.connect` does before reporting a failure). Never at launch, never for another
     failure, never for OpenVPN (no reliable server time); Linux does not ask the gateway. `checkClock()`
     (the app's Check button, `diagnose --check-clock`, on request only) asks the time server
     (`ServerClock.timeServer`: SNTP to `time.apple.com`; on Linux the configured NTP server), keeps it in
     `timeServerClock` and adds it to each rejected sign-in's failure that has no newer measurement.
     Off by 15 s or more (`ClockOffset.isWrong`) makes codes fail.
- A server that did not answer (`unreachable`: refused, timed out, no route, no TLS answer; nothing was
  sent, so the code's period was given back) is tried again, by the app only (`retriesUnreachable`; the CLI
  and the MCP server report the failure): after a connect (manual or at login) and after a drop's automatic
  reconnects (decision D-7), every 30 s, at most 10 tries in all (`UnreachableRetry`:
  `unreachableRetries[id]` with the tries, when the first and the last failed and `nextTryAt`; shared in
  `profiles/<id>/.retry` for `status --json` / `get_status`). Never after `host_not_found`, a rejected
  sign-in or any other failure. Each try connects with `interactive: false` and a fresh code: a protected
  profile uses the session's or the reuse window's secrets, else the tries stop with
  `confirmationRequired`. OpenVPN gives each try 10 s (`--server-poll-timeout 10`) and makes one try per
  run (`--remap-usr1 SIGTERM`). "Try now" is `retryNow(id)`; Stop is `disconnect(id)` (from the CLI too,
  seen on the next poll); a manual connect replaces them. The manager watches the network path while it
  runs (`networkStatus`, `NetworkPath`: online or not and Wi-Fi / Ethernet / cellular / other, for "This
  Mac is online · Wi-Fi"; never a probe): offline the tries wait, online again or on another network they
  start over after 2 s with the count at zero. After a drop the end is the reconnect's (`reconnected`,
  `reconnectFailed`); a manual connect's tries send no events. `failureDetails(id)` is "Copy details":
  plain text (profile name, server with port and UDP/TCP, what went wrong and the tool's reason, whether the
  sign-in was sent, the tries and their times, the next try, the network, the app version; no password,
  code or user name) that the app puts on the pasteboard as ordinary text.
- `disconnect(_ id:)` → helper `stop`; marks the profile *user-stopped* so it is not treated as a drop.
- Drop detection: only `connected → disconnected` with no action in flight and not user-stopped.
  Then: notification (if enabled, see Notifications) and, if `profile.autoReconnect && profile.unattended`
  and secrets exist, reconnect with backoff 5 s / 15 s / 45 s (generation counter; any manual action cancels).
  Automatic and health-forced reconnects never prompt (`interactive: false`): they use the decrypted
  secrets the manager keeps for a session it connected (dropped, overwritten, on user disconnect, final
  reconnect failure or when the profile is forgotten) or the reuse window; otherwise they fail with
  `PTError.confirmationRequired` (not retried; "Could not reconnect" with a Connect action), e.g. for a
  session the CLI started. When the destination of a protected profile changed after the user
  confirmed the session, its secrets are dropped and it is not reconnected (drop or forced health
  reconnect): the event `destinationChanged` becomes the notification "“Acme VPN” was not
  reconnected" / "Its server settings changed after you confirmed the connection. Click to connect
  and confirm again." (shown even with drop notifications off; Connect action like
  `droppedWhileAsleep`). A reconnect already running stops with `DestinationChangedError` the same way.
  On the health path the tunnel is not stopped (`destinationChanged(stillConnected: true)`): the
  notification is "“Acme VPN” server settings changed" / "It is still connected to the server you
  confirmed, which is not responding. Reconnect to confirm the new settings." (no Connect action, a
  click shows the profile; the badge is not marked as dropped).
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
- Activity log (`ActivityLog`, `profiles/<id>/activity.jsonl`): typed events, never sentences, so the app
  also shows what the CLI or `passtunnel mcp` did. A connect this manager starts records `connecting`
  (OpenVPN's first `remote` with its port and UDP/TCP; Forti host and port), `waiting_for_code` (`used` or
  `expiring`, the seconds to wait), `sending` once the helper has the credentials (user name, whether a
  password and a code went, the code's seconds left and template or `separate`), `auth_accepted`
  (OpenVPN `PUSH_REPLY` or a management state past AUTH, openfortivpn "Authenticated."; at the latest
  when connected), `connected` (address), or its failure: `rejected` (the server's `AUTH_FAILED…` reply),
  `unreachable` (tries, reason) or `failed` (the `ConnectionFailure` kind, reason, whether the sign-in was
  sent; nothing for a cancel, which `disconnect` records). A session it
  only follows records nothing (its owner does). Drops record `link_dropped` (whether it reconnects),
  automatic attempts `reconnecting` (attempt of total) and, after a failed one, `next_try`;
  `disconnect` records `disconnected_by_user` when the session was up (for a session this process has
  not seen, from the tool's log) and `stopped_by_user` for a connect, a code wait or pending reconnects
  it ended. The password is never recorded; a code at most as its first three digits (never more than
  half of it), which only the app may show (`ActivityEvent.sentence(showingCodeDigits:)`); the CLI and
  MCP leave them out (`withoutCodeDigits`). `activity(id)` reads the file, `lastSending(id)` gives "sent
  at 09:41:02" / "Sent with 22 s left", and the `activity` publisher sends each event this process records.
  The file keeps the last 500 events (mode 0600); writers take `.activity.lock` (flock) and replace the
  file atomically, readers skip lines they cannot decode. The file watcher ignores both.

## Main window (authenticator-style)

Sidebar-less single list, one row per profile (drag to reorder → `order`):
```
[icon/badge]  Acme VPN                    482 913  ◔ 23 s   [ Connect ]
              OpenVPN · alice · connected 1 h 12 m · 10.8.0.6        ⋯
```
- The live code (if the profile has TOTP) is large, monospaced, grouped 3+3; a circular countdown
  ring; click copies it (toast "Copied"). With "Hide codes until clicked" (`Preferences.hideCodes`, decision D-5)
  it is "••• •••" until clicked: a click shows that profile's code for 20 s without copying it
  (`AppModel.isCodeHidden`, on the `revealedCodes` of the redesigned window's code card), and a click while it shows
  copies it. Copying elsewhere (the ⋯ menu, ⌘C, the menu bar, shortcuts) and auto-type never show a code, and the
  menu bar keeps codes hidden.
  Every copied code and password + code goes through `Pasteboard.copySecret`: `.currentHostOnly` (no
  Universal Clipboard), marked `org.nspasteboard.ConcealedType` and `…TransientType`, and cleared after
  `Preferences.clearClipboardAfter` (Settings → "Clear copied code": 30 s, 1 minute (default) or
  2 minutes) unless the pasteboard's change count moved meanwhile.
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
- Importing an `.ovpn` (Import .ovpn…, a drop; `ImportActions.importOVPN(at:)`): `ProfileStore.analyzeOVPN`
  reads it without writing anything (`ImportDraft`), then `commit` creates the profile. Lines PassTunnel
  skips ([SECURITY.md](../SECURITY.md#importing-an-openvpn-configuration)) are listed in an alert ("Some
  lines of “work.ovpn” were skipped": each line, then why those kinds are safe to leave out) before the
  new profile's editor opens; a blocking line refuses the file with every such line listed, and nothing
  is created. The redesigned window reviews the file first instead (below).
- Opening a `.passtunnel` file (double-click in Finder, AirDrop, the Dock icon, `open`) imports it
  exactly like Import shared profile… (`ImportActions.importShared(at:)`: `ProfileStore.importShare`
  with all its checks, then the new profile's editor), with the main window brought forward. The
  app exports the type `com.furkanprlk.passtunnel.profile` (`ShareFile.typeIdentifier`, conforms
  to `public.json`, extension `passtunnel`) in `UTExportedTypeDeclarations` and claims it in
  `CFBundleDocumentTypes` as Viewer with `LSHandlerRank` Owner: PassTunnel imports the file and never
  edits it in place. `AppDelegate.application(_:open:)` hands the files to `ImportActions.open`
  (`OpenedFiles.route`, Core): one file at a time like the import panel, so several files import
  nothing and say so, and anything that is not a `.passtunnel` file is refused with a message (in the
  redesigned window an `.ovpn` or `.conf` goes to the import review instead; the app does not claim those
  types, so they arrive through Open With or `open -a`).
  Files that start the app wait until launch has finished. The save panel of Share… and the import
  panel use the exported type (the extension's dynamic type in an unbundled `swift run`).

### Redesigned window (behind a switch)

The redesign replaces this window screen by screen behind a hidden switch (`NewInterface`, read once at launch):
`defaults write com.furkanprlk.passtunnel PTNewInterface -bool YES`, then relaunch. Without it everything above
stays as it is. With it, the main window (`MainSplitView`) is a `NavigationSplitView`, about 1080×700 by default
and at least 820×560:
- **Sidebar** (236–320 pt, 272 ideal): the search field, always there; the section "Profiles" with one row per
  profile (`SidebarRow`): the name, the short status in the state's color with its dot (`ProfileStatusRow`) and the
  live code in 13 pt SF Mono on the right ("••• •••" while the detail masks it, below). No icons, no buttons in the
  rows. Drag to reorder (`order`), the context menu above, Return and double-click run the detail's main button. A
  bottom bar holds `+`, which opens the add view below (the File menu keeps the five add and import items), and a
  gear that opens Settings. Without profiles the section says "No profiles yet." / "Add one to get started."
- **Detail** (`ProfileDetailView`): the name (28 bold), where it connects (`vpn.example.com:1194 · OpenVPN · UDP`
  from the first `remote` of `config.ovpn`, `OVPNAnalyzer.endpoint`, with "+N more" when there are several;
  `gw.example.net:443 · FortiGate`), the main button on the right and the long status line below
  (`ProfileStatusLine`); then the code cards below. The main button is `DisplayStatus.action`: Connect
  (also after a drop), Cancel while connecting or waiting for a fresh code, Disconnect once connected, Stop during
  an automatic reconnect, Try again after a failure; Connect, Disconnect and Try again are primary capsules, Cancel
  and Stop secondary, all as wide as the widest label. The toolbar has Edit and ⋯ (Copy Code, Copy Password +
  Code, Share…, Show Log, Default Profile, Delete…). The window shows the default profile (else the first) when
  nothing is selected and the add view is closed.
- **Code cards** (`Views/CodeCards.swift`; their rules are `CodeCard` and `ServerReceives` in Core): two hairline cards
  in equal columns of the same height, stacked at full width when a column is too narrow for them (`CardColumns`).
  - **Current code** (`CurrentCodeCard`, profiles with a TOTP secret): the code in 44 pt SF Mono, the 26 pt
    countdown ring with the seconds beside it (in the text color; amber in the last 5 s and while a connect waits for
    a fresh code; red is kept for errors), "Next 771 204" under it (the next window's code,
    `CodeCard.nextWindow`), then the secondary capsules Copy code and, with the password in the Keychain, Copy
    password + code (`copyCode`, `copyPasswordAndCode`, with every safeguard above). A copy from them, the Profile
    menu or ⋯ turns the button's label into "Copied ✓" for 1.6 s, cleared early when the code changes
    (`AppModel.lastCopy`, `CodeCard.Copy`); the buttons keep the width of the wider label. A click on the code
    copies it. VoiceOver reads the code as one element ("Current code, 4 8 2, 9 1 3, 12 seconds left, next code 7 7
    1, 2 0 4") whose action is the click.
  - **What the server receives** (`ServerReceivesCard`, `ServerReceives`): one row per field in 13 pt SF Mono,
    built from the profile's real format (`OTPComposer.parts`) and user name with a placeholder password, never the
    real one: `user name  alice` ("asked when connecting" when it is asked), `password  ••••••••482913` (always eight
    bullets, never the password's length, then the code where the format puts it); sent separately, `password
    ••••••••` and a `code  482913` row. Footer: "Format: Append · preview with the current code", or "· will send
    the next code" with the next code in the rows while a connect waits for a fresh one; for a code asked each time
    "· asks for the code when connecting" and dimmed example digits, as without a secret ("· no secret added yet");
    "Password only, no one-time code"; a certificate-only OpenVPN profile shows only "Certificate only: …". The
    footer of a profile that is connected says when the sign-in was sent instead of "preview with the current code":
    "Format: Append · sent at 09:41:02" (the last `sending` of the activity log, taken only when it came shortly
    before the tunnel did, `ActivityEvent.sentAt(connectedSince:in:)`; the rows still show the current code). A
    connect that waits keeps "will send the next code". VoiceOver reads the card as one element.
  - **Activity** (`ActivityCard` in `Views/ActivityViews.swift`, under the code cards, full width): the last six events
    of the profile's activity log (`ActivityLog`, written by the app and the CLI), oldest first, each as the time
    (`HH:mm:ss`, `fg3`; an event of an earlier day says which, "Yesterday 17:09:07" or "Fri, Oct 23 17:09:07",
    `ActivityEvent.timeLabel`, with the sentences kept in line) and the sentence in 11.5 pt SF Mono (`ActivityEvent.sentence(showingCodeDigits: true)`:
    the password as eight bullets, a code as its first three digits and bullets, "Sending sam / ••••••••+604 •••").
    Errors are red (`ActivityEvent.tone`: link dropped, no answer, sign-in rejected, failed), waits for a code amber,
    the rest in the text color; the card is live while a session runs (`ActivityFeed`: the app's own events at once,
    the file's changes, such as a session the CLI runs, within a second). Without events it says "Not connected yet".
    VoiceOver reads each entry as one element, hidden values as "hidden". "Show all" opens the log window.
  - **Activity window** (`ActivityLogWindow`, the `Window` scene `activity-log`, not in the Window menu): the window
    of the profile in `AppModel.activityLogProfile`, titled with its name; its whole activity under day headings
    (Today, Yesterday, then the date), scrolled to the latest, with the text selectable. "Errors only" shows the red
    entries; "Show raw log" opens the VPN tool's `vpn.log` as ⋯ → Show Log does (disabled without one). The footnote
    says passwords are never shown and codes only by their first three digits.
  - **Masked codes** (decision D-5, `CodeCard.isMasked`, `AppModel.codesMasked`): codes hidden in Settings
    (`hideCodes`) and codes whose TOTP secret is stored encrypted ("Confirm with Touch ID"), unlocked or not, show as
    "••• •••" for the current and the next code, as bullets in "What the server receives" and in the sidebar row.
    A click on the code shows them for 20 s (`AppModel.revealCodes`), after the confirmation when they are locked;
    copying never shows them. The menu bar panel keeps hidden codes hidden; the current window shares the 20 s of a
    click for hidden codes (above) and keeps its own rule for locked ones.
- **Error states** (`Views/FailureCards.swift`, `ClockBanner.swift`, `OverlapSheet.swift`; the facts are Core's:
  `ConnectionManager.failures`, `unreachableRetries`, `networkStatus`, `clockOffsets`, `overlaps(for:)`). After a
  failure the detail shows a card instead of the code cards, above the activity; `DisplayStatus` words the status
  (`failed` with a reason: `signInRejected`, `hostNotFound`, `unreachable`, else the error's message), which the sidebar
  shows short ("Sign-in rejected", "Server not found", "Unreachable, retrying", "Couldn’t connect"):
  - **Sign-in rejected** (`RejectedCard`): the main button is Try again. "The server answered AUTH_FAILED. PassTunnel
    stopped instead of retrying, so your account won’t get locked." (the server's reply, in SF Mono), then facts, each
    with a glyph and words: "The code was fresh / Sent with 22 s left" (more than `Preferences.freshCodeSeconds` left;
    else "about to expire"), the clock when it was measured ("The clock is off by 48 s / Most likely cause. Fix the
    clock, then try again.", or "The clock is right / Within 2 s of time.apple.com"), and, for a password in the
    Keychain, "Changed your password at work? / Update it in PassTunnel" (opens the editor). "Check the clock" runs the
    on-request check with Apple's time server (`ConnectionManager.checkClock`, decision D-16; the card says what it
    asks and that nothing about the user is sent) and shows the result in the clock row.
  - **Clock banner** (`ClockBanner`), above the detail of any profile while the newest clock measurement of any
    profile or the time server is under an hour old and off by 15 s or more (`ClockOffset.recentWarning`): "This Mac’s
    clock is 48 s behind. Codes are worked out from the time, so every code will be wrong until it’s fixed." with
    Open Date & Time (`x-apple.systempreferences:com.apple.Date-Time-Settings.extension`) and Check again (the same
    check; a newer right measurement ends the banner).
  - **Server unreachable** (`UnreachableCard`): while the tries go on the status is "Can’t reach the server · next try
    in 18 s" (or "waiting for the network", "trying again…") and the main button Stop; once they ended, Try again.
    "No answer after 3 tries. Your password and code were not sent." with "This Mac is online · Wi-Fi" (or offline;
    only the system's own view of the network, never a claim that other sites answer, decision D-13), "203.0.113.10:443
    didn’t answer" with the tool's reason, "On a guest or hotel network?", Try now (`retryNow`, while tries go on) and
    Copy details (`ConnectionManager.failureDetails`, ordinary text on the pasteboard, "Copied ✓" for 1.6 s).
  - **Host not found and other failures** (`MessageCard`): the tool's reason, and that the password and code were not
    sent; a name that was not found also points to the profile's address.
  - **Overlapping tunnels** (`OverlapSheet`): connecting a profile whose routes or DNS names overlap with a connected
    one (`ConnectionManager.overlaps(for:)`, before any prompt for secrets; `AppModel.connect`) asks first: "Lab
    overlaps with Work", a table per connected profile (networks, DNS names and all traffic: Yes or —, Overlap), then
    Cancel, Connect both and Switch to Lab (primary; disconnects the others first). It says only that the shared
    traffic can go through just one of the two tunnels, not which one (decision D-22: not verified on a Mac). The
    CLI and the MCP server warn and go on.
- **First run and add view** (`FirstRunView`, decisions D-13 and D-18): without profiles the detail shows the app
  icon, "Add your first VPN" and "PassTunnel works out the one-time code and sends it with your password when you
  connect. No account. Your passwords and secrets stay on this Mac."; the sidebar's `+` shows the same view titled
  "Add a VPN", with no profile selected (selecting one, an import or Escape closes it). Then:
  - a dashed drop zone, "Drop a .passtunnel or .ovpn file here" with Choose File… (`ImportActions.importFile`: an
    `.ovpn`/`.conf` or `.passtunnel` file, imported as File → Import .ovpn… / Import Shared Profile… do); a drop on it
    is the window's drop, outlining the zone instead of the window;
  - one tile per other way in, as wide as each other (`AddOption`): "Scan a QR code on screen" / "Select the
    authenticator QR open in your browser." (macOS 14 and later, hidden on macOS 13; the editor's Scan QR on screen,
    `ScreenQRScanner`, then like a QR image, `ImportActions.newProfileFromScreen`), "Use a QR image" (an image file;
    its code is read as everywhere, then "What kind of VPN is this code for?" asks OpenVPN or FortiGate and a new
    profile's editor opens with the code filled in and the issuer as its name, `ImportActions.startProfile`) and
    "Enter details by hand" (the same question, then the editor). No footnote about Screen Recording: the picker
    needs no permission, and the fallback that does explains itself first;
  - while the helper is not installed, a card that says what it is for, with Install Helper
    (`HelperInstaller.registerRetrying`, as Settings → Helper; Login Items open when macOS asks for the approval),
    "Open Login Items…" while the approval is pending, and "The helper is installed and running." once it is, until
    the view goes. The card follows the status every 2 s.

  In this window a QR code that no profile can take (dropped, or File → Add Code from QR…) starts a new profile the
  same way instead of saying "Add a VPN first".
- **Open at login**: once there is a profile, the detail ends with "Open PassTunnel at login?" / "Starts quietly in
  the menu bar, without opening the window." and Not Now / Open at Login (the buttons go under the words when the
  window is narrow), until it is answered (`AppModel.answerOpenAtLogin`: the onboarding checkbox's choice, applied
  the same way, and onboarding is done, `PTOnboardingDone`). Not asked when PassTunnel already opens at login or
  does not run as an app.
- **Profile menu**: ⌘↩ runs the main button, ⌘C copies the code (in a text field ⌘C stays the field's), ⇧⌘C the
  password and code, ⌘E edits; off while a sheet is open.
- **Import review** (`ImportReviewView` + `ImportReviewModel`, Editor): every way an `.ovpn` comes in (a drop,
  Import .ovpn… in the File menu, the `+` menu, the first-run and add view, a file opened from Finder with Open
  With or `open -a`) reads it with `ProfileStore.analyzeOVPN` and shows the review in the detail instead of a profile
  (`AppModel.importReview`; the sidebar has no selection, and choosing a profile leaves the review like Cancel:
  nothing was written). A file with a blocking line never gets there: the alert lists every such line, as before.
  Title "Review work.ovpn" (22 bold), "From Downloads · OpenVPN · name it below". Left, "Found in the file": Server
  (the first `remote` in SF Mono, "+N more", transport), Certificates ("CA, client certificate, and key, inside the
  file" / "from files next to it"), Sign-in ("Certificate only", "User name and password", "…, plus a one-time
  code" with a `static-challenge` or a code secret added); a green check, or an amber warning when there is no
  server. Then, when lines are skipped, an amber "2 lines will be skipped" card with the lines in SF Mono (the
  reason as a tooltip and VoiceOver hint) and why that is safe. Right, "Needs you" with "1 of 4 missing" /
  "Nothing missing": Name (the file name), and when the file signs in with a password, User name and Password
  (filled from an inline `<auth-user-pass>`; "Saved in Keychain.") and Code secret: Paste (a secret, an otpauth
  link or a QR image, `CodeSecretInput`, shared with the editor) and Choose image…; a QR image dropped on the
  row or anywhere on the window fills it too. Its live code shows once added. The code secret is required (dashed
  amber field) with a `static-challenge`, optional otherwise. Footer: the first thing missing ("Add the code
  secret to finish."), Cancel (Escape) and Add Profile (Return; off at 38 % until nothing is missing), which runs
  `ProfileStore.commit` and selects the new profile. The two columns stack when the detail is narrow. Accessibility
  identifiers `import.name|username|password|pasteSecret|chooseImage|cancel|add`.
- No toast (the copy buttons say "Copied ✓", VoiceOver still announces "Code copied"), no window subtitle and no
  onboarding sheet. Sheets, alerts, the delete confirmation and drag & drop import are the same as above,
  except that an `.ovpn` goes to the import review.

## Profile editor (sheet)

About 660 × 700 pt, shared by every window that edits profiles (`ProfileEditorView`, built from the design
system below). Title "Edit “Work”" / "New OpenVPN Profile" / "New FortiGate Profile". Four hairline cards with the
labels right-aligned in a 150 pt column (they wrap, never truncate), then an **Advanced** disclosure; the cards
scroll above the footer, with a hairline between them when they do not fit. Footer: **Delete Profile…** (red, on
the left, saved profiles only, `editor.delete`: the row menu's confirmation, `profileDeleteConfirmation`, then
the sheet closes and `AppModel.delete` runs), Cancel, Save (Add Profile for a new profile).
1. **Sign-in**: name. OpenVPN → Configuration: the file name, under it the first server with its port and
   transport (`OVPNAnalyzer.endpointDescription`: "vpn.example.com:1194 · UDP", "vpn.example.com:1194 +1 more ·
   UDP"; from the `remote` line, else `port` / `rport` / `proto`, else 1194 and UDP), and Choose… / Replace… (an
   inline `<auth-user-pass>` block is removed from the file, `OVPNInliner.strippingCredentials`, and its user name
   and password fill empty fields, saved to the profile and the Keychain on Save). FortiGate (interim, decision
   D-19) → Gateway, Port, Trusted certificate (with "Fetch Fingerprint" that reads the server cert SHA-256 via a
   TLS handshake and asks to confirm), DNS and Routes checkboxes. User name (empty = ask; FortiGate: at most 64
   bytes, openfortivpn's limit, checked inline). Password: one secure field when it is kept in the Keychain (no
   confirm field; placeholder "Saved in Keychain" when one is saved, and empty keeps it), else the words for "Ask
   each time" or "None — certificate only".
2. **One-time code** (the hero card): with a secret, "Secret added · 6 digits · 30 s" (the issuer · account of a
   scanned link under it) and the live code with a small countdown ring, so the user can compare it with their
   phone; an encrypted saved secret shows "••• •••" with **Show** (`editor.revealCode`) instead. Without one, what
   the profile does instead (Generate without a secret yet, Ask each time, None). **Scan QR on screen** (below),
   **Choose image…** and **Paste secret** (from the clipboard: a secret in Base32 or hex or an `otpauth://` link as
   text, an image, or an image file), or an image dropped on the card; QR codes are read with Vision
   `VNDetectBarcodesRequest`, and an `otpauth://` link also sets digits, period and algorithm (HOTP and
   `otpauth-migration://` links are refused). Adding a secret selects Generate. The three buttons wrap onto two
   rows when they do not fit. Certificate-only profiles say they use no code.

   **Scan QR on screen** (`editor.scanScreen`, macOS 14 and later; hidden on macOS 13, decision D-20;
   `ScreenQRScanner`): the system's content picker (`SCContentSharingPicker`, a single window or a single display,
   PassTunnel's own windows left out) asks which window shows the QR code, for example the browser page of the
   authenticator setup ("Choose the window or screen that shows the QR code." under the buttons meanwhile). What
   the user picks is captured once with `SCScreenshotManager` at full resolution, which needs no Screen Recording
   permission, and read like an image (`QRDecoder`); the picture stays in memory and is never written anywhere.
   Cancelling the picker changes nothing. Only when the picker does not start or macOS refuses to capture the pick
   does the sheet explain "Scan your screens instead?" (one picture of each display needs Screen Recording
   permission, which macOS asks for the first time; the pictures stay in memory); Scan Screens then asks macOS
   for the permission (`CGRequestScreenCaptureAccess`) and, once allowed, captures every display without
   PassTunnel's windows and takes the first `otpauth://` link found (`QRDecoder.otpAuth(inAny:)`). Without the
   permission it says where to allow it. Nothing found: "No QR code was found on the screen. Make sure the whole
   code is visible, then scan again."
3. **Code format** (when a code is used): one popup, Append, Prepend, password:code, password,code, Custom
   template (a monospaced field validated with `OTPComposer.validate`) and Sent separately (`otpDelivery`
   `.separate`: the OpenVPN static challenge or the FortiGate OTP field; the template is kept for switching back).
   **Server receives**: what the sign-in sends, from `OTPComposer.parts` and the profile's real user name: the
   password always as eight bullets (the editor never has it to show), the live code, or example digits dimmed when
   the code is asked or locked; a code sent separately goes on a second line. Hidden while a custom template is
   invalid.
4. **Switches**: "Require Touch ID before connecting" ("Require your Mac password before connecting" on a Mac
   without Touch ID, `ConfirmationWording.hasTouchID`, where `LAContext.biometryType == .none`; `editor.requireAuth`),
   shown only when the profile uses a stored secret (`usesStoredSecrets`), disabled with a footnote on a Mac
   without a Secure Enclave. On is `requireAuth` `always`, off is `off` (decision D-4). A profile at `connect`
   (still set with `passtunnel set ID require_auth=connect`) shows as on with a footnote: showing codes does not
   ask, or, without a saved password, that the TOTP secret is encrypted and showing the code asks too; switching it
   off and on makes it `always`. "Connect at login" (`connectAtLogin`, `editor.connectAtLogin`; see Launch at
   login), with a footnote while it is on and PassTunnel itself does not open at login ("Turn on “Open at login, in the menu
   bar” in Settings → General.", from `LoginItem.status`), else when connecting asks first (not `unattended`, or a
   protected secret): a notification at login offers the connection then. "Reconnect automatically if the link
   drops" (`autoReconnect`), disabled with the reason when the profile is not `unattended`.

**Advanced** (closed when the sheet opens; Save opens it when the first problem is there), in three cards:
Sign-in — type (read-only after creation), Password: Save in Keychain / Ask each time / None — certificate only
(OpenVPN only), One-time code: None / Generate / Ask each time, and for Generate the Secret field (a secret or an
`otpauth://` link, typed or pasted; its errors show under it), digits, period, algorithm. Connection — the
configuration file and its import date with Reveal in Finder (saved OpenVPN profiles), session limit, health
check host with "Test". Menu bar — icon picker (SF Symbols grid ~24 curated), badge letter, menu-bar style (letter
/ icon / both) with live preview, "Always show in the menu bar" (pin).

Errors show in red under their field; Save scrolls to the first one and focuses it. Save of an existing profile
first runs `vault.applyProtection(from: original, to: edited)`: turning the protection on encrypts without a
prompt; lowering it asks (a cancel keeps the sheet open, nothing saved). New and changed secrets are written with
`vault.store` (encrypted when protected), only on Save.

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

### Menu bar panel (new interface)

Behind the hidden switch of the redesign (`NewInterface`, `PTNewInterface`, decision D-23) the menu bar item is a
panel instead (`MenuBar/MenuBarPanel.swift`, `.menuBarExtraStyle(.window)`): two `MenuBarExtra` scenes, and
`isInserted` puts one of them in the menu bar. Without the switch the menu above is unchanged.
- Status item: the shield glyph (`MenuBarIcon.shield`, a monochrome 16 pt template image), without badges, palettes
  or lock symbol (their preferences stay). While a drop has not been seen (`droppedUnseen`) a small dot sits at its
  top right; it goes when the panel closes or the main window opens. VoiceOver: "PassTunnel, 2 connected" ("PassTunnel,
  not connected"), with ", a connection dropped" for the dot.
- Panel, 330 pt wide, on the system's window material: header "PassTunnel · 2 connected" (just "PassTunnel" while
  nothing is connected); one row per profile (at least 44 pt): 8 pt dot, name and the short `DisplayStatus` in its
  color, the code in SF Mono 13 ("••• •••" while locked or hidden; `hideCodes` is never revealed here) and a switch,
  on while the profile is connected, connecting or reconnecting (turning it off disconnects or cancels). More than
  four rows scroll. Then, for `AppModel.copyTarget` (`CopyTarget`, Core: the default profile when it has a code, else
  the one that sent a code last, `ConnectionManager.lastCodeSent` from `.last-otp`, else the first with a code):
  "Copy Work code ⌘C", "Copy Work password + code ⇧⌘C" (with a password in the Keychain) and, while auto-type is on,
  "Type Work code" (decision D-10; typed 0.3 s after the panel closed, into the field that had the focus). Last
  "Open PassTunnel", "Settings… ⌘," and "Quit ⌘Q". Without profiles: "No VPN profiles yet" and "Add a VPN…".
- A switch leaves the panel open; a profile that needs input opens the credential sheet in the main window, and
  Touch ID asks as it does from the window. Every other item closes the panel first, through the status item's
  button (SwiftUI's `toggleWindow:`) as a click on the shield does: closing the window itself would leave SwiftUI
  taking the panel for open.
- Keyboard (decision D-8): a window-style extra has none of a menu's, so a local event monitor handles the keys while
  the panel is the key window. ↑ and ↓ move between the rows and items (Tab too), Return or Space uses the focused
  one, Escape closes the panel, and ⌘C, ⇧⌘C, ⌘, and ⌘Q run their items whatever has the focus (a shortcut whose item
  is not offered beeps instead of reaching the main menu). Focus shows the system focus ring. VoiceOver: each row is a
  switch named "Connect Work" or "Disconnect Work", with the status and the code as its hint; the items are buttons.

## Notifications (`Notifier`)

`ConnectionManager` never posts notifications: it sends `ConnectionEvent`s, and `ConnectionNotice.forEvent`
(Core, unit-tested) picks the notification for each one, or none when a setting turns it off. `Notifier`
posts it; authorization is asked the first time one is needed. A click shows the profile in the main
window unless noted.
- `dropped` while an automatic reconnect follows: "Acme VPN dropped" / "Reconnecting with a fresh code…"
  ("Reconnecting…" for a profile without a TOTP secret), with a **Stop** action
  (`AppModel.stopReconnecting`): it ends the reconnect, an attempt under way included, like Cancel
  Connecting (a user disconnect); on an older notification whose reconnect is over it does nothing.
- `dropped` without a reconnect: "Acme VPN dropped" / "It will not reconnect automatically.", Connect action.
- `reconnected` (after a drop, after wake, or the forced reconnect of a health outage): "Connected to
  Acme VPN" (below).
- `reconnectFailed`: "Could not reconnect Acme VPN" / the reason, Connect action.
- These four follow **Notify when a connection drops** (`notifyOnDrop`). `unreachable` / `reachableAgain` ("Acme VPN
  is not responding" / "… is responding again") follow **Health check failures** (`notifyHealth`);
  `sessionEnding` ("Acme VPN session is ending" / "The session limit is reached in 10 minutes.") follows
  **Session limit** (`sessionNotifyMin` > 0). `droppedWhileAsleep` and `destinationChanged` (wording under
  ConnectionManager) are always shown, as they replace the automatic reconnect the user turned on.
- Connect at login (`ConnectionNotice.offeredAtLogin` and `notConnectedAtLogin`, wording under Launch at login)
  are always shown: the user turned the switch on.

"Connected to Acme VPN" / "10.8.0.6 · vpn.example.com" (`ConnectionNotice.connected`: the tunnel address,
then the server as the confirmation prompt names it, `ProfileDestination.host`, e.g. "vpn.example.com +1
more"; unknown parts are left out). Shown for connects PassTunnel makes on its own (the reconnects above and
connect at login) and, for a connect the user starts in the app (main window, menu bar, shortcut, notification),
only when the main window is not visible: closed, minimized, hidden, on another Space or covered by other windows
(`NSWindow.occlusionState`), since the window shows the result otherwise (`ConnectionNotice.announcesConnect`).
Connects started by the CLI or an MCP client get none. The same visibility rule gives "Could not connect
Acme VPN" / the error for a failed connect the user started (`AppModel.handleConnectError`).

Not about one connection: "The helper needs an update" (once, while sessions keep an outdated helper from
updating, `HelperAutoUpdate`) and "Allow PassTunnel to type codes" (auto-type without Accessibility permission).

## Settings (`Settings` scene, tabs)

Four tabs (decision D-12): General, Shortcuts, Helper and Updates. Settings are the same in both interfaces
(`NewInterface`).

- **General** (`Settings/GeneralSettings.swift`): one scrolling page of cards in the design system's style (an
  uppercase label over a hairline card of 44 pt rows, the monochrome switch at the trailing edge, a note under the
  card):
  - **General**: "Open at login, in the menu bar" (`SMAppService.mainApp`, see Launch at login; under it the
    Login Items approval with Open Login Items…, or why it is not available), "Show the Dock icon" (`showInDock`),
    "Hide codes until clicked" (`hideCodes`, see Main window), "Clear copied code" after 30 seconds / 1 minute /
    2 minutes (`clearClipboardAfter`, default 1 minute, `settings.clearClipboard`; only if the clipboard still holds
    what PassTunnel copied).
  - **Connection**: "Wait for a fresh code" / "If the current code has 5 s or less left" (`waitForFreshCode`,
    default on, `settings.waitForFreshCode`; a code already sent is never sent again, whatever the setting) and
    "Notify when a connection drops" (`notifyOnDrop`, the drop and the reconnect after it; see Notifications).
  - **Notifications**: "Health check failures" (`notifyHealth`), "Session limit" (`sessionNotifyMin`, with the
    minutes before), Open Notification Settings….
  - **Security**: "Ask again after" 1 / 5 / 15 minutes (`authReuseMinutes`, `settings.authReuse`): how long one
    confirmation unlocks a profile.
  - **Menu bar**, only while the current menu bar is in use (`!NewInterface.isEnabled`; the panel of the new
    interface has no badges, decision D-6): badge palette (pastel / vivid / soft / candy / earth — the menu bar
    colors for connected / connecting / disconnected) with a preview, show lock symbol.
  - **Other**: appearance (system / light / dark), the command-line tool (Install… / Reinstall, see CLI).
  - Footer (what the About tab had): Licenses (the bundled tools' licenses, the sheet of Helper → Show
    Licenses…), Privacy policy (the website's privacy page, `https://passtunnel.github.io/privacy/`, `AppInfo.privacyURL`),
    Source code (the GitHub repository), and the version.

  The window shows 600 pt of the page and scrolls; the `settings-general` render shows all of it.
- **Shortcuts**: enable global hotkeys (default off): ⌃⌥V connect/disconnect default profile,
  ⌃⌥C type/copy code.
- **Helper**: status (enabled / needs approval / not installed / needs an update / updating) with Install /
  Update / Open Login Items / Remove;
  bundled tool versions; "Show licenses" (Resources/licenses). "Needs an update" covers any helper
  that is not this copy's (`AppModel.helperRelation`, from `HelperClient.relation()`); for a newer
  helper the status line says it belongs to a newer version of PassTunnel. The Update Helper click is
  the confirmation, except that replacing a newer helper (relation asked fresh) first shows "Replace
  the helper with an older version?" (Install Older Helper, destructive). A request from
  `passtunnel helper install|uninstall` (`HelperSettings.runPendingAction`) opens this tab; when it
  shows a confirmation for it, it tells the waiting CLI (`asking`), and cancelling that confirmation
  (or leaving the tab, or a newer request replacing it) tells it `declined`; a copy outside `/Applications` shows "Open
  PassTunnel from the Applications folder to install or update the helper from the command line." and
  tells it `refused` (see CLI).
- **Updates**: Sparkle 2 (`AppUpdater`, `SPUStandardUpdaterController`): "Check for updates
  automatically" (Sparkle's own setting, default on via `SUEnableAutomaticChecks`; Sparkle checks once
  a day), current version, last check date, **Check Now**; the app menu has "Check for Updates…".
  `SUAutomaticallyUpdate` is false: an update is installed when the user clicks Install. Feed:
  `https://github.com/<GITHUB_REPO>/releases/latest/download/appcast.xml` (`SUFeedURL`, stamped by
  build-app.sh from scripts/release.env); the feed and the archives are signed with EdDSA
  (`SUPublicEDKey`), and `SURequireSignedFeed` + `SUVerifyUpdateBeforeExtraction` make Sparkle refuse
  an unsigned feed and check an archive before unpacking it. The app is not
  sandboxed, so Sparkle's installer launcher XPC service is off (`SUEnableInstallerLauncherService`
  false). The updater starts in `PassTunnelApp.init` only, so the CLI and the screenshot renderer
  never start it; unbundled runs show the tab disabled. A scheduled update in the menu-bar-only state
  switches to a regular app (Dock icon) without taking focus. Releases: docs/RELEASING.md.

`Preferences` (Core) gets: `badgePalette` (string enum above), `appearance` (system/light/dark),
`showLock`, `hideCodes`, `clearClipboardAfter` (seconds: 30, 60 or 120; others → 60),
`waitForFreshCode`, `showInDock`, `notifyOnDrop`, `notifyHealth`, `sessionNotifyMin`, `hotkeys`,
`autoType`, `defaultProfile`, `authReuseMinutes`.

## Launch at login

`LoginItem` (Core) wraps `SMAppService.mainApp` (status: enabled / needs approval / disabled / unavailable).
Never registered without the user's choice: onboarding step 3 offers "Start PassTunnel at login" (default on; the
redesigned window asks "Open PassTunnel at login?" after the first profile instead) and Settings → General has the
toggle. A login launch (`keyAELaunchedAsLogInItem` or `--background`) starts in the menu bar only; manual launches
open the main window.

**Connect at login** (per profile, `Profile.connectAtLogin`, default off; the editor's switch or `passtunnel set ID
connect_at_login=true`; left out of share files): only a login launch runs it (`AppModel.connectAtLogin` →
`LoginConnector`, Core), never a manual launch. It first waits, at most 90 s (`LoginConnector.readinessTimeout`),
until the helper is ready (enabled, answering with this copy's build, not being updated: an automatic helper
update after an app update runs first) and the Mac is online (`ConnectionManager.networkStatus`, from
`NWPathMonitor`; nothing is contacted). Then it goes through the profiles with the switch in the sidebar order (`order`, then name), each read
again from disk (one switched off or deleted meanwhile is skipped):
- connected or connecting already (a session the helper kept running, or another process's): left alone;
- `unattended` and no protected secret it uses (`vault.requiresConfirmation` false): connected with
  `ConnectionManager.connect(interactive: false)`, one after the other, then "Connected to Acme VPN" (an automatic
  connect, see Notifications). That connect never asks: a secret that turns out to need a confirmation gives
  `confirmationRequired`, and the profile is offered as below;
- anything that would ask (Touch ID or the Mac password, or a user name, password or code): never a prompt at
  login, the notification "“Acme VPN” is set to connect at login" / "Click to connect." instead (Connect action,
  and a click connects too, like `droppedWhileAsleep`; a profile that asks for something then opens the credential
  sheet in the main window);
- a failed connect, or nothing ready in time: "Could not connect “Acme VPN” at login" / the error, "The PassTunnel
  helper is not ready." or "This Mac is offline." (Connect action; a click shows the profile).

## Onboarding (first launch, 3 steps)

The redesigned window has none: its first-run view and the question about opening at login replace it.

1. Welcome — what PassTunnel does (one sentence + illustration with a live fake code).
2. Install the helper — explain why (VPN tools need root; PassTunnel only runs its own signed copies),
   button → `HelperInstaller.register()`; if "requires approval", show the Login Items button and poll
   status until enabled.
3. Add your first VPN — the same three import options as the empty state.

## CLI (`passtunnel`)

Parity with the app; output in the user's language. Every command with a result takes `--json`
([CLI-JSON.md](CLI-JSON.md) describes each object, the error object and the exit codes).
```
passtunnel                                   status of all profiles (= status)
passtunnel status [ID]
passtunnel connect|disconnect|toggle [ID]    ID default: default profile; asks on TTY for `needs`
passtunnel disconnect --all
passtunnel connect [ID] --force              even if another VPN already takes all traffic
                                             (a warning, on stderr, when a connected profile's tunnel claims
                                             the same routes or DNS names; the connect goes ahead)
passtunnel connect|disconnect … --wait [--timeout S]   bound the wait (default 60 s; --timeout implies --wait)
passtunnel code [ID] [-c|--copy]             live code + seconds left
passtunnel list / show ID / set ID key=value…   (keys as in the editor)
passtunnel add NAME --type openvpn|forti / import FILE [--name N] / export ID [-o FILE] / rm ID
passtunnel secret ID password|totp           reads from TTY (no echo) or stdin; totp accepts base32 or otpauth://
passtunnel secret-store [STORE]              Linux only: the secret store in use; STORE sets it (below)
passtunnel default ID / pin ID / unpin ID
passtunnel log ID [-f] [-n N] [--activity]   --activity: the activity log, worded (no code digits)
passtunnel diagnose [--check-clock]          installation, helper, each profile's problems and last clock
                                             measurement; --check-clock also asks the time server
passtunnel helper status|install|uninstall
passtunnel mcp [--allow-connect]             MCP server on stdio (below)
passtunnel completion zsh|bash|fish
passtunnel version
passtunnel debug drop ID                     debug builds only: test hook, not in help or completion (see below)
```
Options for every command, anywhere before `--` (`CLIOptions`, `CLIInvocation.parse`): `--no-input`
(or `PASSTUNNEL_NO_INPUT=1`) never reads stdin or asks on the terminal — `connect` of a profile with
`needs`, `secret`, and `rm` without `--yes` fail with `input_required` (`rm` without `--yes` also
when stdin is not a terminal); `--no-auth-prompt` makes the
CLI's `ConnectionManager` use `PromptlessAuthenticator`, so anything that would show Touch ID fails
with `auth_unavailable`.

Exit codes (`AutomationExit`, `AutomationErrorCode.exitCode`): 0 ok, 1 other error, 2 usage /
invalid argument, 3 not found or (`status ID`) not connected, 4 confirmation or input cancelled or
not possible, 5 helper missing, unapproved, outdated or not answering (also `helper status`), 6
connect failed (incl. server unreachable, host not found, other VPN, destination changed, credentials
rejected or missing), 7 timeout, 130 interrupted. With `--json`, a failure prints
`{"error":{"code","message"}}` on stdout (usage errors too, `CLICommand.requestsJSON`); a failed connect
adds `failure` (`ConnectFailedError`, thrown by `AutomationService.connect` around the error with
`ConnectionManager.failures[id]`). The human output adds the failure's facts after the message
(`ConnectionFailure.details`: "The server answered: AUTH_FAILED. The code was sent with 22 s left. Not
retried, to avoid a lockout.").

`--wait` / `--timeout` (`AutomationService.connect`): the connect already waited for the result;
`--timeout` bounds it, counted after the Touch ID confirmation. On a timeout the half-started
connection is stopped (like Ctrl-C) only if this process started it (`ConnectRole.started`), never
a session it follows that the app or another process started, and the command exits 7. `disconnect --wait` polls until the helper no longer runs the profile.

"Confirm with Touch ID" in the CLI (its own process, so its own reuse window: in practice it asks every
time): `connect` and `toggle` (when connecting) unlock after the other-VPN check and before asking for
credentials; `code` decrypts an encrypted TOTP secret; `set ID require_auth=off|connect|always`
(alias `auth`) runs `vault.applyProtection` before saving (turning it on encrypts without a prompt,
lowering it asks); `secret` writes encrypted when the profile protects that secret; `show` says
"saved in Keychain, encrypted (Touch ID)" (`--json`: `password_encrypted`, `totp_encrypted`). A
cancelled prompt prints "Cancelled." and exits 4 (`auth_cancelled`); when no prompt can be shown (over
SSH: `notInteractive` / `systemCancel`), the Touch ID lockout, a Mac without a login password or
`--no-auth-prompt`, it prints why and exits 4 (`auth_unavailable`). Nothing is ever done without the decrypt. `disconnect` never asks.

`code -c` copies like the app (`Pasteboard.copySecret`) and leaves a detached copy of the binary behind
(`posix_spawn` with `POSIX_SPAWN_SETSID`, stdio to `/dev/null`, internal first argument
`__clear-clipboard <seconds> <changeCount>`, never parsed as a command; both plain digits and the
seconds one of 30, 60 or 120, else it exits with a usage error and does nothing) that clears the
pasteboard after `clearClipboardAfter` from `config.json` (the app's setting, default 1 minute)
unless something else was copied; the command itself returns at once. `import FILE` of an `.ovpn` with
an inline `<auth-user-pass>` block moves its user name to the profile and its password to the Keychain
(`ProfileStore.analyzeOVPN`, then `commit`) and says so. The lines it skipped (kept in the stored
configuration as comments, [SECURITY.md](../SECURITY.md#importing-an-openvpn-configuration)) follow on
stderr, "Skipped lines (kept as comments in the stored configuration):", one per line with why it is
safe to leave out; `--json` adds them as `skipped` (docs/CLI-JSON.md). A blocking line fails the
command with `config_invalid`, listing every such line.

`secret-store [STORE]` exists on Linux only (the Mac has the Keychain; there the command, its help and
completion are absent). Without STORE it prints the store in use, how it was chosen and, when it
cannot be used from this process, why (exit 1). STORE is `auto`, `secret-service`, `systemd-creds` or
`file` (anything else is a usage error): it is saved as the setting `secret_store`, and a store named
explicitly is also recorded as the one in use (`secret_store_used`), so a later `auto` keeps it.
Secrets are not moved: after a change it says to save them again with `passtunnel secret`. `--json`
prints the `SecretStoreReport` ([CLI-JSON.md](CLI-JSON.md#secretstorereport)). On Linux `secret` and
`show` speak of the secret store instead of the Keychain (`secret`: "Password saved in the secret
store (file)."). The CLI on a terminal (stdin a TTY, no `--no-input`, not `mcp`) sets
`SecretStores.interaction`: the file store may ask for its passphrase there (no echo; twice for a new
file) and a locked keyring gets 120 s instead of 15 s to be unlocked. Details: [LINUX.md](LINUX.md#secrets).

`debug drop ID` (test hook, `DebugDrop`; compiled only into debug builds, `#if DEBUG`, since any process
in the login session can post the notification) makes a connected OpenVPN profile drop as if the server ended
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
`--uninstall-helper`; the app shows Settings → Helper and carries the action out there, and the CLI
waits for the new status and prints it. `helper status` stays local. Any local process can make such a
request, and registering points the root helper at the registering copy, so
(`HelperSettings.runPendingAction`): install and update are refused by a copy outside `/Applications`
("Open PassTunnel from the Applications folder…"; a helper waiting for approval only opens Login
Items); a missing helper is registered; replacing an enabled helper always asks ("Replace the
PassTunnel helper?", naming this copy's path), and replacing a newer one asks with the downgrade
warning instead; removal asks too. When the helper is enabled but outdated (another protocol or
build), `helper install` hands off `--update-helper` (`HelperHandoff.update`) instead: after the user
confirms, the app runs the same update as Settings → Helper → Update Helper (active connections
stop), and the CLI waits for the helper to report the current protocol and build. An
`install` hand-off that finds an outdated helper offers the update too; one that finds the current
helper does nothing.

The app answers each hand-off (`HelperHandoff.replyNotification`, `HelperHandoff.Outcome`): `asking`
when it shows a confirmation, `declined` when the user cancels it, `refused` when this copy is not in
`/Applications`. The CLI (`HandoffReplies`, `CLIRunner.wait(for:until:)`, deadline in `HelperHandoffWait`)
polls every 0.5 s: 30 s for `install`, 60 s for `update` and `uninstall`. Once the app asks, it prints
"Waiting for your confirmation in PassTunnel…" and waits up to 10 minutes for the decision. A cancel
("The update was cancelled in PassTunnel. The helper was not replaced." / "The removal was cancelled in
PassTunnel. The helper is still installed."; for `install` "The helper is not installed yet. Finish the
installation in PassTunnel → Settings → Helper."), a refusal ("PassTunnel did not change the helper:
open PassTunnel from the Applications folder, then try again.") or the deadline exits 1. Success is
still decided by polling the helper, never by a reply: any local process can post one, so a forged
reply only changes the message.

### `passtunnel mcp`

`MCPServer` (Core) on stdin/stdout: newline-delimited JSON-RPC 2.0, one message per line, stdout
carries protocol messages only, diagnostics go to stderr ("passtunnel mcp: …"). Dual-era: a request
with `_meta["io.modelcontextprotocol/protocolVersion"]` is served statelessly under that version
(2026-07-28: `clientCapabilities` required, results carry `resultType` and
`_meta["io.modelcontextprotocol/serverInfo"]`; unknown versions get -32022 with the supported list);
`initialize` starts a handshake session for 2025-11-25, 2025-06-18, 2025-03-26 or 2024-11-05 (the
version asked for, else 2025-11-25). Methods: `server/discover`, `initialize`, `ping`, `tools/list`,
`tools/call`; notifications `notifications/initialized`, `notifications/cancelled` (cancels the call;
a cancelled connect is stopped). Requests run concurrently on the main actor. Errors: -32700 parse,
-32600 invalid request (also batches), -32601 unknown method, -32602 invalid params / unknown tool /
no `_meta` without a handshake. Tool failures (including bad arguments) are results with
`isError: true` and the `{"error": …}` object as text. At the end of input the server finishes the
requests it has, then exits 0.

Tools (`MCPTools`): `list_profiles`, `get_status` (`profile_id`?), `get_logs` (`profile_id`,
`lines` 1–500, default 50, `source` `raw` (default) or `activity`: `AutomationService.activity`, the
worded lines plus `events`, without code digits), `diagnose` (`check_clock`, default false: also ask the
time server, `AutomationService.diagnose(checkClock:)`); with `--allow-connect` also `connect` (`profile_id`, `wait`
default true, `timeout_seconds` 1–600, default 60) and `disconnect` (`profile_id`, `wait`,
`timeout_seconds`). Each has an `inputSchema` (closed objects) and, from 2025-06-18, an
`outputSchema` and `structuredContent`; the text content is the same JSON. Results are the
automation objects of `--json`. `connect` mirrors the CLI: refresh, already connected → status,
already connecting → wait for it, `needs` → `input_required`, `checkCanStart`, `vault.unlock` (Touch
ID on the Mac), then `AutomationService.connect`; `wait: false` returns once the attempt shows as
connecting and lets it finish in the server. A failed `connect` is an error result whose error object
carries `failure`; `get_status` shows it too (`ProfileStatus.failure`, in the outputSchema), with
`clock` once the gateway check after a rejected sign-in has answered. `checkCanStart`
also returns the connected profiles whose routes or DNS names overlap with the profile's
(`ProfileOverlap`, ARCHITECTURE.md): the connect goes ahead and its result carries them as `warnings`
(`ConnectWarning`, CLI-JSON.md; the CLI prints them on stderr). The server never calls `ConnectionManager.start()`
(no polling, no auto-reconnect of its own).

The app and the CLI share the files and the Keychain. The app never acts on a cached profile:
connect, copy code, copy password + code and auto-type re-read the stored profile and Keychain item
first, and single-field changes (pin, order, remembered user name) go through `ProfileStore.update`
(read-modify-write). It reloads on `ProfilesWatcher` (FSEvents on the support directory, debounced;
`vpn.log`, `activity.jsonl`, `clock.json`, `network.json`, the management socket, markers and temp files are ignored), on `ProfileChangeSignal` (posted by the
CLI after commands that change profiles or secrets), when it becomes active, and every 5 s.

## Design system

The redesigned interface is built from tokens and base components in `Sources/PassTunnel/App/Design/`;
of the screens above, the profile editor uses them (its rows, fields, switch and "Server receives" preview are in
`Editor/EditorComponents.swift`), and so do the main window and the menu bar panel of the new interface; the
others not yet.
- `Tokens.swift`: `Palette` colors with light, dark and Increase Contrast values (dynamic `NSColor`s that follow
  the window's appearance). Mostly monochrome; green (connected), amber (waiting, the last 5 s) and red (errors)
  only ever come with an icon and words. Window and sidebar backgrounds are the system's, so fills, hairlines,
  the selection and the ring track are translucent. `Typography` (system text styles, SF Mono for codes and
  logs), `Spacing` (4–48), `Radius`, `Elevation` (flat hairline cards; glass only for chrome: Liquid Glass on
  macOS 26, the regular material before) and `Motion`.
- `Buttons.swift`: capsule styles `.primaryCapsule` (monochrome, fg on bg inverted, not the accent color),
  `.secondaryCapsule` and `.smallCapsule`, 28–40 pt high, with the system focus ring.
- `Card.swift`: `Card` (regular, compact), `SectionLabel`, `glass(in:)`. `StatusIcons.swift`: `StatusIcon`
  (SF Symbols, plus the drawn connecting and dropped glyphs, which stand still under Reduce Motion) and
  `StatusDot`, both hidden from VoiceOver since words always come with them.
- In `Views/Components.swift`: `CodeRing` and `CodeCountdown` (amber in the last 5 s, 1 s steps under Reduce
  Motion, the seconds written next to the ring), `GroupedCodeText` (a real space between the digit groups;
  VoiceOver reads "4 8 2, 9 1 3") and `CountdownTimeline`.
- The `components` render (`PASSTUNNEL_RENDER`, light and dark; `components-contrast` with the Increase Contrast
  values) shows every token and component.
- One status per profile for the new views: `DisplayStatus` (Core, `DisplayStatus.swift`; not the `ProfileStatus` of
  the CLI and MCP) is worked out from what `ConnectionManager` publishes. A connection that is up wins, with its
  worst problem (not responding, then setup incomplete, then status unavailable); then a running automatic
  reconnect, which covers its attempts, their code waits and their failures; then a connect under way (waiting for a
  fresh code, connecting); then the last error, a drop not seen yet, and at rest "Touch ID to connect" (either level
  of "Confirm with Touch ID": the new editor shows one switch) or "Disconnected". Each state has a short form for
  rows and the menu bar panel ("Connected · 1h 12m") and a long one for the detail ("Connected · 1h 12m · 10.8.0.6",
  "Waiting for a fresh code · sends in 4 s", "Dropped · next try in 12 s" after a failed attempt). A failure is only
  its message for now; once Core reports why (a rejected sign-in, a server that does not answer), each reason
  becomes a `DisplayStatus.Failure` case. `Views/ProfileStatusViews.swift` adds the icon and color and the views
  `ProfileStatusLine` (detail), `ProfileStatusRow` (dot and short words) and `ProfileStatusDot`, fed by
  `AppModel.displayStatus(_:)`; the new window and the menu bar panel show them, the current window and menu still
  use `StatusKind`. On a selected row's accent color the words turn white (macOS 14 and later; macOS 13 keeps the
  state's color). The `profile-status` render shows every state.
- The `main-split` renders show the redesigned window with the sample profiles, light and dark, once per state of
  the selected profile (`main-split`, `-waiting`, `-dropped`, `-off`, `-failed`), then the code cards with the code
  locked, hidden, just copied, in the smallest window and with a custom format (`-locked`, `-hidden`, `-copied`,
  `-narrow`, `-template`); they are not on the website. Every profile there has sample activity
  (`AppModel.previewActivity`); `activity-log`, `-errors` and `-empty` show the log window.
  The `import-review` renders show the import review in that window: as designed (two lines skipped, the code
  secret missing), `-ready` with the secret added, `-certificate` (a certificate-only file whose keys come from
  files next to it) and `-narrow` at the window's smallest size.
  The `error-` renders show the error states (`AppModel.previewFailures`): `error-rejected-clock` (with the banner),
  `error-rejected`, `error-rejected-clock-ok`, `error-unreachable`, `-offline`, `-ended`, `error-host-not-found`,
  `error-other`, `error-clock-banner` (and `-narrow`), and `overlap-sheet`.
  Offscreen, the glass sidebar of macOS 26 draws without its rows, so there the render lays the window's sidebar
  and detail out side by side, the sidebar on its flat list background. `first-run` (with the helper card, light and
  dark), `first-run-approval`, `add-vpn` and `main-split-login` show the first run, the add view and the question
  about opening at login.

## Accessibility

Every control has a localized accessibility label (text buttons get it from their title; icon-only
controls, the live code and the row's primary button set `.accessibilityLabel` on the control itself —
a label set inside a button's label with `children: .ignore` can leave the button nameless). SwiftUI
exposes it as `AXDescription` (read by VoiceOver and `AXUIElementCopyAttributeValue`), never as
`AXTitle`, and does not list it in `AXAttributeNames`, so System Events shows `name` as missing value.
For UI automation, key controls carry stable, unlocalized `.accessibilityIdentifier`s (`AXIdentifier`):
`profile.<id>`, `profile.<id>.primary`, `profile.<id>.more`, `profile.<id>.code`, `main.add` (in the redesigned
window also `profile.<id>.edit`, `profile.<id>.copyCode`, `profile.<id>.copyPasswordCode`,
`profile.<id>.serverReceives`, `main.settings` and
`firstRun.chooseFile|scanScreen|qrImage|byHand|installHelper|loginItems|notNow|openAtLogin`; its sidebar rows read as name,
status and code, its tiles as buttons with the line under the title as their hint),
`helper.install|update|loginItems|remove|licenses`, `onboarding.back|continue|done|installHelper|loginItems`,
`editor.cancel|save|delete|advanced|requireAuth|connectAtLogin|revealCode|scanScreen`, `settings.authReuse`, and in the
menu bar panel `menu.<id>.toggle`, `menu.add|copyCode|copyPasswordCode|typeCode|open|settings|quit`. The editor's switches are
drawn by the app (monochrome) and read by VoiceOver as standard switches (`accessibilityRepresentation`). While the screen is locked, accessibility clients see no windows at all (the
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
  (`AppModel.previewLockedCodes`; no Secure Enclave key is made), `main-hidden-codes` ("Hide codes until clicked",
  the first code clicked), `settings-general` (the whole page; `-PTNewInterface YES` leaves out the menu bar
  card), `editor/editor-require-auth`, `editor/editor-connect-at-login` (with the footnote of an app that does not
  open at login), `editor/editor-scan-screen` and `editor-scan-screen-none` (macOS 14 and later) and the menu bar
  panel of the new interface: `menubar-panel` (three profiles in mixed states, auto-type on), `menubar-panel-scroll`
  (six) and `menubar-panel-empty`.
- `PASSTUNNEL_RENDER_SCALE=4` renders at that backing scale (1–8; default 2). `scripts/site-assets.sh`
  uses 4 for the website, together with `editor/editor-one-time-code` (the editor sheet of a saved profile with
  its secret, at a fixed time so the code is stable) and `menubar-badges-<palette>` (the menu bar badges alone,
  on a transparent background).

## Content rules

No company or customer names and no real hostnames — examples use Acme, vpn.example.com, alice.
