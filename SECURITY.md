# Security

PassTunnel stores VPN credentials and starts VPN software as root. This document explains, in plain
language, what runs with which privileges, what checks are in place, and where the limits are.
Implementation details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Components and privileges](#components-and-privileges)
- [The privileged helper](#the-privileged-helper)
- [OpenVPN configuration sanitizer](#openvpn-configuration-sanitizer)
- [Secrets and files](#secrets-and-files)
- [Confirm with Touch ID (Secure Enclave)](#confirm-with-touch-id-secure-enclave)
- [Updates](#updates)
- [MCP server and automation](#mcp-server-and-automation)
- [What is not protected](#what-is-not-protected)

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub: on
[github.com/passtunnel/passtunnel](https://github.com/passtunnel/passtunnel) open the **Security**
tab and choose **Report a vulnerability** (private vulnerability reporting / security advisories).
Include the version (Settings → About), your macOS version, the steps to reproduce and what an
attacker gains.

You can expect an acknowledgement within a few days. Fixes are released as a new version and
credited in the advisory unless you prefer otherwise. Only the latest release is supported.

## Components and privileges

| Component | Runs as | Purpose |
|---|---|---|
| `PassTunnel.app` (app and `passtunnel` CLI, one binary) | you | UI, profiles, Keychain access, TOTP, talks to the helper |
| `PassTunnelHelper` | **root**, started on demand by launchd | validates requests and starts or stops the VPN tools |
| bundled `openvpn`, `openfortivpn` (+ `dns-updown`) | **root**, started by the helper | the actual tunnel |

**Why root?** Creating a tunnel interface and changing routes and DNS requires it. PassTunnel does
not use a sudoers rule, a setuid binary or a kernel extension. The helper is registered with
Apple's `SMAppService` and shows up under **System Settings → General → Login Items**, where you
approve it once and can turn it off at any time. You can remove it with Settings → Helper → Remove
Helper… or `passtunnel helper uninstall`.

## The privileged helper

The helper is deliberately small. It accepts four requests over XPC: start OpenVPN, start
FortiGate, stop, and status. It enforces the following rules on every request.

### Who may talk to it

- **Client code-signing requirement.** The XPC connection is restricted with
  `NSXPCConnection.setCodeSigningRequirement` to
  `identifier "com.furkanprlk.passtunnel" and anchor apple generic and certificate leaf[subject.OU] = "YH4NUPFH74"`:
  only the PassTunnel app signed with the project's Developer ID Team ID. Other programs cannot
  connect. Any process running as you can, however, run the `passtunnel` command, which is that
  same signed binary: the helper serves it like the app, and it acts on your own profiles only (see
  [What is not protected](#what-is-not-protected)).
- **Caller identity from the kernel.** The calling user is taken from the connection's audit token
  (effective UID), never from the request.
- **Per-user isolation.** A user can only stop or see the status of tunnels they started.
- Requests larger than 64 KB or that do not decode are rejected.

### Which files it reads

- **Profile directory checks.** The profile folder in a request must resolve, with symlinks
  resolved, to exactly `<your home>/Library/Application Support/PassTunnel/profiles/<profile-id>`.
  It must be a real directory owned by the calling user and not group- or world-writable. The resolved path
  is checked again on the open descriptor, and all further file access goes through that
  descriptor, so the folder cannot be swapped between check and use.
- Profile IDs are limited to letters, digits, `-`, `_` and `.` (no leading dot or dash, no trailing
  dot, at most 64 characters).
- `config.ovpn` must be a regular, single-link file owned by you, not group- or world-writable, at
  most 1 MB, valid UTF-8, and is opened without following symlinks.

### Which programs it runs

- **Only the tools bundled in its own app, run from a root-owned copy.** The helper takes
  `Contents/Resources/bin/openvpn` and `Contents/Resources/bin/openfortivpn` and the libraries in
  `Contents/Frameworks` that they load (OpenSSL's `libcrypto` and `libssl`, `lzo`, `lz4`,
  `pkcs11-helper`) from its own app bundle (located through the kernel, not `argv[0]`). The bundle can
  be changed or renamed by the user who installed it, so the helper does not run the tools from there:
  it copies them, without following symlinks, into `/var/run/passtunnel/tools/<helper build>/`
  (directories `root:wheel` 0755, tools 0555, libraries 0444), with the bundle's layout, so the
  tools' load paths (`@executable_path/../../Frameworks/…`, `@loader_path/…`) resolve to the copied
  libraries and never back into the bundle. Every copied file is checked as copied (below); a copy
  that fails the check, or has an unexpected or missing file, is made again; copies of other helper
  builds are removed unless a tool still runs from them. macOS empties `/var/run` when it starts. A
  path supplied by the client is never executed. System libraries come from macOS.
- **Signature checked on the copies and on the code that runs.** Each tool must satisfy a
  code-signing requirement with its own identifier (`com.furkanprlk.passtunnel.openvpn`,
  `…openfortivpn`) and the project's Team ID; each library must be signed with the project's Team ID.
  The helper checks every copied file (strict validation across all architectures), so a file
  replaced in the bundle while it was being copied gives a copy that is refused. It then starts the
  copied tool **suspended**, before its first instruction, checks the code the kernel actually loaded
  for that process against the same requirement (strict validation, which also fails when the file
  on disk no longer matches what was loaded), and only then lets it run. If that check fails, the
  process is killed before it ran.
- **Only the builds it was released with.** The identifier and Team ID requirements accept every
  build the project ever signed, including an older release's `openvpn` or `libcrypto`. A released
  helper also carries the cdhashes (the hash of a code signature, which the kernel records for the
  running process) of the exact tools and libraries it ships with, compiled into its own signed code.
  It copies only those libraries, and refuses a copied tool or library, a started tool, or a
  `dns-updown` copy with any other cdhash. Every app bundle made by `scripts/build-app.sh` is pinned
  this way, and a signed build fails unless both tools and every bundled library are pinned. Only
  plain development builds (`swift build`, tests) pin nothing: they copy every `.dylib` in
  `Contents/Frameworks` and accept any tool or library that satisfies the requirement.
- **DNS script.** OpenVPN's `dns-updown` script is copied into the root-only run directory and the
  *copy* is signature-checked before OpenVPN may use it. OpenVPN's compiled-in default script path
  (which points into a build machine's Homebrew prefix) is never used. If no script is bundled,
  DNS hooks are disabled and `script-security` is set to 1.
- Tools are started with `posix_spawn` in their own process group, stdin from `/dev/null`, default
  signal handling, no inherited file descriptors and a fixed environment: `PATH=/usr/bin:/bin:/usr/sbin:/sbin`,
  `LC_ALL=C`, and settings that keep the bundled OpenSSL away from the Homebrew paths compiled into
  it (on your Mac they may exist and belong to whoever installed Homebrew): `OPENSSL_CONF=/dev/null` (no
  configuration file), `OPENSSL_MODULES` and `OPENSSL_ENGINES` set to `/var/empty/passtunnel-none`
  (a directory that does not exist inside the root-owned `/var/empty`, so no providers or engines are
  loaded), `SSL_CERT_FILE=/etc/ssl/cert.pem` (the system's root-owned CA bundle) and
  `SSL_CERT_DIR=/var/empty`.
- `stop` only signals the process the helper started for that profile (SIGTERM, then SIGKILL to
  its process group after 5 seconds).

### How OpenVPN is started

- **Only the file the app checked.** The start request carries the SHA-256 of the exact
  `config.ovpn` the app read when it decided where your secrets go (see [Bound to the
  server](#confirm-with-touch-id-secure-enclave)). The helper hashes the file it reads and refuses to
  start a different one, so the file cannot be swapped between that check and the start.
- The user's `config.ovpn` is passed through the [sanitizer](#openvpn-configuration-sanitizer).
  The sanitized copy and the credentials file (user name plus password/code, single lines only) are
  written as new `0600` files into a **root-owned run directory**, `/var/run/passtunnel/<uid>/<profile-id>`
  (`0711` like its parents, which must be real, root-owned directories: you can reach a file in it by
  name, but cannot list, rename or replace anything). The run directory is deleted when the tunnel stops.
- OpenVPN gets fixed flags after `--config`, so they override anything left in the file:
  `--management <run directory>/mgmt.sock unix`, `--management-client-user <your user name>`,
  `--verb` (the configuration's `verb`, at most 4; 3 when it sets none), `--auth-nocache`,
  `--remap-usr1 SIGTERM`, `--connect-retry-max 3`, and explicit `--script-security`/`--dns-updown`
  settings. The cap keeps OpenVPN's debug levels (from 5 every packet, from 7 the data-channel keys,
  from 9 packet contents) out of the log, which you, the app and `get_logs` can read.
- **Management over a per-user unix socket.** The management interface is a unix socket in the
  session's root-owned run directory, not a TCP port. OpenVPN only serves the user named in
  `--management-client-user` (peer credential check). Once the socket exists, the helper also
  hands it to you with mode `0600`; because nobody but root can change entries in that directory,
  this cannot be redirected to another file (the helper still checks it is a socket and never
  follows links). The socket is removed with the run directory when OpenVPN exits.

### How FortiGate is started

- The openfortivpn configuration is **rendered by the helper from typed fields** (host, port, user
  name, password, code, trusted certificate digest, DNS and routes switches). No user-supplied raw
  configuration and no pppd options are accepted.
- Every value is validated so it stays on its own line: host names are limited to host-name
  characters or an IPv6 literal (hex digits, `:` and `.`, with an optional zone id of letters and
  digits), checked character by character before any C function sees them, so no NUL, control
  character or whitespace is accepted; the port must be 1–65535, the trusted certificate must be a
  64-character SHA-256 hex digest, and credentials may not contain line breaks, control characters
  or surrounding whitespace. The app refuses such a host already when a profile is saved or imported.
- The finished file is checked once more before it is written: the expected number of lines, no NUL,
  carriage return or other control byte, and only the keys PassTunnel writes, each once.
- No value is longer than openfortivpn keeps (it copies each into a fixed buffer and silently drops
  the rest): host at most 253 bytes, user name 64, password 255, one-time code 64 (UTF-8 bytes, not
  characters). The app refuses a longer FortiGate user name already when the profile is saved or a
  user name is entered to connect.
- The file is written into the same root-only run directory and the tool always gets `-c <file>`,
  so no default configuration is read. It always sets `ca-file = /etc/ssl/cert.pem`, so
  openfortivpn never falls back to OpenSSL's compiled-in default store.
- The *Fetch fingerprint* button in the editor reads the gateway certificate's SHA-256 digest with
  a TLS handshake that is aborted right after the certificate is received. You confirm the digest
  before it is saved.

### Logs

- The helper creates `vpn.log` in your profile folder itself: any existing entry is unlinked
  (never followed or truncated), a new file is created owned by you with mode `0600`, and its
  descriptor becomes the tool's stdout/stderr. OpenVPN's `--log` options are not used and are
  rejected in configs, so OpenVPN never opens a file path as root.
- Every session starts with an empty log; while it runs, the helper checks the size once a minute
  and cuts a log above 5 MB down to its first 64 KB and last 1 MB (through its own copy of the descriptor).

## OpenVPN configuration sanitizer

Before running a config as root, the helper parses it with a tokenizer that mirrors OpenVPN's own
(quotes, backslash escapes, `#`/`;` comments, leading `--`, `<tag>…</tag>` inline blocks,
`<connection>` blocks, `setenv opt` prefixes). Where the two could disagree it errs on the strict
side: names are compared case-insensitively with all leading dashes removed. Every violation is
reported with its line number, and nothing is run until the config is clean. The app reads configs
with the same tokenizer when it imports them (embedding referenced files, removing credential
blocks), so the app and the helper never read a line differently.

**Rejected directives** (they run programs, load code, write files as root, or override the
helper's settings):

```
up  down  route-up  route-pre-down  ipchange  learn-address
client-connect  client-disconnect  tls-verify  auth-user-pass-verify  tls-crypt-v2-verify
plugin  dns-updown  iproute
daemon  writepid  cd  chroot  user  group  config
status  replay-persist  tmp-dir  tls-export-cert  dev-node
client-config-dir  ifconfig-pool-persist
engine  providers  pkcs11-providers  capath
management*  log*            (every directive starting with these)
script-security N            (when N > 1)
```

**Other rules**

- **No external files.** `ca`, `cert`, `key`, `dh`, `pkcs12`, `extra-certs`, `tls-auth`,
  `tls-crypt`, `tls-crypt-v2`, `secret`, `crl-verify`, `auth-user-pass`, `http-proxy-user-pass` and
  `askpass` must use inline content (`<ca>…</ca>`); otherwise the helper would read arbitrary paths
  as root. `dh none` is allowed. An `http-proxy` credentials argument must be `auto`, `auto-nct` or
  inline. When you import an `.ovpn`, the app embeds referenced files for you.
- **`setenv`** is limited to client metadata (`CLIENT_CERT`, `FORWARD_COMPATIBLE`,
  `PUSH_PEER_INFO`, `FRIENDLY_NAME`, `ALLOW_PASSWORD_SAVE`, `SERVER_POLL_TIMEOUT`,
  `GENERIC_CONFIG`, `IV_*`, `UV_*`), so variables such as `PATH` or `BASH_ENV` cannot steer the DNS
  script.
- `setenv opt <directive>` is checked like the directive itself.
- Lines longer than 254 bytes (OpenVPN would silently split them), NUL bytes, unterminated quotes
  and unclosed blocks are rejected, and so is a backslash outside single quotes that does not escape
  `\`, `"` or whitespace. OpenVPN refuses those too, except a backslash at the end of a line, which
  it would take as escaping the line break; PassTunnel rejects that as well.
- **`static-challenge` is stripped** (lines or blocks), because PassTunnel answers the challenge
  itself.

## Secrets and files

- **Keychain.** Passwords and TOTP secrets are stored only in the macOS Keychain as generic
  passwords (service `PassTunnel`, accounts `<profile-id>/password` and `<profile-id>/totp`) in
  your login keychain. They are not synced to iCloud Keychain, but Migration Assistant and backups
  carry them to another Mac together with the rest of the login keychain (items encrypted with
  [Confirm with Touch ID](#confirm-with-touch-id-secure-enclave) move too, but cannot be decrypted
  there). The app uses the Security framework directly. App and CLI are the same signed binary, so
  the Keychain does not prompt between them.
- **Every write replaces the item.** An existing item may have been created by another app, with
  an access list that lets that app read it, so PassTunnel never updates an item in place: it
  deletes it and adds a new one, which gets the default access list (only PassTunnel may read it
  without asking). If the old item cannot be deleted, nothing is written and PassTunnel says so. If
  the new item cannot be added, the previous value (read before the delete) is added back the same
  way, as a new item.
- **A new profile starts without Keychain items.** Items still stored under its ID (left by a
  profile removed outside the app, or from before a reinstall) are deleted when the profile is
  created, so it never uses a secret you did not give it.
- **Uninstalling** keeps the Keychain items, unless you use `brew uninstall --zap --cask passtunnel`,
  which deletes them. The [README's FAQ](README.md#faq) has the manual steps.
- **Secrets go to the helper only at connect time**, over the code-signature-checked XPC
  connection, and are written only into the root-only run directory, which is removed when the
  tunnel stops. OpenVPN runs with `--auth-nocache`.
- **Support folder.** `~/Library/Application Support/PassTunnel` (`0700`) holds `config.json`
  (preferences) and one folder per profile with `profile.json`, `config.ovpn` and `vpn.log`.
  Files are written with `0600`. These files contain no VPN passwords or TOTP secrets, but
  `config.ovpn` may contain certificates and private keys from your VPN provider, and proxy
  credentials (see below).
- **Credentials in an imported `.ovpn`.** A user name and password in an inline `<auth-user-pass>`
  block are not stored with the configuration: on import the user name moves to the profile and the
  password to the Keychain, and the stored `config.ovpn` keeps a bare `auth-user-pass`. Choosing a
  configuration in the editor fills empty Sign-in fields with them instead, saved with the profile. A
  configuration imported by an earlier version keeps its block until you import it again (sharing
  removes it anyway). Proxy credentials (`<http-proxy-user-pass>`, also embedded from a referenced
  file on import) stay in the local `config.ovpn`.
- **Share files (`.passtunnel`) never contain credentials.** No password, no TOTP secret, no user
  name, and no `<auth-user-pass>` or `<http-proxy-user-pass>` block: both are removed from the
  configuration on export. They do contain the connection settings and, for OpenVPN, the
  configuration file with any embedded certificates and keys, so they are written with `0600` and
  should be shared like the original `.ovpn`. On import, only `config.ovpn` is taken from the file,
  it must already be self-contained, and an `<auth-user-pass>` block (the sender's sign-in, in a file
  exported by an earlier version) is dropped.
- **Clipboard.** A copied code, or password + code, is put on the clipboard for this Mac only (not
  Universal Clipboard), marked concealed and transient so clipboard managers skip it, and cleared
  after 1 minute (30 seconds or 2 minutes in Settings → General → Clear copied code) unless
  something else was copied meanwhile. `passtunnel code -c` does the same: it leaves a small
  detached process behind that clears the clipboard.
- **Auto-type** (off by default) needs Accessibility permission, which is requested only when you
  enable it. Global shortcuts use Carbon hotkeys and do not need any permission.
- **No test hooks in releases.** `passtunnel debug drop`, which ends a connection as if the server
  had (and which any process in your login session could trigger through the running app), exists
  only in debug builds.

## Confirm with Touch ID (Secure Enclave)

Off by default, per profile (`require_auth`: `off`, `connect`, `always`; on a Mac without Touch ID the
setting is called "Confirm with your password", and the login password is the confirmation). The profile
editor has one switch, "Require Touch ID before connecting" ("Require your Mac password before connecting"
without Touch ID): on is `always`; `connect` is set with
`passtunnel set ID require_auth=connect` and shows in the editor as on, with a footnote. Without it, anyone using your
Mac while you are logged in can connect with one click, because the app may read its own Keychain items
without asking.

**What is encrypted.** With the option on, PassTunnel creates a P-256 key-agreement key for the profile
in the Mac's **Secure Enclave** (CryptoKit `SecureEnclave.P256.KeyAgreement`) with the access control
`privateKeyUsage` + `userPresence`: the private key never leaves the Secure Enclave, and the Secure
Enclave uses it only after Touch ID or the login password (or an Apple Watch, where set up). The
Keychain item `<profile-id>/sekey` holds only the key's wrapped blob (`dataRepresentation`, usable by
this Mac's Secure Enclave alone) and its public key. The protected secrets replace their plain Keychain
items with an envelope (`ptse1:` + Base64): a fresh ephemeral P-256 key, ECDH with the profile's public
key, HKDF-SHA256 (salt: both public keys, info `PassTunnel secret v1`) and AES-256-GCM with the item's
account name as authenticated data, so an envelope cannot be moved to another item.

- `connect`: the saved password is encrypted; the TOTP secret stays readable so live codes show
  without a prompt. A profile without a saved password gets its TOTP secret encrypted instead
  (otherwise the option would protect nothing), and its code is hidden until you confirm.
- `always`: the password and the TOTP secret are encrypted; codes are hidden until you confirm.

**Decrypting is the confirmation.** There is no separate yes/no check that could be skipped: without
the Secure Enclave operation, PassTunnel has no password or TOTP secret to send. A cancelled or failed
prompt means no connection; nothing falls back to a plain copy. Saving a new secret to a protected
profile only needs the public key (no prompt). Before PassTunnel encrypts to the public key in
`<profile-id>/sekey`, and again before and after it unlocks the key, it checks that the record's public
key belongs to the Secure Enclave key in the same record: a record replaced by another app (to have new
secrets encrypted to its own key) is never used, and PassTunnel stops with an error asking you to set
the profile up again. Turning the option off, or lowering `always` to
`connect`, needs a successful decrypt; the encrypted items are then rewritten in plain text and the key
item is deleted. Deleting the profile deletes its key item.

**Reuse.** After one confirmation, the decrypted values of that profile stay in the app's memory for
the "Ask again after" time (Settings → General → Security: 1, 5 or 15 minutes). Sleep and screen lock
end it early. LocalAuthentication's own `touchIDAuthenticationAllowableReuseDuration` is left at 0: it
would let a recent Touch ID unlock of the Mac count as the confirmation, which is exactly the situation
this option is for. A connected session keeps its
decrypted secrets in memory so an automatic reconnect after a drop needs no prompt; they are
overwritten (best effort) when you disconnect or the session ends. After the Mac was asleep, a
dropped protected profile is not reconnected on its own: a notification asks you to reconnect. Each
CLI command is a separate process and asks every time it needs a protected secret; `passtunnel mcp`
is one process for as long as the MCP client runs it, so the window (and its end on sleep and
screen lock) applies within it.

**Bound to the server.** The connect prompt names the server the secrets go to ("connect to “Acme VPN”
(vpn.example.com)"; for OpenVPN the first `remote` of the configuration, read exactly as OpenVPN reads
it, followed by "+2 more" when the configuration lists other servers OpenVPN may use). What you
confirm is bound to the profile's destination at that moment: for OpenVPN the exact contents of `config.ovpn` (servers, CA,
proxy, everything the helper runs), for FortiGate the host, port and trusted certificate. When that
changes, in the editor, with `passtunnel set` or by editing the files, the decrypted values held for the
reuse window and for a connected session are dropped. The next connect asks again and names the new
server, and an automatic reconnect (after a drop or a failed health check) does not happen: a
notification "“Acme VPN” was not reconnected" asks you to connect and confirm again. For OpenVPN the
helper also refuses a `config.ovpn` that is not the one the app checked, so a file replaced at the last
moment is not used either: the connect fails and asks you to connect again.

**Limits.**
- It needs a Secure Enclave (Apple silicon or a T2 Mac). Without one (e.g. a virtual machine), the
  option cannot be turned on; it never silently degrades to plain storage.
- Secure Enclave keys do not move to another Mac or survive erasing this one. After migrating, the
  encrypted items cannot be decrypted; PassTunnel says so, removes them and asks you to enter the
  password or TOTP secret again.
- `userPresence` is used (not `biometryCurrentSet`), so adding a fingerprint does not lock you out and
  the password fallback always works.
- A setting changed outside PassTunnel (e.g. `require_auth` edited in `profile.json`) is reconciled
  safely: plain secrets the setting protects are encrypted on the app's next reload or before the CLI
  uses them (no prompt needed); encrypted secrets of a profile set to `off` stay encrypted (using them
  asks) until the setting is lowered in the app or with `passtunnel set`, which decrypts them. Without a
  Secure Enclave such a hand-edited setting cannot be applied and the secrets stay plain.
- It protects against other people at your unlocked Mac and against other processes or apps reading
  the Keychain items (they get ciphertext). It does **not** protect against malware running as you
  that waits for you to confirm, drives the prompt you then approve, or reads the app's memory while a
  session or the reuse window holds the decrypted values. The profile's files (`profile.json`,
  `config.ovpn`) are not protected either: editing them does not decrypt anything and does not
  redirect secrets you already confirmed, but someone with your account can delete the items or the
  profile.

## Updates

- **App updates** come through Sparkle from the feed on the GitHub releases. The feed
  (`appcast.xml`) and every update archive are signed with the project's EdDSA key. The app refuses
  a feed without a valid signature (`SURequireSignedFeed`) and checks an archive's signature before
  unpacking it (`SUVerifyUpdateBeforeExtraction`). An update is installed only when you click
  Install.
- **Releases** are uploaded to a draft release and published only once every file is attached. The
  release tag is signed when the release machine has a signing key. The bundled `openvpn`,
  `openfortivpn` and their libraries come in pinned versions (`scripts/release.env`); a release
  build stops when Homebrew provides any other version. Details: [docs/RELEASING.md](docs/RELEASING.md).
- **Replacing the helper.** Registering the helper points the root daemon at the copy of PassTunnel
  that registers it, so this is limited:
  - After an app update, the app replaces the running helper on its own only when it runs from
    `/Applications` (symlinks resolved; not `~/Applications`, where any process of yours can put a
    copy) and only when the running helper is an older build. The helper reports the build number of
    the app it was started from in every reply, so a newer helper is never downgraded on its own.
  - `passtunnel helper install` and the `--install-helper` / `--update-helper` launch arguments can
    be used by any local process. A copy outside `/Applications` refuses them, and replacing a running
    helper this way always asks you first.
  - Replacing a newer helper with an older one (Settings → Helper → Update Helper, or the above) shows
    a separate warning first.
  - Removing the helper on request from outside the app always asks.

## MCP server and automation

`passtunnel mcp` lets an AI assistant (an MCP client such as Claude Code or Claude Desktop) use
PassTunnel. Treat it like this: **the MCP client gets the same power as running the `passtunnel`
command yourself, limited further by the read-only default.**

- **What it is.** The same signed binary as the app, started by the MCP client as a child process
  under your user, speaking JSON-RPC over its standard input and output. It opens no port and no
  socket; only the process that started it can talk to it. It adds no privilege: any program
  running as you can already run `passtunnel`.
- **Read-only by default.** Without `--allow-connect` the tools are `list_profiles`, `get_status`,
  `get_logs` and `diagnose`. `connect` and `disconnect` are listed and callable only when the
  server was started with `passtunnel mcp --allow-connect`. No tool creates, changes or deletes a
  profile or a secret, in any mode.
- **No secrets in any answer.** No tool returns a password, a TOTP secret, a current one-time code,
  a private key or the contents of a configuration file; there is deliberately no tool for codes.
  `diagnose` says *whether* a password or TOTP secret is saved and names configuration problems by
  directive, never by value. Tests check every tool's output for a profile with a saved password and
  TOTP secret.
- **Logs.** The VPN tools receive credentials through root-owned files, not on the command line,
  and do not log them or key material at the verbosity the helper allows: OpenVPN always runs with
  `--verb` at most 4, whatever the configuration says, and openfortivpn runs at its default level
  (the helper passes no `-v`, and the configuration it writes has no setting for it or for pppd's
  debug output). `get_logs` adds two filters. It leaves out lines that look like key material or
  packet dumps (OpenVPN `TLS: tls_…` traces and any line with a run of 32 or more hex digits, also
  when split into groups by spaces or colons; openfortivpn's `--trusted-cert <digest>` hint is kept,
  as the gateway certificate's digest is public and explains the failure), and it replaces the saved password and TOTP secret,
  `auth-token` values, OpenVPN challenge responses (`CRV1:`, `SCRV1:`, `RV1:`) and
  `password=…` / `otp: …`-style values with `<redacted>`. The saved password and TOTP secret are
  masked by value only when they are stored in plain text; one protected by Confirm with Touch ID
  is not decrypted for this, so only the keyword and pattern rules apply to it. It returns at most
  500 lines; when the log is longer than the 256 KB it reads, the first, partial line is dropped.
  Log lines do contain server names, your user name and IP addresses.
- **Strict arguments.** `profile_id` must be a valid profile id (the same pattern profile folders
  use: lowercase letters, digits and single dashes); unknown arguments, wrong types and
  out-of-range numbers are refused before anything is read.
- **Touch ID still applies.** Connecting a profile with *Confirm with Touch ID* shows the same
  prompt as the app, naming the server, on your Mac: nothing is decrypted or sent until you confirm.
  If no prompt can be shown (for example in an SSH session, or with `passtunnel mcp
  --no-auth-prompt`), the call fails with `auth_unavailable`. A confirmation counts only for the
  server settings the profile had at that moment, exactly as in the app. The MCP server is one
  long-running process, so the [reuse window](#confirm-with-touch-id-secure-enclave) applies to it
  as to the app: a second `connect` of the same profile within the "Ask again after" time (Settings
  → General → Security; 1 minute is the shortest, it cannot be turned off) does not prompt again.
  Sleep and screen lock end the window early, in the MCP server as in the app. Profiles that ask for a
  user name, password or code on every connect cannot be connected through MCP, and there is no
  way to override the check for another VPN that takes all traffic.
- **Prompt injection.** An assistant follows text it reads: a web page, a file, an issue comment or
  a log line can contain instructions. With `--allow-connect`, such instructions could make the
  assistant connect or disconnect a profile, which changes routes and DNS for the whole Mac or
  ends a session. Keep the server read-only unless you need it, turn on Confirm with Touch ID for
  profiles an assistant may connect, and keep your client's per-tool approval on for `connect`
  and `disconnect`.
- **Where the answers go.** Whatever a tool returns (profile names, user names, server names, IP
  addresses, log lines) goes to the assistant and its provider.

For scripts, `--no-input` and `--no-auth-prompt` turn a prompt into an error (`input_required`,
`auth_unavailable`) instead of waiting for an answer that will not come. Neither skips a check:
there is no option that connects a protected profile without the confirmation.

## What is not protected

PassTunnel cannot defend against an attacker who already controls your account or your Mac:

- **A local administrator or root** can read or replace anything, including the app, the helper,
  your files and, with your login password, your Keychain.
- **Malware running as your user** can read your profile folder (configs and embedded keys) and
  logs, can ask the Keychain for PassTunnel's items (macOS shows a consent prompt because the
  requester is not PassTunnel; if you allow it, the secrets are disclosed), and can watch your
  screen or clipboard, where codes appear when you copy (for 1 minute by default) or auto-type
  them. It can also run the `passtunnel` command, the same signed binary as the app, so the
  Keychain and the helper treat it like the app: it reads secrets that are not protected by Confirm
  with Touch ID without any prompt, and it can change a profile's settings and connect it, which
  sends your password to the server it chose. [Confirm with Touch ID](#confirm-with-touch-id-secure-enclave)
  prevents this for the secrets it protects: using them asks, the prompt names the server, and a
  changed destination always asks again.
- **Other accounts on this Mac.** Every local account can use the helper. Sessions are kept apart (a
  user can only stop or see their own), but a VPN changes routes and DNS for the whole Mac: any
  local account can start a full-tunnel profile whose routes and DNS then apply to every logged-in
  user. This is how a VPN client works; PassTunnel does not restrict it further.
- **Older copies of PassTunnel.** Version 1.0.0 lacks the checks under [Updates](#updates) and
  the suspended start of the tools. A copy of it can still register its own helper in place of a
  newer one, without asking. Delete old copies, including disk images and downloads.
- **The helper's build number** is read from the `Info.plist` of the app bundle it was started from.
  Whoever can change that file can make a helper claim another build. The only effect is on
  replacing it: a helper that claims to be newer is not replaced automatically (Settings → Helper
  still offers to, with the warning).
- **A TOTP secret on the same machine as your password** turns two factors into something closer
  to one: anyone who gets your unlocked Mac and Keychain has both ([Confirm with Touch
  ID](#confirm-with-touch-id-secure-enclave) adds Touch ID or your password in front of them). This is the trade-off PassTunnel
  makes for convenience. If your organization requires the second factor on a separate device, use
  *Ask each time* for the one-time code.
- **The VPN configuration itself.** The sanitizer stops configs from running code or touching files
  as root, but a legitimate config still decides where your traffic and DNS go. Only import
  configurations from sources you trust.
- **The bundled tools.** `openvpn`, `openfortivpn` and their libraries run as root, and their own
  vulnerabilities apply. Keep PassTunnel updated to get their fixes.
- **Builds you sign yourself.** The helper trusts the Team ID compiled into it. A build signed with
  a different Team ID has its own trust root, chosen by whoever built it.
