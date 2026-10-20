# Security

PassTunnel stores VPN credentials and starts VPN software as root. This document explains, in plain
language, what runs with which privileges, what checks are in place, and where the limits are.
Implementation details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Components and privileges](#components-and-privileges)
- [The privileged helper](#the-privileged-helper)
- [OpenVPN configuration sanitizer](#openvpn-configuration-sanitizer)
- [Secrets and files](#secrets-and-files)
- [What is not protected](#what-is-not-protected)

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub: on
[github.com/Furkanprlk/passtunnel](https://github.com/Furkanprlk/passtunnel) open the **Security**
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
  only the PassTunnel app signed with the project's Developer ID Team ID. Other processes,
  including other apps running as you, cannot send requests.
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

- **Only the tools bundled in its own app.** The helper starts `Contents/Resources/bin/openvpn` or
  `Contents/Resources/bin/openfortivpn` next to its own executable (located through the kernel,
  not `argv[0]`). A path supplied by the client is never executed.
- **Signature verified before every launch.** Each tool must satisfy a code-signing requirement
  with its own identifier (`com.furkanprlk.passtunnel.openvpn`, `…openfortivpn`) and the project's
  Team ID, checked with strict validation across all architectures.
- **DNS script.** OpenVPN's `dns-updown` script is copied into the root-only run directory and the
  *copy* is signature-checked before OpenVPN may use it. OpenVPN's compiled-in default script path
  (which points into a build machine's Homebrew prefix) is never used. If no script is bundled,
  DNS hooks are disabled and `script-security` is set to 1.
- Tools are started with `posix_spawn` in their own process group, with a fixed environment
  (`PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `LC_ALL=C`), stdin from `/dev/null`, default signal
  handling and no inherited file descriptors.
- `stop` only signals the process the helper started for that profile (SIGTERM, then SIGKILL to
  its process group after 5 seconds).

### How OpenVPN is started

- The user's `config.ovpn` is passed through the [sanitizer](#openvpn-configuration-sanitizer).
  The sanitized copy and the credentials file (user name plus password/code, single lines only) are
  written as new `0600` files into a **root-owned run directory**, `/var/run/passtunnel/<uid>/<profile-id>`
  (`0711` like its parents, which must be real, root-owned directories: you can reach a file in it by
  name, but cannot list, rename or replace anything). The run directory is deleted when the tunnel stops.
- OpenVPN gets fixed flags after `--config`, so they override anything left in the file:
  `--management <run directory>/mgmt.sock unix`, `--management-client-user <your user name>`,
  `--auth-nocache`, `--remap-usr1 SIGTERM`, `--connect-retry-max 3`, and explicit
  `--script-security`/`--dns-updown` settings.
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
  characters or an IPv6 literal, the port must be 1–65535, the trusted certificate must be a
  64-character SHA-256 hex digest, and credentials may not contain line breaks, control characters
  or surrounding whitespace.
- The file is written into the same root-only run directory and the tool always gets `-c <file>`,
  so no default configuration is read.
- The *Fetch fingerprint* button in the editor reads the gateway certificate's SHA-256 digest with
  a TLS handshake that is aborted right after the certificate is received. You confirm the digest
  before it is saved.

### Logs

- The helper creates `vpn.log` in your profile folder itself: any existing entry is unlinked
  (never followed or truncated), a new file is created owned by you with mode `0600`, and its
  descriptor becomes the tool's stdout/stderr. OpenVPN's `--log` options are not used and are
  rejected in configs, so OpenVPN never opens a file path as root.

## OpenVPN configuration sanitizer

Before running a config as root, the helper parses it with a tokenizer that mirrors OpenVPN's own
(quotes, backslash escapes, `#`/`;` comments, leading `--`, `<tag>…</tag>` inline blocks,
`<connection>` blocks, `setenv opt` prefixes). Where the two could disagree it errs on the strict
side: names are compared case-insensitively with all leading dashes removed. Every violation is
reported with its line number, and nothing is run until the config is clean.

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
  and unclosed blocks are rejected.
- **`static-challenge` is stripped** (lines or blocks), because PassTunnel answers the challenge
  itself.

## Secrets and files

- **Keychain.** Passwords and TOTP secrets are stored only in the macOS Keychain as generic
  passwords (service `PassTunnel`, accounts `<profile-id>/password` and `<profile-id>/totp`) with
  the accessibility class *after first unlock, this device only*: they are not synced to iCloud
  Keychain and not included in migrations to another Mac. The app uses the Security framework
  directly. App and CLI are the same signed binary, so the Keychain does not prompt between them.
- **Secrets go to the helper only at connect time**, over the code-signature-checked XPC
  connection, and are written only into the root-only run directory, which is removed when the
  tunnel stops. OpenVPN runs with `--auth-nocache`.
- **Support folder.** `~/Library/Application Support/PassTunnel` (`0700`) holds `config.json`
  (preferences) and one folder per profile with `profile.json`, `config.ovpn` and `vpn.log`.
  Files are written with `0600`. These files contain no passwords or
  TOTP secrets, but `config.ovpn` may contain certificates and private keys from your VPN provider.
- **Share files (`.passtunnel`) never contain credentials.** No password, no TOTP secret, no user
  name. They do contain the connection settings and, for OpenVPN, the configuration file with any
  embedded certificates and keys, so they are written with `0600` and should be shared like the
  original `.ovpn`. On import, only `config.ovpn` is taken from the file, and it must already be
  self-contained.
- **Auto-type** (off by default) needs Accessibility permission, which is requested only when you
  enable it. Global shortcuts use Carbon hotkeys and do not need any permission.

## What is not protected

PassTunnel cannot defend against an attacker who already controls your account or your Mac:

- **A local administrator or root** can read or replace anything, including the app, the helper,
  your files and, with your login password, your Keychain.
- **Malware running as your user** can read your profile folder (configs and embedded keys) and
  logs, can ask the Keychain for PassTunnel's items (macOS shows a consent prompt because the
  requester is not PassTunnel; if you allow it, the secrets are disclosed), and can watch your
  screen or clipboard, where codes appear when you copy or auto-type them.
- **A TOTP secret on the same machine as your password** turns two factors into something closer
  to one: anyone who gets your unlocked Mac and Keychain has both. This is the trade-off PassTunnel
  makes for convenience. If your organization requires the second factor on a separate device, use
  *Ask each time* for the one-time code.
- **The VPN configuration itself.** The sanitizer stops configs from running code or touching files
  as root, but a legitimate config still decides where your traffic and DNS go. Only import
  configurations from sources you trust.
- **The bundled tools.** `openvpn`, `openfortivpn` and their libraries run as root, and their own
  vulnerabilities apply. Keep PassTunnel updated to get their fixes.
- **Builds you sign yourself.** The helper trusts the Team ID compiled into it. A build signed with
  a different Team ID has its own trust root, chosen by whoever built it.
