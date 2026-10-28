# `passtunnel` JSON output and exit codes

Every `passtunnel` command that produces a result accepts `--json`. The result is printed on
**stdout** as one JSON document (snake_case keys, sorted, dates in ISO 8601 UTC); progress messages,
hints and prompts go to stderr. Without `--json` the output is the human one, unchanged.

The same objects are returned by the MCP server (`passtunnel mcp`, see the README section *Use with
AI assistants*): `ProfileSummary`, `ProfileStatus`, `HelperReport`, `LogReport` and the error object
below come from one implementation (`Sources/PassTunnelCore/Automation.swift`).

No output ever contains a password, a TOTP secret, a key or the contents of a configuration file.
`code --json` is the only command that prints a one-time code, and only because you asked for it;
the MCP server has no such tool.

- [Options for scripts](#options-for-scripts)
- [Exit codes](#exit-codes)
- [Errors](#errors)
- [Objects](#objects): [ProfileSummary](#profilesummary), [ProfileStatus](#profilestatus), [ConnectWarning](#connectwarning), [ConnectionFailure](#connectionfailure), [ClockOffset](#clockoffset), [HelperReport](#helperreport), [SecretStoreReport](#secretstorereport), [LogReport](#logreport), [ActivityEvent](#activityevent), [DiagnoseReport](#diagnosereport)
- [Commands](#commands)

## Options for scripts

| Option | Effect |
|---|---|
| `--json` | JSON result on stdout; failures as `{"error": …}` (also for usage errors). |
| `--no-input` | Never read standard input and never ask on the terminal (user name, password, code, `rm` confirmation, `secret`). Fails with `input_required` instead. Also set by `PASSTUNNEL_NO_INPUT=1` in the environment. |
| `--no-auth-prompt` | Never show the Touch ID / Mac password prompt. A protected profile fails with `auth_unavailable` instead. For unattended scripts. |
| `--wait` | `connect`, `disconnect`: return only once connected / stopped, or failed. |
| `--timeout SECONDS` | Limit for `--wait` (default 60, implies `--wait`). For `connect` it counts from after the Touch ID confirmation. |

`--no-input` and `--no-auth-prompt` are accepted anywhere on the command line (before `--`).
Without them, a Touch ID prompt is still shown when a protected profile connects: that is the
human confirmation, and a script cannot answer it.

## Exit codes

| Code | Meaning | Error codes |
|---|---|---|
| 0 | OK | |
| 1 | Other error | `config_invalid`, `file_error`, `keychain_error`, `internal` |
| 2 | Usage error: unknown command or option, invalid value | `invalid_argument` |
| 3 | Not found; `status ID`: the profile is not connected | `profile_not_found`, `not_connected` |
| 4 | A confirmation or input was needed but was cancelled or is not possible | `auth_cancelled`, `auth_unavailable`, `input_required`, `cancelled` |
| 5 | The helper is not installed, not approved, outdated or not answering | `helper_not_installed`, `helper_outdated`, `helper_unavailable` |
| 6 | Connecting failed | `connect_failed`, `server_unreachable`, `host_not_found`, `credentials_rejected`, `credentials_missing`, `other_vpn_active`, `destination_changed` |
| 7 | Timeout | `timeout` |
| 130 | Interrupted (Ctrl-C) | |

`status ID` exits 3 when the profile is not connected but still prints its status object.
`helper status` exits 5 when the helper is not usable but still prints its `HelperReport`.

## Errors

```json
{
  "error" : {
    "code" : "profile_not_found",
    "message" : "Profile “nope” was not found."
  }
}
```

`code` is stable and meant for programs; `message` is for people and follows the macOS language
(English or Turkish). A failed `connect` adds `failure`, a [ConnectionFailure](#connectionfailure)
(not when `--timeout` ran out first).

| Code | When |
|---|---|
| `invalid_argument` | Bad command line, invalid profile id or value, no default profile and no id given, `secret` with an empty value |
| `profile_not_found` | No such profile, or no profiles at all |
| `not_connected` | The profile is not connected (test hooks) |
| `input_required` | No terminal or `--no-input`, and the profile asks for a user name, password or code on every connect, or `rm` without `--yes`; `secret` with `--no-input` |
| `cancelled` | You answered no (`rm`) |
| `auth_cancelled` | The Touch ID / Mac password prompt was cancelled |
| `auth_unavailable` | The prompt cannot be shown (SSH session, `--no-auth-prompt`, Touch ID locked, no Secure Enclave) |
| `helper_not_installed` | The privileged helper is not installed, needs approval in Login Items, or is missing from the app |
| `helper_outdated` | The helper belongs to another PassTunnel version: `passtunnel helper install` |
| `helper_unavailable` | The helper did not answer |
| `connect_failed` | The VPN did not come up (see `passtunnel log ID`) |
| `server_unreachable` | The server did not answer (refused, timed out, no route); the sign-in was not sent |
| `host_not_found` | The server's name could not be resolved |
| `credentials_rejected` | The server refused the sign-in (not retried) |
| `credentials_missing` | No saved password or TOTP secret |
| `other_vpn_active` | Another VPN already routes all traffic (`connect --force` overrides) |
| `destination_changed` | The server settings changed after you confirmed: connect again and confirm |
| `timeout` | `--timeout` passed, or the VPN tool's own limit |
| `config_invalid` | Missing or rejected OpenVPN configuration, missing FortiGate server, unreadable file, a profile or share file of a VPN type that needs a newer PassTunnel |
| `file_error` | A file could not be read or written |
| `keychain_error` | The secret store (the Keychain on the Mac; on Linux secret-service, systemd-creds or the passphrase-encrypted file) refused or cannot be used, or a protected secret cannot be decrypted; `message` says why |
| `internal` | Anything else |

## Objects

### ProfileSummary

From `list`, `add`, `import`, `pin`, `unpin` and the MCP tool `list_profiles`.

```json
{
  "auto_reconnect" : false,
  "connect_at_login" : true,
  "id" : "work",
  "is_default" : true,
  "name" : "Work",
  "otp_mode" : "totp",
  "password_mode" : "keychain",
  "pinned" : false,
  "protected" : true,
  "require_auth" : "connect",
  "type" : "openvpn",
  "username" : "alice"
}
```

`protected`: connecting asks for Touch ID or the Mac password. `type`: `openvpn` or `forti`.
`password_mode`: `keychain`, `ask` or `none`; `otp_mode`: `none`, `totp` or `ask`; `require_auth`:
`off`, `connect` or `always`. `connect_at_login`: the app connects the profile when it opens at login
(one that asks first gets a notification instead). The MCP tool adds `state` (as in ProfileStatus); `list` does not ask
the helper and leaves it out.

A profile whose VPN type this version does not know (made by a newer PassTunnel) is listed with its stored `type` and
`"needs_newer_version" : true` (left out otherwise); its settings read as empty. Commands and tools that use it fail with
`config_invalid`, except `rm`, which deletes it.

### ProfileStatus

From `status`, `connect`, `disconnect`, `toggle` and the MCP tools `get_status`, `connect`,
`disconnect`.

```json
{
  "auto_reconnect" : false,
  "duration_seconds" : 4210,
  "id" : "work",
  "ip" : "10.8.0.6",
  "is_default" : true,
  "name" : "Work",
  "protected" : true,
  "since" : "2026-10-21T08:14:03Z",
  "state" : "connected",
  "type" : "openvpn"
}
```

`state` is `disconnected`, `connecting` or `connected`. Present only when they apply: `phase`
(while connecting, in the user's language), `ip`, `since`, `duration_seconds`, `health`
(`reachable` / `unreachable`, only from a process that runs health checks), `error` (why the last
attempt in this process failed) and `failure` (the same as a [ConnectionFailure](#connectionfailure);
also after a cancelled attempt, which has no `error`), `warning` (connected, but part of the network
setup failed), `status_unavailable` (connected, but the management interface did not answer: `ip`
and `since` may be stale) and `warnings` (only in the result of `connect`: a list of
[ConnectWarning](#connectwarning)). While the app tries a server that did not answer again (every 30 s, at most 10
tries; also when this process is the CLI or the MCP server, as long as the app runs): `tries` (how many
found it unreachable, counted from zero again when the network changes) and `next_try_at` (absent while a
try runs and while the computer is offline: the next try then starts when the network is back). `passtunnel
disconnect ID` stops those tries.

```json
{
  "auto_reconnect" : false,
  "id" : "work",
  "is_default" : true,
  "name" : "Work",
  "next_try_at" : "2026-10-25T09:42:50Z",
  "protected" : false,
  "state" : "disconnected",
  "tries" : 3,
  "type" : "openvpn"
}
```

### ConnectWarning

Something to know about a `connect` that went ahead anyway: `warnings` in the ProfileStatus a `connect`
(or a `toggle` that connects) returns (CLI with `--json`, and the MCP tool), always an array of objects, left out when there is none. The
connection is never refused for it; the CLI also prints it on stderr.

```json
{
  "all_traffic" : [
    "lab"
  ],
  "domains" : [
    "example.com"
  ],
  "kind" : "overlap",
  "name" : "Work",
  "routes" : [
    "10.9.0.0/16"
  ],
  "with" : "work"
}
```

`kind` `overlap`: the profile `with` (its id; `name` is what it is called) is connected, and its tunnel
takes over some of the same networks or DNS names as the profile being connected, so traffic for them
goes through only one of the two tunnels. `routes`: the networks both send through their tunnel (CIDR,
IPv4 and IPv6; where one holds the other, the narrower), `domains`: the DNS names both look up through
theirs (equal, or one inside the other: `corp.example.com` is inside `example.com`, `notexample.com` is
not), `all_traffic`: the profiles (ids) among the two that send all traffic through their tunnel, when any
does (that meets whatever the other takes over). What a tunnel takes over comes from the profile's
`route`, `redirect-gateway`, `dhcp-option` and `dns` lines and from what its server pushed (or, for
FortiGate, handed out and routed) the last time it connected, so a profile that has not connected yet is
compared by its own lines only. New kinds may be added.

### ConnectionFailure

Why a connect failed: `failure` in ProfileStatus and in the error object of a failed `connect` (CLI
and MCP).

```json
{
  "at" : "2026-10-25T09:41:02Z",
  "code_seconds_left" : 22,
  "code_sent" : true,
  "credentials_sent" : true,
  "kind" : "auth_rejected",
  "reply" : "AUTH_FAILED"
}
```

| `kind` | Error code | When |
|---|---|---|
| `auth_rejected` | `credentials_rejected` | The server refused the sign-in (OpenVPN `AUTH_FAILED`, openfortivpn "Could not authenticate"). It is never retried, also not by the automatic reconnect: retrying could lock the account |
| `host_not_found` | `host_not_found` | The server's name could not be resolved |
| `unreachable` | `server_unreachable` | The server did not answer: connection refused or timed out, no route, no TLS answer in time. The sign-in was not sent |
| `configuration` | `config_invalid`, `connect_failed`, `credentials_missing`, … | The configuration, a key or the server's certificate was refused (OpenVPN `Options error`, `VERIFY ERROR`; openfortivpn's gateway certificate), or something the profile needs is missing |
| `setup` | `connect_failed` | The tunnel came up, but its network setup failed |
| `timeout` | `timeout` | The sign-in was sent, but the tunnel did not come up in time |
| `cancelled` | `cancelled`, `auth_cancelled`, `connect_failed` | Stopped before it finished |
| `tool_unsupported` | `connect_failed` | The VPN tool does not run on this version of macOS: dyld stopped it at launch (`reason`: `Symbol not found: _strchrnul`, `Library not loaded: …`). Nothing was sent |
| `failed` | `connect_failed`, `helper_*`, … | Anything else |

`credentials_sent`: the sign-in reached the server (OpenVPN finished the TLS handshake, which sends
it; openfortivpn connected to the gateway; or the server answered it). `code_sent`: a one-time code
went with it, so that code's period is used up; when it did not, PassTunnel gives the period back and
the next connect sends a code at once (not after `cancelled`). Present only when they apply: `reply` (the server's answer,
`auth_rejected`), `reason` (the VPN tool's words, e.g. `Connection refused`, `Name or service not
known`, `certificate has expired`), `code_seconds_left` (the code's seconds left when it was sent),
`tries` (`unreachable`), `clock` (`auth_rejected`: a [ClockOffset](#clockoffset), how far the clock was
off when it was measured after the rejection or checked on request since; see below). `reply` and
`reason` pass through the same redaction as `log --json`. New kinds may be added.

After a FortiGate rejects a sign-in, the process that sent it asks the gateway for its time (one
`HEAD /` request over TLS, trusted as openfortivpn trusts the gateway; at most 5 s), so a wrong clock
can be told from a wrong password. A failed `connect` waits for that check before it reports the
failure. OpenVPN servers tell no reliable time: their `clock` comes only from `diagnose --check-clock`
(on request) in the same process. Linux does not ask the gateway (docs/LINUX.md).

### ClockOffset

How far this computer's clock is from a time source: `clock` in ConnectionFailure and in
[DiagnoseReport](#diagnosereport).

```json
{
  "checked_at" : "2026-10-25T09:41:03Z",
  "offset_seconds" : 48,
  "server" : "vpn.example.com",
  "source" : "gateway"
}
```

`offset_seconds`: the source's time minus this computer's, in whole seconds; positive when this
computer's clock is behind, negative when it is ahead. From 15 s either way, one-time codes made
from this clock are likely refused. `source`: `gateway` (the FortiGate gateway's HTTP `Date`, after a
rejected sign-in) or `time_server` (SNTP, only on request: `time.apple.com` on the Mac, the NTP
server the system is set up with on Linux). `server`: the host that was asked. `checked_at`: when,
by this computer's clock. New sources may be added.

### HelperReport

From `helper status` and inside the MCP tools `get_status` and `diagnose`.

```json
{
  "expected_protocol_version" : 3,
  "outdated" : false,
  "protocol_version" : 3,
  "responding" : true,
  "state" : "enabled"
}
```

`state`: `enabled`, `requires_approval`, `not_installed` or `missing_from_bundle`. `error` says why
it did not answer. On Linux the report is about the daemon `passtunneld`: `enabled` when its socket
exists, `not_installed` otherwise, and `outdated` when it speaks another protocol or is not the build
installed with this `passtunnel` (restart it).

### SecretStoreReport

Linux only: from `secret-store` and, as `secret_store`, inside the MCP tool `diagnose`.

```json
{
  "available" : true,
  "chosen_by" : "recorded",
  "name" : "secret-service",
  "setting" : "auto"
}
```

`name`: the store in use, `secret-service`, `systemd-creds` or `file` (or the unknown value of
`PASSTUNNEL_SECRET_STORE`). `available`: it can be used from this process now (a Secret Service that
answers, systemd 256 or later for a user, a passphrase that can be had for the file). `setting`: `auto`
or a store's name. `chosen_by`: `environment` (`PASSTUNNEL_SECRET_STORE`), `setting`, `recorded` (where
the first secret was saved) or `auto` (detected, nothing recorded yet). `error` says why it is not
available.

### DiagnoseReport

From `diagnose` and the MCP tool `diagnose`: the installation and what would stop each profile from
connecting, without connecting and without any secret's value.

```json
{
  "app_path" : "/Applications/PassTunnel.app",
  "build" : "45",
  "helper" : { "expected_protocol_version" : 3, "protocol_version" : 3, "responding" : true, "state" : "enabled" },
  "in_applications" : true,
  "network" : { "interface" : "wifi", "online" : true },
  "profiles" : [
    {
      "asks_for" : [],
      "clock" : { "checked_at" : "2026-10-25T09:41:03Z", "offset_seconds" : 48, "server" : "vpn.example.com", "source" : "gateway" },
      "id" : "work",
      "name" : "Work",
      "ok" : true,
      "password_saved" : true,
      "problems" : [],
      "protected" : false,
      "server" : "vpn.example.com",
      "totp_saved" : true,
      "type" : "forti"
    }
  ],
  "tools" : [
    { "name" : "openvpn", "ok" : true, "version" : "OpenVPN 2.7.8 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [MH/RECVDA] [AEAD]" },
    { "name" : "openfortivpn", "ok" : true, "version" : "1.24.1" }
  ],
  "version" : "1.2.0"
}
```

`helper`: a [HelperReport](#helperreport). Per profile: `ok` (nothing found that would stop a
connect; the server can still refuse it), `server`, `protected`, `password_saved` / `totp_saved`
(whether, never the value), `asks_for` (fields asked on every connect: `username`, `password`, `otp`),
`problems` (error objects), and `clock`, the profile's last [ClockOffset](#clockoffset) when there is
one (any process's; a FortiGate gateway's after a rejected sign-in). Linux adds `secret_store`, a
[SecretStoreReport](#secretstorereport). With `--check-clock` (MCP: `check_clock: true`) the time
server is asked as well: `clock` is its ClockOffset, or `clock_error` says why it could not be
measured. Without it, `diagnose` contacts nothing. `network`: whether the computer is online
(`online`) and over what kind of interface (`interface`: `wifi`, `ethernet`, `cellular` or `other`), as the
system sees its network path (macOS `NWPathMonitor`; Linux the routes and links); both absent when it is
not known. Finding out contacts nothing either. `tools` (the Mac, in an app bundle): each VPN tool of the
app run with `--version` as the user (no input, an empty environment, at most 10 s, nothing contacted):
`ok` and `version` (the first line it printed), or `problem` saying why it did not start, such as
"This VPN tool does not run on this version of macOS (Symbol not found: _strchrnul). …" when dyld
stopped it.

### LogReport

From `log ID --json` and the MCP tool `get_logs`.

```json
{
  "id" : "work",
  "lines" : [
    "Peer Connection Initiated with [AF_INET]203.0.113.10:1194",
    "Initialization Sequence Completed"
  ],
  "source" : "raw",
  "truncated" : true
}
```

`source` is `raw` for the VPN tool's log (OpenVPN or openfortivpn output of the current or last
session) and `activity` for `log ID --activity` / `get_logs` with `source: "activity"`: the profile's
activity log, what PassTunnel did and saw, also for sessions the app or another terminal started. Then
`lines` words each event in the user's language with its local time ("2026-10-25 09:41:02  Connecting
to vpn.example.com:1194 (UDP)") and `events` has the same events as [ActivityEvent](#activityevent)
objects, oldest first. `truncated`: the log has more lines (or events) than were returned. In both,
anything that looks like a credential is replaced by `<redacted>`.

### ActivityEvent

One event of the activity log (`profiles/<id>/activity.jsonl`, the last 500 events): `at` (ISO 8601),
`event`, and the fields of that event.

```json
{
  "at" : "2026-10-25T09:41:02Z",
  "code" : true,
  "event" : "sending",
  "format" : "{password}{otp}",
  "password" : true,
  "seconds_left" : 22,
  "username" : "alice"
}
```

| `event` | Fields | When |
|---|---|---|
| `connecting` | `host`, `port` (absent when unknown), `protocol` (`udp`, `tcp`) | The VPN tool is started for this server (OpenVPN: the first `remote`) |
| `waiting_for_code` | `reason` (`used`: this period's code was already sent; `expiring`: 5 s or less left), `seconds` | The next one-time code is waited for |
| `sending` | `username`, `password` (a password was sent), `code` (a code was sent), `seconds_left` (the code's, from a TOTP secret), `format` (the template, e.g. `{password}{otp}`, or `separate`; only with a code) | The credentials were handed to the VPN tool |
| `auth_accepted` | | The server accepted the sign-in |
| `connected` | `address` (`""` when unknown) | The tunnel is up |
| `link_dropped` | `will_reconnect` | The connection ended without anyone stopping it |
| `reconnecting` | `attempt`, `of` | An automatic reconnect attempt starts |
| `unreachable` | `tries`, `reason` (the tool's words, e.g. `Connection refused`) | The server did not answer; the sign-in was not sent |
| `next_try` | `next_at` | The next automatic attempt starts then |
| `rejected` | `reply` (what the server answered, e.g. `AUTH_FAILED`; absent when it said nothing) | The server refused the sign-in; not retried |
| `failed` | `failure` (a [ConnectionFailure](#connectionfailure) `kind`: `host_not_found`, `configuration`, `setup`, `timeout`, `tool_unsupported` or `failed`), `reason`, `credentials_sent` | The attempt failed otherwise |
| `stopped_by_user` | | A connect, a code wait or the automatic reconnects were stopped |
| `disconnected_by_user` | | A connection that was up was ended |

Never a password and never a code digit: the file keeps at most the first three digits of a code
for the app, and the CLI and the MCP server leave them out. New kinds of events may be added; skip
the ones you do not know.

## Commands

| Command | `--json` result |
|---|---|
| `status` | array of ProfileStatus |
| `status ID` | ProfileStatus (exit 3 when not connected) |
| `connect [ID] [--force] [--wait] [--timeout S]` | ProfileStatus after connecting, with [`warnings`](#connectwarning) when tunnels overlap; already connected: its status |
| `disconnect [ID] [--wait] [--timeout S]` | ProfileStatus |
| `disconnect --all [--wait]` | array of ProfileStatus |
| `toggle [ID]` | ProfileStatus |
| `code [ID] [-c]` | `{"profile": "work", "code": "123456", "remaining": 17, "period": 30}` |
| `list` | array of ProfileSummary |
| `show ID` | `{"profile": {…settings…}, "is_default", "password_saved", "totp_saved", "password_encrypted", "totp_encrypted", "config_file", "remote"}` |
| `set ID key=value…` | the `show` object after the change |
| `add NAME --type T` | ProfileSummary of the new profile |
| `import FILE` | ProfileSummary of the new profile with `skipped` (below) |
| `export ID [-o FILE]` | `{"id": "work", "path": "/Users/alice/work.passtunnel"}` |
| `rm ID --yes` | `{"id": "work", "deleted": true}` |
| `secret ID password\|totp` | `{"id": "work", "secret": "totp", "saved": true, "encrypted": false}`, never the value or a code |
| `secret-store [STORE]` | Linux only: SecretStoreReport, after saving STORE when given (exit 1 when the store is not available) |
| `default [ID]` | `{"default": "work"}`; `null` and exit 1 when none is set |
| `pin ID`, `unpin ID` | ProfileSummary |
| `log ID [-n N]` | LogReport: `{"id": "work", "lines": […], "source": "raw", "truncated": false}`, the last N lines (at most 500) |
| `log ID --activity [-n N]` | LogReport with `"source": "activity"` and `events`, the last N events (at most 500) |
| `diagnose [--check-clock]` | DiagnoseReport; `--check-clock` asks the time server too (exit 0 also when that fails: `clock_error`) |
| `helper status` | HelperReport (exit 5 unless enabled, answering and current) |
| `version` | `{"version": "1.1.0", "build": "12", "app_path": "/Applications/PassTunnel.app", "helper_protocol_version": 3}` |

`import` adds `skipped` to the ProfileSummary: the lines of an `.ovpn` that PassTunnel left out of the
stored configuration (kept there as comments, see
[SECURITY.md](../SECURITY.md#importing-an-openvpn-configuration)); empty for a `.passtunnel` file.

```json
"skipped" : [
  {
    "directive" : "up",
    "line" : 5,
    "reason" : "program",
    "text" : "up /etc/openvpn/update-dns"
  }
]
```

`line` is the line number in the file; `directive` is the directive as the sanitizer names it (`up`,
`setenv PATH`); `text` is the line, trimmed, with control characters shown as `�` and cut to 232 bytes.
`reason` is one of `program` (runs a program), `script_security` (a level above 1),
`dns` (a DNS script), `process` (how OpenVPN runs, or a file it writes as root), `logging`,
`management` and `environment` (a `setenv` for scripts). A line that refuses the file fails the
command with `config_invalid` instead, its message listing every such line.

`connect`, `disconnect` and `toggle` always waited for the result; `--wait` makes that explicit and
`--timeout` bounds it. A `connect` that runs out of time stops the half-started connection and
fails with `timeout`; a connection that was already on its way (started in the app or another
terminal) is left alone. `log --json` drops OpenVPN's notes about PassTunnel's own management
polls and replaces anything that looks like a credential with `<redacted>`; `log -f` cannot be
combined with `--json` or `--activity`. `helper install` and `helper uninstall` have no JSON output.

### Examples

```sh
# Connect, wait at most 90 s, fail instead of asking anything
passtunnel connect work --timeout 90 --no-input --json

# Is it up? (exit 0 connected, 3 not connected)
passtunnel status work --json | jq -r .ip

# Unattended: never show Touch ID; protected profiles fail with auth_unavailable (exit 4)
PASSTUNNEL_NO_INPUT=1 passtunnel connect work --no-auth-prompt --wait
```
