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
- [Objects](#objects): [ProfileSummary](#profilesummary), [ProfileStatus](#profilestatus), [HelperReport](#helperreport), [SecretStoreReport](#secretstorereport), [LogReport](#logreport), [ActivityEvent](#activityevent)
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
| 6 | Connecting failed | `connect_failed`, `credentials_rejected`, `credentials_missing`, `other_vpn_active`, `destination_changed` |
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
(English or Turkish).

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
| `credentials_rejected` | The server refused the sign-in |
| `credentials_missing` | No saved password or TOTP secret |
| `other_vpn_active` | Another VPN already routes all traffic (`connect --force` overrides) |
| `destination_changed` | The server settings changed after you confirmed: connect again and confirm |
| `timeout` | `--timeout` passed, or the VPN tool's own limit |
| `config_invalid` | Missing or rejected OpenVPN configuration, missing FortiGate server, unreadable file |
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
attempt in this process failed), `warning` (connected, but part of the network setup failed) and
`status_unavailable` (connected, but the management interface did not answer: `ip` and `since` may
be stale).

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
| `unreachable` | `tries` | The server did not answer |
| `next_try` | `next_at` | The next automatic attempt starts then |
| `rejected` | `reply` (what the server answered, e.g. `AUTH_FAILED`; absent when it said nothing) | The server refused the sign-in; not retried |
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
| `connect [ID] [--force] [--wait] [--timeout S]` | ProfileStatus after connecting; already connected: its status |
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
