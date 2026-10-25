# Golden cases

The behavior the Mac app, the iPhone app and the Android app share, as JSON cases: TOTP codes,
`otpauth://` links, code formats, OpenVPN configs, `.passtunnel` share files, profile identifiers,
profile fields and merging ([docs/MOBILE.md](../docs/MOBILE.md), "Shared logic").

- `swift test` runs every case against `PassTunnelKit` (`Tests/PassTunnelKitTests/FixtureTests.swift`),
  so the files are always what the Mac app does.
- The Android port reads a copy pinned to a commit of this repository; its check fails when the copy
  is not that commit's `fixtures/`. Update the pin to take new cases.

## Format

Each file is one JSON object. `about` says what the file covers; every other key is a **group**: an
array of cases for one operation. A case is an object with

- `name` (optional) and `note` (optional): for people, never compared;
- the group's **inputs** (table below);
- **every** output of the operation. The test runs the operation on the inputs and compares the
  complete set of outputs, so an output can be neither missing nor extra.

A failure is the output `error`: `{"kind": "…", "detail": "…"}`, `detail` only where the kind has one:

| `kind` | `detail` |
|---|---|
| `invalid_secret` | — |
| `invalid_otpauth_uri` | the reason, in English (the apps show it translated) |
| `hotp_not_supported` | — |
| `invalid_template` | the reason, in English |
| `unsupported_share_file` | — |
| `ovpn_referenced_file` | the path as written in the config |
| `ovpn_not_allowed` | none; `violations` lists the sanitizer's lines instead (`"line 8: up (not allowed)"`) |
| `invalid_field` | the field (canonical key) |
| `empty_name` | — |
| `wrong_profile_type` | the profile id (always `acme` here) |

Conventions: times are seconds since 1970 (fractions and negative values allowed); bytes are lower-case
hex (`secret_hex`, `hex`) or Base64 (`binary_files`); profiles use the keys of `profile.json`
(snake_case, see [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), "Model"), and a profile in an output
lists every field; `null` is "none". Invisible characters (BOM, no-break space, zero-width space, NUL
and other control characters, line separator) are written as `\uXXXX` escapes. Example hosts and names follow the repository's rules (`vpn.example.com`,
`203.0.113.x`, `Acme`, `alice`).

## Files

| File | Group | Inputs | Outputs | Swift |
|---|---|---|---|---|
| `totp.json` | `code` | `secret_hex`, `digits`, `period`, `algorithm` (`sha1`, `sha256`, `sha512`), `time` | `code` | `TOTP.code` |
| | `remaining` | `period`, `time` | `remaining` (seconds left in the window, 1…period) | `TOTP.remaining` |
| | `decode_secret` | `input` (what the user pastes) | `hex` or `error` | `TOTP.decodeSecret` |
| | `base32_encode` | `hex` | `base32` | `TOTP.base32Encode` |
| `otpauth.json` | `parse` | `uri` | `label`, `account`, `issuer`, `secret_hex`, `digits`, `period`, `algorithm`, or `error` | `OTPAuthURI` |
| `codes.json` | `presets` | `preset` | `template` | `OTPTemplatePreset` |
| | `validate_template` | `template` | `valid: true` or `error` | `OTPComposer.validate` |
| | `compose` | `password`, `otp` (or `null`), `delivery`, `template`, `type` | `secret` (what is sent as the password), `separate_otp` (FortiGate's code field, or `null`) | `OTPComposer.compose` |
| `ovpn-sanitizer.json` | `tokens` | `line` | `tokens` (`[]` for blank and comment lines, `null` for lines OpenVPN rejects) | `OVPNSanitizer.tokens(of:)` |
| | `sanitize` | `config` | `output` (the config to run; unchanged unless something is stripped), or `violations` (`line`, `directive`, `reason`) | `OVPNSanitizer.sanitize` |
| | `verbosity` | `config` | `verb` (or `null`) | `OVPNSanitizer.verbosity(of:)` |
| `ovpn-analyzer.json` | `analyze` | `config` | `password_mode`, `otp_mode`, `otp_delivery`, `remote`, `remotes`, `server_description`, `redirects_gateway` (`true`, `false` or `null`) | `OVPNAnalyzer` |
| `ovpn-inliner.json` | `inline` | `config`, `files` (path → text), `binary_files` (path → Base64) | `output` or `error` | `OVPNInliner.inline` |
| | `prepare` | same | `output` or `error` (inlined, then the sanitizer's check) | `OVPNInliner.prepare` |
| | `strip_credentials` | `config`, `blocks` (optional; default both) | `output`, `username`, `password`, `removed` (sorted) | `OVPNInliner.strippingCredentials` |
| `ovpn-import.json` | `review` | `config`, `files`, `binary_files` (as `inline`) | `stored` (the config an import stores, `null` when a line blocks it), `skipped` and `blocking` (`line` of the file as given, `directive`, `text`, `reason`: a skip reason code or the sanitizer's words), `servers` (`host`, `port`, `tcp`), `certificates` (`name`, `file` or `null`), `password_mode`, `otp_mode`, `otp_delivery`, `username`, `password`, `needs`; or `error` | `OVPNImportReport.make` |
| `share-files.json` | `decode` | `file` (the file's JSON; a string is the raw text) | `profile` (every field), `files` (name → text), or `error` | `ShareFile.decode` |
| | `encode` | `profile` (missing fields take their defaults), `files` (name → text) | `file` (the JSON written; `files` in Base64) | `ShareFile.data` |
| `slugs.json` | `make` | `profile_name`, `max_length` (optional, default 24) | `id` | `Slug.make` |
| | `suffixed` | `base`, `n` | `id` | `Slug.suffixed` |
| | `is_valid` | `id` | `valid` | `Slug.isValid` |
| `profile-merge.json` | `merge` | `original`, `edited`, `current` (profiles; missing fields take their defaults) | `merged` (every field), `changed_fields` | `ProfileMerge` |
| `profile-fields.json` | `set` | `type`, `key`, `value` (on a new profile `acme`) | `canonical_key`, `stored` (the value as `passtunnel show` prints it), or `error` | `ProfileFields.set` |

`inline`, `prepare` and `review` write `files` and `binary_files` into a new temporary folder: the
config's folder is `config/` in it, so `../shared/ca.crt` is a file next to that folder. Paths are always
relative.

`review` is the import of an `.ovpn` ([SECURITY.md](../SECURITY.md#importing-an-openvpn-configuration)):
a line the sanitizer refuses is either skipped, and stored as the comment `# PassTunnel skipped: <text>`,
or blocks the file. `text` is the line trimmed, at most 232 bytes of UTF-8 (cut with "…"), with control
characters, line separators and bidirectional formatting shown as U+FFFD and tabs as spaces. The skip
`reason` codes are `program`, `script_security`, `dns`, `process`, `logging`, `management` and
`environment`.

`make` folds Turkish letters itself, then transliterates with ICU's `Any-Latin; Latin-ASCII` (Android:
`android.icu.text.Transliterator`, API 29).

Not here, on purpose: FortiGate config rendering (no FortiGate on the phones yet), the secret envelope
(keys never leave a device), the Keychain, and what the Mac's `ProfileStore` does on import and save
(which share-file fields it takes, range checks); see [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).

## Adding or changing cases

1. Change the behavior in `PassTunnelKit` with its unit tests, as usual.
2. Add or update the cases here, with the values the Swift code gives. Never write down what the code
   should do but does not: the code is the reference, and a disagreement is a bug to fix in the code
   first.
3. `swift test` must pass. A new file or group also needs its operation in
   `Tests/PassTunnelKitTests/FixtureRunner.swift`, and a row in the table above.
4. Android takes the change by moving its pinned copy to the new commit, and fixes its code until its
   tests pass.
