# Contributing to PassTunnel

Issues and pull requests are welcome. For anything larger than a small fix, open an issue first so
the approach can be agreed on before you write the code.

Before changing code, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (targets, storage, helper
protocol, security rules) and [docs/APP.md](docs/APP.md) (app and CLI behavior). The
[Contributing section of the README](README.md#contributing) lists the rules for code: new VPN
backends, localized strings, no third-party dependencies besides Sparkle and swift-crypto.

## Branches

| Branch | What it is |
|---|---|
| `dev` | The default branch. All work is merged here first. |
| `main` | What was released. It only takes pull requests from `dev`, and every merge into it can produce a release. |
| `feat/123-short-name`, `fix/123-short-name`, … | One branch per issue, created from `dev`. |

1. Pick or open an issue. Create the branch from `dev`, named after the type and the issue number
   (GitHub's *Create a branch* button on the issue works; change the base to `dev` if needed).
2. Commit as you like on the branch. Commits must be signed (`main` and `dev` refuse unsigned
   commits; GitHub signs the squash commit when the pull request is merged).
3. Open a pull request into `dev`. Link the issue in the description with `Closes #123` (or
   `Fixes`, `Resolves`; `Refs #123` when the issue stays open).
4. New functionality and bug fixes come with tests (XCTest, in `Tests/`) that fail without the
   change; `swift test` must pass. Tests never touch real data: see the README section
   "Building and testing".
5. The checks must pass: `Build and test` (`swift build` and `swift test` on macOS, and
   PassTunnelKit built for iOS), `Linux (x86_64)` and `Linux (aarch64)` (the Linux targets built and
   tested, and the `passtunnel` command tried, see [Linux](#linux)), `Release scripts`, `Site` (the
   website's static checks) and `PR title`. Review comments must be resolved.
6. The pull request is **squash-merged**: its title becomes the one commit on `dev`.

Releases are made by merging `dev` into `main` (a pull request from `dev`, merged with a merge
commit). See [Releases](#releases).

## Pull request titles

The title is the commit message on `dev`, it decides the next version number, and it is the line
users read in the release notes and in the update window. It follows
[Conventional Commits](https://www.conventionalcommits.org/):

```
type(optional scope): description
```

| Type | Use it for | Release |
|---|---|---|
| `feat` | something new for users | minor (1.4.2 → 1.5.0) |
| `fix` | a bug fix for users | patch (1.4.2 → 1.4.3) |
| `perf` | faster or lighter, same behavior | patch |
| `docs`, `refactor`, `test`, `build`, `ci`, `chore`, `style`, `revert` | everything else | none |

Add `!` after the type (`feat!: …`) for a change that breaks existing setups (profiles, CLI output,
MCP tools); that makes a major release.

Write the description for users, in the imperative, without a final period:

- `feat: fill in the one-time code for GlobalProtect`
- `fix(cli): exit with 3 when a profile does not exist`
- `perf: start the helper without waiting for the status poll`

The `PR title` check runs again when you edit the title, so a wrong title is fixed by renaming
the pull request.

## Releases

Merging `dev` into `main` starts the release workflow. It reads the commit subjects since the last
release: a `feat`, `fix`, `perf` or breaking change makes a release, otherwise nothing is released.
The release notes are those subjects, grouped into breaking changes, new features and fixes. The
maintainer approves the release job, which then builds, signs, notarizes and publishes everything
(the app, the Sparkle update, the MCP bundle, the MCP Registry entry and the Homebrew cask).
Details are in [docs/RELEASING.md](docs/RELEASING.md).

## Website

The website at <https://passtunnel.github.io/> is the static page in [`site/`](site/). Its
rules (no scripts or styles inline, facts only, real screenshots from the app's renderer), the
checks and how to preview it and regenerate its images are in [docs/WEBSITE.md](docs/WEBSITE.md).
Site changes follow the same flow as code (a `docs:` pull request into `dev`); the `Site` check runs
`scripts/check-site.sh`, and the site is deployed with the next release merge into `main`: the
`Publish site` workflow hands that commit to
[PassTunnel/passtunnel.github.io](https://github.com/PassTunnel/passtunnel.github.io), which serves
the root of the host.

## Linux

The `passtunnel` command (the CLI and the MCP server) and the code under it also build on Linux
([docs/LINUX.md](docs/LINUX.md)): PassTunnelKit, PassTunnelVPNConfig, PassTunnelShared,
PassTunnelCore, the CLI library PassTunnelCLI and the Linux-only executable target
PassTunnelCommand, whose product is `passtunnel`; the macOS app and helper are not built there.
Linux also builds the root daemon: the library PassTunnelDaemon and the executable
PassTunnelDaemonCommand, whose product is `passtunneld`. The
`Linux` checks build all of it, run the tests that build on Linux (`PassTunnelKitTests` with the golden
cases, `PassTunnelCoreTests` without the Apple-only ones, and `PassTunnelDaemonTests`) in the official
Swift container on x86_64 and aarch64, and try the built `passtunnel`: `--version`, `list --json` and
an MCP session. Then, as root in the container, they start `passtunneld` and talk to it (see below).
To do the same locally with Docker, from the repository root:

```sh
docker run --rm -v "$PWD":/src -w /src swift:6.4.1-noble swift test

# A shell in the container, then build and run passtunnel with its own support directory:
docker run --rm -it -v "$PWD":/src -w /src swift:6.4.1-noble bash
swift build
export PASSTUNNEL_HOME=$(mktemp -d)       # instead of ~/.local/share/passtunnel
"$(swift build --show-bin-path)/passtunnel" list --json
"$(swift build --show-bin-path)/passtunnel" mcp      # JSON-RPC lines on stdin
```

A development build reports version `0.0.0-dev`. Until the later steps of the Linux plan, it has no
secret store (saving a password or TOTP secret fails with `keychain_error`; the tests keep secrets in
memory, `PASSTUNNEL_SECRET_STORE=memory`, which only debug builds accept), and without a running
`passtunneld` connecting fails with `helper_not_installed`.

The daemon runs as root and refuses to start from a file that anyone but root could replace (every
directory above it root-owned and not group- or world-writable), so it is installed first. In the
container, which has its own `/run/passtunnel`:

```sh
swift build
install -m 0755 "$(swift build --show-bin-path)/passtunneld" /usr/local/sbin/passtunneld
/usr/local/sbin/passtunneld &              # its own socket: /run/passtunnel/daemon.sock
"$(swift build --show-bin-path)/passtunnel" helper status --json
apt-get update && apt-get install -y socat openvpn
printf '%s\n' '{"op":"hello"}' | socat - UNIX-CONNECT:/run/passtunnel/daemon.sock
groupadd --system passtunnel               # root and this group may start connections
```

Under systemd the daemon is started by `packaging/linux/passtunnel.socket` (socket activation); the
unit files are not installed by anything yet. The tests never touch `/run/passtunnel`: they run the
daemon's library with a temporary run root, home and user database, and a shell script in place of
openvpn. The CI step "Smoke-test passtunneld" shows a full session with the distribution's openvpn.

Code in these targets must keep building on Linux, without changing what the Mac does: Linux code
goes in the same files behind `#if os(Linux)` / `#if canImport(…)` (the seams are listed in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#targets)), CryptoKit is swift-crypto's `Crypto` there,
Combine is a small stand-in in PassTunnelCore, and `String(localized:)` is an English-only stand-in.
A test file that needs an Apple-only framework goes behind `#if os(macOS)` (the whole file, or the
tests that need it), so the rest of `PassTunnelCoreTests` keeps running on Linux.

## Dependabot

Dependabot opens pull requests into `dev` for GitHub Actions (`ci: …`, no release) and for Swift
packages (`fix(deps): …`, a patch release, since those ship in the app). They need no issue link.

## Fuzzing

The code that parses untrusted text is fuzzed with libFuzzer. The harnesses live in their own
package under [`fuzz/`](fuzz/) (one per target: the OpenVPN config sanitizer, FortiGate config
rendering, the OpenVPN management-interface parser, `otpauth://` URIs and MCP JSON-RPC decoding).
That package is not part of the app: `swift build` and `swift test` at the repository root never
build it, and nothing in it ships in any binary. It links the parsing libraries of the main package
so the fuzzers run the exact sources the app and the helper use.

libFuzzer needs the open-source Swift toolchain — the one in Xcode has no libFuzzer runtime on
macOS. Install a toolchain from [swift.org/install](https://www.swift.org/install/macos/), then:

```sh
# Use the open-source toolchain for this shell (id from: ls /Library/Developer/Toolchains).
export TOOLCHAINS=$(plutil -extract CFBundleIdentifier raw \
    /Library/Developer/Toolchains/swift-latest.xctoolchain/Info.plist)

fuzz/run.sh                     # 60 s per fuzzer
fuzz/run.sh 300                 # 300 s per fuzzer
fuzz/run.sh 300 FuzzOVPNSanitizer   # just one
```

`run.sh` builds with `-sanitize=fuzzer,address` and runs each harness against the seed corpus in
`fuzz/corpus/`. A failing input is copied into `fuzz/findings/` and the run exits non-zero. The
`Fuzz` workflow runs the same script briefly on pull requests that touch the parsers and longer on a
weekly schedule.

A crash is a bug: fix it in its own commit with a regression test (an XCTest in `Tests/`), add the
reproducing input to the seed corpus, and — if the fix changes the sanitizer — keep the rules in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [SECURITY.md](SECURITY.md) true.
