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
   change; `swift test` must pass ([Tests](#tests)). Tests never touch real data: see the README
   section "Building and testing".
5. The checks must pass: `Build and test` (`swift build` and `swift test` on macOS, and
   PassTunnelKit built for iOS), `Linux (x86_64)` and `Linux (aarch64)` (the Linux targets built and
   tested, and the `passtunnel` command tried, see [Linux](#linux)), `Release scripts`, `Site` (the
   website's static checks) and `PR title`. `Linux release` and `Docker image` (the Linux tarball and
   the Dockerfile, built and tried on both architectures) run as well. Review comments must be
   resolved.
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

The scope is optional and free (`cli`, `mcp`, …), except `linux`: it marks work on the Linux version
([docs/LINUX.md](docs/LINUX.md)), such as `feat(linux): …` or `fix(linux): …`. Linux has no release
yet, so these pull requests make no release of the app and are left out of its release notes, also
with `!`. Phase 3 of [docs/LINUX.md](docs/LINUX.md#phases), which releases Linux, revisits this.

Write the description for users, in the imperative, without a final period:

- `feat: fill in the one-time code for GlobalProtect`
- `fix(cli): exit with 3 when a profile does not exist`
- `perf: start the helper without waiting for the status poll`

The `PR title` check runs again when you edit the title, so a wrong title is fixed by renaming
the pull request.

## Coding standards

- **Swift.** Follow the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/)
  for names and signatures, and match the style of the file you change (indentation, line length,
  naming, comment density). The package builds in Swift language mode 5 with tools 5.10, uses macOS 13
  APIs, and has no dependencies beyond Sparkle and swift-crypto, each pinned to an exact version in
  `Package.swift`.
- **Warnings.** A change adds no compiler warnings. Treat the output of `swift build` as part of the
  review; do not silence a warning without a reason in the code.
- **Language.** English identifiers and sparse English comments. Every user-facing string goes
  through `String(localized:)` and has a Turkish translation in `Localizable.xcstrings`;
  `LocalizationTests` fails otherwise ([docs/APP.md](docs/APP.md#localization)).
- **Accessibility.** Controls have a localized accessibility label
  ([docs/APP.md](docs/APP.md#accessibility)).
- **Security rules.** Code that runs as root, parses untrusted text or handles secrets follows
  [Rules for all code](docs/ARCHITECTURE.md#rules-for-all-code) and the rules in
  [SECURITY.md](SECURITY.md); it never runs a client-supplied path or raw configuration.
- **Content.** No company or customer names and no real host names in code, tests, docs or
  screenshots (use `Acme`, `vpn.example.com`).
- **Shell and workflows.** Scripts are Bash and pass `shellcheck` where CI runs it (the site
  scripts); GitHub Actions are pinned to full commit SHAs.

There is no automatic formatter or linter for Swift in the repository yet, so these standards are
checked in review, against the pull request checklist
([`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)).

## Tests

**Policy: new functionality and bug fixes come with automated tests, and a pull request without them
is not merged.** This is checked in review by the maintainer and by the checklist item
"New functionality or the fixed bug is covered by a test" in every pull request.

- **New functionality** gets tests for its behavior and its failure cases, in the same pull request.
  A change to something the phone apps share (codes, `otpauth://` links, OpenVPN configurations,
  share files, profile merging) also updates the golden cases in [`fixtures/`](fixtures/README.md).
- **A bug fix** gets a regression test that fails without the fix. A fix for a crash found by the
  fuzzers also adds the input to the seed corpus ([Fuzzing](#fuzzing)).
- **A change to the helper or the sanitizer** adds tests for what it now allows and refuses, and keeps
  [SECURITY.md](SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) true.
- **Documentation, website and CI-only changes** need no unit test, but must pass their checks
  (`Site`, `Release scripts`).
- **How.** XCTest in `Tests/` (`PassTunnelCoreTests`, `PassTunnelKitTests`, `PassTunnelDaemonTests`);
  run `swift test` (see [Building and testing](README.md#building-and-testing)). Tests never touch
  your real Keychain, support folder, a live VPN, a gateway or a time server; they use the isolation
  described in [Rules for all code](docs/ARCHITECTURE.md#rules-for-all-code).
- **When.** The `Build and test` and `Linux` checks run the whole suite on every pull request and on
  every push to `dev`, and a pull request cannot be merged while they fail. Unit tests that build on
  Linux run there too ([Linux](#linux)).

## Reporting bugs and asking for features

Use the [issue tracker](https://github.com/PassTunnel/passtunnel/issues). Search first, then pick
the **Bug report** or **Feature request** form, which asks for the PassTunnel version, how it was
installed, the macOS version, the VPN type and a log. Remove host names, user names, IP addresses and
anything you would not post publicly from logs, and never paste passwords, TOTP secrets,
`otpauth://` links or private keys.

**Security problems are not reported in the tracker.** Use the private channel in
[SECURITY.md](SECURITY.md#reporting-a-vulnerability). Questions about conduct go to the channel in
the [Code of Conduct](CODE_OF_CONDUCT.md#enforcement). How the project decides what to do with an
issue: [GOVERNANCE.md](GOVERNANCE.md#decision-making); what is planned: [ROADMAP.md](ROADMAP.md).

## Contributions and license

PassTunnel is under the [MIT License](LICENSE). By opening a pull request you state that you wrote the
change (or have the right to submit it) and that it may be distributed under that license; you keep
your copyright. Do not submit code you took from a project under an incompatible license (the mobile
spec lists the engines that must not be copied from: [docs/MOBILE.md](docs/MOBILE.md#android-the-vpn-client)).
There is no contributor license agreement and no `Signed-off-by` requirement.
<!-- TODO(maintainer): decide whether to adopt the Developer Certificate of Origin (https://developercertificate.org/): require `Signed-off-by:` on commits, add a check to pull-request.yml, and replace the last sentence above. For silver (dco, a SHOULD) it is Unmet until then. -->

## Releases

Merging `dev` into `main` starts the release workflow. It reads the commit subjects since the last
release: a `feat`, `fix`, `perf` or breaking change makes a release, otherwise nothing is released
(one with the scope `linux` never does). The release notes are those subjects, grouped into breaking
changes, new features and fixes. The maintainer approves the release job, which then builds, signs,
notarizes and publishes everything (the app, the Sparkle update, the MCP bundle, the MCP Registry
entry and the Homebrew cask).
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

A development build reports version `0.0.0-dev`. Without a running `passtunneld` (below),
connecting fails with `helper_not_installed`. Secrets go to the Linux secret stores
([docs/LINUX.md](docs/LINUX.md#secrets)); in the container above that is the file store, so try it
with a passphrase file:

```sh
printf '%s\n' 'a long test passphrase' > /tmp/pp && chmod 600 /tmp/pp
export PASSTUNNEL_PASSPHRASE_FILE=/tmp/pp PASSTUNNEL_SECRET_STORE=file
"$(swift build --show-bin-path)/passtunnel" secret-store
```

The tests never use a real store: they keep secrets in memory (`PASSTUNNEL_SECRET_STORE=memory`,
which only debug builds accept), run the stores against fakes of `secret-tool` and `systemd-creds`
(those tests run on the Mac too) and the file store in a temporary directory. The Linux jobs add one
real Secret Service round trip in a throwaway session bus and keyring (`RealSecretServiceTests`,
skipped unless `PASSTUNNEL_TEST_SECRET_SERVICE=1`).

The daemon runs as root and refuses to start from a file that anyone but root could replace (every
directory above it root-owned and not group- or world-writable), so it is installed first. In the
container, which has its own `/run/passtunnel`:

```sh
swift build
install -m 0755 "$(swift build --show-bin-path)/passtunneld" /usr/local/sbin/passtunneld
/usr/local/sbin/passtunneld &              # its own socket: /run/passtunnel/daemon.sock
"$(swift build --show-bin-path)/passtunnel" helper status --json
apt-get update && apt-get install -y socat openvpn openfortivpn
printf '%s\n' '{"op":"hello"}' | socat - UNIX-CONNECT:/run/passtunnel/daemon.sock
groupadd --system passtunnel               # root and this group may start connections
```

Under systemd the daemon is started by `packaging/linux/passtunnel.socket` (socket activation); the
release tarball installs the unit files. The tests never touch `/run/passtunnel`: they run the
daemon's library with a temporary run root, home and user database, and shell scripts in place of
openvpn, openfortivpn and pppd. The CI step "Smoke-test passtunneld" shows full sessions with the
distribution's openvpn and openfortivpn.

The release tarball (`passtunnel` and `passtunneld` with the Swift runtime linked in, the units, a
README and the licenses; [docs/LINUX.md](docs/LINUX.md#distribution)) is built in the Swift image of
Ubuntu 22.04, for the architecture Docker runs:

```sh
docker run --rm -v "$PWD":/src -w /src swift:6.4.1-jammy scripts/build-linux.sh   # → dist/
```

The `Dockerfile` at the root builds an image that runs `passtunnel mcp` (for MCP directories):

```sh
docker build -t passtunnel .
docker run -i --rm passtunnel      # JSON-RPC lines on stdin
```

The `Linux release` and `Docker image` checks build both on x86_64 and aarch64, try the tarball in a
clean Ubuntu 22.04 container and run an MCP session with the image; the tarball is kept as an
artifact of the run.

Code in these targets must keep building on Linux, without changing what the Mac does: Linux code
goes in the same files behind `#if os(Linux)` / `#if canImport(…)` (the seams are listed in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#targets)), CryptoKit is swift-crypto's `Crypto` there
(and scrypt comes from its `CryptoExtras`), Combine is a small stand-in in PassTunnelCore, and
`String(localized:)` is an English-only stand-in.
A test file that needs an Apple-only framework goes behind `#if os(macOS)` (the whole file, or the
tests that need it), so the rest of `PassTunnelCoreTests` keeps running on Linux.

## Dependabot

Dependabot opens pull requests into `dev` for GitHub Actions (`ci: …`, no release) and for Swift
packages (`fix(deps): …`, a patch release, since those ship in the app), and for the base images of the
`Dockerfile` (`build(deps): …`, no release). They need no issue link. The images pinned in the Linux
CI jobs (`.github/workflows/ci.yml`) are not covered: Dependabot does not update `container:` images or
image names in workflow variables, so they are bumped by hand with the Dockerfile's build image.

## Fuzzing

The code that parses untrusted text is fuzzed with libFuzzer. The harnesses live in their own
package under [`fuzz/`](fuzz/) (one per target: the OpenVPN config sanitizer, the import review that
skips some of the lines it refuses, FortiGate config rendering, the OpenVPN management-interface parser,
`otpauth://` URIs and MCP JSON-RPC decoding).
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
