# Roadmap

What PassTunnel intends to do, and not to do, over the next twelve months (from October 2026). It is
a statement of intent by a single maintainer ([GOVERNANCE.md](GOVERNANCE.md)), not a promise: there
are no dates, and the order can change. The issues linked below are where the details and the
decisions are; a feature is only "done" when its pull request is merged and released.

## Planned

| Area | What | Where |
|---|---|---|
| More VPN types | OpenConnect as a backend (Cisco AnyConnect, GlobalProtect, Pulse/Ivanti), bundled and signature-checked like `openvpn` and `openfortivpn`, with import and validation rules documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [SECURITY.md](SECURITY.md) | [#2](https://github.com/PassTunnel/passtunnel/issues/2) |
| Intel Macs | A universal build of app, helper and CLI, with x86_64 slices of the bundled tools, and CI and release on both architectures. The fallback without a Secure Enclave must stay safe | [#3](https://github.com/PassTunnel/passtunnel/issues/3) |
| Shortcuts and Siri | App Intents for connect, disconnect and status, under the same confirmation rules as the menu bar and CLI | [#4](https://github.com/PassTunnel/passtunnel/issues/4) |
| Linux | The command line and MCP server and the root daemon are built and tested in CI; next are packages (polkit, systemd units, apt and dnf repositories, release automation) and, after them, a desktop app | [#5](https://github.com/PassTunnel/passtunnel/issues/5), [docs/LINUX.md](docs/LINUX.md#phases) |
| Mobile | An Android VPN client and an iPhone companion in their own repositories, sharing the code and test fixtures of this one. Android first ships codes and profiles, then the VPN; the iPhone gets AutoFill, App Intents and widgets later | [docs/MOBILE.md](docs/MOBILE.md#phases) |

Ongoing, not tied to an issue:

- Security fixes for the latest release, following [SECURITY.md](SECURITY.md#how-reports-are-handled).
- Keeping the bundled `openvpn`, `openfortivpn` and their libraries current: the pinned versions in
  [`scripts/release.env`](scripts/release.env) are moved by pull request, and Dependabot proposes
  updates for GitHub Actions, Swift packages and the Docker base images.
- Keeping the documentation true to the code (the pull request checklist asks for it).
- Meeting the remaining [OpenSSF Best Practices](https://www.bestpractices.dev/projects/15779)
  criteria that need code or CI changes (stricter compiler warnings, test coverage measurement,
  dynamic analysis), separate from this documentation work.

## Not planned

- **A service of our own.** No accounts, no sync server, no analytics, no telemetry. The app talks
  only to the VPN servers, hosts the user sets up, and GitHub for updates
  ([SECURITY.md](SECURITY.md#network-connections)). Sync between devices would be its own decision,
  and today's design keeps secrets out of iCloud on purpose.
- **Running scripts or arbitrary options from a profile as root.** The sanitizer and the typed
  FortiGate fields stay strict ([SECURITY.md](SECURITY.md#openvpn-configuration-sanitizer)); a feature
  that needs a refused directive is a new backend with its own rules, not a relaxed rule.
- **FortiGate IPsec/IKEv2.** Its one-time-code prompts use extensions only FortiClient implements
  ([docs/LINUX.md](docs/LINUX.md#phases)).
- **FortiGate on the phones, for now.** There is no library under a compatible license, and recent
  FortiOS versions removed SSL VPN tunnel mode ([docs/MOBILE.md](docs/MOBILE.md#the-two-apps)).
- **Support for old versions.** Only the latest release gets fixes
  ([SECURITY.md](SECURITY.md#supported-versions)).
- **Windows.** Mentioned as a later, separate decision in [docs/MOBILE.md](docs/MOBILE.md#phases);
  nothing is planned for the next twelve months.

## How to influence it

Open or comment on an issue. Requests that fit the principles above and come with a use case are
welcome; the maintainer decides ([GOVERNANCE.md](GOVERNANCE.md#decision-making)).
