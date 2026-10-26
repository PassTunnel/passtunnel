# Assurance case

This document argues why PassTunnel meets its security requirements. The requirements themselves, in
plain language, are in [SECURITY.md](../SECURITY.md); the design is in
[ARCHITECTURE.md](ARCHITECTURE.md) (macOS) and [LINUX.md](LINUX.md). This page does not repeat them:
it names the threats, the trust boundaries, the design principles and the weakness classes, and
points to where each is handled and where it is tested.

- [Security requirements](#security-requirements)
- [Threat model](#threat-model)
- [Trust boundaries](#trust-boundaries)
- [Secure design principles](#secure-design-principles)
- [Common weaknesses and how they are countered](#common-weaknesses-and-how-they-are-countered)
- [Supply chain](#supply-chain)
- [Evidence](#evidence)
- [Residual risk](#residual-risk)

## Security requirements

What a user can expect ([SECURITY.md](../SECURITY.md)):

1. **R1.** Passwords and TOTP secrets are stored only in the system's secret store, and leave it
   only to be sent to the VPN server the user chose.
2. **R2.** Starting VPN software as root cannot be abused by another program or another user to run
   code as root or to read or write files as root.
3. **R3.** A profile configuration cannot make PassTunnel run programs or read files the user did not
   intend.
4. **R4.** Updates and the tools that run as root are the ones the project released.
5. **R5.** The optional MCP server cannot reveal secrets and, by default, cannot change a connection.
6. **R6.** With *Confirm with Touch ID* on, secrets are not used without the user's confirmation, and
   what was confirmed is the server the secrets go to.

## Threat model

**Assets:** VPN passwords, TOTP secrets and private keys in configurations; the ability to run code
as root; the routes and DNS of the whole machine; the update channel; the user's trust in the
release files.

**Attackers considered** (and where they are handled):

| Attacker | Goal | Handled by |
|---|---|---|
| Another local program or user, not root | Get root through the helper or daemon; steer the tools; read another user's tunnel | helper checks: [SECURITY.md](../SECURITY.md#the-privileged-helper) |
| A configuration file from an untrusted source (downloaded `.ovpn`, shared `.passtunnel`) | Run code or read files as root at connect | [sanitizer](../SECURITY.md#openvpn-configuration-sanitizer), [import review](../SECURITY.md#importing-an-openvpn-configuration) |
| A malicious or compromised VPN server or gateway | Push options that raise log levels or change local behavior; return hostile data | fixed flags and `--pull-filter` ([SECURITY.md](../SECURITY.md#how-openvpn-is-started)), typed FortiGate fields, certificate pinning by digest |
| A network attacker | Impersonate the gateway, the update feed or a release download | TLS verification in the tools; signed feed and archives; [provenance](RELEASING.md#checking-the-provenance) |
| A person at the unlocked Mac | Connect or read codes with one click | [Confirm with Touch ID](../SECURITY.md#confirm-with-touch-id-secure-enclave) |
| Another app reading the Keychain | Read passwords and TOTP secrets | [Keychain rules](../SECURITY.md#secrets-and-files), Secure Enclave envelopes |
| An MCP client fed hostile text (prompt injection) | Make the MCP client connect, disconnect or leak secrets | [read-only default, no secret in any answer](../SECURITY.md#mcp-server-and-automation) |
| A supply-chain attacker (dependency, build tool, CI workflow, release asset) | Ship altered code or tools | [Supply chain](#supply-chain) |

**Out of scope**, because no client-side measure can help ([SECURITY.md](../SECURITY.md#what-is-not-protected)):
an administrator or root on the machine, malware running as the user for secrets not protected by
Confirm with Touch ID, vulnerabilities in the bundled tools themselves (fixed by updating), and a
legitimate configuration that sends traffic where its author wants.

## Trust boundaries

| Boundary | Untrusted side | Trusted side | What crosses it and how it is checked |
|---|---|---|---|
| App or CLI to helper (macOS XPC) | any local process | the root helper | The connection requires the project's code signature (Team ID); the caller's uid comes from the audit token; requests over 64 KB or undecodable are refused; the profile folder and `config.ovpn` are opened without following links and checked on the descriptor |
| CLI to daemon (Linux socket) | any local process | `passtunneld` | Unix socket, caller identity from the kernel, root or members of the group `passtunnel` only; the same file checks ([LINUX.md](LINUX.md#daemon-security-rules)) |
| Helper to bundled tools | the app bundle on disk (changeable by the user who installed it) | root-owned staged copies | Copied into a root-owned directory, signature and cdhash checked on the copy and again on the loaded code of a process started suspended ([SECURITY.md](../SECURITY.md#which-programs-it-runs)) |
| Configuration files to helper | `.ovpn`, `.passtunnel` | the sanitized copy in a root-owned run directory | Tokenizer that mirrors OpenVPN's, deny rules and allowlists, no external files, SHA-256 of the file the app checked |
| App to secret store | other apps | Keychain or Secure Enclave | Items replaced on write, never updated in place; envelopes bound to the account name and the destination |
| App and helper to the network | servers, networks | the user's intent | Only the VPN servers, hosts the user set up, and GitHub for updates ([SECURITY.md](../SECURITY.md#network-connections)) |
| MCP client to `passtunnel mcp` | the MCP client and what it read | the user's session | stdio only, strict argument validation, no secrets in answers, write tools off by default |
| Update feed to the app | the network, the release host | the installed app | EdDSA signature of feed and archive, checked before unpacking ([SECURITY.md](../SECURITY.md#updates)) |

## Secure design principles

| Principle | How PassTunnel applies it |
|---|---|
| Least privilege | Only the helper (and the tools it starts) runs as root, on demand, with four requests; no sudoers rule, setuid binary or kernel extension. Tools get a fixed, minimal environment and no inherited descriptors |
| Complete mediation | The helper validates every request and applies the sanitizer at every connect, whatever the app did before. Protected secrets are only usable through a Secure Enclave decryption, so there is no separate yes/no check to skip |
| Fail-safe defaults | MCP is read-only unless `--allow-connect`; Touch ID protection never degrades to plain storage; a failed copy, check or prompt means no connection; unknown sanitizer directives block until decided |
| Economy of mechanism | The helper is small and links only the sanitizer and the shared request code, not the rest of the logic ([ARCHITECTURE.md](ARCHITECTURE.md#targets)) |
| Separation of privilege, defence in depth | Several independent checks for the same risk: code signature of the client, kernel-provided identity, root-owned copies, signature and cdhash pins, sanitizer, fixed flags, root-owned run directory |
| Least common mechanism | Tunnels and run directories are per user; secrets are written only into the root-only run directory and removed when the tunnel stops |
| Open design | The code, the rules and this analysis are public; security does not depend on secrecy of the design |
| Input validation by allowlist | Profile ids, host names, ports, digests, credentials, environment variables, device names, request sizes and MCP arguments are checked against what is allowed; the sanitizer's `setenv` and `dev` rules are allowlists |
| Avoid time-of-check/time-of-use | Descriptors are checked and then used; the helper refuses a `config.ovpn` that differs from the hash the app showed the user |
| Psychological acceptability | The helper is approved with the system's Login Items switch; Touch ID prompts name the server; limits are written down instead of hidden |
| Minimize the attack surface | No listening port in the app or the MCP server; no scripts from profiles; no network service run by the project |

## Common weaknesses and how they are countered

| Weakness (CWE) | Countered by | Tested by |
|---|---|---|
| Injection into the tools: OS command, argument and configuration injection (CWE-78, 88, 77) | Tools started with `posix_spawn` and fixed arguments, never a shell; OpenVPN options after `--config` fixed; the openfortivpn configuration rendered from typed, validated fields and checked again before it is written; credentials in root-owned files, not arguments | `HelperSecurityTests`, `OVPNImportTests`, `DaemonTests`; fuzzers for the sanitizer, the import review and FortiGate rendering |
| Path traversal and link following (CWE-22, 59) | Profile folder resolved and compared with the expected path, opened by descriptor without following symlinks; ids limited to a safe pattern; configuration files must be inline; the helper creates the log file itself | `HelperSecurityTests`, `ToolStagerTests` |
| Time-of-check/time-of-use races (CWE-367) | Checks on open descriptors; root-owned run directory; copy-then-verify of tools; configuration hash | `HelperSecurityTests`, `ToolStagerTests`, `SecretBindingTests` |
| Privilege escalation, improper privilege management (CWE-250, 269) | Code-signing requirement on the client; kernel identity; root-owned staged tools verified by signature, cdhash and the loaded code; helper replaced only under strict conditions; the Linux daemon refuses to start from a path anyone but root could replace | `HelperSecurityTests`, `HelperAutoUpdateTests`, `HelperBuildTests`, `DaemonTests` |
| Disclosure of secrets: cleartext storage, logs (CWE-312, 532, 200) | Keychain or Secure Enclave envelopes; no secret on command lines; log verbosity capped; `get_logs` redacts and filters key material; clipboard concealed and cleared; share files carry no credentials | `AutomationTests`, `SecretBindingTests`, `HelperLogCapTests` |
| Incorrect certificate validation (CWE-295) | The tools verify the gateway against the system store or a pinned SHA-256 digest; the app's own gateway clock probe accepts only the pinned digest or what the system trusts and sends no credentials; `ca-file` is fixed so no compiled-in default store is used | `ServerClockTests`, `TLSFingerprintTests` |
| Download of code without integrity check (CWE-494, 345) | Signed feed and archives (`SURequireSignedFeed`, `SUVerifyUpdateBeforeExtraction`); notarized, hardened-runtime builds; immutable releases; build provenance | the `Release scripts` check; [RELEASING.md](RELEASING.md) |
| Weak cryptography (CWE-327) | Only vetted primitives from CryptoKit and swift-crypto; see [SECURITY.md](../SECURITY.md#cryptography) | `SecretStoresTests`, `UserPresenceTests` |
| Memory safety (CWE-119, 416, 787) | The app, helper, CLI and daemon are written in Swift; the C tools are bundled in pinned, signed versions; parsers of untrusted text are fuzzed with AddressSanitizer | `fuzz/`, the `Fuzz` workflow |
| Resource exhaustion (CWE-400) | Limits on request size, configuration size (1 MB), line length, log size and MCP output (500 lines); timeouts on probes | `OVPNStressTests`, `HelperLogCapTests` |
| Malformed input (CWE-20) | `otpauth://` links, MCP JSON-RPC, management-interface lines and configurations are validated and refused when invalid; unknown MCP arguments are refused | fuzzers for `otpauth://`, MCP JSON-RPC and the management parser |
| Insecure defaults (CWE-1188) | Read-only MCP, auto-type off, protections that never fall back to plain text | `AutomationTests` |
| Prompt injection through an MCP client | No tool returns a secret or a code; write tools are off by default and still need Touch ID where set; the documentation tells users to keep per-tool approval on | `AutomationTests` |
| Hard-coded or leaked credentials (CWE-798) | No secrets in the repository (secret scanning with push protection is on); release secrets only in a protected environment, used by a job that runs on `main` after approval; the temporary keychain and files are deleted at the end of the run | the release workflow |

## Supply chain

- **Source:** protected branches without bypass, signed commits, required checks, linear history on
  `dev`, and a ruleset that protects release tags ([GOVERNANCE.md](../GOVERNANCE.md#decision-making)).
- **Dependencies:** two Swift packages (Sparkle, swift-crypto), each pinned to an exact version in
  `Package.swift`; the bundled tools pinned in `scripts/release.env`, with the build stopping on any
  other version; Dependabot for Swift packages, Actions and Docker images.
- **CI:** GitHub Actions pinned to full commit SHAs, minimal workflow permissions, the OpenSSF
  Scorecard run on every push to `dev` and weekly.
- **Release:** built by a workflow that waits for the maintainer's approval in the environment
  `release`, signed with Developer ID, notarized, attested with build provenance (checked against
  every file before publishing) and published as an immutable release; the Homebrew cask and the MCP
  Registry entry are written by the same run ([RELEASING.md](RELEASING.md#automatic-releases)).

## Evidence

- Unit and integration tests in `Tests/`, run on every pull request on macOS and on Linux (x86_64
  and aarch64); the policy is in [CONTRIBUTING.md](../CONTRIBUTING.md#tests).
- Fuzzing of the parsers of untrusted text ([CONTRIBUTING.md](../CONTRIBUTING.md#fuzzing)).
- Published security advisories on the
  [Security tab](https://github.com/PassTunnel/passtunnel/security/advisories); a fix that changes a
  rule updates [SECURITY.md](../SECURITY.md) and this case.

## Residual risk

The argument above holds for the attackers and requirements listed and claims no more: the limits are
in [SECURITY.md](../SECURITY.md#what-is-not-protected). The project has one maintainer and has had no
independent security audit; the assurance rests on the design, the tests and the fuzzing described
here, and on the public record of advisories. A finding that shows a gap in this case is fixed and
recorded here and in SECURITY.md.
