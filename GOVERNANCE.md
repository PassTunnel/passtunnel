# Governance

PassTunnel is a small project with one maintainer. This document says how decisions are made, who
does what, who holds which access, and what the current limits are, including the ones that are not
solved yet.

- [Decision making](#decision-making)
- [Roles and responsibilities](#roles-and-responsibilities)
- [Who holds which access](#who-holds-which-access)
- [Bus factor and access continuity](#bus-factor-and-access-continuity)
- [Changing this document](#changing-this-document)

## Decision making

1. **Issue first.** Anything larger than a small fix starts as a
   [GitHub issue](https://github.com/PassTunnel/passtunnel/issues) so the approach is agreed before
   code is written ([CONTRIBUTING.md](CONTRIBUTING.md)).
2. **The maintainer decides.** Scope, design, releases and security fixes are decided by the
   maintainer, after discussion in the issue or pull request. There is no voting. What is planned and
   what is not is in [ROADMAP.md](ROADMAP.md); a decision that changes a rule of the code is written
   into [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) or [SECURITY.md](SECURITY.md) in the same pull
   request.
3. **Everything goes through a pull request.** Nobody pushes to `dev` or `main`, the maintainer
   included: the branch rulesets have no bypass actors. A pull request needs the required checks
   (`Build and test`, `Linux (x86_64)`, `Linux (aarch64)`, `Release scripts`, `Site`, `PR title`;
   `Source branch` on `main`), resolved review threads and signed commits, and is squash-merged into
   `dev`. [`.github/CODEOWNERS`](.github/CODEOWNERS) names the maintainer as reviewer of every change.
   The rulesets do not require an approving review (the count is 0), because with one maintainer
   nobody else could approve; the checks and the signed history are what is enforced.
4. **Releases are decided by merging.** A pull request from `dev` into `main` starts the release
   workflow, which computes the version from the Conventional Commits titles and waits for the
   maintainer's approval before it builds and signs anything
   ([docs/RELEASING.md](docs/RELEASING.md#how-a-release-happens)).
5. **Conduct.** Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Roles and responsibilities

| Role | Who | What they do |
|---|---|---|
| Maintainer and organization owner | [`Furkanprlk`](https://github.com/Furkanprlk) | Sets direction, reviews and merges every pull request, approves releases, owns the GitHub organization, the signing identities and the deploy keys, triages issues, answers security reports and publishes advisories, enforces the Code of Conduct |
| Security contact | the maintainer | Receives reports through GitHub's private vulnerability reporting and follows the [response process](SECURITY.md#how-reports-are-handled) |
| Contributors | anyone | Open issues, discuss, send pull requests, follow [CONTRIBUTING.md](CONTRIBUTING.md); no special access is needed or given |
| Dependabot | automation | Opens pull requests for GitHub Actions, Swift packages and Docker base images ([`.github/dependabot.yml`](.github/dependabot.yml)); the maintainer reviews them like any other |
| Release workflow | automation | Builds, signs, notarizes, attests and publishes after the maintainer approves ([`.github/workflows/release.yml`](.github/workflows/release.yml)) |

There are no other maintainers, committers or reviewers today. Someone who contributes regularly and
well can be offered a role; this document is updated when that happens.

## Who holds which access

| What | Where it lives | Held by |
|---|---|---|
| GitHub organization `PassTunnel`, its repositories, rulesets and settings | GitHub | the maintainer (the only owner) |
| Environment `release`: Developer ID certificate, notarization API key, Sparkle signing key, Homebrew tap deploy key | GitHub environment secrets of this repository; approval needed per release | the maintainer approves; GitHub secrets cannot be read back |
| Developer ID signing identity and Apple notarization account (Team ID in [`Identifiers.swift`](Sources/PassTunnelShared/Identifiers.swift)) | Apple Developer account | the maintainer |
| Sparkle EdDSA private key (signs the update feed and archives) | `SPARKLE_PRIVATE_KEY` secret; [docs/RELEASING.md](docs/RELEASING.md#one-time-setup) asks for an offline backup | the maintainer |
| Homebrew tap | [PassTunnel/homebrew-tap](https://github.com/PassTunnel/homebrew-tap), deploy key `TAP_DEPLOY_KEY` | the maintainer |
| Website | [PassTunnel/passtunnel.github.io](https://github.com/PassTunnel/passtunnel.github.io), deploy key `SITE_DEPLOY_KEY` in environment `website` | the maintainer |
| MCP Registry entry `io.github.PassTunnel/passtunnel` | published by the release workflow with GitHub's OIDC token; no secret | follows ownership of the GitHub organization |
| Commit signing key (SSH) | the maintainer's machine; the public key is on the GitHub account | the maintainer |
| Private vulnerability reports and draft advisories | GitHub Security tab | the maintainer |
| Mobile apps ([docs/MOBILE.md](docs/MOBILE.md)): repositories and store developer accounts | GitHub, Google Play, App Store | the maintainer |

## Bus factor and access continuity

**The bus factor is 1.** Every item in the table above is held by one person. If the maintainer
cannot continue, nobody else can currently approve or publish a release, merge a pull request into a
protected branch, or read a private vulnerability report. This is a real limit of the project, not a
hypothetical one.

What this means for users and for anyone who would carry the project on:

- The source is MIT-licensed ([LICENSE](LICENSE)) and can be forked and built by anyone
  ([README](README.md#build-from-source)).
- Installed copies keep working. They only update from releases signed with the Sparkle key
  ([SECURITY.md](SECURITY.md#updates)); without that key no update reaches them, and a fork has to
  be installed by hand. The root helper trusts the Developer ID Team ID compiled into it, so a fork
  signed with another identity is a separate trust root
  ([SECURITY.md](SECURITY.md#what-is-not-protected)).
- Everything needed to release is described in [docs/RELEASING.md](docs/RELEASING.md), and the
  release itself is a workflow, not a manual procedure, so a successor with the secrets can release
  without reconstructing the process.

What is not in place yet: a second person with administrative access, and a way for the project to
pass to someone if the maintainer is unavailable. Inventing one here would be a claim the repository
cannot back, so the decision is left open.

<!-- TODO(maintainer): decide access continuity and write it here. For silver (access_continuity: someone else must be able to create and close issues, accept changes and release within a week of the maintainer becoming unavailable) this needs at least: a second organization owner or a trusted successor; their approval right on environment `release`; a sealed escrow of the secrets that GitHub cannot read back (Developer ID .p12 and password, notarization API key, Sparkle private key, deploy keys) kept offline with that person; and the Apple Developer account recovery path. Name the person or the mechanism, or leave the criterion unmet. -->

## Changing this document

Governance changes go through a pull request like any other change and are decided by the maintainer.
When a second maintainer joins, the roles table, the access table and the bus factor section are
updated in the same pull request.
