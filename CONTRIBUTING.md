# Contributing to PassTunnel

Issues and pull requests are welcome. For anything larger than a small fix, open an issue first so
the approach can be agreed on before you write the code.

Before changing code, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (targets, storage, helper
protocol, security rules) and [docs/APP.md](docs/APP.md) (app and CLI behavior). The
[Contributing section of the README](README.md#contributing) lists the rules for code: new VPN
backends, localized strings, no third-party dependencies besides Sparkle.

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
5. The checks must pass: `Build and test` (`swift build` and `swift test` on macOS), `Release
   scripts` and `PR title`. Review comments must be resolved.
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

## Dependabot

Dependabot opens pull requests into `dev` for GitHub Actions (`ci: …`, no release) and for Swift
packages (`fix(deps): …`, a patch release, since those ship in the app). They need no issue link.
