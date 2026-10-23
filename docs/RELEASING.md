# Releasing PassTunnel

A release is a signed and notarized disk image for people who download it, a zip archive plus a
signed `appcast.xml` for Sparkle (in-app updates), a Homebrew cask, and an MCP bundle (`.mcpb`) for
Claude Desktop and the MCP Registry. `scripts/release.sh` builds all of them into `dist/`; with
`--publish` it also tags the commit and creates the GitHub release.

The disk image is attached twice, as `PassTunnel-VERSION.dmg` and as `PassTunnel.dmg` (the same
bytes), so <https://github.com/PassTunnel/passtunnel/releases/latest/download/PassTunnel.dmg> always
downloads the latest one. Pre-releases never become "latest", and releases up to 1.1.3 have only the
versioned name.

Releases are made by GitHub Actions: merging `dev` into `main` starts
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which works out the version and
the release notes, waits for the maintainer's approval, runs `release.sh --publish` on a macOS runner,
attaches signed build provenance, updates the Homebrew tap and the MCP Registry (see
[Automatic releases](#automatic-releases)).
Releasing from a Mac with the same script still works (see [Releasing from a Mac](#releasing-from-a-mac)).

Where things are published is set once, in [`scripts/release.env`](../scripts/release.env):

| Variable | Used for |
|---|---|
| `GITHUB_REPO` | GitHub releases, download URLs, the feed URL and links stamped into `Info.plist` (`SUFeedURL`, `PTGitHubRepository`) by `build-app.sh`, the cask |
| `TAP_REPO` | the Homebrew tap (`<owner>/homebrew-tap` → `brew trust <owner>/tap`, then `brew install --cask <owner>/tap/passtunnel`) |

If they change, also update the URLs written out in `README.md`, `SECURITY.md`,
`THIRD_PARTY_NOTICES.md` and the fallback in `AppInfo.repository`; `ProjectLinksTests` fails until
they all match.

## One-time setup

1. **Developer ID certificate.** A *Developer ID Application* certificate with its private key in the
   login keychain, for the Team ID in `Sources/PassTunnelShared/Identifiers.swift` (`PT.teamID`).
   `security find-identity -v -p codesigning` must list it. `release.sh` picks it by Team ID; set
   `PASSTUNNEL_SIGN_IDENTITY` to use another one.
2. **Notarization credentials.** Create an app-specific password in your Apple Account settings, then:

   ```sh
   xcrun notarytool store-credentials passtunnel \
       --apple-id "<Apple ID>" --team-id "<Team ID>" --password "<app-specific password>"
   ```

   `release.sh` uses the profile `passtunnel` (`NOTARY_PROFILE` overrides it).
3. **Sparkle signing key.** Updates are signed with an EdDSA key whose public half is
   `SUPublicEDKey` in `Resources/Info.plist`. The private key is in the login keychain of the
   release Mac (created with Sparkle's `generate_keys`, item "Private key for signing Sparkle
   updates"). It signs the update archives and the appcast itself. **Back it up** somewhere safe and
   offline; without it, installed copies can never be updated again. Export it to a path outside
   the repository (the export is the bare private key):

   ```sh
   swift package resolve
   SPARKLE=.build/artifacts/sparkle/Sparkle/bin
   $SPARKLE/generate_keys -x ~/Desktop/sparkle-private-key.txt   # export, outside the repository
   $SPARKLE/generate_keys -f ~/Desktop/sparkle-private-key.txt   # import on another Mac
   $SPARKLE/generate_keys -p                                     # show the public key
   ```

   Move the exported file to its offline storage and delete it from the Mac (`rm -P`). The
   `.gitignore` lists `sparkle-private-key.txt` and other key files as a safety net only.
   `release.sh` refuses to run when the key in the keychain does not match `SUPublicEDKey`.
4. **GitHub.** `gh auth login` with access to `GITHUB_REPO` and `TAP_REPO`. Once, as the owner, in
   the GitHub settings (`release.sh` does not change them):
   - `GITHUB_REPO` → Settings → General → Releases: enable **immutable releases**. A published
     release's assets and tag can then no longer be changed or replaced, so an `appcast.xml` or
     zip cannot be swapped later. `release.sh` already uploads everything to a draft before it
     publishes, which is what immutable releases need.
   - `TAP_REPO` → Settings → Rules: a ruleset for `main` that blocks force pushes and deletion and
     requires signed commits, with deploy keys allowed to bypass it (the release workflow pushes
     the cask with one, see [Automatic releases](#automatic-releases)). The cask is what
     `brew install` trusts.
5. **Tag signing key (optional, recommended).** `release.sh` signs the release tag (`git tag -s`)
   when git has a signing key, and otherwise creates an unsigned annotated tag with a warning. With
   an SSH key, for example:

   ```sh
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_ed25519.pub
   ```

   Add the same key to the GitHub account as a *signing* key so the tag shows as verified (GPG works
   too: `user.signingkey` set to the key ID).
6. **Tools.** Xcode (Swift 5.10+, `xcstringstool`, `notarytool`, `stapler`),
   `brew install openvpn openfortivpn` (bundled into the app, at the versions pinned in
   `release.env`; see [Bundled tools](#bundled-tools)) and `jq` (part of macOS 15 and later, else
   `brew install jq`). No Node.js or npm: the MCP bundle is built with macOS tools and `jq` only.
   Optional: `brew install mcp-publisher`, then `release.sh` also validates
   `dist/server.json` (it only validates; publishing is the workflow's job).

## Automatic releases

### How a release happens

1. Work is merged into `dev` through squash-merged pull requests whose titles follow Conventional
   Commits ([CONTRIBUTING.md](../CONTRIBUTING.md#pull-request-titles)).
2. A pull request from `dev` into `main` is merged with a merge commit. Its checks are the ones of
   `dev` plus `Source branch` (only `dev` may go into `main`).
3. The push to `main` starts **Release**:
   - **Plan** runs `scripts/next-version.sh --notes FILE`. It looks at the commit subjects since the
     highest `vX.Y.Z` tag (merge commits and subjects that are not Conventional Commits are ignored):
     a breaking change (`!` or a `BREAKING CHANGE:` footer) makes a major release, `feat` a minor
     one, `fix` or `perf` a patch; anything else releases nothing and the run ends there. The notes
     list those subjects under *Breaking changes*, *New features* and *Fixes*, without the type and
     with GitHub's `(#123)`. They become the GitHub release notes and the text of the update window.
   - **Build and publish** waits for approval in the environment `release` (Actions → the run →
     *Review deployments*). It then installs `openvpn` and `openfortivpn` with Homebrew, puts the
     Developer ID identity and the notarytool profile into a temporary keychain, writes the Sparkle
     key to a file and runs `scripts/release.sh VERSION --publish --draft --notes-file …`, which
     tags, builds and uploads everything to a **draft** release. It then creates a build provenance
     attestation for the dmg, zip and MCP bundle (`actions/attest-build-provenance`), checks its
     Sigstore bundle against the three files and `PassTunnel.dmg` (the dmg's copy, same digest),
     attaches it to the draft as `PassTunnel-VERSION.intoto.jsonl` and publishes the draft with
     `scripts/release.sh VERSION --publish-draft --attach dist/PassTunnel-VERSION.intoto.jsonl`
     (which checks that the draft has all its files; a pre-release is marked as such and never
     becomes "latest"). The provenance has to be attached before publishing, because an immutable
     release takes no new files afterwards. Last, it pushes `dist/passtunnel.rb` to the tap as
     `Casks/passtunnel.rb` (commit `Update PassTunnel to VERSION`). The keychain and the secret
     files are deleted at the end, whatever happened.
   - **MCP Registry** runs `publish-mcp.yml` for the new tag.

Nothing in the repository is changed by a release: the version is in the tag only (`build-app.sh`
stamps it into the app), and `docs/CHANGELOG.md` is not updated (it covers 1.1.1 and earlier). The
tag is an unsigned annotated tag (the runner has no signing key); the attestations and the
immutable release are the proof of origin.

### Checking the provenance

Every release made by the workflow carries `PassTunnel-VERSION.intoto.jsonl`: the Sigstore bundle
(one JSON line) of the build provenance attestation of `PassTunnel-VERSION.dmg`,
`PassTunnel-VERSION.zip` and `PassTunnel-mcp-VERSION.mcpb`. `PassTunnel.dmg` has the same bytes as
`PassTunnel-VERSION.dmg`, and an attestation is found by the file's SHA-256 digest, not by its name,
so it covers that copy too. It says which commit and which run of `release.yml` built the files, and
is signed with the run's GitHub identity (Sigstore, recorded in the public transparency log). The same attestation is stored on GitHub, so either of these checks a
downloaded file:

```sh
gh attestation verify PassTunnel-1.2.0.dmg -R PassTunnel/passtunnel
gh attestation verify PassTunnel-1.2.0.dmg -R PassTunnel/passtunnel --bundle PassTunnel-1.2.0.intoto.jsonl
gh attestation verify PassTunnel.dmg -R PassTunnel/passtunnel
```

The first asks GitHub for the attestation; the second uses the bundle from the release instead
(offline, apart from Sigstore's trust root). Add
`--signer-workflow PassTunnel/passtunnel/.github/workflows/release.yml` to also require that the
release workflow made it (that value is case-sensitive). The bundle is not listed in `SHA256SUMS`:
that file is uploaded with the draft before the attestation exists, and the bundle is signed
itself. OpenSSF Scorecard's *Signed-Releases* check looks for such a file among the
release's assets (`.intoto.jsonl` counts as provenance). Releases made from a Mac have no
provenance: the attestation needs the workflow's GitHub identity.

### When a run fails

Fix the cause and use Actions → Release → Run workflow on `main`. When `HEAD` already has the tag of
an unfinished release, that version is built again: `release.sh` replaces the draft's files and
removes files it did not build (a provenance bundle of the earlier build would not match the new
files), and a new attestation is attached before the draft is published. `PassTunnel.dmg` is one
of the files it builds: it is copied again from the new disk image and replaces the draft's copy. A
published release is final, and the run then only reports it.

### Setup

The environment `release` (Settings → Environments) allows only the branch `main`, needs the
maintainer's approval, and holds these secrets:

| Secret | What |
|---|---|
| `DEVELOPER_ID_P12_BASE64`, `DEVELOPER_ID_P12_PASSWORD` | the Developer ID Application certificate and its private key, as a base64 `.p12` and its password. Export only that one identity. |
| `NOTARY_KEY_P8_BASE64`, `NOTARY_KEY_ID`, `NOTARY_ISSUER_ID` | an App Store Connect API key with the Developer role (Users and Access → Integrations → Team Keys), for notarytool |
| `SPARKLE_PRIVATE_KEY` | the Sparkle EdDSA private key, as `generate_keys -x` writes it |
| `TAP_DEPLOY_KEY` | the private half of an ed25519 deploy key with write access on `TAP_REPO` |

Secrets of an environment are only given to jobs that run in it, so pull requests and forks never
see them. Anyone who can approve a release can sign an update for every installed copy: keep the
GitHub account behind a passkey or security key, and keep the offline backup of the Sparkle key
(see One-time setup), since GitHub secrets cannot be read back.

The branch rulesets (Settings → Rules): `dev` and `main` refuse direct pushes, force pushes,
deletion and unsigned commits; `dev` takes squash merges, `main` merge commits; the required checks
are `Build and test`, `Release scripts` and `PR title`, plus `Source branch` on `main`. Actions must be
pinned to full commit SHAs.

## Releasing from a Mac

The release workflow runs these same steps. Doing it by hand is for a release the workflow cannot
make (GitHub Actions down) or for test builds. `release.sh` refuses `--publish` except on `main`;
tag from the `main` that is on GitHub, and the tap and the MCP Registry are then not updated for you
(steps 4 and the workflow `Publish to MCP Registry`).


1. **Release notes.** Write them to a file outside the repository, for example with
   `scripts/next-version.sh --notes /tmp/notes.md`, and pass `--notes-file /tmp/notes.md` to every
   `release.sh` call below. Without `--notes-file`, `release.sh` takes the section `## [1.2.0]` of
   [`CHANGELOG.md`](CHANGELOG.md) (a pre-release `1.2.0-rc.1` uses its own section if there is one,
   else the one of `1.2.0`). The notes become the GitHub release notes and the text of the update
   window.
2. **Build and check** (nothing is published):

   ```sh
   scripts/release.sh 1.2.0
   ```

   The script stops at the first problem: not on `main`, uncommitted changes, an existing tag, no
   changelog section, a missing identity, notarization profile or Sparkle key, Homebrew tool
   versions that differ from the pins in `release.env`, or no `jq`. It then builds with
   `build-app.sh --sign … --version 1.2.0` (`CFBundleShortVersionString` = the version,
   `CFBundleVersion` = the commit count, which Sparkle compares), notarizes and staples the app,
   makes the Sparkle zip, makes a signed disk image (the app and a link to Applications), notarizes
   and staples it, checks both with Gatekeeper (`spctl`), builds the MCP bundle, and writes:

   | File | |
   |---|---|
   | `dist/PassTunnel-1.2.0.dmg` | download for people |
   | `dist/PassTunnel.dmg` | the same disk image under a name without the version, for the `…/releases/latest/download/PassTunnel.dmg` link; written again by every build (a copy left by an earlier build is deleted first) |
   | `dist/PassTunnel-1.2.0.zip` | Sparkle update archive |
   | `dist/appcast.xml` | Sparkle feed: the feed and the zip are EdDSA-signed, download URLs on the `v1.2.0` release |
   | `dist/PassTunnel-mcp-1.2.0.mcpb` | MCP bundle for Claude Desktop and the MCP Registry |
   | `dist/SHA256SUMS` | checksums of the dmg (under both names), zip and MCP bundle |
   | `dist/passtunnel.rb` | Homebrew cask (from `scripts/homebrew/passtunnel.rb.template`) |
   | `dist/server.json` | the MCP Registry entry for this release (for reference; the workflow publishes its own copy) |
   | `dist/release-notes-1.2.0.md` | the changelog section |
   | `dist/notarization-1.2.0.txt` | notarization submission IDs |

   Try the disk image on a clean Mac (or user account) before publishing.
3. **Publish:**

   ```sh
   scripts/release.sh 1.2.0 --publish            # or --publish --draft to review it on GitHub first
   ```

   This repeats the build, creates the tag `v1.2.0` (signed if a signing key is set up, see
   One-time setup), pushes it, creates a **draft** GitHub release with the dmg (as
   `PassTunnel-1.2.0.dmg` and `PassTunnel.dmg`), zip, MCP bundle, `appcast.xml` and `SHA256SUMS`,
   checks that all six are attached, and only then publishes it (pre-releases are marked as such
   and never become "latest"). Publishing it starts the MCP Registry
   workflow; check that its run under Actions succeeds. With `--draft` it stops before publishing; publish
   the draft on GitHub, run the command again without `--draft`, or publish it without building
   again with `scripts/release.sh 1.2.0 --publish-draft` (`--attach FILE`, repeatable, first uploads
   further files to the draft; that is how the workflow adds the provenance). The feed URL in the app is
   `…/releases/latest/download/appcast.xml`, so installed copies see the update as soon as the
   release is published (not while it is a draft or a pre-release). Pre-release appcasts also use
   the Sparkle channel `beta`, which the app does not follow.
   If the push or the release fails, run the same command again: a tag at `HEAD` is reused, and a
   draft release of the tag gets its assets replaced, `PassTunnel.dmg` included (other files on the
   draft, such as a provenance bundle of an earlier build, are removed). A published release is
   final (with immutable releases GitHub refuses changes); fix problems with a new version.
4. **Homebrew tap.** Copy `dist/passtunnel.rb` to `Casks/passtunnel.rb` in the tap repository
   (`TAP_REPO`), check it and push:

   ```sh
   brew trust passtunnel/tap
   brew audit --cask --online passtunnel/tap/passtunnel
   brew style passtunnel/tap
   brew install --cask passtunnel/tap/passtunnel
   ```

   Since Homebrew 6, casks from a tap that is not trusted are not loaded, so the README's install
   instructions start with `brew trust passtunnel/tap`.

   The cask has `auto_updates true`: Sparkle updates the app, and `brew upgrade` only touches it
   with `--greedy`. Its `zap` also deletes the Keychain items of the service `PassTunnel` (as the
   user, through `security delete-generic-password`). Skip the tap for pre-releases.

## MCP bundle and MCP Registry

`PassTunnel-mcp-VERSION.mcpb` is an [MCP bundle](https://github.com/modelcontextprotocol/mcpb): a zip
with `manifest.json`, the launcher `server/passtunnel-mcp` and the app icon, from
[`packaging/mcpb/`](../packaging/mcpb). It does not contain the app. The launcher runs
`/Applications/PassTunnel.app/Contents/MacOS/PassTunnel mcp` (with `--allow-connect` when the
bundle's setting *Allow connect and disconnect* is on; clients pass it as
`PASSTUNNEL_MCP_ALLOW_CONNECT=true`), and prints an install hint and exits 127 when the app is
missing. It never downloads or installs anything. The name must contain "mcp": the registry
refuses bundle URLs without it.

`scripts/build-mcpb.sh VERSION [OUTPUT_DIR]` builds it (`release.sh` calls it with its work
directory; run it alone for a quick check, it signs and publishes nothing). It sets the version in
the manifest, converts `Resources/AppIcon.icns` to a 512×512 `icon.png`, checks the manifest, packs
the three files with `zip`, and checks the result again. It uses only macOS tools and `jq`, never a
package manager: the release Mac holds the signing identity, the Sparkle key and the notarization
credentials, and a three-file zip is no reason to run code fetched from a registry there.
`scripts/build-mcpb.sh --check` only checks that the tools are there (`release.sh` does that before
the build).

- **Reproducible.** The files are packed in a fixed order (`icon.png`, `manifest.json`,
  `server/passtunnel-mcp`) with fixed modes (644, and 755 for the launcher), all dated
  2020-01-01 00:00 UTC, without directory entries or extra attributes (`zip -X -D`). The same sources
  and version give the same SHA-256 on any Mac, whatever its time zone or umask.
- **Manifest checks** (jq, MCPB manifest 0.3, before and after packing): only fields the 0.3 schema
  knows; `manifest_version` `0.3`; `name`, `description` and `author.name` set; `version` is the
  version built; `server.type` `binary`; `server.entry_point` is an executable file in the bundle and
  `server.mcp_config` runs it (`command`, `args`), passing the setting as
  `PASSTUNNEL_MCP_ALLOW_CONNECT`; `compatibility.platforms` contains `darwin`; `tools` are named and
  unique; `user_config.allow_connect` is a boolean that defaults to `false`; every
  `${user_config.…}` names a setting; the icon is a PNG.
- **Bundle checks:** `unzip -Z1` lists exactly the three files in order, the launcher is
  `-rwxr-xr-x` in the zip, the extracted files equal the staged ones, `unzip -p … manifest.json`
  reads back as the same JSON, and `unzip -t` passes.

To check a bundle with the official [mcpb CLI](https://github.com/modelcontextprotocol/mcpb) too
(after changing the manifest, or when the MCPB format moves on), do it by hand on a machine without
release credentials, or at least in an empty temporary directory with npm install scripts disabled:
extract the bundle and run the CLI's `validate` on the extracted `manifest.json` and `info` on the
`.mcpb` (it reports the bundle as not signed; MCPB signatures are not used). Then install the bundle in
Claude Desktop. The release itself never runs it.

The registry entry `io.github.PassTunnel/passtunnel` is published by
[`.github/workflows/publish-mcp.yml`](../.github/workflows/publish-mcp.yml), not by `release.sh`,
because the registry only accepts a bundle URL that is publicly reachable, which a draft's assets
are not. When a release is published, the workflow checks out its tag, downloads
`PassTunnel-mcp-VERSION.mcpb` from the release, checks it against `SHA256SUMS` and the version in its
manifest, writes `server.json` with `scripts/make-server-json.sh VERSION SHA256` (the repository's
`server.json` with `version` set to the release and a `packages` entry: `registryType` `mcpb`, the
asset's download URL, `fileSha256`, `transport` stdio), validates it and publishes it, logging in
with the job's GitHub OIDC token (no secret). `release.sh` writes the same file to
`dist/server.json`. So the release commit needs no change to `server.json`: it holds the metadata
(name, description, links), and its `version` is whatever was published last without a bundle; edit
the metadata there and it takes effect with the next release.

- The registry accepts each version once and keeps it. The workflow first asks the registry for the
  version and stops successfully when it is already there, so re-running it is safe; a failed run
  can be re-run as is.
- Pre-releases are skipped. To list one, or to publish a release again after a failed run, use
  Actions → Publish to MCP Registry → Run workflow with the tag (`v1.2.0`).
- A release without a `.mcpb` asset (1.1.0 and earlier) cannot be published by the workflow; the
  run fails with a message.

## Signed appcast

The app sets `SURequireSignedFeed` and `SUVerifyUpdateBeforeExtraction` (`Resources/Info.plist`):
Sparkle rejects an `appcast.xml` without a valid EdDSA signature of the feed itself, and checks the
zip's signature before unpacking it. `generate_appcast` signs the feed when the archived app
requires it (`release.sh` falls back to `sign_update` and checks the result with
`sign_update --verify`). The signature is an XML comment at the end of the file, so any edit to a
generated `appcast.xml` invalidates it; regenerate it instead.

Order of the switch-over: 1.0.0 does not require a signed feed and accepts the signed appcast of the
next release as is. Builds with these settings installed before that release is published (local
builds, a pre-release DMG) see only the unsigned 1.0.0 appcast as "latest", so their update check
fails until the first signed release is out; they never install anything from an unsigned feed.
`SUVerifyUpdateBeforeExtraction` also means the EdDSA key cannot be rotated any more (Sparkle would
otherwise accept a new key on an update signed with the same Developer ID): keep the key safe (see
One-time setup).

## Bundled tools

`openvpn`, `openfortivpn` and their libraries come from the release Mac's Homebrew.
`bundle-tools.sh` prints the formula versions it bundles and stops the build unless each one
matches its pin in `release.env` (`OPENVPN_VERSION`, `OPENFORTIVPN_VERSION`, `OPENSSL4_VERSION`,
`LZ4_VERSION`, `LZO_VERSION`, `PKCS11_HELPER_VERSION`; the name is the formula in capitals without
`@`, `-` as `_`, so `openssl@3` would be `OPENSSL3_VERSION`). A pin is the Cellar directory name,
including a Homebrew revision such as `1.24.1_1`; a formula without a pin, or a pin that is not
bundled, also stops it. When Homebrew moves a tool to another library (openvpn 2.7.8_1 moved from
`openssl@3` to `openssl@4`), the build lists the new formula as not pinned and the old pin as not
bundled: add the one and remove the other.

To move to new versions:

```sh
brew update
brew outdated openvpn openfortivpn openssl@4 lz4 lzo pkcs11-helper
HOMEBREW_VERIFY_ATTESTATIONS=1 brew upgrade openvpn openfortivpn   # and the libraries
scripts/build-app.sh                                               # prints the versions it found
```

Read the upstream changelogs (security fixes in particular), set the new versions in `release.env`,
build again and send the pins as a pull request (`fix(deps): bundle openvpn 2.7.8`, so it releases).
The release workflow installs the tools with the runner's Homebrew, so it stops the release as soon
as Homebrew has moved past a pin; the same pull request fixes that. For a local build against other
versions, `PASSTUNNEL_ALLOW_UNPINNED_TOOLS=1 scripts/build-app.sh` only warns; `release.sh`
refuses to run with it set.

### Tool cdhash pins

The helper runs only the exact tool and library builds it shipped with: it copies `openvpn`,
`openfortivpn` and the dylibs in `Contents/Frameworks` into `/var/run/passtunnel/tools/<helper build>/`
(root-owned) and checks every copy against the pins before running the tools from there.
`build-app.sh` therefore signs the bundled tools and their libraries **before** compiling, writes the
cdhash of every architecture of `openvpn`, `openfortivpn`, `dns-updown` and every
`Contents/Frameworks/*.dylib` to `Sources/PassTunnelShared/PinnedTools+Generated.swift`
(gitignored, deleted when the script exits) and builds with `swift build -c release -Xswiftc
-DPASSTUNNEL_TOOL_PINS`. Without that define (`swift build`, `swift test`) nothing is pinned and the
helper only checks the tools' signing identifier and Team ID.

- Never re-sign anything in `Contents/Resources/bin` or a dylib in `Contents/Frameworks` after the
  build (by hand or in a script): a new signature changes the cdhash, and the helper then refuses to
  start the tools. To change a tool, a library or the identity, run `build-app.sh` again.
- The script checks that each bundled tool's and dylib's cdhashes are in the pins and in the signed
  helper binary, and a `--sign` build fails unless `openvpn`, `openfortivpn` and every bundled dylib
  are pinned.
- A `PinnedTools+Generated.swift` left by an interrupted build changes nothing for `swift build` /
  `swift test` (its contents are inside `#if PASSTUNNEL_TOOL_PINS`); the next `build-app.sh` rewrites it.

## Local test runs

`scripts/release.sh 1.2.0-rc.1 --allow-branch` builds from the current branch (still needs a
clean tree); `--skip-notarize` skips notarization and stapling for a quick look. Neither can be
combined with `--publish`. Running the built app from `dist/` or `build/` never replaces the
installed helper on its own: the automatic helper update only runs from `/Applications`.

## After an update

Sparkle replaces the app while the helper keeps running the old build (and the tunnels it runs).
On launch the app sees that the helper's build differs. When the app runs from `/Applications` and
the helper is an older build (lower `CFBundleVersion`, which is why it must only grow), and no
PassTunnel session is active (no `openvpn`/`openfortivpn` started by a PassTunnel helper, for any
user), it re-registers the helper right away, which needs no approval. With sessions active,
Settings → Helper shows "Needs an update", the app notifies once, and the update runs as soon as the
last session ends. A newer helper is never replaced on its own. The decision is `HelperAutoUpdate`
in Core.
