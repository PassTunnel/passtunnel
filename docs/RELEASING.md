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
   when git has a signing key, and otherwise creates an unsigned annotated tag with a warning
   (`REQUIRE_SIGNED_TAG=1` makes that an error and also requires the tag to verify against
   `.github/allowed_signers`; the release workflow sets it). The release tag key itself is only in
   the environment `release` (see [Signed tags](#signed-tags)), so a tag made on a Mac is signed
   with the maintainer's own key and does not verify against that file. With an SSH key, for
   example:

   ```sh
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_ed25519.pub
   ```

   Add the same key to the GitHub account as a *signing* key so the tag shows as verified (GPG works
   too: `user.signingkey` set to the key ID).
6. **Tools.** Xcode (Swift 5.10+, `xcstringstool`, `notarytool`, `stapler`),
   `brew install openvpn openfortivpn openconnect` (bundled into the app, at the versions pinned in
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
     Commits with the scope `linux` (`feat(linux): …`, `fix(linux)!: …`) are work on the Linux
     version, which has no release yet: they count for nothing, breaking or not, and are not in the
     notes. Phase 3 of [docs/LINUX.md](LINUX.md#phases), which releases Linux, revisits this.
   - **Build and publish** waits for approval in the environment `release` (Actions → the run →
     *Review deployments*). It then installs `openvpn`, `openfortivpn` and `openconnect` with Homebrew, puts the
     Developer ID identity and the notarytool profile into a temporary keychain, writes the Sparkle
     key and the tag signing key to files, sets up git to sign tags with the latter
     ([Signed tags](#signed-tags)) and runs
     `REQUIRE_SIGNED_TAG=1 scripts/release.sh VERSION --publish --draft --notes-file …`, which
     builds, creates the signed tag, checks its signature before pushing it and uploads everything
     to a **draft** release; the workflow then checks that the tag on GitHub is that verified tag. It then creates a build provenance
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
tag is signed ([Signed tags](#signed-tags)); the tag signature, the attestations and the immutable
release are the proof of origin.

### Signed tags

The workflow signs each release tag with an SSH key of its own (ed25519, the secret
`TAG_SIGNING_KEY`), and the tagger is the maintainer's GitHub noreply address
(`Furkanprlk <18267444+Furkanprlk@users.noreply.github.com>`). The key is registered as a signing
key on that account, so GitHub shows the tag as **Verified**. Its public half is in
[`.github/allowed_signers`](../.github/allowed_signers), and anyone can check a tag against it
with git 2.34 or later:

```sh
git clone https://github.com/PassTunnel/passtunnel.git && cd passtunnel
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v v1.6.0
```

It prints `Good "git" signature for 18267444+Furkanprlk@users.noreply.github.com with ED25519
key SHA256:…` and exits with 0; an unsigned tag (`no signature found`) or a tag signed with another
key (`No principal matched`) makes it fail. Take `.github/allowed_signers` from a checkout you
trust (or compare its key with the one above), not from the tag being checked. `release.sh` runs
the same check (`REQUIRE_SIGNED_TAG=1`) before it pushes the tag, so the workflow never pushes a
tag that fails it, and the workflow compares the tag on GitHub with the verified one afterwards.

Tags up to and including `v1.5.0` are not signed with this key: `v1.1.0` and `v1.1.1` (made on a
Mac) carry the maintainer's own signature, the others are unsigned annotated tags. Releases made on
a Mac ([Releasing from a Mac](#releasing-from-a-mac)) are signed with the maintainer's own key, if
one is set up, and also do not verify against `.github/allowed_signers`.

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
published release is final, and the run then only reports it. The tag that is already on GitHub is
used as it is (the tag ruleset forbids changing or deleting `v*` tags); `release.sh` checks its
signature before the build and stops if it does not verify. Since the workflow checks a tag before
pushing it, that only happens with a tag pushed before tags were signed.

### Setup

The environment `release` (Settings → Environments) allows only the branch `main`, needs the
maintainer's approval, and holds these secrets:

| Secret | What |
|---|---|
| `DEVELOPER_ID_P12_BASE64`, `DEVELOPER_ID_P12_PASSWORD` | the Developer ID Application certificate and its private key, as a base64 `.p12` and its password. Export only that one identity. |
| `NOTARY_KEY_P8_BASE64`, `NOTARY_KEY_ID`, `NOTARY_ISSUER_ID` | an App Store Connect API key with the Developer role (Users and Access → Integrations → Team Keys), for notarytool |
| `SPARKLE_PRIVATE_KEY` | the Sparkle EdDSA private key, as `generate_keys -x` writes it |
| `TAP_DEPLOY_KEY` | the private half of an ed25519 deploy key with write access on `TAP_REPO` |
| `TAG_SIGNING_KEY` | the private half of the ed25519 key that signs release tags, in OpenSSH format without a passphrase. Its public half is `.github/allowed_signers` and a *signing* key of the maintainer's GitHub account; the workflow stops when the secret does not match that file ([Signed tags](#signed-tags)) |

Secrets of an environment are only given to jobs that run in it, so pull requests and forks never
see them. Anyone who can approve a release can sign an update for every installed copy: keep the
GitHub account behind a passkey or security key, and keep the offline backup of the Sparkle key
(see One-time setup), since GitHub secrets cannot be read back.

The branch rulesets (Settings → Rules): `dev` and `main` refuse direct pushes, force pushes,
deletion and unsigned commits; `dev` takes squash merges, `main` merge commits; the required checks
are `Build and test`, `Release scripts`, `Site` and `PR title`, plus `Source branch` on `main`
(`Bundled tools` and `Bundled tools on macOS 15` run as well and are worth adding). Actions must be
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
   One-time setup; the release tag key of [Signed tags](#signed-tags) is not on the Mac), pushes it, creates a **draft** GitHub release with the dmg (as
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

`openvpn`, `openfortivpn`, `openconnect` and their libraries come from the release Mac's Homebrew.
`bundle-tools.sh` prints the formula versions it bundles and stops the build unless each one
matches its pin in `release.env` (`OPENVPN_VERSION`, `OPENFORTIVPN_VERSION`, `OPENSSL4_VERSION`,
`LZ4_VERSION`, `LZO_VERSION`, `PKCS11_HELPER_VERSION`; for openconnect `OPENCONNECT_VERSION`,
`GNUTLS_VERSION`, `NETTLE_VERSION`, `GMP_VERSION`, `P11_KIT_VERSION`, `LIBTASN1_VERSION`,
`LIBIDN2_VERSION`, `LIBUNISTRING_VERSION`, `GETTEXT_VERSION`, `STOKEN_VERSION`,
`LIBTOMCRYPT_VERSION`, `LIBTOMMATH_VERSION`; the name is the formula in capitals without `@`, `-` as
`_`, so `openssl@3` would be `OPENSSL3_VERSION`). A pin is the Cellar directory name,
including a Homebrew revision such as `1.24.1_1`; a formula without a pin, or a pin that is not
bundled, also stops it. When Homebrew moves a tool to another library (openvpn 2.7.8_1 moved from
`openssl@3` to `openssl@4`), the build lists the new formula as not pinned and the old pin as not
bundled: add the one and remove the other.

To move to new versions:

```sh
brew update
brew outdated openvpn openfortivpn openconnect openssl@4 lz4 lzo pkcs11-helper gnutls nettle gmp \
    p11-kit libtasn1 libidn2 libunistring gettext stoken libtomcrypt libtommath
HOMEBREW_VERIFY_ATTESTATIONS=1 brew upgrade openvpn openfortivpn openconnect   # and the libraries
scripts/build-app.sh                                               # prints the versions it found
```

Read the upstream changelogs (security fixes in particular), set the new versions in `release.env`,
build again and send the pins as a pull request (`fix(deps): bundle openvpn 2.7.8`, so it releases).
The release workflow and the Repeatable build run `brew update`, install `openvpn`, `openfortivpn`
and `openconnect` and upgrade exactly the bundled formulas (the runner image ships older versions of some, which
`brew install` leaves alone), so both stop as soon as Homebrew has moved past a pin; the same pull
request fixes that. For a local build against other
versions, `PASSTUNNEL_ALLOW_UNPINNED_TOOLS=1 scripts/build-app.sh` only warns; `release.sh`
refuses to run with it set.

### Minimum macOS of the tools

The bottles are built for the newest macOS. `bundle-tools.sh` (so every build, the release's
included) ends with `scripts/check-tool-symbols.sh`, which fails when a bundled tool or dylib imports
from macOS a symbol its minimum macOS does not export ([ARCHITECTURE.md](ARCHITECTURE.md), Minimum macOS
of the tools):

```
error: Frameworks/libopenconnect.5.dylib imports _strchrnul from /usr/lib/libSystem.B.dylib, which macOS 13.0 does not export (built for macOS 26.0)
```

A new tool version that does this would abort at launch on older Macs. Keep the old pin and report it
upstream, build the tool for the older macOS ourselves, or, for a tool the app can refuse below a later
macOS (as Cisco AnyConnect below 15.4), raise its minimum in `TOOL_MINIMUMS` together with that
refusal in the app. A weak import (the tool copes with the symbol missing) can be allowed in
`WEAK_IMPORTS` after reading the tool's code. `scripts/test-check-tool-symbols.sh` is its self-test
(the `Bundled tools` CI job runs it), and `Bundled tools on macOS 15` runs each tool with `--version`
on the oldest arm64 runner.

The symbol lists in `scripts/system-symbols/<version>/` come from SDKs of that macOS version
(`SOURCES` names them, with the checksums of the stubs read). When a tool starts to load another macOS
library ("has no symbol list"), or a tool needs a list for another version, write them with an SDK of
that version, or with the SDKs just before and after it (a symbol is then listed when both export it;
the script refuses a set of SDKs that are all newer than the version):

```sh
scripts/make-system-symbols.sh 13.0 MacOSX12.3.sdk MacOSX13.1.sdk -- /usr/lib/libSystem.B.dylib \
    /usr/lib/libresolv.9.dylib /usr/lib/libutil.dylib /usr/lib/libz.1.dylib   # a new library
scripts/make-system-symbols.sh 15.4 MacOSX15.4.sdk -- /usr/lib/libSystem.B.dylib …
```

Without install names it rewrites the libraries already listed for that version. An SDK is the
`Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX*.sdk` of the Xcode that shipped it
(12.3: Xcode 13.3, 13.1: Xcode 14.2, 15.4: Xcode 16.3; the Command Line Tools for Xcode 26 also
install `/Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk`, with the same stubs, which the 15.4
lists were made from); only its `SDKSettings.json` and the `.tbd` stubs are read (llvm-readtapi of
the current Xcode, and jq). The 15.4 lists are for openconnect's closure (`TOOL_MINIMUMS`); a library
it shares with `openvpn` or `openfortivpn` is held to 13.0, the lower of the two.

### Tool cdhash pins

The helper runs only the exact tool and library builds it shipped with: it copies `openvpn`,
`openfortivpn`, `openconnect` (not run yet) and the dylibs in `Contents/Frameworks` into `/var/run/passtunnel/tools/<helper build>/`
(root-owned) and checks every copy against the pins before running the tools from there.
`build-app.sh` therefore signs the bundled tools and their libraries **before** compiling, writes the
cdhash of every architecture of `openvpn`, `openfortivpn`, `openconnect`, `dns-updown` and every
`Contents/Frameworks/*.dylib` to `Sources/PassTunnelShared/PinnedTools+Generated.swift`
(gitignored, deleted when the script exits) and builds with `swift build -c release -Xswiftc
-DPASSTUNNEL_TOOL_PINS`. Without that define (`swift build`, `swift test`) nothing is pinned and the
helper only checks the tools' signing identifier and Team ID.

- Never re-sign anything in `Contents/Resources/bin` or a dylib in `Contents/Frameworks` after the
  build (by hand or in a script): a new signature changes the cdhash, and the helper then refuses to
  start the tools. To change a tool, a library or the identity, run `build-app.sh` again.
- The script checks that each bundled tool's and dylib's cdhashes are in the pins and in the signed
  helper binary, and a `--sign` build fails unless `openvpn`, `openfortivpn`, `openconnect` and every
  bundled dylib are pinned.
- A `PinnedTools+Generated.swift` left by an interrupted build changes nothing for `swift build` /
  `swift test` (its contents are inside `#if PASSTUNNEL_TOOL_PINS`); the next `build-app.sh` rewrites it.

## Linux tarball

Not part of a release yet: Linux is released from phase 3 of [docs/LINUX.md](LINUX.md#phases), and
`release.sh` and the release workflow build only the Mac files. `scripts/build-linux.sh --version
1.2.0` builds `dist/passtunnel-1.2.0-linux-<arch>.tar.gz` on Linux (in the `swift:6.4.1-jammy`
container, once per architecture), with the commit count as its build number, as `build-app.sh`
gives the app; the CI jobs `Linux release` build it for every pull request with the development
version `0.0.0-dev` and keep it as a workflow artifact. See [docs/LINUX.md](LINUX.md#distribution).
Its `swift build` calls run through `scripts/swift-retry.sh`, which runs a build once more when the
toolchain's build system crashed while planning it (exit 139, "Program crashed" with a `swift-build`
frame in the report) and never otherwise. Such a crash happens before anything is compiled and
produces no output, so the tarball is the same as without it.

## Verifying a release

The build is repeatable: building the same commit again, with the same Xcode and the same Homebrew
bottles of the bundled tools, gives the same `PassTunnel.app` byte for byte apart from the code
signatures. The signatures cannot be repeated (only the maintainer's Developer ID key makes them, and
they carry a secure time stamp), and neither can what contains them: the disk image and the zip
hold the signed and stapled app, and the disk image is signed and notarized itself. What is compared
is therefore the app inside them, with every signature removed: `codesign --remove-signature` on
copies of each Mach-O file, and the `_CodeSignature/CodeResources` files and the stapled ticket
(`Contents/CodeResources`) left out. `scripts/compare-app.sh A.app B.app` does exactly that.

To check a release (from the first one made with this script; earlier versions lack `--tools-from`):

```sh
git clone https://github.com/PassTunnel/passtunnel && cd passtunnel
git checkout v1.2.0
ditto -x -k PassTunnel-1.2.0.zip /tmp/release     # or copy PassTunnel.app out of the disk image
plutil -extract DTXcodeBuild raw /tmp/release/PassTunnel.app/Contents/Info.plist   # the Xcode to use
brew install openvpn openfortivpn openconnect      # the versions in scripts/release.env
scripts/verify-build.sh /tmp/release/PassTunnel.app
```

`verify-build.sh` refuses to run with another Xcode than the one in `DTXcodeBuild` (choose one with
`xcode-select -s` or `DEVELOPER_DIR`). It builds the checked-out commit in a new worktree with
`build-app.sh --version <the app's version> --tools-from <the app>` and compares the result with
`compare-app.sh`; it prints each file that differs and fails, or ends with `same apart from the code
signatures`. A difference in `Contents/Resources/bin` or `Contents/Frameworks` stops the build
earlier, at `--tools-from`. What it relies on:

- **The tools and the pins.** The helper and the app have the cdhashes of the signed tools compiled
  in ([Tool cdhash pins](#tool-cdhash-pins)), which depend on the Developer ID signature.
  `--tools-from` checks that each tool and dylib of the release is this build's apart from its
  signature and then uses the release's signed copies instead of signing its own, so the rebuild
  pins the same cdhashes.
- **The bundled tools** are Homebrew's bottles for the macOS version of the build (the release
  workflow runs on `macos-26`), copied unmodified apart from their load paths and the configuration
  paths overwritten in `libp11-kit` and `libgnutls` (the same bytes every time). They are the same
  only if the bottle is the same: Homebrew can publish a new bottle of the same version (a new
  `rebuild`), and bottles for other macOS versions are other builds. The build of the tools
  themselves is Homebrew's, outside this repository.
- **The length of the build path.** Swift (6.4.1 and earlier) compiles the length of each source
  file's absolute path, though not the path itself, into optimized code: the file-name length
  passed to `swift_isEscapingClosureAtFileLocation`, for example at every inlined
  `DispatchQueue.sync` (the Swift main branch no longer does it, swiftlang/swift `3cb4db3`). The
  rebuild must therefore run in a directory whose path has as many characters as the original
  build's. `verify-build.sh` makes its worktree at such a path in `/private/tmp`, by default 40
  characters, the length of the release workflow's `/Users/runner/work/passtunnel/passtunnel`; a
  release built on a Mac needs `--path-length` with the length of its checkout's path.
- **The version stamps.** `CFBundleVersion` is the commit count (a full clone, not a shallow one).
  `PTGitDescribe` is `git describe` of the commit with a 12-digit hash, leaving out the tags on the
  commit itself, so it is the same before the release's tag exists (`release.sh` creates it after
  the build) and at the tag. `DTXcodeBuild` is the Xcode build.

`build-app.sh` links without a debug map (`-Xlinker -S`): the map named every object file by its
absolute path in `.build` with its modification time, so two builds of the same checkout differed.
No dSYM is made from it, and the symbol table stays. The workflow **Repeatable build**
(`.github/workflows/repeatable.yml`, not a required check) runs `verify-build.sh` on an ad-hoc build
of every pull request and push (with the Homebrew tools held to the pins in `release.env`, as in a release), and builds the Linux tarball twice, from two copies of the checkout, and compares
the two.

The [Linux tarball](#linux-tarball) is repeatable as well: `build-linux.sh` in the documented
container, with the checkout mounted at `/src`, gives the same tarball for the same commit, version
and build number. The fixed `/src` matters as on the Mac (the path is in BoringSSL's file names and
its length in Swift's code). The files are in name order, owned by root and dated at the commit (or
`SOURCE_DATE_EPOCH`), gzip writes no name or time stamp, and the build makes no debug information
(`-debug-info-format none`): Swift's named the Clang modules by their signatures in the module
cache, which change from one build to the next, and although `strip --strip-debug` removed it, the
build ID (a hash the linker computes over everything, debug information included) differed. Check a tarball by building it again and
comparing the SHA-256 digests.

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
