# Releasing PassTunnel

A release is a signed and notarized disk image for people who download it, a zip archive plus a
signed `appcast.xml` for Sparkle (in-app updates), and a Homebrew cask. `scripts/release.sh` builds
all of them into `dist/`; with `--publish` it also tags the commit and creates the GitHub release.

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
   - `TAP_REPO` → Settings → Rules: a ruleset for `main` that blocks force pushes and deletion (the
     app repository has one), and ideally requires signed commits. The cask is what
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
6. **Tools.** Xcode (Swift 5.10+, `xcstringstool`, `notarytool`, `stapler`) and
   `brew install openvpn openfortivpn` (bundled into the app, at the versions pinned in
   `release.env`; see [Bundled tools](#bundled-tools)).

## Every release

1. **Changelog.** Add a section to [`CHANGELOG.md`](CHANGELOG.md) on `main`:

   ```markdown
   ## [1.2.0] - 2026-11-03

   - What changed, written for users.
   ```

   It becomes the GitHub release notes and the text of the update window. A pre-release
   (`1.2.0-rc.1`) uses its own section if there is one, else the one of `1.2.0`.
2. **Build and check** (nothing is published):

   ```sh
   scripts/release.sh 1.2.0
   ```

   The script stops at the first problem: not on `main`, uncommitted changes, an existing tag, no
   changelog section, a missing identity, notarization profile or Sparkle key, or Homebrew tool
   versions that differ from the pins in `release.env`. It then builds with
   `build-app.sh --sign … --version 1.2.0` (`CFBundleShortVersionString` = the version,
   `CFBundleVersion` = the commit count, which Sparkle compares), notarizes and staples the app,
   makes the Sparkle zip, makes a signed disk image (the app and a link to Applications), notarizes
   and staples it, checks both with Gatekeeper (`spctl`), and writes:

   | File | |
   |---|---|
   | `dist/PassTunnel-1.2.0.dmg` | download for people |
   | `dist/PassTunnel-1.2.0.zip` | Sparkle update archive |
   | `dist/appcast.xml` | Sparkle feed: the feed and the zip are EdDSA-signed, download URLs on the `v1.2.0` release |
   | `dist/SHA256SUMS` | checksums of the dmg and zip |
   | `dist/passtunnel.rb` | Homebrew cask (from `scripts/homebrew/passtunnel.rb.template`) |
   | `dist/release-notes-1.2.0.md` | the changelog section |
   | `dist/notarization-1.2.0.txt` | notarization submission IDs |

   Try the disk image on a clean Mac (or user account) before publishing.
3. **Publish:**

   ```sh
   scripts/release.sh 1.2.0 --publish            # or --publish --draft to review it on GitHub first
   ```

   This repeats the build, creates the tag `v1.2.0` (signed if a signing key is set up, see
   One-time setup), pushes it, creates a **draft** GitHub release with the dmg, zip, `appcast.xml`
   and `SHA256SUMS`, checks that all four are attached, and only then publishes it (pre-releases
   are marked as such and never become "latest"). With `--draft` it stops before publishing; publish
   the draft on GitHub, or run the command again without `--draft`. The feed URL in the app is
   `…/releases/latest/download/appcast.xml`, so installed copies see the update as soon as the
   release is published (not while it is a draft or a pre-release). Pre-release appcasts also use
   the Sparkle channel `beta`, which the app does not follow.
   If the push or the release fails, run the same command again: a tag at `HEAD` is reused, and a
   draft release of the tag gets its assets replaced. A published release is final (with immutable
   releases GitHub refuses changes); fix problems with a new version.
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
matches its pin in `release.env` (`OPENVPN_VERSION`, `OPENFORTIVPN_VERSION`, `OPENSSL3_VERSION`,
`OPENSSL4_VERSION`, `LZ4_VERSION`, `LZO_VERSION`, `PKCS11_HELPER_VERSION`; the name is the formula
in capitals without `@`, `-` as `_`). A pin is the Cellar directory name, including a Homebrew
revision such as `1.24.1_1`; a formula without a pin, or a pin that is not bundled, also stops it.

To move to new versions:

```sh
brew update
brew outdated openvpn openfortivpn openssl@3 openssl@4 lz4 lzo pkcs11-helper
HOMEBREW_VERIFY_ATTESTATIONS=1 brew upgrade openvpn openfortivpn   # and the libraries
scripts/build-app.sh                                               # prints the versions it found
```

Read the upstream changelogs (security fixes in particular), set the new versions in `release.env`,
build again and commit the pins together with a changelog line. For a local build against other
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
