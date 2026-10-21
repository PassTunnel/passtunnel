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
   updates"). **Back it up** somewhere safe and offline; without it, installed copies can never be
   updated again:

   ```sh
   swift package resolve
   .build/artifacts/sparkle/Sparkle/bin/generate_keys -x sparkle-private-key.txt   # export
   .build/artifacts/sparkle/Sparkle/bin/generate_keys -f sparkle-private-key.txt   # import on another Mac
   .build/artifacts/sparkle/Sparkle/bin/generate_keys -p                           # show the public key
   ```

   Delete the exported file once it is stored safely. `release.sh` refuses to run when the key in
   the keychain does not match `SUPublicEDKey`.
4. **GitHub.** `gh auth login` with access to `GITHUB_REPO` and `TAP_REPO`.
5. **Tools.** Xcode (Swift 5.10+, `xcstringstool`, `notarytool`, `stapler`) and
   `brew install openvpn openfortivpn` (bundled into the app).

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
   changelog section, a missing identity, notarization profile or Sparkle key. It then builds with
   `build-app.sh --sign … --version 1.2.0` (`CFBundleShortVersionString` = the version,
   `CFBundleVersion` = the commit count, which Sparkle compares), notarizes and staples the app,
   makes the Sparkle zip, makes a signed disk image (the app and a link to Applications), notarizes
   and staples it, checks both with Gatekeeper (`spctl`), and writes:

   | File | |
   |---|---|
   | `dist/PassTunnel-1.2.0.dmg` | download for people |
   | `dist/PassTunnel-1.2.0.zip` | Sparkle update archive |
   | `dist/appcast.xml` | Sparkle feed, EdDSA-signed, download URLs on the `v1.2.0` release |
   | `dist/SHA256SUMS` | checksums of the dmg and zip |
   | `dist/passtunnel.rb` | Homebrew cask (from `scripts/homebrew/passtunnel.rb.template`) |
   | `dist/release-notes-1.2.0.md` | the changelog section |
   | `dist/notarization-1.2.0.txt` | notarization submission IDs |

   Try the disk image on a clean Mac (or user account) before publishing.
3. **Publish:**

   ```sh
   scripts/release.sh 1.2.0 --publish            # or --publish --draft to review it on GitHub first
   ```

   This repeats the build, creates the annotated tag `v1.2.0`, pushes it and creates the GitHub
   release with the dmg, zip, `appcast.xml` and `SHA256SUMS` (pre-releases are marked as such). The
   feed URL in the app is `…/releases/latest/download/appcast.xml`, so installed copies see the
   update as soon as the release is published (not while it is a draft or a pre-release).
   Pre-release appcasts also use the Sparkle channel `beta`, which the app does not follow.
   If the push or the release fails, run the same command again: a tag at `HEAD` is reused.
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
   with `--greedy`. Skip the tap for pre-releases.

## Local test runs

`scripts/release.sh 1.2.0-rc.1 --allow-branch` builds from the current branch (still needs a
clean tree); `--skip-notarize` skips notarization and stapling for a quick look. Neither can be
combined with `--publish`. Running the built app from `dist/` or `build/` never replaces the
installed helper on its own: the automatic helper update only runs from an Applications folder.

## After an update

Sparkle replaces the app while the helper keeps running the old build (and the tunnels it runs).
On launch the app sees that the helper's build differs. With no active PassTunnel session (no
`openvpn`/`openfortivpn` started by a PassTunnel helper, for any user) it re-registers the helper
right away, which needs no approval. Otherwise Settings → Helper shows "Needs an update", the app
notifies once, and the update runs as soon as the last session ends. The decision is
`HelperAutoUpdate` in Core.
