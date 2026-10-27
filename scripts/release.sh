#!/bin/bash
# Builds a signed, notarized PassTunnel release into dist/.
#
#   scripts/release.sh VERSION [--draft] [--skip-notarize] [--allow-branch] [--publish]
#                      [--notes-file FILE]
#   scripts/release.sh VERSION --publish-draft [--attach FILE]...
#
#   VERSION          semantic version: 1.2.0, 1.3.0-rc.1, …
#   --skip-notarize  sign only (no notarization, no stapling); never use for a published release
#   --allow-branch   build from the current branch instead of main (local test runs; not with --publish)
#   --publish        create and push the tag vVERSION (signed when git has a signing key), then
#                    create the GitHub release as a draft, upload the files and publish it
#   --draft          with --publish: leave the release as a draft (publish it on GitHub later, or
#                    with --publish-draft)
#   --notes-file FILE
#                    the release notes (Markdown) from FILE instead of the section "## [VERSION]" of
#                    docs/CHANGELOG.md (the release workflow passes the notes of next-version.sh)
#   --publish-draft  build nothing: upload the --attach files to the existing draft release vVERSION,
#                    check that it has all its files and publish it (the release workflow attaches
#                    the build provenance this way)
#   --attach FILE    with --publish-draft: a further file for the draft (repeatable); it may not have
#                    the name of a file this script builds
#
# Without --publish or --publish-draft nothing leaves this Mac apart from the notarization uploads:
# no tag, no push, no release. Output: dist/PassTunnel-VERSION.dmg, dist/PassTunnel.dmg (the same
# disk image under a name without the version, for the …/releases/latest/download/PassTunnel.dmg
# link), dist/PassTunnel-VERSION.zip (Sparkle update), dist/PassTunnel-mcp-VERSION.mcpb (MCP
# bundle), dist/SHA256SUMS, dist/appcast.xml, dist/passtunnel.rb (Homebrew cask), dist/server.json
# (MCP Registry entry, published by the publish-mcp workflow), dist/release-notes-VERSION.md.
# Repository slugs and tool versions come from scripts/release.env. Setup and the whole procedure:
# docs/RELEASING.md.
#
# Environment: PASSTUNNEL_SIGN_IDENTITY (default: the Developer ID Application identity of the Team ID
# in Identifiers.swift), NOTARY_PROFILE (notarytool keychain profile, default: passtunnel),
# SPARKLE_PRIVATE_KEY_FILE (the Sparkle EdDSA private key as generate_keys -x exports it, instead of
# the key in the keychain; the release workflow uses it because the Sparkle tools cannot read a key
# without a keychain prompt there), REQUIRE_SIGNED_TAG=1 (with --publish: stop unless the tag is
# signed and its signature checks out against .github/allowed_signers, the release tag key; the
# release workflow sets it; without it an unsigned tag is only a warning).
# PASSTUNNEL_ALLOW_UNPINNED_TOOLS is refused: bundled tool versions must match release.env.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/scripts/release.env"

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
usage() { sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'; }

VERSION=""
DRAFT=0
SKIP_NOTARIZE=0
ALLOW_BRANCH=0
PUBLISH=0
NOTES_FILE=""
PUBLISH_DRAFT=0
ATTACH=()
while (($#)); do
    case "$1" in
        --draft) DRAFT=1 ;;
        --skip-notarize) SKIP_NOTARIZE=1 ;;
        --allow-branch) ALLOW_BRANCH=1 ;;
        --publish) PUBLISH=1 ;;
        # Relative to the directory release.sh was started from (the script has changed to ROOT).
        --notes-file) (($# >= 2)) || die "--notes-file needs a file"; NOTES_FILE="$2"
                      [[ "$NOTES_FILE" == /* ]] || NOTES_FILE="$OLDPWD/$NOTES_FILE"; shift ;;
        --publish-draft) PUBLISH_DRAFT=1 ;;
        --attach) (($# >= 2)) || die "--attach needs a file"
                  if [[ "$2" == /* ]]; then ATTACH+=("$2"); else ATTACH+=("$OLDPWD/$2"); fi; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; die "unknown option: $1" ;;
        *) [[ -z "$VERSION" ]] || die "more than one version given"; VERSION="$1" ;;
    esac
    shift
done
[[ -n "$VERSION" ]] || { usage >&2; exit 2; }

# Semantic Versioning 2.0 without build metadata (it would end up in file names and the tag).
ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER="^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$ID(\.$ID)*)?$"
[[ "$VERSION" =~ $SEMVER ]] || die "'$VERSION' is not a semantic version (like 1.2.0 or 1.2.0-rc.1)"
BASE_VERSION="${VERSION%%-*}"
PRERELEASE=0
[[ "$VERSION" == *-* ]] && PRERELEASE=1
TAG="v$VERSION"
NOTARY_PROFILE="${NOTARY_PROFILE:-passtunnel}"
DOWNLOAD_PREFIX="https://github.com/$GITHUB_REPO/releases/download/$TAG/"
DIST="$ROOT/dist"
WORK="$DIST/.work-$VERSION"
DMG_NAME="PassTunnel-$VERSION.dmg"
# The same bytes as DMG_NAME; …/releases/latest/download/PassTunnel.dmg is always the latest one.
STABLE_DMG_NAME="PassTunnel.dmg"
ZIP_NAME="PassTunnel-$VERSION.zip"
MCPB_NAME="PassTunnel-mcp-$VERSION.mcpb"
SPARKLE_BIN="$ROOT/.build/artifacts/sparkle/Sparkle/bin"

if ((PUBLISH_DRAFT)); then
    ((!PUBLISH && !DRAFT && !SKIP_NOTARIZE && !ALLOW_BRANCH)) && [[ -z "$NOTES_FILE" ]] \
        || die "--publish-draft builds nothing and only takes --attach"
fi
((${#ATTACH[@]} == 0 || PUBLISH_DRAFT)) || die "--attach only works with --publish-draft"
((PUBLISH && ALLOW_BRANCH)) && die "--publish releases from main only; drop --allow-branch"
((PUBLISH && SKIP_NOTARIZE)) && die "--publish needs a notarized build; drop --skip-notarize"
((DRAFT && !PUBLISH)) && echo "note: --draft only matters with --publish"
REQUIRE_SIGNED_TAG="${REQUIRE_SIGNED_TAG:-0}"
[[ "$REQUIRE_SIGNED_TAG" == 0 || "$REQUIRE_SIGNED_TAG" == 1 ]] || die "REQUIRE_SIGNED_TAG must be 0 or 1"
[[ -z "${PASSTUNNEL_ALLOW_UNPINNED_TOOLS:-}" ]] \
    || die "unset PASSTUNNEL_ALLOW_UNPINNED_TOOLS: releases bundle the tool versions pinned in scripts/release.env"

# The files of every release, in the order they are uploaded.
RELEASE_ASSETS=("$DMG_NAME" "$STABLE_DMG_NAME" "$ZIP_NAME" "$MCPB_NAME" appcast.xml SHA256SUMS)

# Whether git signs the tag: user.signingkey, or gpg.format ssh with a default key.
has_signing_key() {
    [[ -n "$(git config --get user.signingkey || true)" || "$(git config --get gpg.format || true)" == ssh ]]
}

# Fails unless TAG carries a valid signature of the release tag key in .github/allowed_signers.
verify_tag() {
    git -c gpg.ssh.allowedSignersFile="$ROOT/.github/allowed_signers" tag -v "$TAG" >/dev/null \
        || die "tag $TAG is not signed by the release tag key in .github/allowed_signers"
    echo "tag $TAG: signature verified against .github/allowed_signers"
}

# Fails unless the draft release of TAG has every asset named in the arguments.
check_draft_assets() {
    local uploaded name
    uploaded="$(gh release view "$TAG" --repo "$GITHUB_REPO" --json assets --jq '.assets[].name')"
    for name in "$@"; do
        grep -qxF "$name" <<<"$uploaded" || die "$name is missing from the draft release $TAG"
    done
}

# Publishes the complete draft release of TAG. Pre-releases are marked as such and never become
# "latest".
publish_draft() {
    local tap_name="${TAP_REPO%%/*}/${TAP_REPO#*/homebrew-}"
    if ((PRERELEASE)); then
        gh release edit "$TAG" --repo "$GITHUB_REPO" --draft=false --prerelease --latest=false
    else
        gh release edit "$TAG" --repo "$GITHUB_REPO" --draft=false --latest
    fi
    echo
    echo "Released. Copy dist/passtunnel.rb to Casks/passtunnel.rb in $TAP_REPO ($tap_name) and push it."
    if ((PRERELEASE)); then
        echo "Pre-releases are not published to the MCP Registry (run the publish-mcp workflow by hand to list one)."
    else
        echo "The publish-mcp workflow now publishes $VERSION to the MCP Registry; check it under Actions."
    fi
}

# MARK: --publish-draft (no build)

if ((PUBLISH_DRAFT)); then
    step "publishing the draft release $TAG on $GITHUB_REPO"
    command -v gh >/dev/null || die "gh is not installed"
    IS_DRAFT="$(gh release view "$TAG" --repo "$GITHUB_REPO" --json isDraft --jq .isDraft 2>/dev/null)" \
        || die "there is no release $TAG on $GITHUB_REPO (scripts/release.sh $VERSION --publish --draft creates it)"
    [[ "$IS_DRAFT" == "true" ]] || die "release $TAG is already published; a published release is final"
    ATTACH_NAMES=()
    for f in ${ATTACH[@]+"${ATTACH[@]}"}; do
        [[ -f "$f" && -s "$f" ]] || die "$f not found or empty"
        name="$(basename "$f")"
        for built in "${RELEASE_ASSETS[@]}"; do
            [[ "$name" != "$built" ]] || die "--attach $f would replace the release file $built"
        done
        ATTACH_NAMES+=("$name")
    done
    if ((${#ATTACH[@]})); then
        gh release upload "$TAG" --repo "$GITHUB_REPO" --clobber "${ATTACH[@]}"
    fi
    check_draft_assets "${RELEASE_ASSETS[@]}" ${ATTACH_NAMES[@]+"${ATTACH_NAMES[@]}"}
    publish_draft
    exit 0
fi

# MARK: checks (all before the long build)

step "checking the repository"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" ]]; then
    ((ALLOW_BRANCH)) || die "on branch '$BRANCH'; releases are made from main (--allow-branch for a local test run)"
    echo "building from branch $BRANCH (--allow-branch)"
fi
[[ -z "$(git status --porcelain)" ]] || { git status --short >&2; die "the working tree is not clean"; }
COMMIT="$(git rev-parse HEAD)"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    # Re-running --publish after a failed push or release: the tag is ours if it points at HEAD.
    TAG_COMMIT="$(git rev-parse "$TAG^{commit}")"
    ((PUBLISH)) && [[ "$TAG_COMMIT" == "$COMMIT" ]] || die "tag $TAG already exists"
    echo "tag $TAG exists at HEAD; continuing"
fi
if ((PUBLISH && REQUIRE_SIGNED_TAG)); then
    has_signing_key || die "REQUIRE_SIGNED_TAG=1, but git has no signing key (gpg.format, user.signingkey)"
    # A tag that is already there (re-run) cannot be replaced (tag rules); it must be signed already.
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then verify_tag; fi
fi

# The section "## [VERSION] …" up to the next "## "; a pre-release falls back to its base version.
changelog_section() {
    awk -v v="$1" '
        /^## / { if (found) exit; if ($0 ~ "^## \\[?" v "\\]?([ ]|$)") { found = 1; next } }
        found { print }
    ' docs/CHANGELOG.md | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
}
if [[ -n "$NOTES_FILE" ]]; then
    step "reading the release notes from $NOTES_FILE"
    [[ -f "$NOTES_FILE" ]] || die "$NOTES_FILE not found"
    NOTES="$(sed -e '/./,$!d' "$NOTES_FILE")"
    [[ -n "$NOTES" ]] || die "$NOTES_FILE is empty"
else
    step "reading the release notes from docs/CHANGELOG.md"
    NOTES="$(changelog_section "$(sed 's/[.]/\\\\./g' <<<"$VERSION")")"
    if [[ -z "$NOTES" && "$PRERELEASE" == 1 ]]; then
        NOTES="$(changelog_section "$(sed 's/[.]/\\\\./g' <<<"$BASE_VERSION")")"
        [[ -n "$NOTES" ]] && echo "no section for $VERSION; using the one for $BASE_VERSION"
    fi
    [[ -n "$NOTES" ]] || die "docs/CHANGELOG.md has no section '## [$VERSION]'"
fi

step "checking signing and notarization"
if [[ -z "${PASSTUNNEL_SIGN_IDENTITY:-}" ]]; then
    TEAM_ID="$(sed -n 's/.*static let teamID = "\([A-Z0-9]*\)".*/\1/p' Sources/PassTunnelShared/Identifiers.swift)"
    [[ -n "$TEAM_ID" ]] || die "could not read teamID from Identifiers.swift"
    PASSTUNNEL_SIGN_IDENTITY="$(security find-identity -v -p codesigning \
        | sed -n "s/.*\"\(Developer ID Application: .*($TEAM_ID)\)\"/\1/p" | head -1)"
    [[ -n "$PASSTUNNEL_SIGN_IDENTITY" ]] || die "no 'Developer ID Application' identity for team $TEAM_ID in the keychain"
fi
IDENTITY="$PASSTUNNEL_SIGN_IDENTITY"
echo "identity: $IDENTITY"
if ((!SKIP_NOTARIZE)); then
    xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1 \
        || die "notarytool profile '$NOTARY_PROFILE' does not work (xcrun notarytool store-credentials $NOTARY_PROFILE …)"
    echo "notarytool profile: $NOTARY_PROFILE"
fi

step "checking the Sparkle tools and key"
swift package resolve >/dev/null
for tool in generate_appcast generate_keys sign_update; do
    [[ -x "$SPARKLE_BIN/$tool" ]] || die "$SPARKLE_BIN/$tool not found (swift package resolve)"
done
# The public key of a key file of generate_keys -x: base64 of the 32-byte seed (or, in Sparkle's older
# format, of the 64-byte private key followed by the 32-byte public key).
sparkle_file_public_key() {
    local size openssl
    size="$(base64 -D -i "$1" | wc -c | tr -d ' ')"
    case "$size" in
        96) base64 -D -i "$1" | tail -c 32 | base64 ;;
        32) openssl="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"
            [[ -x "$openssl" ]] || { echo "error: reading the key needs openssl@3 (brew install openssl@3)" >&2; return 1; }
            # DER of an Ed25519 PKCS#8 private key: the fixed header, then the seed.
            { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'; base64 -D -i "$1"; } \
                | "$openssl" pkey -inform DER -pubout -outform DER | tail -c 32 | base64 ;;
        *) echo "error: the key decodes to $size bytes, not 32 or 96" >&2; return 1 ;;
    esac
}
SPARKLE_KEY=()
if [[ -n "${SPARKLE_PRIVATE_KEY_FILE:-}" ]]; then
    KEY_SOURCE="key file $SPARKLE_PRIVATE_KEY_FILE"
    [[ -f "$SPARKLE_PRIVATE_KEY_FILE" ]] || die "SPARKLE_PRIVATE_KEY_FILE: $SPARKLE_PRIVATE_KEY_FILE not found"
    KEY="$(sparkle_file_public_key "$SPARKLE_PRIVATE_KEY_FILE")" || die "cannot read the Sparkle $KEY_SOURCE"
    SPARKLE_KEY=(--ed-key-file "$SPARKLE_PRIVATE_KEY_FILE")
else
    KEY_SOURCE="keychain"
    KEY="$("$SPARKLE_BIN/generate_keys" -p 2>/dev/null)" || die "no Sparkle signing key in the keychain (see docs/RELEASING.md)"
fi
PLIST_KEY="$(plutil -extract SUPublicEDKey raw Resources/Info.plist)"
[[ "$KEY" == "$PLIST_KEY" ]] || die "the Sparkle key in the $KEY_SOURCE ($KEY) is not the SUPublicEDKey in Resources/Info.plist ($PLIST_KEY)"
echo "EdDSA public key: $KEY"

step "checking the MCP bundle tools"
# jq, zip, unzip and sips; jq also writes dist/server.json.
"$ROOT/scripts/build-mcpb.sh" --check

if ((PUBLISH)); then
    step "checking GitHub"
    command -v gh >/dev/null || die "gh is not installed"
    gh repo view "$GITHUB_REPO" >/dev/null || die "repository $GITHUB_REPO not found (or gh is not logged in)"
    # A draft left by an interrupted run is reused (its assets are replaced); a published release is final.
    EXISTING_DRAFT=0
    if IS_DRAFT="$(gh release view "$TAG" --repo "$GITHUB_REPO" --json isDraft --jq .isDraft 2>/dev/null)"; then
        [[ "$IS_DRAFT" == "true" ]] || die "release $TAG already exists on $GITHUB_REPO"
        EXISTING_DRAFT=1
        echo "draft release $TAG exists; its assets will be replaced"
    fi
    git fetch -q origin main
    git merge-base --is-ancestor HEAD origin/main || die "HEAD is not on origin/main; push main first"
fi

# MARK: build

rm -rf "$WORK"
mkdir -p "$WORK"
# The stable-named copy carries no version, so one left in dist/ by an earlier build must not
# survive this one (it is written again below, from this build's disk image).
rm -f "$DIST/$STABLE_DMG_NAME"
NOTARY_LOG="$WORK/notarization.txt"
: > "$NOTARY_LOG"

step "building $VERSION"
"$ROOT/scripts/build-app.sh" --sign "$IDENTITY" --version "$VERSION"
APP="$WORK/PassTunnel.app"
ditto "$ROOT/build/PassTunnel.app" "$APP"
SHORT="$(plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")"
BUILD="$(plutil -extract CFBundleVersion raw "$APP/Contents/Info.plist")"
[[ "$SHORT" == "$VERSION" ]] || die "the app says version $SHORT, expected $VERSION"
echo "version $SHORT, build $BUILD"
codesign --verify --deep --strict "$APP" || die "codesign --verify --deep --strict failed"

# Submits a file and waits; fails with the notarization log unless Apple accepted it.
notarize() {
    local file="$1" label="$2" out id status
    echo "submitting $(basename "$file") (this usually takes a few minutes)"
    out="$(xcrun notarytool submit "$file" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json)" || true
    id="$(plutil -extract id raw - <<<"$out" 2>/dev/null || true)"
    status="$(plutil -extract status raw - <<<"$out" 2>/dev/null || true)"
    echo "$label: id=${id:-?} status=${status:-?}" | tee -a "$NOTARY_LOG"
    if [[ "$status" != "Accepted" ]]; then
        echo "$out" >&2
        [[ -n "$id" ]] && xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE" >&2 || true
        die "notarization of $(basename "$file") failed"
    fi
}

if ((SKIP_NOTARIZE)); then
    step "skipping notarization of the app (--skip-notarize)"
else
    step "notarizing the app"
    ditto -c -k --keepParent "$APP" "$WORK/notarize-app.zip"
    notarize "$WORK/notarize-app.zip" app
    rm -f "$WORK/notarize-app.zip"
    xcrun stapler staple "$APP"
    xcrun stapler validate "$APP"
    ASSESS="$(spctl -a -vvv -t exec "$APP" 2>&1 || true)"
    echo "$ASSESS"
    grep -q "accepted" <<<"$ASSESS" && grep -q "source=Notarized Developer ID" <<<"$ASSESS" \
        || die "Gatekeeper does not accept the app as notarized"
fi

step "creating the Sparkle archive"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$WORK/$ZIP_NAME"

step "creating the disk image"
STAGE="$WORK/dmg"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/PassTunnel.app"
ln -s /Applications "$STAGE/Applications"
for attempt in 1 2 3; do
    # hdiutil sometimes fails with "Resource busy" right after the files were written.
    hdiutil create -quiet -volname "PassTunnel $VERSION" -srcfolder "$STAGE" -fs HFS+ \
        -format UDZO -imagekey zlib-level=9 -ov "$WORK/$DMG_NAME" && break
    ((attempt < 3)) || die "hdiutil create failed"
    sleep 3
done
rm -rf "$STAGE"
codesign --force --sign "$IDENTITY" --timestamp "$WORK/$DMG_NAME"
codesign --verify --strict "$WORK/$DMG_NAME"

if ((SKIP_NOTARIZE)); then
    step "skipping notarization of the disk image (--skip-notarize)"
else
    step "notarizing the disk image"
    notarize "$WORK/$DMG_NAME" dmg
    xcrun stapler staple "$WORK/$DMG_NAME"
    xcrun stapler validate "$WORK/$DMG_NAME"
    ASSESS="$(spctl -a -vvv -t open --context context:primary-signature "$WORK/$DMG_NAME" 2>&1 || true)"
    echo "$ASSESS"
    grep -q "accepted" <<<"$ASSESS" && grep -q "source=Notarized Developer ID" <<<"$ASSESS" \
        || die "Gatekeeper does not accept the disk image as notarized"
fi

# The disk image again under the name without the version: the same bytes, so the same checksum
# and the same provenance digest.
cp "$WORK/$DMG_NAME" "$WORK/$STABLE_DMG_NAME"
cmp -s "$WORK/$DMG_NAME" "$WORK/$STABLE_DMG_NAME" || die "$STABLE_DMG_NAME differs from $DMG_NAME"

step "building the MCP bundle"
"$ROOT/scripts/build-mcpb.sh" "$VERSION" "$WORK"
MCPB_SHA="$(shasum -a 256 "$WORK/$MCPB_NAME" | awk '{print $1}')"

step "writing the MCP Registry entry"
# The publish-mcp workflow writes the same file from the published asset and publishes it.
"$ROOT/scripts/make-server-json.sh" "$VERSION" "$MCPB_SHA" > "$WORK/server.json"
if command -v mcp-publisher >/dev/null; then
    (cd "$WORK" && mcp-publisher validate server.json) || die "mcp-publisher validate rejects dist/server.json"
else
    echo "note: mcp-publisher is not installed; server.json is checked when the workflow publishes it"
fi

step "writing checksums and release notes"
(cd "$WORK" && shasum -a 256 "$DMG_NAME" "$STABLE_DMG_NAME" "$ZIP_NAME" "$MCPB_NAME" > SHA256SUMS)
cat "$WORK/SHA256SUMS"
printf '%s\n' "$NOTES" > "$WORK/release-notes-$VERSION.md"

# Markdown subset used in the changelog (headings, lists, paragraphs, **bold**, `code`, links) to
# HTML for the update window.
markdown_to_html() {
    /usr/bin/python3 -I -c '
import html, re, sys
def inline(t):
    t = html.escape(t, quote=False)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r"<a href=\"\2\">\1</a>", t)
    return t
out, para, in_list = [], [], False
def flush():
    global para
    if para: out.append("<p>" + inline(" ".join(para)) + "</p>"); para = []
for raw in sys.stdin.read().splitlines():
    line = raw.rstrip()
    m = re.match(r"^(#{1,6})\s+(.*)", line)
    item = re.match(r"^\s*[-*]\s+(.*)", line)
    if item:
        flush()
        if not in_list: out.append("<ul>"); in_list = True
        out.append("<li>" + inline(item.group(1)) + "</li>")
        continue
    if in_list and line.startswith("  ") and line.strip():
        out[-1] = out[-1][:-5] + " " + inline(line.strip()) + "</li>"
        continue
    if in_list: out.append("</ul>"); in_list = False
    if m:
        flush(); level = min(len(m.group(1)) + 1, 6)
        out.append("<h%d>%s</h%d>" % (level, inline(m.group(2)), level))
    elif not line.strip():
        flush()
    else:
        para.append(line.strip())
if in_list: out.append("</ul>")
flush()
print("\n".join(out))
'
}

step "generating the appcast"
FEED="$WORK/appcast"
mkdir -p "$FEED"
cp "$WORK/$ZIP_NAME" "$FEED/"
markdown_to_html <<<"$NOTES" > "$FEED/PassTunnel-$VERSION.html"
APPCAST_ARGS=(--download-url-prefix "$DOWNLOAD_PREFIX" --embed-release-notes --maximum-deltas 0
              --link "https://github.com/$GITHUB_REPO")
# Pre-releases go to the "beta" channel, which the app does not subscribe to.
((PRERELEASE)) && APPCAST_ARGS+=(--channel beta)
# ${a[@]+…}: an empty array under set -u in bash 3.2.
"$SPARKLE_BIN/generate_appcast" "${APPCAST_ARGS[@]}" ${SPARKLE_KEY[@]+"${SPARKLE_KEY[@]}"} -o "$WORK/appcast.xml" "$FEED"
grep -q 'sparkle:edSignature=' "$WORK/appcast.xml" || die "the appcast has no EdDSA signature"
# The app sets SURequireSignedFeed, so the feed itself must carry an EdDSA signature (an XML comment
# at the end). generate_appcast adds it when the archived app requires it; sign_update otherwise.
if ! grep -q '<!-- sparkle-signatures:' "$WORK/appcast.xml"; then
    "$SPARKLE_BIN/sign_update" ${SPARKLE_KEY[@]+"${SPARKLE_KEY[@]}"} "$WORK/appcast.xml"
fi
grep -q '<!-- sparkle-signatures:' "$WORK/appcast.xml" || die "the appcast feed is not signed"
"$SPARKLE_BIN/sign_update" ${SPARKLE_KEY[@]+"${SPARKLE_KEY[@]}"} --verify "$WORK/appcast.xml" || die "the appcast feed signature does not verify"
grep -q "url=\"$DOWNLOAD_PREFIX$ZIP_NAME\"" "$WORK/appcast.xml" || die "the appcast does not point at $DOWNLOAD_PREFIX$ZIP_NAME"
rm -rf "$FEED"

step "generating the Homebrew cask"
DMG_SHA="$(shasum -a 256 "$WORK/$DMG_NAME" | awk '{print $1}')"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@SHA256@|$DMG_SHA|g" -e "s|@GITHUB_REPO@|$GITHUB_REPO|g" \
    scripts/homebrew/passtunnel.rb.template > "$WORK/passtunnel.rb"
if command -v ruby >/dev/null; then
    ruby -c "$WORK/passtunnel.rb" >/dev/null || die "the generated cask is not valid Ruby"
fi

step "moving the results to dist/"
rm -rf "$WORK/PassTunnel.app"
for f in "$DMG_NAME" "$STABLE_DMG_NAME" "$ZIP_NAME" "$MCPB_NAME" SHA256SUMS appcast.xml passtunnel.rb server.json "release-notes-$VERSION.md"; do
    mv -f "$WORK/$f" "$DIST/$f"
done
mv -f "$NOTARY_LOG" "$DIST/notarization-$VERSION.txt"
rm -rf "$WORK"

if ((PUBLISH)); then
    step "publishing $TAG on $GITHUB_REPO"
    if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        if has_signing_key; then
            git tag -s "$TAG" -m "PassTunnel $VERSION"
        else
            ((!REQUIRE_SIGNED_TAG)) || die "REQUIRE_SIGNED_TAG=1, but git has no signing key"
            echo "warning: no git signing key configured; creating an unsigned annotated tag (docs/RELEASING.md)" >&2
            git tag -a "$TAG" -m "PassTunnel $VERSION"
        fi
    fi
    # Checked before the push: a pushed release tag can no longer be changed or deleted.
    ((!REQUIRE_SIGNED_TAG)) || verify_tag
    git push origin "$TAG"
    ASSETS=()
    for f in "${RELEASE_ASSETS[@]}"; do ASSETS+=("$DIST/$f"); done
    # Draft first, upload, check, then publish: with immutable releases a published release's assets
    # can no longer be added or replaced, so it must be complete before it is published.
    if ((EXISTING_DRAFT)); then
        # Files of an earlier attempt that this build does not replace go: a provenance bundle
        # (--attach) describes the files it was made for, not this build.
        DRAFT_ASSETS="$(gh release view "$TAG" --repo "$GITHUB_REPO" --json assets --jq '.assets[].name')"
        while IFS= read -r name; do
            [[ -n "$name" ]] || continue
            printf '%s\n' "${RELEASE_ASSETS[@]}" | grep -qxF "$name" && continue
            echo "removing $name of an earlier attempt from the draft"
            gh release delete-asset "$TAG" "$name" --repo "$GITHUB_REPO" --yes
        done <<<"$DRAFT_ASSETS"
        gh release upload "$TAG" --repo "$GITHUB_REPO" --clobber "${ASSETS[@]}"
    else
        CREATE_ARGS=(--repo "$GITHUB_REPO" --verify-tag --draft --title "PassTunnel $VERSION"
                     --notes-file "$DIST/release-notes-$VERSION.md")
        ((PRERELEASE)) && CREATE_ARGS+=(--prerelease)
        gh release create "$TAG" "${CREATE_ARGS[@]}" "${ASSETS[@]}"
    fi
    check_draft_assets "${RELEASE_ASSETS[@]}"
    if ((DRAFT)); then
        echo
        echo "Draft release $TAG is ready on GitHub; publish it there, run this again without --draft, or"
        echo "publish it with: scripts/release.sh $VERSION --publish-draft [--attach FILE]..."
        echo "Publishing it starts the publish-mcp workflow (MCP Registry; not for pre-releases)."
    else
        publish_draft
    fi
else
    echo
    echo "Built $VERSION (build $BUILD) in dist/. Nothing was published (use --publish)."
fi
