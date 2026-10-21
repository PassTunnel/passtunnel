#!/bin/bash
# Builds a signed, notarized PassTunnel release into dist/.
#
#   scripts/release.sh VERSION [--draft] [--skip-notarize] [--allow-branch] [--publish]
#
#   VERSION          semantic version: 1.2.0, 1.3.0-rc.1, …
#   --skip-notarize  sign only (no notarization, no stapling); never use for a published release
#   --allow-branch   build from the current branch instead of main (local test runs; not with --publish)
#   --publish        create and push the tag vVERSION, then create the GitHub release with the files
#   --draft          with --publish: create the release as a draft
#
# Without --publish nothing leaves this Mac apart from the notarization uploads: no tag, no push, no
# release. Output: dist/PassTunnel-VERSION.dmg, dist/PassTunnel-VERSION.zip (Sparkle update),
# dist/SHA256SUMS, dist/appcast.xml, dist/passtunnel.rb (Homebrew cask), dist/release-notes-VERSION.md.
# Repository slugs come from scripts/release.env. Setup and the whole procedure: docs/RELEASING.md.
#
# Environment: PASSTUNNEL_SIGN_IDENTITY (default: the Developer ID Application identity of the Team ID
# in Identifiers.swift), NOTARY_PROFILE (notarytool keychain profile, default: passtunnel).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/scripts/release.env"

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }

VERSION=""
DRAFT=0
SKIP_NOTARIZE=0
ALLOW_BRANCH=0
PUBLISH=0
while (($#)); do
    case "$1" in
        --draft) DRAFT=1 ;;
        --skip-notarize) SKIP_NOTARIZE=1 ;;
        --allow-branch) ALLOW_BRANCH=1 ;;
        --publish) PUBLISH=1 ;;
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
ZIP_NAME="PassTunnel-$VERSION.zip"
SPARKLE_BIN="$ROOT/.build/artifacts/sparkle/Sparkle/bin"

((PUBLISH && ALLOW_BRANCH)) && die "--publish releases from main only; drop --allow-branch"
((PUBLISH && SKIP_NOTARIZE)) && die "--publish needs a notarized build; drop --skip-notarize"
((DRAFT && !PUBLISH)) && echo "note: --draft only matters with --publish"

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

step "reading the release notes from docs/CHANGELOG.md"
# The section "## [VERSION] …" up to the next "## "; a pre-release falls back to its base version.
changelog_section() {
    awk -v v="$1" '
        /^## / { if (found) exit; if ($0 ~ "^## \\[?" v "\\]?([ ]|$)") { found = 1; next } }
        found { print }
    ' docs/CHANGELOG.md | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
}
NOTES="$(changelog_section "$(sed 's/[.]/\\\\./g' <<<"$VERSION")")"
if [[ -z "$NOTES" && "$PRERELEASE" == 1 ]]; then
    NOTES="$(changelog_section "$(sed 's/[.]/\\\\./g' <<<"$BASE_VERSION")")"
    [[ -n "$NOTES" ]] && echo "no section for $VERSION; using the one for $BASE_VERSION"
fi
[[ -n "$NOTES" ]] || die "docs/CHANGELOG.md has no section '## [$VERSION]'"

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
for tool in generate_appcast generate_keys; do
    [[ -x "$SPARKLE_BIN/$tool" ]] || die "$SPARKLE_BIN/$tool not found (swift package resolve)"
done
KEY="$("$SPARKLE_BIN/generate_keys" -p 2>/dev/null)" || die "no Sparkle signing key in the keychain (see docs/RELEASING.md)"
PLIST_KEY="$(plutil -extract SUPublicEDKey raw Resources/Info.plist)"
[[ "$KEY" == "$PLIST_KEY" ]] || die "the Sparkle key in the keychain ($KEY) is not the SUPublicEDKey in Resources/Info.plist ($PLIST_KEY)"
echo "EdDSA public key: $KEY"

if ((PUBLISH)); then
    step "checking GitHub"
    command -v gh >/dev/null || die "gh is not installed"
    gh repo view "$GITHUB_REPO" >/dev/null || die "repository $GITHUB_REPO not found (or gh is not logged in)"
    ! gh release view "$TAG" --repo "$GITHUB_REPO" >/dev/null 2>&1 || die "release $TAG already exists on $GITHUB_REPO"
    git fetch -q origin main
    git merge-base --is-ancestor HEAD origin/main || die "HEAD is not on origin/main; push main first"
fi

# MARK: build

rm -rf "$WORK"
mkdir -p "$WORK"
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

step "writing checksums and release notes"
(cd "$WORK" && shasum -a 256 "$DMG_NAME" "$ZIP_NAME" > SHA256SUMS)
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
"$SPARKLE_BIN/generate_appcast" "${APPCAST_ARGS[@]}" -o "$WORK/appcast.xml" "$FEED"
grep -q 'sparkle:edSignature=' "$WORK/appcast.xml" || die "the appcast has no EdDSA signature"
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
for f in "$DMG_NAME" "$ZIP_NAME" SHA256SUMS appcast.xml passtunnel.rb "release-notes-$VERSION.md"; do
    mv -f "$WORK/$f" "$DIST/$f"
done
mv -f "$NOTARY_LOG" "$DIST/notarization-$VERSION.txt"
rm -rf "$WORK"

if ((PUBLISH)); then
    step "publishing $TAG on $GITHUB_REPO"
    if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        git tag -a "$TAG" -m "PassTunnel $VERSION"
    fi
    git push origin "$TAG"
    RELEASE_ARGS=(--repo "$GITHUB_REPO" --verify-tag --title "PassTunnel $VERSION"
                  --notes-file "$DIST/release-notes-$VERSION.md")
    ((DRAFT)) && RELEASE_ARGS+=(--draft)
    ((PRERELEASE)) && RELEASE_ARGS+=(--prerelease)
    gh release create "$TAG" "${RELEASE_ARGS[@]}" \
        "$DIST/$DMG_NAME" "$DIST/$ZIP_NAME" "$DIST/appcast.xml" "$DIST/SHA256SUMS"
    TAP_NAME="${TAP_REPO%%/*}/${TAP_REPO#*/homebrew-}"
    echo
    echo "Released. Copy dist/passtunnel.rb to Casks/passtunnel.rb in $TAP_REPO ($TAP_NAME) and push it."
else
    echo
    echo "Built $VERSION (build $BUILD) in dist/. Nothing was published (use --publish)."
fi
