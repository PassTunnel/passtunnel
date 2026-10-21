#!/bin/bash
# Builds build/PassTunnel.app.
#
#   scripts/build-app.sh                                   # ad-hoc signed (local testing)
#   scripts/build-app.sh --sign "Developer ID Application: Name (TEAMID)"
#   scripts/build-app.sh --sign "…" --version 1.2.0          # CFBundleShortVersionString (release.sh)
#
# Signing is inside-out (dylibs, tools, Sparkle, helper, app) with the hardened runtime. Only a
# Developer ID build can talk to the helper: the helper checks the Team ID of its clients and of the tools.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# GITHUB_REPO (feed URL and links in Info.plist)
source "$ROOT/scripts/release.env"
IDENTITY="-"
VERSION=""
while (($#)); do
    case "$1" in
        --sign) IDENTITY="${2:?--sign needs an identity}"; shift 2 ;;
        --version) VERSION="${2:?--version needs a version}"; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

cd "$ROOT"
APP="$ROOT/build/PassTunnel.app"
C="$APP/Contents"

echo "==> swift build -c release"
swift build -c release
BIN_DIR="$(swift build -c release --show-bin-path)"

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$C/MacOS" "$C/Resources" "$C/Library/LaunchDaemons" "$C/Frameworks"
cp "$BIN_DIR/PassTunnel" "$C/MacOS/PassTunnel"
cp "$BIN_DIR/PassTunnelHelper" "$C/MacOS/PassTunnelHelper"
# Sparkle is linked as @rpath/Sparkle.framework; in the bundle it lives in Contents/Frameworks.
install_name_tool -add_rpath "@executable_path/../Frameworks" "$C/MacOS/PassTunnel" 2>/dev/null
cp "$ROOT/Resources/com.furkanprlk.passtunnel.helper.plist" "$C/Library/LaunchDaemons/"

DESCRIBE="$(git describe --tags --always --dirty 2>/dev/null || echo unknown)"
BUILD_NUMBER="$(git rev-list --count HEAD 2>/dev/null || echo 1)"
if [[ -n "$VERSION" ]]; then
    SHORT_VERSION="$VERSION"
elif [[ "$DESCRIBE" =~ ^v?([0-9]+\.[0-9]+(\.[0-9]+)?)(-|$) ]]; then
    SHORT_VERSION="${BASH_REMATCH[1]}"
else
    SHORT_VERSION="0.0.0"
fi
sed -e "s/__SHORT_VERSION__/$SHORT_VERSION/" -e "s/__BUILD_NUMBER__/$BUILD_NUMBER/" \
    -e "s/__GIT_DESCRIBE__/$DESCRIBE/" -e "s|__GITHUB_REPO__|$GITHUB_REPO|g" \
    "$ROOT/Resources/Info.plist" > "$C/Info.plist"
plutil -lint -s "$C/Info.plist"
printf 'APPL????' > "$C/PkgInfo"

# SwiftPM resource bundle (Bundle.module looks for it next to the .app, which codesign forbids, so
# app code should load resources through Bundle.main).
for bundle in "$BIN_DIR"/*.bundle; do
    [[ -d "$bundle" ]] && cp -R "$bundle" "$C/Resources/"
done
# `swift build` copies .xcstrings uncompiled; compile them into Contents/Resources/<lang>.lproj.
for xcs in "$ROOT"/Sources/PassTunnel/Resources/*.xcstrings; do
    [[ -f "$xcs" ]] || continue
    if xcrun --find xcstringstool >/dev/null 2>&1; then
        xcrun xcstringstool compile "$xcs" --output-directory "$C/Resources"
    else
        echo "warning: xcstringstool not found (needs Xcode); $(basename "$xcs") not compiled" >&2
    fi
done
[[ -f "$ROOT/Resources/AppIcon.icns" ]] && cp "$ROOT/Resources/AppIcon.icns" "$C/Resources/"

echo "==> bundling VPN tools"
"$ROOT/scripts/bundle-tools.sh" "$APP"

echo "==> embedding Sparkle"
# After bundle-tools.sh, which recreates Contents/Frameworks.
[[ -d "$BIN_DIR/Sparkle.framework" ]] || { echo "Sparkle.framework not found in $BIN_DIR" >&2; exit 1; }
ditto "$BIN_DIR/Sparkle.framework" "$C/Frameworks/Sparkle.framework"
SPARKLE_LICENSE="$ROOT/.build/artifacts/sparkle/Sparkle/LICENSE"
if [[ -f "$SPARKLE_LICENSE" ]]; then
    cp "$SPARKLE_LICENSE" "$C/Resources/licenses/Sparkle-LICENSE.txt"
else
    echo "warning: Sparkle license not found at $SPARKLE_LICENSE" >&2
fi

echo "==> signing with: $([[ "$IDENTITY" == "-" ]] && echo "ad-hoc" || echo "$IDENTITY")"
SIGN=(codesign --force --options runtime --sign "$IDENTITY")
[[ "$IDENTITY" != "-" ]] && SIGN+=(--timestamp)

for lib in "$C/Frameworks"/*.dylib; do "${SIGN[@]}" "$lib"; done
# Sparkle, inside-out: its XPC services (only used by sandboxed apps, signed anyway), the installer
# (Autoupdate), the progress app (Updater.app), then the framework. The XPC services keep whatever
# entitlements they ship with.
SPARKLE="$C/Frameworks/Sparkle.framework/Versions/B"
for xpc in "$SPARKLE"/XPCServices/*.xpc; do
    [[ -d "$xpc" ]] || continue
    "${SIGN[@]}" --preserve-metadata=entitlements "$xpc"
done
"${SIGN[@]}" "$SPARKLE/Autoupdate"
"${SIGN[@]}" "$SPARKLE/Updater.app"
"${SIGN[@]}" "$C/Frameworks/Sparkle.framework"
"${SIGN[@]}" --identifier com.furkanprlk.passtunnel.openvpn "$C/Resources/bin/openvpn"
"${SIGN[@]}" --identifier com.furkanprlk.passtunnel.openfortivpn "$C/Resources/bin/openfortivpn"
if [[ -f "$C/Resources/bin/dns-updown" ]]; then
    # Non-Mach-O: the signature is stored in extended attributes; the helper verifies its own copy.
    "${SIGN[@]}" --identifier com.furkanprlk.passtunnel.dns-updown "$C/Resources/bin/dns-updown"
fi
"${SIGN[@]}" --identifier com.furkanprlk.passtunnel.helper "$C/MacOS/PassTunnelHelper"
"${SIGN[@]}" "$APP"

echo "==> verifying"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -dv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier|flags|Authority=Developer" || true
echo "--- spctl (fails without notarization; informational only)"
spctl -a -vv "$APP" 2>&1 || true
echo "==> done: $APP ($SHORT_VERSION, build $BUILD_NUMBER, $DESCRIBE)"
