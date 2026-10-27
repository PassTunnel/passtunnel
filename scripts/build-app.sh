#!/bin/bash
# Builds build/PassTunnel.app.
#
#   scripts/build-app.sh                                   # ad-hoc signed (local testing)
#   scripts/build-app.sh --sign "Developer ID Application: Name (TEAMID)"
#   scripts/build-app.sh --sign "…" --version 1.2.0          # CFBundleShortVersionString (release.sh)
#   scripts/build-app.sh --version 1.2.0 --tools-from PassTunnel.app   # rebuild a release (verify-build.sh)
#
# Signing is inside-out (dylibs, tools, Sparkle, helper, app) with the hardened runtime; an ad-hoc
# build signs the app without library validation, or it could not load Sparkle. Only a Developer ID
# build can talk to the helper: the helper checks the Team ID of its clients and of the tools.
# The tools and their dylibs are signed first: the helper is compiled with their cdhashes (PinnedTools),
# stages exactly these builds into a root-owned directory and runs them from there.
# --tools-from (ad-hoc only) takes the signed tools and dylibs from a released app instead of signing
# its own, after checking that they are this build's apart from the signature: the pins compiled in
# are then the release's, and the rest of the bundle can be compared with it (docs/RELEASING.md,
# Verifying a release).
#
# The build is repeatable: the same commit, Xcode and Homebrew bottles give the same bundle, apart
# from the code signatures. The Xcode build is recorded in Info.plist (DTXcodeBuild).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# GITHUB_REPO (feed URL and links in Info.plist)
source "$ROOT/scripts/release.env"
IDENTITY="-"
VERSION=""
TOOLS_FROM=""
while (($#)); do
    case "$1" in
        --sign) IDENTITY="${2:?--sign needs an identity}"; shift 2 ;;
        --version) VERSION="${2:?--version needs a version}"; shift 2 ;;
        --tools-from) TOOLS_FROM="${2:?--tools-from needs an app}"; shift 2 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ -n "$TOOLS_FROM" ]]; then
    [[ "$IDENTITY" == "-" ]] || { echo "error: --tools-from is for ad-hoc builds only" >&2; exit 2; }
    [[ -d "$TOOLS_FROM/Contents" ]] || { echo "error: $TOOLS_FROM is not an app bundle" >&2; exit 2; }
    TOOLS_FROM="$(cd "$TOOLS_FROM" && pwd)"
fi

cd "$ROOT"
APP="$ROOT/build/PassTunnel.app"
C="$APP/Contents"
SIGN=(codesign --force --options runtime --sign "$IDENTITY")
[[ "$IDENTITY" != "-" ]] && SIGN+=(--timestamp)
TOOLS=(openvpn openfortivpn dns-updown)
PINS="$ROOT/Sources/PassTunnelShared/PinnedTools+Generated.swift"

rm -rf "$APP"
mkdir -p "$C/MacOS" "$C/Resources" "$C/Library/LaunchDaemons" "$C/Frameworks"

echo "==> bundling VPN tools"
"$ROOT/scripts/bundle-tools.sh" "$APP"

if [[ -n "$TOOLS_FROM" ]]; then
    echo "==> taking the signed VPN tools from $TOOLS_FROM"
    # The same files on both sides, and each one this build's apart from its signature.
    diff <(cd "$C" && ls Resources/bin/* Frameworks/*.dylib) \
        <(cd "$TOOLS_FROM/Contents" && ls Resources/bin/* Frameworks/*.dylib) \
        || { echo "error: $TOOLS_FROM bundles other tools or libraries" >&2; exit 1; }
    for f in "$C"/Resources/bin/* "$C"/Frameworks/*.dylib; do
        theirs="$TOOLS_FROM/Contents/${f#"$C"/}"
        "$ROOT/scripts/compare-app.sh" "$f" "$theirs" >/dev/null \
            || { echo "error: ${f#"$C"/} differs from the one in $TOOLS_FROM apart from the signature" >&2; exit 1; }
        # ditto keeps the signature, also dns-updown's, which is in extended attributes.
        rm -f "$f"
        ditto "$theirs" "$f"
    done
else
    echo "==> signing VPN tools with: $([[ "$IDENTITY" == "-" ]] && echo "ad-hoc" || echo "$IDENTITY")"
    for lib in "$C/Frameworks"/*.dylib; do "${SIGN[@]}" "$lib"; done
    "${SIGN[@]}" --identifier com.furkanprlk.passtunnel.openvpn "$C/Resources/bin/openvpn"
    "${SIGN[@]}" --identifier com.furkanprlk.passtunnel.openfortivpn "$C/Resources/bin/openfortivpn"
    if [[ -f "$C/Resources/bin/dns-updown" ]]; then
        # Non-Mach-O: the signature is stored in extended attributes; the helper verifies its own copy.
        "${SIGN[@]}" --identifier com.furkanprlk.passtunnel.dns-updown "$C/Resources/bin/dns-updown"
    fi
fi

# The CDHash of every architecture of a signed file (a script has one), one per line. It is what the
# kernel records for a running process and what the helper compares (kSecCodeInfoUnique).
cdhashes_of() {
    local archs arch
    archs="$(lipo -archs "$1" 2>/dev/null || true)"
    if [[ -z "$archs" ]]; then
        codesign -dvvv "$1" 2>&1 | sed -n 's/^CDHash=//p'
    else
        for arch in $archs; do codesign -dvvv -a "$arch" "$1" 2>&1 | sed -n 's/^CDHash=//p'; done
    fi
}

# "name": ["cdhash", …], line for the pins file; fails without a cdhash.
pin_entry() {
    local name="$1" f="$2" hashes h list=""
    hashes="$(cdhashes_of "$f")"
    [[ -n "$hashes" ]] || { echo "error: no cdhash for $name" >&2; return 1; }
    for h in $hashes; do
        [[ "$h" =~ ^[0-9a-f]{40}$ ]] || { echo "error: unexpected cdhash for $name: $h" >&2; return 1; }
        list+="${list:+, }\"$h\""
    done
    echo "        \"$name\": [$list],"
    echo "  $name: $hashes" | tr '\n' ' ' >&2; echo >&2
}

echo "==> pinning tool and library cdhashes"
# Compiled into the helper (and the app, unused there) with PASSTUNNEL_TOOL_PINS; never committed.
# Without the define, PinnedTools.swift pins nothing (swift build, swift test).
trap 'rm -f "$PINS"' EXIT
{
    echo "// Generated by scripts/build-app.sh for this build's tools. Not in the repository."
    echo "#if PASSTUNNEL_TOOL_PINS"
    echo "extension PinnedTools {"
    echo "    static let generatedCDHashes: [String: Set<String>] = ["
    for tool in "${TOOLS[@]}"; do
        f="$C/Resources/bin/$tool"
        hashes=""
        if [[ -f "$f" ]]; then
            hashes="$(cdhashes_of "$f")"
        elif [[ "$tool" != dns-updown ]]; then
            echo "error: $f missing" >&2; exit 1
        fi
        if [[ -f "$f" && -z "$hashes" ]]; then echo "error: no cdhash for $tool" >&2; exit 1; fi
        list=""
        for h in $hashes; do
            [[ "$h" =~ ^[0-9a-f]{40}$ ]] || { echo "error: unexpected cdhash for $tool: $h" >&2; exit 1; }
            list+="${list:+, }\"$h\""
        done
        # A bundle without dns-updown pins an empty set: the helper then refuses any dns-updown.
        echo "        \"$tool\": [$list],"
        echo "  $tool: ${hashes:-none (not bundled)}" | tr '\n' ' ' >&2; echo >&2
    done
    echo "    ]"
    # Every dylib in Contents/Frameworks (the tools' dependency closure from bundle-tools.sh).
    echo "    static let generatedLibraryCDHashes: [String: Set<String>] = ["
    nlibs=0
    for lib in "$C/Frameworks"/*.dylib; do
        [[ -f "$lib" ]] || continue
        pin_entry "$(basename "$lib")" "$lib" || exit 1
        nlibs=$((nlibs + 1))
    done
    ((nlibs > 0)) || echo "        :"
    echo "    ]"
    echo "}"
    echo "#endif"
} > "$PINS"

echo "==> swift build -c release"
# -Xlinker -S: no debug map (the stabs that name every object file by its absolute path in .build,
# with its modification time). Nothing uses it: no dSYM is made from it, and the symbol table stays.
# Without it, the executables differed between two checkouts and two builds of the same checkout.
BUILD=(swift build -c release -Xswiftc -DPASSTUNNEL_TOOL_PINS -Xlinker -S)
"${BUILD[@]}"
BIN_DIR="$("${BUILD[@]}" --show-bin-path)"

echo "==> assembling $APP"
cp "$BIN_DIR/PassTunnel" "$C/MacOS/PassTunnel"
cp "$BIN_DIR/PassTunnelHelper" "$C/MacOS/PassTunnelHelper"
# Sparkle is linked as @rpath/Sparkle.framework; in the bundle it lives in Contents/Frameworks.
install_name_tool -add_rpath "@executable_path/../Frameworks" "$C/MacOS/PassTunnel" 2>/dev/null

# LC_RPATH entries of a Mach-O file, one per line.
rpaths_of() {
    otool -l "$1" | awk '/cmd LC_RPATH/ { r = 1 } r && $1 == "path" { sub(/^ *path /, ""); sub(/ \(offset [0-9]+\)$/, ""); print; r = 0 }'
}
# SwiftPM leaves build-machine rpaths in both executables (/usr/lib/swift, @loader_path and the
# Xcode toolchain). The Swift runtime ships with macOS 13+ and is loaded by absolute /usr/lib/swift
# paths, so the app keeps only Contents/Frameworks (for Sparkle) and the helper keeps none.
for exe in PassTunnel PassTunnelHelper; do
    keep=""
    [[ "$exe" == PassTunnel ]] && keep="@executable_path/../Frameworks"
    while IFS= read -r rp; do
        if [[ -n "$rp" && "$rp" != "$keep" ]]; then
            install_name_tool -delete_rpath "$rp" "$C/MacOS/$exe" 2>/dev/null
        fi
    done < <(rpaths_of "$C/MacOS/$exe")
done
cp "$ROOT/Resources/com.furkanprlk.passtunnel.helper.plist" "$C/Library/LaunchDaemons/"

# A release is tagged after its build (release.sh), so the tag of this version is left out when it is
# on this commit: rebuilt at the tag, the app says what the release says. A fixed abbreviation, as the
# default one grows with the repository.
DESCRIBE_ARGS=(--tags --always --dirty --abbrev=12)
if [[ -n "$VERSION" && "$(git rev-parse -q --verify "refs/tags/v$VERSION^{commit}" 2>/dev/null)" == "$(git rev-parse HEAD 2>/dev/null)" ]]; then
    DESCRIBE_ARGS+=(--exclude "v$VERSION")
fi
DESCRIBE="$(git describe "${DESCRIBE_ARGS[@]}" 2>/dev/null || echo unknown)"
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
# The Xcode that built the app (as Xcode itself records it), for rebuilding a release.
XCODE_BUILD="$(xcodebuild -version 2>/dev/null | sed -n 's/^Build version //p')"
[[ -n "$XCODE_BUILD" ]] && plutil -insert DTXcodeBuild -string "$XCODE_BUILD" "$C/Info.plist"
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

echo "==> checking rpaths"
# Only bundle-relative rpaths, and every @rpath load must resolve inside the bundle.
for exe in "$C/MacOS/PassTunnel" "$C/MacOS/PassTunnelHelper"; do
    rps="$(rpaths_of "$exe")"
    while IFS= read -r rp; do
        [[ -z "$rp" || "$rp" == @executable_path/* ]] && continue
        echo "error: $exe has the rpath $rp" >&2; exit 1
    done <<<"$rps"
    while IFS= read -r dep; do
        found=0
        while IFS= read -r rp; do
            if [[ -n "$rp" && -e "${rp/#@executable_path/$(dirname "$exe")}/${dep#@rpath/}" ]]; then found=1; fi
        done <<<"$rps"
        ((found)) || { echo "error: $(basename "$exe"): $dep does not resolve in the bundle" >&2; exit 1; }
    done < <(otool -L "$exe" | tail -n +2 | awk '$1 ~ /^@rpath\// { print $1 }')
    echo "  $(basename "$exe"): ${rps:-no rpaths}"
done

echo "==> signing with: $([[ "$IDENTITY" == "-" ]] && echo "ad-hoc" || echo "$IDENTITY")"
# The tools and their dylibs are signed already (above); signing them again would change the cdhashes.
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
"${SIGN[@]}" --identifier com.furkanprlk.passtunnel.helper "$C/MacOS/PassTunnelHelper"
APP_SIGN=("${SIGN[@]}")
if [[ "$IDENTITY" == "-" ]]; then
    # Ad-hoc only: the app without library validation, so it can load Sparkle. An ad-hoc signature has
    # no Team ID, and library validation (part of the hardened runtime) then refuses every non-system
    # library ("different Team IDs"), even one signed ad-hoc as well. The rest of the hardened runtime
    # stays on. A Developer ID build keeps library validation and is signed without entitlements.
    ENTITLEMENTS="$ROOT/build/adhoc.entitlements"
    cat > "$ENTITLEMENTS" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
EOF
    APP_SIGN+=(--entitlements "$ENTITLEMENTS")
fi
"${APP_SIGN[@]}" "$APP"

echo "==> verifying"
codesign --verify --deep --strict --verbose=2 "$APP"
# The tools in the bundle are the ones pinned, and the pins are in the helper that was signed.
for tool in "${TOOLS[@]}"; do
    f="$C/Resources/bin/$tool"
    [[ -f "$f" ]] || continue
    for h in $(cdhashes_of "$f"); do
        grep -q "\"$tool\": \[.*\"$h\"" "$PINS" || { echo "error: $tool ($h) is not the pinned build" >&2; exit 1; }
        LC_ALL=C grep -aq "$h" "$C/MacOS/PassTunnelHelper" || { echo "error: the helper lacks the pin of $tool" >&2; exit 1; }
    done
done
# Every bundled dylib likewise (the helper stages and checks exactly the pinned ones).
for lib in "$C/Frameworks"/*.dylib; do
    [[ -f "$lib" ]] || continue
    name="$(basename "$lib")"
    for h in $(cdhashes_of "$lib"); do
        grep -q "\"$name\": \[.*\"$h\"" "$PINS" || { echo "error: $name ($h) is not the pinned build" >&2; exit 1; }
        LC_ALL=C grep -aq "$h" "$C/MacOS/PassTunnelHelper" || { echo "error: the helper lacks the pin of $name" >&2; exit 1; }
    done
done
# A release must never ship a helper that accepts any team-signed tool or library.
if [[ "$IDENTITY" != "-" ]]; then
    for tool in openvpn openfortivpn; do
        grep -Eq "\"$tool\": \[\"[0-9a-f]{40}\"" "$PINS" || { echo "error: $tool is not pinned in a signed build" >&2; exit 1; }
    done
    libs=0
    for lib in "$C/Frameworks"/*.dylib; do
        [[ -f "$lib" ]] || continue
        libs=$((libs + 1))
        grep -Eq "\"$(basename "$lib")\": \[\"[0-9a-f]{40}\"" "$PINS" \
            || { echo "error: $(basename "$lib") is not pinned in a signed build" >&2; exit 1; }
    done
    ((libs > 0)) || { echo "error: no tool libraries in Contents/Frameworks" >&2; exit 1; }
fi
echo "  tool and library pins: $(grep -Eo '[0-9a-f]{40}' "$PINS" | wc -l | tr -d ' ') cdhashes in PassTunnelHelper"
codesign -dv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier|flags|Authority=Developer" || true
echo "--- spctl (fails without notarization; informational only)"
spctl -a -vv "$APP" 2>&1 || true
echo "==> done: $APP ($SHORT_VERSION, build $BUILD_NUMBER, $DESCRIBE)"
