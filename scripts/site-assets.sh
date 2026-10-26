#!/bin/bash
# Regenerates every image of the website in site/assets/img/ (see docs/WEBSITE.md, "Images").
#
#   scripts/site-assets.sh
#
# Builds the app and runs its offscreen renderer (PASSTUNNEL_RENDER, at backing scale 4) with sample
# profiles, a temporary support folder and a throwaway Keychain service: nothing is shown on screen,
# and no real profile, secret, VPN or helper is touched. The screenshots are written as near-lossless
# WebP at the size they are displayed (1x), one and a half times (@1.5x) and twice that (@2x); the
# small images (icons) as lossless WebP at 1x and 2x. The favicon and the Apple
# touch icon come from Resources/AppIcon.icns, and the 1200x630 social image is scripts/site/og.html
# rendered with headless Google Chrome.
#
# It also writes the images the README shows to docs/images/ (the 2x screenshots as PNG).
#
# Needs macOS with Xcode, cwebp (brew install webp) and Google Chrome (or CHROME=/path/to/chrome).
# After a run, check that the width and height attributes and the srcset width descriptors in
# site/index.html still match the sizes printed at the end.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/site/assets/img"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"

die() { echo "error: $*" >&2; exit 1; }

[[ "$(uname -s)" == Darwin ]] || die "this script needs macOS (it runs the app's renderer)"
command -v cwebp >/dev/null || die "cwebp is missing (brew install webp)"
command -v sips >/dev/null || die "sips is missing"
[[ -x "$CHROME" ]] || die "Google Chrome not found at $CHROME (set CHROME=...)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Building the app"
cd "$ROOT"
swift build --product PassTunnel >/dev/null
BIN="$(swift build --show-bin-path)/PassTunnel"

echo "==> Rendering (offscreen, sample data only)"
RENDER="$TMP/render"
PASSTUNNEL_RENDER_SCALE=4 PASSTUNNEL_RENDER="$RENDER" "$BIN" >/dev/null

width() { sips -g pixelWidth "$1" | awk '/pixelWidth/ { print $2 }'; }
height() { sips -g pixelHeight "$1" | awk '/pixelHeight/ { print $2 }'; }

# Light and dark versions replace each other on the page, so they must have the same size.
same_size() {
    [[ "$(width "$1")x$(height "$1")" == "$(width "$2")x$(height "$2")" ]] ||
        die "$(basename "$1") and $(basename "$2") differ in size"
}

rm -rf "$OUT"
mkdir -p "$OUT"

# webp SOURCE NAME WIDTH: NAME.webp at WIDTH px (1x) and NAME@2x.webp at twice that, lossless.
webp() {
    local src="$1" name="$2" w="$3"
    [[ -f "$src" ]] || die "the renderer did not write $(basename "$src")"
    cwebp -quiet -lossless -z 9 -exact -metadata none -resize "$w" 0 "$src" -o "$OUT/$name.webp"
    cwebp -quiet -lossless -z 9 -exact -metadata none -resize "$((w * 2))" 0 "$src" -o "$OUT/$name@2x.webp"
}

# shot SOURCE NAME WIDTH [CUT]: a screenshot as NAME.webp at WIDTH px (1x), NAME@1.5x.webp and NAME@2x.webp,
# near-lossless (no pixel off by more than 2 of 255, about 30% smaller than lossless). WIDTH must be
# even, so that 1.5x is a whole number of pixels (site/index.html lists the widths in srcset). CUT
# removes that many pixels (of the render) from the bottom first.
shot() {
    local src="$1" name="$2" w="$3" cut="${4:-0}" crop=()
    (( cut == 0 )) || crop=(-crop 0 0 "$(width "$src")" "$(($(height "$src") - cut))")
    [[ -f "$src" ]] || die "the renderer did not write $(basename "$src")"
    (( w % 2 == 0 )) || die "the 1x width of $name must be even"
    cwebp -quiet -lossless -near_lossless 60 -z 9 -exact -metadata none ${crop[@]+"${crop[@]}"} -resize "$w" 0 "$src" -o "$OUT/$name.webp"
    cwebp -quiet -lossless -near_lossless 60 -z 9 -exact -metadata none ${crop[@]+"${crop[@]}"} -resize "$((w * 3 / 2))" 0 "$src" -o "$OUT/$name@1.5x.webp"
    cwebp -quiet -lossless -near_lossless 60 -z 9 -exact -metadata none ${crop[@]+"${crop[@]}"} -resize "$((w * 2))" 0 "$src" -o "$OUT/$name@2x.webp"
}

# themed SOURCE_BASE NAME WIDTH [CUT]: the light and the dark render (SOURCE_BASE.png, SOURCE_BASE-dark.png).
themed() {
    same_size "$1.png" "$1-dark.png"
    shot "$1.png" "$2-light" "$3" "${4:-0}"
    shot "$1-dark.png" "$2-dark" "$3" "${4:-0}"
}

echo "==> Converting screenshots"
themed "$RENDER/main-split-hero" hero 640                       # hero: a narrow split window (800 pt), two tunnels
themed "$RENDER/main-split" main 640                            # README: the split window, six tunnels (not on the page)
themed "$RENDER/editor/editor-one-time-code" editor-code 480    # profile editor sheet
themed "$RENDER/menubar-panel" menubar-panel 360                # menu bar panel
themed "$RENDER/first-run" first-run 520                        # first run: import options, helper card

# Settings, General: the window ends with a line showing the version, which is not a real one in a
# render (0.0.0) and which the site does not print, so the last 190 px (48 pt) are cropped off.
themed "$RENDER/settings-general" settings-general 400 190

echo "==> README images (docs/images/, the 2x screenshots as PNG)"
command -v dwebp >/dev/null || die "dwebp is missing (brew install webp)"
README_OUT="$ROOT/docs/images"
rm -rf "$README_OUT"
mkdir -p "$README_OUT"
for name in main-light main-dark first-run-light editor-code-light menubar-panel-light menubar-panel-dark settings-general-light; do
    dwebp -quiet "$OUT/$name@2x.webp" -o "$README_OUT/$name.png"
done

# The page shows the narrow hero instead, so the six-tunnel window is not published with the site.
rm -f "$OUT"/main-*.webp

echo "==> Icons"
# The macOS icon is drawn on Apple's grid: an 824 px rounded square centered in a 1024 px image.
# The site shows only the rounded square.
sips -s format png "$ROOT/Resources/AppIcon.icns" --out "$TMP/icon-full.png" >/dev/null
[[ "$(width "$TMP/icon-full.png")" == 1024 ]] || die "expected a 1024 px icon in AppIcon.icns"
sips --cropToHeightWidth 824 824 "$TMP/icon-full.png" --out "$TMP/icon.png" >/dev/null
for size in 28 32 72; do
    webp "$TMP/icon.png" "app-icon-$size" "$size"
done
sips -z 64 64 "$TMP/icon.png" --out "$OUT/favicon.png" >/dev/null
sips -z 180 180 "$TMP/icon.png" --out "$OUT/apple-touch-icon.png" >/dev/null

echo "==> Social preview image (headless Chrome)"
"$CHROME" --headless=new --disable-gpu --hide-scrollbars --no-first-run --no-default-browser-check \
    --user-data-dir="$TMP/chrome" --force-device-scale-factor=1 --window-size=1200,630 \
    --allow-file-access-from-files --virtual-time-budget=3000 \
    --screenshot="$TMP/og.png" "file://$ROOT/scripts/site/og.html" >/dev/null 2>&1
[[ "$(width "$TMP/og.png")x$(height "$TMP/og.png")" == 1200x630 ]] || die "og.png is not 1200x630"
cp "$TMP/og.png" "$OUT/og.png"

echo "==> Written to site/assets/img/"
for f in "$OUT"/*; do
    printf '  %-36s %5sx%-5s %4s KB\n' "$(basename "$f")" "$(width "$f")" "$(height "$f")" \
        "$(( ($(wc -c <"$f") + 1023) / 1024 ))"
done
