#!/bin/bash
# Checks that the bundled openconnect reads no PKCS#11 module files from the Homebrew prefix
# (bundle-tools.sh overwrites the paths compiled into libp11-kit): it puts a module file into each
# module directory Homebrew's p11-kit reads (etc/pkcs11/modules and etc/modules), whose "remote:" line
# would make p11-kit run `touch <marker>`, then runs `openconnect --version`, which already loads the
# modules. Both must start and print their version (exit 0, "OpenConnect version v<version>"); then
# Homebrew's own openconnect must have created both markers (the test works), the bundled one none.
# The version is the one in Homebrew's Cellar, which must be the pin in release.env unless
# PASSTUNNEL_ALLOW_UNPINNED_TOOLS=1 (as in CI's Bundled tools job).
# Afterwards it removes its module files, and the directories it created. Runs as the user who owns the
# Homebrew prefix (CI's Bundled tools job; never with sudo).
#
#   scripts/test-bundled-config-paths.sh App.app
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 App.app}"
BREW="${HOMEBREW_PREFIX:-/opt/homebrew}"
BUNDLED="$APP/Contents/Resources/bin/openconnect"
HOMEBREWS="$BREW/opt/openconnect/bin/openconnect"
[[ -x "$BUNDLED" ]] || { echo "error: $BUNDLED not found" >&2; exit 1; }
[[ -x "$HOMEBREWS" ]] || { echo "error: $HOMEBREWS not found (brew install openconnect)" >&2; exit 1; }
OPENCONNECT_VERSION="$(sed -n 's/^OPENCONNECT_VERSION=//p' "$(dirname "$0")/release.env")"
[[ -n "$OPENCONNECT_VERSION" ]] || { echo "error: no OPENCONNECT_VERSION in release.env" >&2; exit 1; }
cellar="$(basename "$(realpath "$BREW/opt/openconnect")")"
if [[ "$cellar" != "$OPENCONNECT_VERSION" && "${PASSTUNNEL_ALLOW_UNPINNED_TOOLS:-}" != 1 ]]; then
    echo "error: Homebrew has openconnect $cellar, release.env pins $OPENCONNECT_VERSION" >&2
    exit 1
fi
# The upstream version, without Homebrew's revision (9.21_1 → 9.21).
VERSION_LINE="OpenConnect version v${cellar%%_*}"

WORK="$(mktemp -d)"
DIRS=("$BREW/etc/pkcs11/modules" "$BREW/etc/modules")
created=()
files=()
cleanup() {
    local f d i
    for f in ${files[@]+"${files[@]}"}; do rm -f "$f"; done
    # Innermost first; only what this script created.
    for ((i = ${#created[@]} - 1; i >= 0; i--)); do
        d="${created[$i]}"
        rmdir "$d" 2>/dev/null || echo "warning: $d not removed (not empty)" >&2
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

# Distinct names: a module file in etc/modules replaces one of the same name in etc/pkcs11/modules.
name="passtunnel-test-$$-$RANDOM"
for i in "${!DIRS[@]}"; do
    dir="${DIRS[$i]}"
    # Each missing directory level, outermost first.
    missing=()
    d="$dir"
    while [[ ! -e "$d" ]]; do missing=("$d" ${missing[@]+"${missing[@]}"}); d="$(dirname "$d")"; done
    for d in ${missing[@]+"${missing[@]}"}; do mkdir "$d"; created+=("$d"); done
    f="$dir/$name-$i.module"
    [[ ! -e "$f" ]] || { echo "error: $f exists" >&2; exit 1; }
    files+=("$f")
    printf 'remote: |/usr/bin/touch %s/marker-%s\n' "$WORK" "$i" > "$f"
done

# Runs `$1 --version` with no environment and prints whether it started as expected and which module
# files it ran.
ran_module() {
    local out status=0
    rm -f "$WORK"/marker-*
    out="$(env -i "$1" --version 2>&1)" || status=$?
    echo "--- $1 --version (exit $status): $(head -n 1 <<<"$out")"
    if [[ "$status" == 0 && "$(head -n 1 <<<"$out")" == "$VERSION_LINE" ]]; then
        echo "    started"
    else
        echo "    did not start as expected (exit 0 and \"$VERSION_LINE\" first):"
        head -n 5 <<<"$out" | sed 's/^/      /'
    fi
    for i in "${!DIRS[@]}"; do
        [[ -e "$WORK/marker-$i" ]] && echo "    ran the module in ${DIRS[$i]}"
    done
    return 0
}
homebrew="$(ran_module "$HOMEBREWS")"
bundled="$(ran_module "$BUNDLED")"
echo "$homebrew"
echo "$bundled"
failures=0
for which in homebrew bundled; do
    if ! grep -qx "    started" <<<"${!which}"; then
        echo "error: the $which openconnect did not start and print its version; the test proves nothing" >&2
        failures=$((failures + 1))
    fi
done
for dir in "${DIRS[@]}"; do
    if ! grep -qF "ran the module in $dir" <<<"$homebrew"; then
        echo "error: Homebrew's openconnect did not run the module in $dir; the test proves nothing there" >&2
        failures=$((failures + 1))
    fi
done
if grep -q "ran the module" <<<"$bundled"; then
    echo "FAIL: the bundled openconnect ran a module from $BREW" >&2
    failures=$((failures + 1))
fi
((failures == 0)) || exit 1
echo "ok: the bundled openconnect reads no PKCS#11 modules from $BREW; Homebrew's ran both."
