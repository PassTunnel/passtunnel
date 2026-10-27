#!/bin/bash
# Writes the lists of what macOS system libraries export on a given macOS version (arm64), which
# check-tool-symbols.sh holds the bundled tools and their libraries to (docs/ARCHITECTURE.md, Bundled
# VPN tools; docs/RELEASING.md, Bundled tools).
#
#   scripts/make-system-symbols.sh VERSION SDK [SDK …] [-- INSTALL_NAME …]
#
#   VERSION       the macOS version the lists are for; they go to scripts/system-symbols/VERSION/
#   SDK           a macOS SDK directory (…/MacOSX13.1.sdk). With several, a symbol is listed only when
#                 every one of them exports it
#   INSTALL_NAME  a library to list (/usr/lib/libSystem.B.dylib); default: the ones already listed
#                 for VERSION
#
# An SDK's stubs (.tbd) tell what a library exports on the SDK's own macOS version, not since when. So
# the lists for VERSION come from the SDK of exactly that version or, when there is none at hand, from
# the SDKs just before and just after it: what both export is there on VERSION too. A list holds the
# library's exports and those of the libraries it re-exports (libSystem: libsystem_c, libsystem_kernel,
# …), one symbol per line, sorted, linker directives ($ld$hide$…) left out. VERSION/SOURCES records the
# SDKs and the checksums of the stubs read. Needs llvm-readtapi (Xcode 16 or later) and jq.
set -euo pipefail
export LC_ALL=C

die() { echo "error: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+$ ]] || die "usage: $0 VERSION SDK [SDK …] [-- INSTALL_NAME …] (VERSION like 13.0)"
shift
SDKS=()
while (($#)) && [[ "$1" != -- ]]; do
    [[ -f "$1/SDKSettings.json" ]] || die "$1 is not a macOS SDK (no SDKSettings.json)"
    SDKS+=("$(cd "$1" && pwd)")
    shift
done
((${#SDKS[@]})) || die "no SDK given"
[[ "${1:-}" == -- ]] && shift
OUT="$ROOT/scripts/system-symbols/$VERSION"
LIBS=("$@")
if ((${#LIBS[@]} == 0)) && [[ -d "$OUT" ]]; then
    while IFS= read -r f; do
        f="${f#"$OUT"}"
        LIBS+=("${f%.txt}")
    done < <(find "$OUT" -name '*.txt' | sort)
fi
((${#LIBS[@]})) || die "no library given and none listed for $VERSION yet"
for lib in "${LIBS[@]}"; do [[ "$lib" == /* ]] || die "not an install name: $lib"; done

READTAPI="$(xcrun --find llvm-readtapi)" || die "llvm-readtapi not found (Xcode 16 or later)"
command -v jq >/dev/null || die "jq not found"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The arm64 macOS exports of the stub of `install` in `sdk`, and of the libraries it re-exports that the
# stub does not carry itself, one per line. The stub's checksum goes to $WORK/sums.
exports_of() {
    local sdk="$1" install="$2" tbd json name
    tbd="$sdk${install%.dylib}.tbd"
    [[ -f "$tbd" ]] || die "$(basename "$sdk") has no stub for $install (${tbd#"$sdk"/})"
    printf '  %s  %s\n' "$(shasum -a 256 "$tbd" | cut -d' ' -f1)" "$(basename "$sdk")/${tbd#"$sdk"/}" >> "$WORK/sums"
    json="$WORK/$(basename "$tbd").json"
    "$READTAPI" -extract --arch=arm64 "$tbd" --filetype=tbd-v5 -o "$json" \
        || die "llvm-readtapi could not read $tbd"
    jq -r '
        def mac: (.targets // ["arm64-macos"]) | index("arm64-macos") != null;
        [.main_library] + (.libraries // []) | .[] | (.exported_symbols // []) + (.reexported_symbols // [])
        | .[] | select(mac) | (.data // {}), (.text // {})
        | (.global // [])[], (.weak // [])[], (.thread_local // [])[],
          ((.objc_class // [])[] | "_OBJC_CLASS_$_\(.)", "_OBJC_METACLASS_$_\(.)"),
          ((.objc_eh_type // [])[] | "_OBJC_EHTYPE_$_\(.)"),
          ((.objc_ivar // [])[] | "_OBJC_IVAR_$_\(.)")
    ' "$json" | grep -v '^[$]ld[$]' || true
    # Re-exported libraries the stub does not include are read from their own stubs.
    jq -r '
        ([.main_library] + (.libraries // []) | map(.install_names[].name)) as $have
        | [.main_library] + (.libraries // []) | .[] | (.reexported_libraries // [])[]
        | select((.targets // ["arm64-macos"]) | index("arm64-macos") != null)
        | .names[] | select(. as $n | $have | index($n) | not)
    ' "$json" | while IFS= read -r name; do
        exports_of "$sdk" "$name"
    done
}

{
    echo "# What each library and the libraries it re-exports export on macOS $VERSION (arm64)."
    echo "# Written by scripts/make-system-symbols.sh from these SDKs (a symbol is listed when every one"
    echo "# of them exports it), with the checksums of the stubs read:"
} > "$WORK/SOURCES"
for sdk in "${SDKS[@]}"; do
    name="$(jq -r '.CanonicalName // empty' "$sdk/SDKSettings.json")"
    sdk_version="$(jq -r '.Version // empty' "$sdk/SDKSettings.json")"
    [[ -n "$sdk_version" ]] || die "$sdk/SDKSettings.json has no Version"
    echo "$(basename "$sdk") (${name:-?}, macOS $sdk_version)" >> "$WORK/SOURCES"
done
if ((${#SDKS[@]} == 1)); then
    v="$(jq -r .Version "${SDKS[0]}/SDKSettings.json")"
    [[ "$v" == "$VERSION" || "$v" == "$VERSION.0" ]] \
        || die "the SDK is for macOS $v, not $VERSION; give the SDKs just before and after $VERSION instead"
fi

rm -rf "$OUT"
mkdir -p "$OUT"
for lib in "${LIBS[@]}"; do
    echo "$lib:" >> "$WORK/SOURCES"
    first=1
    for sdk in "${SDKS[@]}"; do
        : > "$WORK/sums"
        exports_of "$sdk" "$lib" | sort -u > "$WORK/this"
        [[ -s "$WORK/this" ]] || die "$(basename "$sdk") lists no arm64 exports for $lib"
        cat "$WORK/sums" >> "$WORK/SOURCES"
        if ((first)); then
            mv "$WORK/this" "$WORK/list"
            first=0
        else
            comm -12 "$WORK/list" "$WORK/this" > "$WORK/both"
            mv "$WORK/both" "$WORK/list"
        fi
    done
    dest="$OUT$lib.txt"
    mkdir -p "$(dirname "$dest")"
    mv "$WORK/list" "$dest"
    printf '%6d  %s\n' "$(wc -l < "$dest")" "${dest#"$ROOT"/}"
done
mv "$WORK/SOURCES" "$OUT/SOURCES"
echo "Sources: ${OUT#"$ROOT"/}/SOURCES"
