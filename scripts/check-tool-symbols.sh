#!/bin/bash
# Checks that the VPN tools bundled into an app start on their minimum macOS: every symbol the tools
# (Contents/Resources/bin) and their libraries (Contents/Frameworks) import from a macOS library must be
# exported by it on that version, as scripts/system-symbols/<version>/ lists it (make-system-symbols.sh).
# bundle-tools.sh runs it on every build.
#
#   scripts/check-tool-symbols.sh App.app [--symbols DIR] [--minimum TOOL=VERSION …]
#
# The tools come from Homebrew's bottles, built on the newest macOS (minos 26.0). dyld does not refuse
# them for that on an older macOS; it stops a tool at launch when a symbol it or one of its libraries
# imports is missing ("Symbol not found", exit 134), which is what this rules out.
#
# A tool's minimum is the app's (LSMinimumSystemVersion in Resources/Info.plist) or, for a tool the app
# refuses below a later version, that version (TOOL_MINIMUMS); a library's is the lowest of the tools
# that load it. A weak import of a macOS symbol is refused too, unless WEAK_IMPORTS lists it (the tool
# must then cope with it missing), and so is a symbol looked up in the flat namespace, which cannot be
# checked. --symbols (another lists directory) and --minimum (another minimum for a tool) are for
# test-check-tool-symbols.sh.
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Tools the app runs only from a later macOS than its own minimum, with that version. Cisco AnyConnect
# (openconnect) needs macOS 15.4: Homebrew's openconnect and libidn2 import strchrnul.
TOOL_MINIMUMS=(openconnect=15.4)
# Weak imports of macOS symbols that a tool or library handles being absent: "file:symbol".
WEAK_IMPORTS=()

die() { echo "error: $*" >&2; exit 1; }

APP=""
SYMBOLS="$ROOT/scripts/system-symbols"
while (($#)); do
    case "$1" in
        --symbols) SYMBOLS="${2:?--symbols needs a directory}"; shift 2 ;;
        --minimum) TOOL_MINIMUMS+=("${2:?--minimum needs TOOL=VERSION}"); shift 2 ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown argument: $1" ;;
        *) [[ -z "$APP" ]] || die "one app only"; APP="$1"; shift ;;
    esac
done
[[ -n "$APP" && -d "$APP/Contents" ]] || die "usage: $0 App.app [--symbols DIR] [--minimum TOOL=VERSION]"
BIN="$APP/Contents/Resources/bin"
FW="$APP/Contents/Frameworks"
DEFAULT="$(plutil -extract LSMinimumSystemVersion raw "$ROOT/Resources/Info.plist")"
[[ "$DEFAULT" =~ ^[0-9]+\.[0-9]+$ ]] || die "unexpected LSMinimumSystemVersion in Resources/Info.plist: $DEFAULT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

is_macho() { lipo -archs "$1" >/dev/null 2>&1; }
is_system() { [[ "$1" == /usr/lib/* || "$1" == /System/* ]]; }
# True when version $1 is lower than $2 (13.0 < 15.4).
version_lt() { awk -v a="$1" -v b="$2" 'BEGIN { split(a, x, "."); split(b, y, "."); exit !(x[1] < y[1] || (x[1] == y[1] && x[2] < y[2])) }'; }
# The name nm gives a library ("from libSystem"), as cctools' guess_short_name makes it: "Security" for
# …/Security.framework/Versions/A/Security; for a dylib, its file name without ".dylib", a one-character
# version (libSystem.B, libcrypto.4, but not libgnutls.30) and "_debug" or "_profile".
short_name() {
    local base
    base="$(basename "$1")"
    if [[ "$1" != *.framework/* ]]; then
        base="${base%.dylib}"
        [[ "$base" =~ \..$ ]] && base="${base%??}"
        base="${base%_debug}"
        base="${base%_profile}"
    fi
    echo "$base"
}
# The libraries `file` loads, without its own install name.
loads_of() {
    local self
    self="$(otool -arch arm64 -D "$1" 2>/dev/null | sed -n 2p)"
    otool -arch arm64 -L "$1" | tail -n +2 | awk '{print $1}' | while read -r dep; do
        [[ "$dep" == "$self" ]] || echo "$dep"
    done
}

minimum_of_tool() {
    local tool="$1" entry min="$DEFAULT"
    for entry in ${TOOL_MINIMUMS[@]+"${TOOL_MINIMUMS[@]}"}; do
        [[ "${entry%%=*}" == "$tool" ]] && min="${entry#*=}"
    done
    echo "$min"
}

# --- minimums ---------------------------------------------------------------------------------------
# "<path> <version>" for every Mach-O file: each tool's, then each bundled library's, the lowest of the
# tools whose closure holds it.
: > "$WORK/minimums"
set_minimum() {
    local file="$1" min="$2" prev
    prev="$(awk -v f="$file" '$1 == f {print $2}' "$WORK/minimums")"
    if [[ -z "$prev" ]]; then
        echo "$file $min" >> "$WORK/minimums"
    elif version_lt "$min" "$prev"; then
        awk -v f="$file" -v m="$min" '$1 == f {$2 = m} {print}' "$WORK/minimums" > "$WORK/m" && mv "$WORK/m" "$WORK/minimums"
    else
        return 1
    fi
}
tools=()
for f in "$BIN"/*; do
    [[ -f "$f" ]] && is_macho "$f" && tools+=("$f")
done
((${#tools[@]})) || die "no tools in $BIN"
for tool in "${tools[@]}"; do
    min="$(minimum_of_tool "$(basename "$tool")")"
    [[ "$min" =~ ^[0-9]+\.[0-9]+$ ]] || die "bad minimum for $(basename "$tool"): $min"
    set_minimum "$tool" "$min" || true
    queue=("$tool")
    i=0
    while ((i < ${#queue[@]})); do
        file="${queue[$i]}"; i=$((i + 1))
        while read -r dep; do
            case "$dep" in
                @executable_path/../../Frameworks/*|@loader_path/*|@rpath/*) lib="$FW/$(basename "$dep")" ;;
                *) is_system "$dep" && continue
                   die "$(basename "$file") loads $dep, which is neither a macOS library nor in Contents/Frameworks" ;;
            esac
            [[ -f "$lib" ]] || die "$(basename "$file") loads $dep, which is not in Contents/Frameworks"
            # Further down only when this tool lowers its minimum (or it is new).
            if set_minimum "$lib" "$min"; then queue+=("$lib"); fi
        done < <(loads_of "$file")
    done
done
for lib in "$FW"/*.dylib; do
    [[ -f "$lib" ]] || continue
    # A library no tool loads is held to the app's minimum.
    awk -v f="$lib" '$1 == f {found = 1} END {exit !found}' "$WORK/minimums" || echo "$lib $DEFAULT" >> "$WORK/minimums"
done

# --- imports ----------------------------------------------------------------------------------------
errors=0
fail() { echo "error: $*" >&2; errors=$((errors + 1)); }
echo "macOS symbols imported by the bundled tools and libraries (lists in ${SYMBOLS#"$ROOT"/}):"
while read -r file min; do
    name="${file#"$APP/Contents/"}"
    lists="$SYMBOLS/$min"
    if [[ ! -d "$lists" ]]; then
        fail "$name: no symbol lists for macOS $min; make them with scripts/make-system-symbols.sh $min SDK"
        continue
    fi
    # Short name → install name of each library it loads ("-" for a bundled one).
    : > "$WORK/libs"
    while read -r dep; do
        short="$(short_name "$dep")"
        if awk -v s="$short" '$1 == s {found = 1} END {exit !found}' "$WORK/libs"; then
            fail "$name: two libraries named $short; their imports cannot be told apart"
        fi
        if is_system "$dep"; then echo "$short $dep" >> "$WORK/libs"; else echo "$short -" >> "$WORK/libs"; fi
    done < <(loads_of "$file")
    # "<weak|strong> <symbol> <library short name, or ? when not looked up in one>".
    nm -arch arm64 -m -u "$file" | awk '
        /\(undefined/ {
            weak = ($0 ~ /\) weak external /) ? "weak" : "strong"
            sym = ""
            for (i = 1; i < NF; i++) if ($i == "external") { sym = $(i + 1); break }
            from = "?"
            if (match($0, /\(from [^)]*\)$/)) from = substr($0, RSTART + 6, RLENGTH - 7)
            if (sym != "") print weak, sym, from
        }' > "$WORK/imports"
    count=0
    while read -r short install; do
        [[ "$install" == - ]] && continue
        list="$lists$install.txt"
        awk -v s="$short" '$3 == s {print $2}' "$WORK/imports" | sort -u > "$WORK/want"
        count=$((count + $(wc -l < "$WORK/want")))
        if [[ ! -f "$list" ]]; then
            [[ -s "$WORK/want" ]] || continue
            fail "$name loads $install, which has no symbol list for macOS $min (scripts/make-system-symbols.sh $min SDK -- $install)"
            continue
        fi
        while read -r sym; do
            fail "$name imports $sym from $install, which macOS $min does not export (built for macOS $(otool -arch arm64 -l "$file" | awk '/minos/ {print $2; exit}'))"
        done < <(comm -23 "$WORK/want" "$list")
        while read -r sym; do
            entry="$(basename "$file"):$sym"
            if [[ " ${WEAK_IMPORTS[*]-} " != *" $entry "* ]]; then
                fail "$name imports $sym from $install weakly; list \"$entry\" in WEAK_IMPORTS once the tool copes with it missing"
            fi
        done < <(awk -v s="$short" '$1 == "weak" && $3 == s {print $2}' "$WORK/imports")
    done < "$WORK/libs"
    while read -r sym from; do
        fail "$name imports $sym from \"$from\", which it does not load (flat namespace?); it cannot be checked"
    done < <(awk 'NR == FNR {known[$1] = 1; next} !($3 in known) {print $2, $3}' "$WORK/libs" "$WORK/imports")
    printf '  %-36s macOS %-5s %4d symbols\n' "$name" "$min" "$count"
done < "$WORK/minimums"
if ((errors)); then
    echo "error: $errors problem(s): the bundled tools would not start on their minimum macOS; see docs/RELEASING.md (Bundled tools)" >&2
    exit 1
fi
echo "All imports are exported on each file's minimum macOS."
