#!/bin/bash
# Checks that the VPN tools bundled into an app start on their minimum macOS: every symbol the tools
# (Contents/Resources/bin) and their libraries (Contents/Frameworks) import from a macOS library must be
# exported by it on that version, as scripts/system-symbols/<version>/ lists it (make-system-symbols.sh).
# bundle-tools.sh runs it on every build.
#
#   scripts/check-tool-symbols.sh App.app [--symbols DIR] [--minimum TOOL=VERSION …]
#
# The tools come from Homebrew's bottles, built on the newest macOS (minos 26.0). dyld does not refuse
# them for that on an older macOS; it stops a tool at launch when a library it loads is missing or a
# symbol it or one of its libraries imports is ("Symbol not found", exit 134), which is what this rules
# out.
#
# A tool's minimum is the app's (LSMinimumSystemVersion in Resources/Info.plist) or, for a tool the app
# refuses below a later version, that version (TOOL_MINIMUMS); a library's is the lowest of the tools
# that load it. The imports are what dyld binds (dyld_info -imports: the chained fixups or bind opcodes),
# with nm's undefined symbols added. Refused as well: a macOS library loaded (not weakly) without a list
# for the minimum, even with nothing imported from it; a weak import of a macOS symbol unless
# WEAK_IMPORTS lists it (the tool must then cope with it missing); a symbol looked up in the flat
# namespace; a bundled library that re-exports a macOS library or symbol (its importers would bypass
# the check); and any bundled load path other than the layout bundle-tools.sh writes (a tool:
# @executable_path/../../Frameworks/<name>, a library: @loader_path/<name>). --symbols (another lists
# directory) and --minimum (another minimum for a tool) are for test-check-tool-symbols.sh.
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Tools the app runs only from a later macOS than its own minimum, with that version. Cisco AnyConnect
# (openconnect) needs macOS 15.4: Homebrew's libopenconnect imports strchrnul. The libraries only
# openconnect loads are held to 15.4 with it; one it shares with openvpn or openfortivpn stays at 13.0.
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
        -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown argument: $1" ;;
        *) [[ -z "$APP" ]] || die "one app only"; APP="$1"; shift ;;
    esac
done
[[ -n "$APP" && -d "$APP/Contents" ]] || die "usage: $0 App.app [--symbols DIR] [--minimum TOOL=VERSION]"
BIN="$APP/Contents/Resources/bin"
FW="$APP/Contents/Frameworks"
DEFAULT="$(plutil -extract LSMinimumSystemVersion raw "$ROOT/Resources/Info.plist")"
[[ "$DEFAULT" =~ ^[0-9]+\.[0-9]+$ ]] || die "unexpected LSMinimumSystemVersion in Resources/Info.plist: $DEFAULT"
command -v dyld_info >/dev/null || die "dyld_info not found (macOS 13 or later)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TAB=$'\t'

is_macho() { lipo -archs "$1" >/dev/null 2>&1; }
is_system() { [[ "$1" == /usr/lib/* || "$1" == /System/* ]]; }
# True when version $1 is lower than $2 (13.0 < 15.4).
version_lt() { awk -v a="$1" -v b="$2" 'BEGIN { split(a, x, "."); split(b, y, "."); exit !(x[1] < y[1] || (x[1] == y[1] && x[2] < y[2])) }'; }
# The name dyld_info and nm give a library ("from libSystem"), as cctools' guess_short_name makes it:
# "Security" for …/Security.framework/Versions/A/Security; for a dylib, its file name without
# ".dylib", a one-character version (libSystem.B, libcrypto.4, but not libgnutls.30) and "_debug" or
# "_profile".
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
# "<load command>\t<library>" for each library `file` loads, in load-command order (the library
# ordinals), without its own install name (LC_ID_DYLIB).
loads_of() {
    otool -arch arm64 -l "$1" | awk '
        $1 == "cmd" { cmd = $2; next }
        $1 == "name" && cmd ~ /^LC_(LOAD|LOAD_WEAK|REEXPORT|LOAD_UPWARD|LAZY_LOAD)_DYLIB$/ {
            name = $0
            sub(/^ *name /, "", name)
            sub(/ \(offset [0-9]+\)$/, "", name)
            print cmd "\t" name
            cmd = ""
        }'
}
# The bundled library a load path names, in the layout bundle-tools.sh writes; "" for anything else.
bundled_target() {
    local file="$1" dep="$2" name
    case "$file" in
        "$BIN"/*) [[ "$dep" == @executable_path/../../Frameworks/* ]] || return 0; name="${dep#@executable_path/../../Frameworks/}" ;;
        *) [[ "$dep" == @loader_path/* ]] || return 0; name="${dep#@loader_path/}" ;;
    esac
    [[ -n "$name" && "$name" != */* && "$name" != .* ]] && echo "$FW/$name"
    return 0
}

minimum_of_tool() {
    local tool="$1" entry min="$DEFAULT"
    for entry in ${TOOL_MINIMUMS[@]+"${TOOL_MINIMUMS[@]}"}; do
        [[ "${entry%%=*}" == "$tool" ]] && min="${entry#*=}"
    done
    echo "$min"
}

# --- minimums ---------------------------------------------------------------------------------------
# "<path>\t<version>" for every Mach-O file: each tool's, then each bundled library's, the lowest of
# the tools whose closure holds it.
: > "$WORK/minimums"
minimum_of() { awk -F'\t' -v f="$1" '$1 == f {print $2}' "$WORK/minimums"; }
set_minimum() {
    local file="$1" min="$2" prev
    prev="$(minimum_of "$file")"
    if [[ -z "$prev" ]]; then
        printf '%s\t%s\n' "$file" "$min" >> "$WORK/minimums"
    elif version_lt "$min" "$prev"; then
        awk -F'\t' -v OFS='\t' -v f="$file" -v m="$min" '$1 == f {$2 = m} {print}' "$WORK/minimums" > "$WORK/m"
        mv "$WORK/m" "$WORK/minimums"
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
        while IFS="$TAB" read -r _ dep; do
            is_system "$dep" && continue
            lib="$(bundled_target "$file" "$dep")"
            [[ -n "$lib" ]] || die "${file#"$APP/Contents/"} loads $dep, outside the layout bundle-tools.sh writes"
            [[ -f "$lib" ]] || die "${file#"$APP/Contents/"} loads $dep, which is not in Contents/Frameworks"
            # Further down only when this tool lowers its minimum (or it is new).
            if set_minimum "$lib" "$min"; then queue+=("$lib"); fi
        done < <(loads_of "$file")
    done
done
for lib in "$FW"/*.dylib; do
    [[ -f "$lib" ]] || continue
    # A library no tool loads is held to the app's minimum.
    [[ -n "$(minimum_of "$lib")" ]] || printf '%s\t%s\n' "$lib" "$DEFAULT" >> "$WORK/minimums"
done

# --- imports ----------------------------------------------------------------------------------------
errors=0
fail() { echo "error: $*" >&2; errors=$((errors + 1)); }
echo "macOS symbols imported by the bundled tools and libraries (lists in ${SYMBOLS#"$ROOT"/}):"
while IFS="$TAB" read -r file min; do
    name="${file#"$APP/Contents/"}"
    lists="$SYMBOLS/$min"
    if [[ ! -d "$lists" ]]; then
        fail "$name: no symbol lists for macOS $min; make them with scripts/make-system-symbols.sh $min SDK"
        continue
    fi
    # "<short name>\t<install name, or - for a bundled library>\t<load command>" per library it loads.
    : > "$WORK/libs"
    while IFS="$TAB" read -r cmd dep; do
        short="$(short_name "$dep")"
        if awk -F'\t' -v s="$short" '$1 == s {found = 1} END {exit !found}' "$WORK/libs"; then
            fail "$name: two libraries named $short; their imports cannot be told apart"
        fi
        if is_system "$dep"; then
            printf '%s\t%s\t%s\n' "$short" "$dep" "$cmd" >> "$WORK/libs"
            if [[ "$cmd" == LC_REEXPORT_DYLIB ]]; then
                fail "$name re-exports $dep; what it passes on from macOS would not be checked"
            elif [[ "$cmd" != LC_LOAD_WEAK_DYLIB && ! -f "$lists$dep.txt" ]]; then
                # dyld stops a tool when a library it loads (not weakly) is missing.
                fail "$name loads $dep, which has no symbol list for macOS $min (scripts/make-system-symbols.sh $min SDK -- $dep)"
            fi
        else
            printf '%s\t-\t%s\n' "$short" "$cmd" >> "$WORK/libs"
        fi
    done < <(loads_of "$file")
    # "<weak|strong>\t<symbol>\t<library short name, or ? when not looked up in one>": what dyld binds,
    # and nm's undefined symbols.
    {
        # "  0x0001  _strchrnul [weak-import] (from libSystem)" (chained fixups: with the import's
        # index), "  _nowhere  (from <flat-namespace>)" (bind opcodes).
        dyld_info -arch arm64 -imports "$file" | awk '
            /-imports:/ { on = 1; next }
            on && NF {
                line = $0
                sub(/^[ \t]+/, "", line)
                sub(/^0x[0-9a-fA-F]+[ \t]+/, "", line)
                sym = line
                sub(/[ \t].*$/, "", sym)
                weak = (line ~ /\[weak-import\]/) ? "weak" : "strong"
                from = "?"
                if (match(line, /\(from [^)]*\)$/)) from = substr(line, RSTART + 6, RLENGTH - 7)
                print weak "\t" sym "\t" from
            }'
        nm -arch arm64 -m -u "$file" | awk '
            /\(undefined/ {
                weak = ($0 ~ /\) weak external /) ? "weak" : "strong"
                sym = ""
                for (i = 1; i < NF; i++) if ($i == "external") { sym = $(i + 1); break }
                from = "?"
                if (match($0, /\(from [^)]*\)$/)) from = substr($0, RSTART + 6, RLENGTH - 7)
                if (sym != "") print weak "\t" sym "\t" from
            }'
    } | sort -u > "$WORK/imports"
    # Re-exported symbols ("[re-export] _x (from libSystem)" in the export trie).
    dyld_info -arch arm64 -exports "$file" | awk '
        /\[re-export\]/ {
            from = "?"
            if (match($0, /\(from [^)]*\)$/)) from = substr($0, RSTART + 6, RLENGTH - 7)
            sym = $0; sub(/^.*\[re-export\] */, "", sym); sub(/ .*$/, "", sym)
            print sym "\t" from
        }' > "$WORK/reexports"
    count=0
    while IFS="$TAB" read -r short install _; do
        [[ "$install" == - ]] && continue
        list="$lists$install.txt"
        awk -F'\t' -v s="$short" '$3 == s {print $2}' "$WORK/imports" | sort -u > "$WORK/want"
        count=$((count + $(wc -l < "$WORK/want")))
        while IFS="$TAB" read -r sym _; do
            fail "$name re-exports $sym from $install; what it passes on from macOS would not be checked"
        done < <(awk -F'\t' -v s="$short" '$2 == s' "$WORK/reexports")
        if [[ ! -f "$list" ]]; then
            # Only a weak load gets here (a strong one failed above): its imports cannot be checked.
            [[ -s "$WORK/want" ]] && fail "$name imports from $install, which has no symbol list for macOS $min"
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
        done < <(awk -F'\t' -v s="$short" '$1 == "weak" && $3 == s {print $2}' "$WORK/imports")
    done < "$WORK/libs"
    # Imports and re-exports from a library it does not load: the flat namespace, or a name dyld_info
    # and nm make otherwise than short_name. Not "<weak-def-coalesce>": a weak definition of the file's
    # own, which dyld binds to the first image that defines it, and to the file's own copy at worst.
    { awk -F'\t' '{print $1}' "$WORK/libs"; echo "<weak-def-coalesce>"; } > "$WORK/known"
    while IFS="$TAB" read -r sym from; do
        fail "$name looks up $sym in \"$from\", which is not a library it loads (flat namespace?); it cannot be checked"
    done < <(awk -F'\t' -v known="$WORK/known" '
        BEGIN { while ((getline line < known) > 0) k[line] = 1 }
        FILENAME == ARGV[1] && !($3 in k) { print $2 "\t" $3 }
        FILENAME == ARGV[2] && !($2 in k) { print $1 "\t" $2 }' "$WORK/imports" "$WORK/reexports")
    printf '  %-36s macOS %-5s %4d symbols\n' "$name" "$min" "$count"
done < "$WORK/minimums"
if ((errors)); then
    echo "error: $errors problem(s): the bundled tools would not start on their minimum macOS; see docs/RELEASING.md (Bundled tools)" >&2
    exit 1
fi
echo "All imports are exported on each file's minimum macOS."
