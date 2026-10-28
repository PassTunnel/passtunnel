#!/bin/bash
# Self-test of check-tool-symbols.sh on small tools and libraries compiled here (macOS with Xcode; they
# are never run): one that imports strchrnul (macOS 15.4 and later) fails against macOS 13.0, also with
# its symbol table stripped, and passes when its minimum is 15.4; a library inherits the lowest minimum
# of the tools that load it; refused are weak imports, flat-namespace lookups, a macOS library loaded
# without a symbol list (also with nothing imported from it), re-exports of macOS libraries or symbols
# and load paths outside bundle-tools.sh's layout; a bundle path with spaces works.
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECK="$ROOT/scripts/check-tool-symbols.sh"
LISTS="$ROOT/scripts/system-symbols"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "ok: $1"; }
failed() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# Symbol lists for the test: the real 13.0 ones, and a "15.4" made of them plus strchrnul.
SYMS="$WORK/symbols"
mkdir -p "$SYMS"
cp -R "$LISTS/13.0" "$SYMS/13.0"
cp -R "$LISTS/13.0" "$SYMS/15.4"
{ cat "$LISTS/13.0/usr/lib/libSystem.B.dylib.txt"; echo _strchrnul; } | sort -u > "$SYMS/15.4/usr/lib/libSystem.B.dylib.txt"
grep -qx _strchrnul "$LISTS/13.0/usr/lib/libSystem.B.dylib.txt" && { echo "error: the 13.0 list has _strchrnul" >&2; exit 1; }

cc() { xcrun clang -arch arm64 -mmacosx-version-min=26.0 -Wno-unused-command-line-argument "$@"; }

# A new app bundle with the given tools (name=C source) and optional library (libnew.dylib).
SRC="$WORK/src"
mkdir -p "$SRC"
cat > "$SRC/old.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("old"); return 0; }
EOF
cat > "$SRC/new.c" <<'EOF'
#include <string.h>
int main(int argc, char **argv) { return *strchrnul(argv[0], 'x') + argc; }
EOF
cat > "$SRC/weak.c" <<'EOF'
#include <stddef.h>
extern char *strchrnul(const char *, int) __attribute__((weak_import));
int main(int argc, char **argv) { return strchrnul == NULL ? 0 : *strchrnul(argv[0], 'x') + argc; }
EOF
cat > "$SRC/zlib.c" <<'EOF'
#include <zlib.h>
int main(void) { return zlibVersion()[0]; }
EOF
cat > "$SRC/lib.c" <<'EOF'
#include <string.h>
char *find_end(const char *s) { return strchrnul(s, 'x'); }
EOF
cat > "$SRC/uselib.c" <<'EOF'
char *find_end(const char *s);
int main(int argc, char **argv) { return *find_end(argv[0]) + argc; }
EOF
cat > "$SRC/flat.c" <<'EOF'
extern int nowhere(void);
int main(void) { return nowhere(); }
EOF
cat > "$SRC/own.c" <<'EOF'
int own(void) { return 1; }
EOF
printf '%s\n' _own _strchrnul > "$SRC/reexported.txt"

new_app() {
    local app="$WORK/$1.app"
    rm -rf "$app"
    mkdir -p "$app/Contents/Resources/bin" "$app/Contents/Frameworks"
    echo "$app"
}
add_tool() {
    local app="$1" name="$2" src="$3"
    shift 3
    cc -o "$app/Contents/Resources/bin/$name" "$SRC/$src" "$@"
}
add_lib() {
    cc -dynamiclib -install_name @rpath/libnew.dylib -o "$1/Contents/Frameworks/libnew.dylib" "$SRC/lib.c"
}
# A tool that loads libnew.dylib as bundle-tools.sh writes it (@executable_path/../../Frameworks/…),
# or by another path.
add_lib_tool() {
    local app="$1" name="$2" path="${3:-@executable_path/../../Frameworks/libnew.dylib}"
    cc -o "$app/Contents/Resources/bin/$name" "$SRC/uselib.c" -L"$app/Contents/Frameworks" -lnew
    install_name_tool -change @rpath/libnew.dylib "$path" "$app/Contents/Resources/bin/$name" 2>/dev/null
}

# expect NAME 0|1 [grep pattern] -- check arguments
expect() {
    local name="$1" want="$2" pattern="$3" out status
    shift 4
    status=0
    out="$("$CHECK" "$@" 2>&1)" || status=$?
    if [[ "$want" == 0 && "$status" != 0 ]]; then
        failed "$name: exit $status"; echo "$out" >&2; return
    fi
    if [[ "$want" == 1 && "$status" == 0 ]]; then
        failed "$name: passed"; echo "$out" >&2; return
    fi
    if [[ -n "$pattern" ]] && ! grep -qE -- "$pattern" <<<"$out"; then
        failed "$name: no line matching /$pattern/"; echo "$out" >&2; return
    fi
    pass "$name"
}

app="$(new_app old)"
add_tool "$app" openvpn old.c
expect "only old symbols pass" 0 "Resources/bin/openvpn +macOS 13.0" -- "$app" --symbols "$SYMS"
expect "the real 13.0 lists pass them too" 0 "" -- "$app"

app="$(new_app new)"
add_tool "$app" openvpn new.c
expect "strchrnul fails on 13.0" 1 \
    "Resources/bin/openvpn imports _strchrnul from /usr/lib/libSystem.B.dylib, which macOS 13.0 does not export" \
    -- "$app" --symbols "$SYMS"
expect "strchrnul passes for a tool whose minimum is 15.4" 0 "Resources/bin/openvpn +macOS 15.4" \
    -- "$app" --symbols "$SYMS" --minimum openvpn=15.4
expect "a minimum without symbol lists fails" 1 "no symbol lists for macOS 14.0" \
    -- "$app" --symbols "$SYMS" --minimum openvpn=14.0
cp "$app/Contents/Resources/bin/openvpn" "$app/Contents/Resources/bin/openconnect"
rm "$app/Contents/Resources/bin/openvpn"
expect "openconnect's minimum is 15.4 (TOOL_MINIMUMS)" 0 "Resources/bin/openconnect +macOS 15.4" \
    -- "$app" --symbols "$SYMS"

app="$(new_app weak)"
add_tool "$app" openvpn weak.c
expect "a weak import fails, also where the symbol exists" 1 "imports _strchrnul from /usr/lib/libSystem.B.dylib weakly" \
    -- "$app" --symbols "$SYMS" --minimum openvpn=15.4

app="$(new_app stripped)"
add_tool "$app" openvpn new.c
strip -N "$app/Contents/Resources/bin/openvpn"
if nm -m -u "$app/Contents/Resources/bin/openvpn" | grep -q strchrnul; then
    echo "error: strip -N kept the import in the symbol table" >&2
    exit 1
fi
expect "an import that only the fixups name fails" 1 \
    "Resources/bin/openvpn imports _strchrnul from /usr/lib/libSystem.B.dylib, which macOS 13.0 does not export" \
    -- "$app" --symbols "$SYMS"

app="$(new_app flat)"
add_tool "$app" openvpn flat.c -Wl,-undefined,dynamic_lookup
expect "a flat-namespace lookup fails" 1 "looks up _nowhere in \"<flat-namespace>\"" -- "$app" --symbols "$SYMS"

app="$(new_app zlib)"
add_tool "$app" openvpn zlib.c -lz
expect "a macOS library without a list fails" 1 "loads /usr/lib/libz.1.dylib, which has no symbol list for macOS 13.0" \
    -- "$app" --symbols "$SYMS"
add_tool "$app" openvpn old.c -Wl,-needed_library,/usr/lib/libz.1.dylib
expect "so does one nothing is imported from" 1 "loads /usr/lib/libz.1.dylib, which has no symbol list for macOS 13.0" \
    -- "$app" --symbols "$SYMS"
add_tool "$app" openvpn old.c -Wl,-weak_library,/usr/lib/libz.1.dylib
expect "but not one loaded weakly, with nothing imported from it" 0 "" -- "$app" --symbols "$SYMS"

app="$(new_app reexport)"
add_tool "$app" openvpn old.c -Wl,-reexport_library,/usr/lib/libresolv.9.dylib
expect "re-exporting a macOS library fails" 1 "re-exports /usr/lib/libresolv.9.dylib" -- "$app" --symbols "$SYMS"
cc -dynamiclib -install_name @rpath/libnew.dylib -o "$app/Contents/Frameworks/libnew.dylib" "$SRC/own.c" \
    -Wl,-reexported_symbols_list,"$SRC/reexported.txt"
cc -o "$app/Contents/Resources/bin/openvpn" "$SRC/old.c" -L"$app/Contents/Frameworks" -lnew
install_name_tool -change @rpath/libnew.dylib @executable_path/../../Frameworks/libnew.dylib \
    "$app/Contents/Resources/bin/openvpn" 2>/dev/null
expect "re-exporting a macOS symbol fails" 1 "Frameworks/libnew.dylib re-exports _strchrnul from /usr/lib/libSystem.B.dylib" \
    -- "$app" --symbols "$SYMS" --minimum openvpn=15.4

app="$(new_app layout)"
add_lib "$app"
add_lib_tool "$app" openvpn @rpath/libnew.dylib
expect "an @rpath load fails" 1 "loads @rpath/libnew.dylib, outside the layout" -- "$app" --symbols "$SYMS"
add_lib_tool "$app" openvpn @executable_path/../../Frameworks/sub/libnew.dylib
expect "a load from another directory fails" 1 "Frameworks/sub/libnew.dylib, outside the layout" -- "$app" --symbols "$SYMS"

app="$(new_app "with space")"
add_lib "$app"
add_lib_tool "$app" "open vpn"
expect "a bundle path with spaces works" 0 "Frameworks/libnew.dylib +macOS 15.4" \
    -- "$app" --symbols "$SYMS" --minimum "open vpn=15.4"
expect "and still fails on 13.0" 1 "Frameworks/libnew.dylib imports _strchrnul" -- "$app" --symbols "$SYMS"

app="$(new_app lib)"
add_lib "$app"
add_lib_tool "$app" openfortivpn
expect "a library's strchrnul fails on 13.0" 1 \
    "Frameworks/libnew.dylib imports _strchrnul from /usr/lib/libSystem.B.dylib, which macOS 13.0 does not export" \
    -- "$app" --symbols "$SYMS"
expect "a library loaded only by a 15.4 tool is held to 15.4" 0 "Frameworks/libnew.dylib +macOS 15.4" \
    -- "$app" --symbols "$SYMS" --minimum openfortivpn=15.4
add_lib_tool "$app" openvpn
expect "a library loaded by a 13.0 tool too is held to 13.0" 1 "Frameworks/libnew.dylib imports _strchrnul" \
    -- "$app" --symbols "$SYMS" --minimum openfortivpn=15.4

if ((failures)); then
    echo "$failures test(s) failed" >&2
    exit 1
fi
echo "All check-tool-symbols.sh tests passed."
