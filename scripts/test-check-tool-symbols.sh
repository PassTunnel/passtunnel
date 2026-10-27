#!/bin/bash
# Self-test of check-tool-symbols.sh on small tools and libraries compiled here (macOS with Xcode; they
# are never run): one that imports strchrnul (macOS 15.4 and later) fails against macOS 13.0 and
# passes when its minimum is 15.4, a library inherits the lowest minimum of the tools that load it, weak
# imports are refused, and so is a macOS library without a symbol list.
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
uses_lib() { echo -L"$1/Contents/Frameworks" -lnew -Wl,-rpath,@executable_path/../../Frameworks; }

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

app="$(new_app zlib)"
add_tool "$app" openvpn zlib.c -lz
expect "a macOS library without a list fails" 1 "loads /usr/lib/libz.1.dylib, which has no symbol list for macOS 13.0" \
    -- "$app" --symbols "$SYMS"

app="$(new_app lib)"
add_lib "$app"
# shellcheck disable=SC2046  # the flags are words
add_tool "$app" openfortivpn uselib.c $(uses_lib "$app")
expect "a library's strchrnul fails on 13.0" 1 \
    "Frameworks/libnew.dylib imports _strchrnul from /usr/lib/libSystem.B.dylib, which macOS 13.0 does not export" \
    -- "$app" --symbols "$SYMS"
expect "a library loaded only by a 15.4 tool is held to 15.4" 0 "Frameworks/libnew.dylib +macOS 15.4" \
    -- "$app" --symbols "$SYMS" --minimum openfortivpn=15.4
# shellcheck disable=SC2046
add_tool "$app" openvpn uselib.c $(uses_lib "$app")
expect "a library loaded by a 13.0 tool too is held to 13.0" 1 "Frameworks/libnew.dylib imports _strchrnul" \
    -- "$app" --symbols "$SYMS" --minimum openfortivpn=15.4

if ((failures)); then
    echo "$failures test(s) failed" >&2
    exit 1
fi
echo "All check-tool-symbols.sh tests passed."
