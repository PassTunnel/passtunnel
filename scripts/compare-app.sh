#!/bin/bash
# Compares two builds of PassTunnel.app, or two files, apart from their code signatures.
#
#   scripts/compare-app.sh A.app B.app
#   scripts/compare-app.sh A/Contents/Resources/bin/openvpn B/Contents/Resources/bin/openvpn
#
# Every file, directory and symbolic link must be in both, with the same permissions and contents,
# except the signatures: Mach-O files are compared with `codesign --remove-signature` applied to
# copies; signatures kept in extended attributes (scripts such as dns-updown) are not compared, as
# extended attributes are not; and the _CodeSignature/CodeResources files (the sealed resources of
# each signed bundle) and Contents/CodeResources (the notarization ticket stapled to a release) are
# left out. Prints each difference and exits with 1 if there is one. Used by verify-build.sh and
# build-app.sh --tools-from (docs/RELEASING.md, Verifying a release).
set -euo pipefail

A="${1:?usage: $0 A B}"
B="${2:?usage: $0 A B}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

is_macho() { lipo -archs "$1" >/dev/null 2>&1; }

# Same contents apart from the signature.
same_file() {
    local a="$1" b="$2"
    if is_macho "$a" && is_macho "$b"; then
        cp "$a" "$WORK/a" && cp "$b" "$WORK/b"
        chmod u+w "$WORK/a" "$WORK/b"
        # An unsigned file has nothing to remove; codesign then fails, which changes nothing.
        codesign --remove-signature "$WORK/a" 2>/dev/null || true
        codesign --remove-signature "$WORK/b" 2>/dev/null || true
        cmp -s "$WORK/a" "$WORK/b"
    else
        cmp -s "$a" "$b"
    fi
}

if [[ -f "$A" && -f "$B" ]]; then
    same_file "$A" "$B" && exit 0
    echo "differs: $A $B"
    exit 1
fi
[[ -d "$A" && -d "$B" ]] || { echo "error: compare two files or two directories" >&2; exit 2; }

# The entries of a tree with their type and permissions (as `ls -l` shows them), without the
# signatures' files.
listing() {
    (cd "$1" && find . \( -path '*/_CodeSignature/CodeResources' -o -path './Contents/CodeResources' \) -prune \
        -o -print0 | xargs -0 stat -f '%Sp %N' | LC_ALL=C sort -k2)
}
listing "$A" >"$WORK/list-a"
listing "$B" >"$WORK/list-b"
status=0
if ! diff "$WORK/list-a" "$WORK/list-b"; then
    echo "the files, their types or their permissions differ (< $A, > $B)"
    status=1
fi
while read -r mode path; do
    case "$mode" in
        -*)
            [[ -f "$B/$path" && ! -L "$B/$path" ]] || continue
            same_file "$A/$path" "$B/$path" || { echo "differs: ${path#./}"; status=1; } ;;
        l*)
            [[ -L "$B/$path" ]] || continue
            [[ "$(readlink "$A/$path")" == "$(readlink "$B/$path")" ]] || { echo "link differs: ${path#./}"; status=1; } ;;
    esac
done <"$WORK/list-a"
((status == 0)) && echo "same apart from the code signatures: $A $B"
exit "$status"
