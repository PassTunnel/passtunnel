#!/bin/bash
# Builds the MCP Bundle PassTunnel-mcp-VERSION.mcpb (for Claude Desktop and other MCPB clients, and the
# MCP Registry entry) from packaging/mcpb/.
#
#   scripts/build-mcpb.sh VERSION [OUTPUT_DIR]     # OUTPUT_DIR defaults to dist/
#   scripts/build-mcpb.sh --check                  # only check that the tools it needs are there
#
# The bundle is a zip with manifest.json (version set to VERSION), the launcher server/passtunnel-mcp
# and the app icon (Resources/AppIcon.icns at 512×512). The launcher starts the MCP server of the
# installed app, so the bundle works only with PassTunnel in /Applications. release.sh calls this; it
# can also run on its own (nothing is signed or published). Only macOS tools and jq are used, no
# package manager: the zip has a fixed file order, modes and timestamps, so the same sources and
# VERSION give the same bytes. The manifest is checked with jq (MCPB manifest 0.3, the fields used here).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

die() { echo "error: $*" >&2; exit 1; }

VERSION="${1:-}"
OUT_DIR="${2:-$ROOT/dist}"
[[ -n "$VERSION" && $# -le 2 ]] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
CHECK_ONLY=0
if [[ "$VERSION" == "--check" && $# -eq 1 ]]; then
    CHECK_ONLY=1
else
    ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
    SEMVER="^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$ID(\.$ID)*)?$"
    [[ "$VERSION" =~ $SEMVER ]] || die "'$VERSION' is not a semantic version (like 1.2.0 or 1.2.0-rc.1)"
fi

command -v jq >/dev/null || die "jq not found (part of macOS 15 and later, else brew install jq)"
for tool in zip unzip sips; do
    command -v "$tool" >/dev/null || die "$tool not found"
done
if ((CHECK_ONLY)); then
    echo "MCP bundle tools: $(jq --version), zip, unzip, sips"
    exit 0
fi

# The MCP Registry only accepts bundle URLs that contain "mcp".
NAME="PassTunnel-mcp-$VERSION.mcpb"
SRC="$ROOT/packaging/mcpb"
# The bundle's files, in the order they are packed (and listed).
FILES=(icon.png manifest.json server/passtunnel-mcp)
# Timestamp of every packed file (zip stores local time without a zone, so it is set and read in UTC).
STAMP=202001010000.00

# Checks manifest $1 against the MCPB manifest 0.3 fields this bundle relies on; prints each problem.
manifest_problems() {
    jq -r --arg version "$VERSION" '
        def need(ok; problem): if ok then empty else problem end;
        def text: type == "string" and length > 0;
        . as $m
        | need(type == "object"; "not a JSON object"),
          ((keys - ["$schema", "_meta", "author", "compatibility", "description", "display_name", "documentation",
                    "dxt_version", "homepage", "icon", "icons", "keywords", "license", "localization",
                    "long_description", "manifest_version", "name", "privacy_policies", "prompts",
                    "prompts_generated", "repository", "screenshots", "server", "support", "tools",
                    "tools_generated", "user_config", "version"])[] | "unknown field \(.) (the 0.3 schema allows no others)"),
          need(.manifest_version == "0.3"; "manifest_version is not \"0.3\""),
          need((.name | text) and (.name | test("^[a-z0-9][a-z0-9-]*$")); "name is missing or not lowercase letters, digits and -"),
          need(.version == $version; "version is not \"\($version)\""),
          need(.description | text; "description is missing"),
          need(.author.name | text; "author.name is missing"),
          need(.server.type == "binary"; "server.type is not \"binary\""),
          need(.server.entry_point | text; "server.entry_point is missing"),
          need(.server.mcp_config.command | text; "server.mcp_config.command is missing"),
          need(.server.mcp_config.args | type == "array" and all(.[]; type == "string"); "server.mcp_config.args is not a list of strings"),
          need(any(.server.mcp_config.args[]?; . == "${__dirname}/\($m.server.entry_point)"); "server.mcp_config.args does not run server.entry_point"),
          need(.server.mcp_config.env.PASSTUNNEL_MCP_ALLOW_CONNECT == "${user_config.allow_connect}"; "server.mcp_config.env does not pass user_config.allow_connect"),
          need(any(.compatibility.platforms[]?; . == "darwin"); "compatibility.platforms does not contain \"darwin\""),
          need(.tools | type == "array" and length > 0 and all(.[]; .name | text); "tools is not a list of named tools"),
          need([.tools[]?.name] | length == (unique | length); "tool names are not unique"),
          need(.user_config.allow_connect.type == "boolean"; "user_config.allow_connect.type is not \"boolean\""),
          need(.user_config.allow_connect.default == false; "user_config.allow_connect.default is not false"),
          need(.icon == null or (.icon | text); "icon is not a file name"),
          ([.. | strings | scan("\\$\\{user_config\\.([A-Za-z0-9_]+)\\}") | .[0]] - (.user_config // {} | keys) | unique[]
           | "${user_config.\(.)} names no user_config entry")
    ' "$1"
}

# Checks the manifest.json in bundle directory $1 and the files it names; $2 says which bundle.
check_bundle() {
    local dir="$1" what="$2" problems entry icon
    problems="$(manifest_problems "$dir/manifest.json")" || die "manifest.json ($what) is not valid JSON"
    [[ -z "$problems" ]] || die "manifest.json ($what):"$'\n'"$problems"
    entry="$(jq -r .server.entry_point "$dir/manifest.json")"
    [[ -f "$dir/$entry" && -x "$dir/$entry" ]] || die "server.entry_point $entry is not an executable file ($what)"
    icon="$(jq -r '.icon // empty' "$dir/manifest.json")"
    if [[ -n "$icon" ]]; then
        [[ -f "$dir/$icon" ]] || die "icon $icon is missing ($what)"
        [[ "$(head -c 8 "$dir/$icon" | od -An -tx1 | tr -d ' \n')" == "89504e470d0a1a0a" ]] || die "icon $icon is not a PNG ($what)"
    fi
}

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
B="$STAGE/bundle"
mkdir -p "$B/server"
sed "s/@VERSION@/$VERSION/g" "$SRC/manifest.json" > "$B/manifest.json"
! grep -q '@[A-Z_]*@' "$B/manifest.json" || die "manifest.json still has a placeholder"
install -m 755 "$SRC/server/passtunnel-mcp" "$B/server/passtunnel-mcp"
sh -n "$B/server/passtunnel-mcp" || die "server/passtunnel-mcp is not valid sh"
sips -s format png -Z 512 "$ROOT/Resources/AppIcon.icns" --out "$B/icon.png" >/dev/null \
    || die "could not convert Resources/AppIcon.icns to icon.png"
chmod 644 "$B/manifest.json" "$B/icon.png"
(cd "$B" && TZ=UTC touch -t "$STAMP" "${FILES[@]}")

echo "checking manifest.json and packing $NAME"
check_bundle "$B" "staged"
mkdir -p "$OUT_DIR"
OUT="$(cd "$OUT_DIR" && pwd)/$NAME"
rm -f "$OUT"
# -X: no uid/gid or extra timestamps, -D: no directory entries; the Unix modes (the launcher's exec
# bit) are kept.
(cd "$B" && TZ=UTC zip -q -X -D -9 "$OUT" "${FILES[@]}")

# Check what was packed: exactly the three files in order, unchanged, the launcher executable, and a
# valid manifest of this version that reads back as the same JSON.
LISTED="$(unzip -Z1 "$OUT" | tr '\n' ' ')"
[[ "$LISTED" == "${FILES[*]} " ]] || die "unexpected files in $NAME: $LISTED"
[[ "$(unzip -Z "$OUT" server/passtunnel-mcp | awk '{print $1}')" == "-rwxr-xr-x" ]] \
    || die "server/passtunnel-mcp is not executable in $NAME"
CHECK="$STAGE/check"
mkdir -p "$CHECK"
unzip -q "$OUT" -d "$CHECK"
for f in "${FILES[@]}"; do
    cmp -s "$B/$f" "$CHECK/$f" || die "$f in $NAME differs from the staged file"
done
[[ "$(unzip -p "$OUT" manifest.json | jq -S .)" == "$(jq -S . "$B/manifest.json")" ]] \
    || die "manifest.json in $NAME does not read back as the staged manifest"
check_bundle "$CHECK" "in $NAME"
unzip -tq "$OUT" >/dev/null || die "$NAME fails the zip integrity test"

echo "built $OUT"
shasum -a 256 "$OUT"
