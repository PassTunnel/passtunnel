#!/bin/bash
# Prints the MCP Registry entry of a release: server.json (name, description, links) with "version"
# set to VERSION and a "packages" entry for the release's MCP bundle.
#
#   scripts/make-server-json.sh VERSION MCPB_SHA256 > server.json
#
# The bundle's URL is https://github.com/GITHUB_REPO/releases/download/vVERSION/PassTunnel-mcp-VERSION.mcpb
# (GITHUB_REPO from release.env). release.sh writes dist/server.json with it; the workflow
# .github/workflows/publish-mcp.yml runs it with the SHA-256 of the published asset and publishes the
# result. Needs jq.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# GITHUB_REPO
source "$ROOT/scripts/release.env"

die() { echo "error: $*" >&2; exit 1; }

[[ $# -eq 2 ]] || { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
VERSION="$1"
SHA="$2"
ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER="^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$ID(\.$ID)*)?$"
[[ "$VERSION" =~ $SEMVER ]] || die "'$VERSION' is not a semantic version"
[[ "$SHA" =~ ^[0-9a-f]{64}$ ]] || die "'$SHA' is not a SHA-256 in lowercase hex"
command -v jq >/dev/null || die "jq not found"

URL="https://github.com/$GITHUB_REPO/releases/download/v$VERSION/PassTunnel-mcp-$VERSION.mcpb"
jq --arg version "$VERSION" --arg url "$URL" --arg sha "$SHA" '
    .version = $version
    | .packages = [{
        registryType: "mcpb",
        identifier: $url,
        version: $version,
        fileSha256: $sha,
        transport: {type: "stdio"}
      }]
' "$ROOT/server.json"
