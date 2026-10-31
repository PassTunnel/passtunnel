#!/bin/bash
# Starts the GlobalProtect test server (Tests/globalprotect/README.md). TEST ONLY. Needs Docker; changes nothing
# outside the image, the container and the network it makes.
#
#   Tests/globalprotect/start-server.sh DOWNLOADS OUT
#
# 1. The openconnect release tarball of the version scripts/release.env pins (OPENCONNECT_VERSION), from
#    infradead.org into DOWNLOADS (kept there: the CI job caches it), checked against fake-gp-server.sha256,
#    which must name that version, before anything is read from it.
# 2. Only tests/fake-gp-server.py taken out of it, into a temporary directory, never into this repository; the
#    image built with it as the build context `fake-gp` (Dockerfile).
# 3. The container started at 172.31.212.10 on the network passtunnel-fake-gp (172.31.212.0/24), and waited for
#    until every server is configured; the test CA and the server key's pin copied to OUT/ca.pem and OUT/pin.txt.
#
# Nothing from the tarball runs outside the container. Remove it all with
#   docker rm -f passtunnel-fake-gp; docker network rm passtunnel-fake-gp
set -euo pipefail

fail() {
    echo "error: $*" >&2
    exit 1
}

DOWNLOADS="${1:?a directory for the openconnect tarball}"
OUT="${2:?a directory for ca.pem and pin.txt}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NAME=passtunnel-fake-gp
mkdir -p "$DOWNLOADS" "$OUT"

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d ' ' -f 1
}

version="$(sed -n 's/^OPENCONNECT_VERSION=//p' "$ROOT/scripts/release.env")"
[[ "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || fail "no OPENCONNECT_VERSION in scripts/release.env"
read -r sum file <"$HERE/fake-gp-server.sha256"
[[ "$sum" =~ ^[0-9a-f]{64}$ ]] || fail "Tests/globalprotect/fake-gp-server.sha256 holds no SHA-256"
[[ "$file" == "openconnect-$version.tar.gz" ]] ||
    fail "Tests/globalprotect/fake-gp-server.sha256 is for $file, scripts/release.env pins openconnect $version: update it with the pin"

tarball="$DOWNLOADS/$file"
if [[ ! -f "$tarball" || "$(sha256 "$tarball")" != "$sum" ]]; then
    rm -f "$tarball" "$tarball.part"
    curl -fsSL --proto '=https' --retry 3 --max-time 120 -o "$tarball.part" "https://www.infradead.org/openconnect/download/$file"
    mv "$tarball.part" "$tarball"
fi
got="$(sha256 "$tarball")"
if [[ "$got" != "$sum" ]]; then
    rm -f "$tarball"
    fail "$file has SHA-256 $got, not $sum: not used"
fi
echo "$file: SHA-256 $sum"

context="$(mktemp -d)"
trap 'rm -rf "$context"' EXIT
tar -xzf "$tarball" -C "$context" --strip-components=2 "openconnect-$version/tests/fake-gp-server.py"
[[ -f "$context/fake-gp-server.py" && ! -L "$context/fake-gp-server.py" ]] || fail "no tests/fake-gp-server.py in $file"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker network rm "$NAME" >/dev/null 2>&1 || true
docker build -q -t "$NAME" --build-context "fake-gp=$context" "$HERE" >/dev/null
docker network create --subnet 172.31.212.0/24 "$NAME" >/dev/null
docker run -d --name "$NAME" --network "$NAME" --ip 172.31.212.10 "$NAME" >/dev/null
for try in $(seq 60); do
    docker exec "$NAME" test -e /run/fake-gp-ready 2>/dev/null && break
    if [[ "$try" -eq 60 ]] || ! docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -qx true; then
        docker logs "$NAME" >&2 || true
        fail "the test server did not start"
    fi
    sleep 1
done
docker logs "$NAME"
docker cp "$NAME:/etc/fake-gp/ca.pem" "$OUT/ca.pem"
docker exec "$NAME" cat /etc/fake-gp/pin.txt | tee "$OUT/pin.txt"
