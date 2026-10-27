#!/bin/bash
# Builds the Linux release tarball passtunnel-VERSION-linux-ARCH.tar.gz (docs/LINUX.md, Distribution):
# passtunnel and passtunneld in release mode with the Swift standard library linked statically, the
# systemd units, a README, the license and the third-party notices.
#
#   scripts/build-linux.sh [--version VERSION] [--build-number N] [--output DIR]
#
#   --version VERSION   the version compiled in (default 0.0.0-dev, what development builds report)
#   --build-number N    the build number (default: the number of commits up to HEAD)
#   --output DIR        where the tarball goes (default dist/)
#
# Runs on Linux, for the architecture it runs on (x86_64 or aarch64), in the Swift image of the oldest
# supported Ubuntu (22.04), so that the binaries run on every later glibc. From the repository root:
#
#   docker run --rm -v "$PWD":/src -w /src swift:6.4.1-jammy scripts/build-linux.sh
#
# The version and the build number are compiled in: BuildVersion+Generated.swift (passtunnel's
# `--version`) and DaemonBuild+Generated.swift (passtunneld's build_number in hello and helper_build in
# every reply) are written for the build with -DPASSTUNNEL_BUILD_VERSION and removed afterwards, like
# build-app.sh's PinnedTools+Generated.swift. The build number is the commit count, as the Mac app's
# CFBundleVersion: the same for both binaries and both architectures, growing with every commit on
# main. A shallow clone cannot count its commits; fetch the whole history or pass --build-number.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="0.0.0-dev"
BUILD_NUMBER=""
OUT="$ROOT/dist"
while (($#)); do
    case "$1" in
        --version) VERSION="${2:?--version needs a version}"; shift 2 ;;
        --build-number) BUILD_NUMBER="${2:?--build-number needs a number}"; shift 2 ;;
        --output) OUT="${2:?--output needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ "$(uname -s)" == Linux ]] || die "this builds on Linux only, for example in the container named in --help"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|aarch64) ;;
    *) die "unsupported architecture: $ARCH" ;;
esac
# What next-version.sh prints (1.2.0), a pre-release (1.2.0-rc.1) or the development version. It goes
# into a Swift string literal and the file name, so nothing else is accepted.
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "not a version: $VERSION"
if [[ -z "$BUILD_NUMBER" ]]; then
    git -C "$ROOT" rev-parse -q --verify HEAD >/dev/null \
        || die "cannot count the commits of $ROOT (not a git checkout, or git refuses it: in a container add it to safe.directory); pass --build-number"
    [[ "$(git -C "$ROOT" rev-parse --is-shallow-repository)" == false ]] \
        || die "$ROOT is a shallow clone: fetch the whole history (git fetch --unshallow) or pass --build-number"
    BUILD_NUMBER="$(git -C "$ROOT" rev-list --count HEAD)"
fi
[[ "$BUILD_NUMBER" =~ ^[1-9][0-9]{0,8}$ ]] || die "not a build number: $BUILD_NUMBER"
# File dates in the tarball: the commit's, unless SOURCE_DATE_EPOCH says otherwise.
EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
[[ "$EPOCH" =~ ^[0-9]+$ ]] || die "not a time stamp: $EPOCH"
for tool in swift git ldd strip tar gzip sha256sum; do
    command -v "$tool" >/dev/null || die "$tool is missing"
done

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
NAME="passtunnel-$VERSION-linux-$ARCH"
GEN_VERSION="$ROOT/Sources/PassTunnelCore/BuildVersion+Generated.swift"
GEN_DAEMON="$ROOT/Sources/PassTunnelDaemon/DaemonBuild+Generated.swift"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"; rm -f "$GEN_VERSION" "$GEN_DAEMON"' EXIT

echo "==> $NAME, build $BUILD_NUMBER"
cat >"$GEN_VERSION" <<EOF
// Written by scripts/build-linux.sh for one build; never committed (see BuildVersion.swift).
#if PASSTUNNEL_BUILD_VERSION
extension BuildVersion {
    static let generatedVersion = "$VERSION"
    static let generatedBuild: String? = "$BUILD_NUMBER"
}
#endif
EOF
cat >"$GEN_DAEMON" <<EOF
// Written by scripts/build-linux.sh for one build; never committed (see DaemonBuild.swift).
#if PASSTUNNEL_BUILD_VERSION
extension DaemonBuild {
    static let generatedNumber: Int? = $BUILD_NUMBER
}
#endif
EOF

cd "$ROOT"
swift --version
# No debug information (strip removes it below anyway): Swift's named the Clang modules it imports by
# their signatures in the module cache, which differ from one build to the next, and the linker's build
# ID, which strip keeps, is a hash over all of it.
BUILD=(swift build -c release --static-swift-stdlib -debug-info-format none -Xswiftc -DPASSTUNNEL_BUILD_VERSION)
"${BUILD[@]}" --product passtunnel
"${BUILD[@]}" --product passtunneld
BIN="$("${BUILD[@]}" --show-bin-path)"

# The version went in, and nothing of Swift is loaded from the system.
HOME_FOR_CHECK="$STAGE/home"
mkdir -p "$HOME_FOR_CHECK"
reported="$(PASSTUNNEL_HOME="$HOME_FOR_CHECK" "$BIN/passtunnel" --version)"
[[ "$reported" == "PassTunnel $VERSION ($BUILD_NUMBER)" ]] || die "passtunnel --version says: $reported"
for exe in passtunnel passtunneld; do
    if ldd "$BIN/$exe" | grep -E 'not found|libswift|libFoundation|lib_Foundation|libdispatch|libBlocksRuntime|libicu'; then
        die "$exe needs the libraries above from the system"
    fi
done

echo "==> staging"
D="$STAGE/$NAME"
install -d -m 0755 "$D" "$D/bin" "$D/sbin" "$D/lib" "$D/lib/systemd" "$D/lib/systemd/system" "$D/licenses"
install -m 0755 "$BIN/passtunnel" "$D/bin/passtunnel"
install -m 0755 "$BIN/passtunneld" "$D/sbin/passtunneld"
# Debug information only; the symbols stay for backtraces.
strip --strip-debug "$D/bin/passtunnel" "$D/sbin/passtunneld"
install -m 0644 "$ROOT/packaging/linux/passtunnel.socket" "$D/lib/systemd/system/passtunnel.socket"
# The unit names the packages' /usr/sbin; the tarball installs under /usr/local.
sed 's|^ExecStart=/usr/sbin/passtunneld$|ExecStart=/usr/local/sbin/passtunneld|' \
    "$ROOT/packaging/linux/passtunnel.service" >"$D/lib/systemd/system/passtunnel.service"
chmod 0644 "$D/lib/systemd/system/passtunnel.service"
grep -qx 'ExecStart=/usr/local/sbin/passtunneld' "$D/lib/systemd/system/passtunnel.service" \
    || die "packaging/linux/passtunnel.service no longer has ExecStart=/usr/sbin/passtunneld"
install -m 0644 "$ROOT/packaging/linux/README.md" "$D/README.md"
install -m 0644 "$ROOT/LICENSE" "$D/LICENSE"
install -m 0644 "$ROOT/packaging/linux/licenses/"*.txt "$D/licenses/"
# The packages' own texts, from the checkouts of the versions Package.resolved pins.
for package in swift-crypto swift-asn1; do
    for file in LICENSE NOTICE; do
        src="$ROOT/.build/checkouts/$package/$file.txt"
        [[ -f "$src" ]] || die "$src is missing"
        install -m 0644 "$src" "$D/licenses/$package-$file.txt"
    done
done

# The version Package.resolved pins for a package identity.
pinned() {
    awk -v id="\"$1\"," '$1 == "\"identity\"" { here = ($3 == id) } here && $1 == "\"version\"" { gsub(/"/, "", $3); print $3; exit }' \
        "$ROOT/Package.resolved"
}
CRYPTO_VERSION="$(pinned swift-crypto)"
ASN1_VERSION="$(pinned swift-asn1)"
[[ -n "$CRYPTO_VERSION" && -n "$ASN1_VERSION" ]] || die "no swift-crypto or swift-asn1 in Package.resolved"
BORINGSSL="$(sed -n 's/.* at revision \([0-9a-f]*\).*/\1/p' "$ROOT/.build/checkouts/swift-crypto/Sources/CCryptoBoringSSL/hash.txt")"
SWIFT_VERSION="$(swift --version 2>/dev/null | sed -n 's/^Swift version //p')"
{
    cat "$ROOT/packaging/linux/THIRD_PARTY_NOTICES.md"
    printf '\n## In this build\n\n| | |\n|---|---|\n'
    printf '| PassTunnel | %s (build %s), linux-%s |\n' "$VERSION" "$BUILD_NUMBER" "$ARCH"
    printf '| Swift | %s |\n' "${SWIFT_VERSION:-unknown}"
    printf '| swift-crypto | %s (BoringSSL %s) |\n' "$CRYPTO_VERSION" "${BORINGSSL:-unknown}"
    printf '| swift-asn1 | %s |\n' "$ASN1_VERSION"
} >"$D/THIRD_PARTY_NOTICES.md"
chmod 0644 "$D/THIRD_PARTY_NOTICES.md"

echo "==> packing"
TARBALL="$OUT/$NAME.tar.gz"
rm -f "$TARBALL"
# Files owned by root (extracted by root, they stay root's, as the daemon requires), in name order,
# dated EPOCH; gzip without a name or time stamp.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" -C "$STAGE" -cf - "$NAME" \
    | gzip -9 -n >"$TARBALL"
tar -tvzf "$TARBALL"
sha256sum "$TARBALL"
echo "==> done: $TARBALL"
