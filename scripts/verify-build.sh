#!/bin/bash
# Rebuilds the commit checked out here and checks that the result is a given PassTunnel.app apart from
# its code signatures (docs/RELEASING.md, Verifying a release).
#
#   scripts/verify-build.sh PassTunnel.app [--path-length N] [--keep]
#
#   PassTunnel.app   a release (from its disk image or zip), or any build of this commit
#   --path-length N  the length of the path the app was built in (default: 40, the release workflow's
#                    /Users/runner/work/passtunnel/passtunnel)
#   --keep           keep the rebuild (its directory is printed)
#
# The rebuild runs in a new worktree of this repository at HEAD, in a directory whose path has the
# same length as the original build's. The path itself is not in the binaries, but Swift (6.4.1 and
# earlier) compiles the length of a source file's path into optimized code: the file-name length it
# passes to swift_isEscapingClosureAtFileLocation (for each inlined DispatchQueue.sync, for example),
# while the name itself is left out. The Swift main branch no longer does (swiftlang/swift 3cb4db3). It runs `build-app.sh --version V
# --tools-from PassTunnel.app`: the same version, and the app's own signed VPN tools and dylibs (after
# checking that they are this build's apart from their signatures), so that the tool pins compiled into
# the app and the helper are the app's. Then it compares the two bundles with compare-app.sh.
#
# Needs the Xcode recorded in the app (DTXcodeBuild in Info.plist) and Homebrew's openvpn,
# openfortivpn and openconnect (with their libraries) at the versions in scripts/release.env.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP=""
LENGTH=40
KEEP=0
while (($#)); do
    case "$1" in
        --path-length) LENGTH="${2:?--path-length needs a number}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown argument: $1" ;;
        *) [[ -z "$APP" ]] || die "one app only"; APP="$1"; shift ;;
    esac
done
[[ -n "$APP" && -f "$APP/Contents/Info.plist" ]] || die "usage: $0 PassTunnel.app [--path-length N] [--keep]"
[[ "$LENGTH" =~ ^[1-9][0-9]*$ ]] || die "not a length: $LENGTH"
APP="$(cd "$APP" && pwd)"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]] || die "$ROOT has uncommitted changes"

info() { plutil -extract "$1" raw "$APP/Contents/Info.plist" 2>/dev/null || true; }
VERSION="$(info CFBundleShortVersionString)"
[[ -n "$VERSION" ]] || die "no CFBundleShortVersionString in $APP"
WANT_XCODE="$(info DTXcodeBuild)"
HAVE_XCODE="$(xcodebuild -version 2>/dev/null | sed -n 's/^Build version //p')"
if [[ -z "$WANT_XCODE" ]]; then
    echo "warning: $APP does not say which Xcode built it (no DTXcodeBuild); using $HAVE_XCODE" >&2
elif [[ "$WANT_XCODE" != "$HAVE_XCODE" ]]; then
    die "$APP was built with Xcode build $WANT_XCODE, this is $HAVE_XCODE (xcode-select -s, or DEVELOPER_DIR)"
fi
echo "==> rebuilding $(git -C "$ROOT" describe --tags --always) as PassTunnel $VERSION (Xcode build $HAVE_XCODE)"

# A directory whose path is LENGTH characters long: a new one in /private/tmp, plus a padded name.
BASE="$(mktemp -d /private/tmp/ptv.XXXXXX)"
PAD=$((LENGTH - ${#BASE} - 1))
((PAD >= 1)) || die "cannot make a path of $LENGTH characters in /private/tmp"
NAME="$(printf 'passtunnel%0*d' 200 0)"
NAME="${NAME:0:PAD}"
DIR="$BASE/$NAME"
if ((KEEP == 0)); then
    trap 'git -C "$ROOT" worktree remove --force "$DIR" 2>/dev/null || true; rm -rf "$BASE"' EXIT
fi
git -C "$ROOT" worktree add --quiet --detach "$DIR" HEAD
echo "    in $DIR (${#DIR} characters)"

"$DIR/scripts/build-app.sh" --version "$VERSION" --tools-from "$APP"
echo "==> comparing"
"$ROOT/scripts/compare-app.sh" "$APP" "$DIR/build/PassTunnel.app"
((KEEP)) && echo "kept: $DIR (git worktree remove --force $DIR)"
exit 0
