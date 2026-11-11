#!/bin/bash
# Prints the release notes for the update window (Markdown): the notes of this release followed by
# those of the releases just before it, newest first, each under its version heading.
#
#   scripts/update-notes.sh [--earlier N] [--rev REV] VERSION NOTES_FILE
#
#   VERSION      the version being released (1.8.1, 1.9.0-rc.1, …)
#   NOTES_FILE   its release notes (Markdown), as given to release.sh
#   --earlier N  how many earlier releases to add at most (default: 5; 0 adds none)
#   --rev REV    the commit being released (default: HEAD)
#
# Works on the git repository of the current directory. Sparkle's update window shows only the notes
# of the update it offers, so someone who skipped releases would not see what those brought;
# release.sh embeds this text in the appcast instead of the notes of this release alone. The GitHub
# release, the tap and the MCP Registry keep this release's notes only.
#
# The earlier releases are the highest stable tags vX.Y.Z reachable from REV that are lower than
# VERSION (pre-release tags never count). Their notes are worked out again from the commit subjects
# with scripts/next-version.sh --ignore-tag TAG TAG, the same way the release workflow made them;
# a tag whose commits do not give its own version (a release made by hand, history before
# Conventional Commits) has no notes this way. The list stops at the first earlier release without
# notes, with a warning on stderr, so it never skips one in the middle. Without any earlier notes,
# the output is NOTES_FILE unchanged, as before. Exits non-zero only for wrong arguments or an
# unreadable NOTES_FILE; release.sh then falls back to this release's notes.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; }
warn() {
    echo "warning: $*" >&2
    # An annotation on the run, so it is not lost in the long log of the release job.
    [[ "${GITHUB_ACTIONS:-}" != true ]] || echo "::warning title=Update notes::$*" >&2
}

EARLIER=5
REV=HEAD
ARGS=()
while (($#)); do
    case "$1" in
        --earlier) (($# >= 2)) || die "--earlier needs a number"; EARLIER="$2"; shift ;;
        --rev) (($# >= 2)) || die "--rev needs a commit"; REV="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; die "unknown option: $1" ;;
        *) ARGS+=("$1") ;;
    esac
    shift
done
((${#ARGS[@]} == 2)) || { usage >&2; exit 2; }
VERSION="${ARGS[0]}"
NOTES_FILE="${ARGS[1]}"
[[ "$EARLIER" =~ ^(0|[1-9][0-9]?)$ ]] || die "--earlier takes a number from 0 to 99, not '$EARLIER'"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] \
    || die "'$VERSION' is not a semantic version"
BASE=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")
[[ -f "$NOTES_FILE" ]] || die "$NOTES_FILE not found"
NOTES="$(sed -e '/./,$!d' "$NOTES_FILE")"
[[ -n "$NOTES" ]] || die "$NOTES_FILE is empty"

NEXT_VERSION="$(cd "$(dirname "$0")" && pwd)/next-version.sh"
STABLE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

# Whether the version X.Y.Z of the last match of STABLE is lower than VERSION's X.Y.Z (a pre-release
# 1.9.0-rc.1 comes after 1.8.x, so its base version is what counts).
lower_than_version() {
    local i
    for i in 0 1 2; do
        ((BASH_REMATCH[i + 1] == BASE[i])) && continue
        ((BASH_REMATCH[i + 1] < BASE[i]))
        return
    done
    return 1
}

SECTIONS=""
ADDED=0
if ((EARLIER > 0)); then
    if ! git rev-parse -q --verify "$REV^{commit}" >/dev/null 2>&1; then
        warn "'$REV' is not a commit of this repository; the update notes cover $VERSION only"
    else
        TMP="$(mktemp -d)"
        trap 'rm -rf "$TMP"' EXIT
        FOUND=0
        while read -r tag; do
            ((ADDED < EARLIER)) || break
            [[ "$tag" =~ $STABLE ]] || continue
            lower_than_version || continue
            FOUND=1
            rm -f "$TMP/notes.md"
            got="$("$NEXT_VERSION" --ignore-tag "$tag" --notes "$TMP/notes.md" "$tag" 2>/dev/null)" || got=""
            if [[ "v$got" != "$tag" || ! -s "$TMP/notes.md" ]]; then
                warn "no release notes for $tag from the commit history; the update notes stop before it"
                break
            fi
            SECTIONS+=$'\n\n'"## ${tag#v}"$'\n\n'"$(cat "$TMP/notes.md")"
            ADDED=$((ADDED + 1))
        done < <(git tag --merged "$REV" --list 'v*' --sort=-v:refname)
        # The first release, or a clone without its tags (git fetch --tags).
        ((FOUND)) || warn "no release tag before $VERSION in the history of $REV; the update notes cover $VERSION only"
    fi
fi

if ((ADDED == 0)); then
    printf '%s\n' "$NOTES"
else
    echo "update notes: $VERSION and $ADDED earlier release(s)" >&2
    printf '## %s\n\n%s%s\n' "$VERSION" "$NOTES" "$SECTIONS"
fi
