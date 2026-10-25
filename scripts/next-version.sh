#!/bin/bash
# Prints the version the next release gets, from the commit subjects since the last release.
#
#   scripts/next-version.sh [--notes FILE] [REV]
#
#   REV           the commit to release (default: HEAD)
#   --notes FILE  also write the release notes (Markdown) to FILE
#
# Works on the git repository of the current directory. The last release is the highest tag vX.Y.Z
# reachable from REV (pre-release tags like v1.2.0-rc.1 do not count; without a tag it is 0.0.0).
# Every commit after it, merges excluded, whose subject follows Conventional Commits
# (type(scope)!: description, the types of the PR title check in .github/workflows/pull-request.yml)
# counts; other subjects (merge commits, older history) are ignored:
#
#   '!' after the type or scope, or a BREAKING CHANGE: footer   major (1.4.2 -> 2.0.0)
#   feat                                                        minor (1.4.2 -> 1.5.0)
#   fix, perf                                                   patch (1.4.2 -> 1.4.3)
#   anything else                                               no release
#
# Commits with the scope linux (feat(linux): …, fix(linux)!: …) are work on the Linux version, which
# has no release yet: they count for nothing, breaking or not, and are not in the notes. Phase 3 of
# docs/LINUX.md, which releases Linux, revisits this.
#
# Prints the version (like 1.5.0) when there is something to release and nothing when there is not;
# both exit 0. A summary goes to stderr. The notes list the commits under "### Breaking changes",
# "### New features" and "### Fixes" (perf too), oldest first, each subject without its type and with
# a capital first letter, keeping GitHub's "(#123)"; FILE is not written when there is no release.
# The release workflow (.github/workflows/release.yml) runs this on main and passes the notes to
# release.sh --notes-file.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; }

NOTES_FILE=""
REV=""
while (($#)); do
    case "$1" in
        --notes) (($# >= 2)) || die "--notes needs a file"; NOTES_FILE="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; die "unknown option: $1" ;;
        *) [[ -z "$REV" ]] || die "more than one revision given"; REV="$1" ;;
    esac
    shift
done
REV="${REV:-HEAD}"
git rev-parse -q --verify "$REV^{commit}" >/dev/null || die "'$REV' is not a commit"

# Keep the types in step with the PR title check.
TYPES='feat|fix|perf|docs|refactor|test|build|ci|chore|revert|style'
SUBJECT="^($TYPES)(\([A-Za-z0-9._/-]+\))?(!)?: ([^ ].*)$"
STABLE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

# The highest stable tag reachable from REV, by version (not by date).
LAST_TAG=""
MAJOR=0 MINOR=0 PATCH=0
while read -r tag; do
    [[ "$tag" =~ $STABLE ]] || continue
    LAST_TAG="$tag"
    MAJOR="${BASH_REMATCH[1]}" MINOR="${BASH_REMATCH[2]}" PATCH="${BASH_REMATCH[3]}"
    break
done < <(git tag --merged "$REV" --list 'v*' --sort=-v:refname)

if [[ -n "$LAST_TAG" ]]; then
    RANGE="$LAST_TAG..$REV"
    echo "last release: $LAST_TAG" >&2
else
    RANGE="$REV"
    echo "last release: none (counting from 0.0.0)" >&2
fi

# Capitalises the first letter (bash 3.2, as on macOS, has no ${var^}).
capitalise() { printf '%s%s' "$(printf '%s' "${1:0:1}" | tr '[:lower:]' '[:upper:]')" "${1:1}"; }

BUMP=0          # 0 none, 1 patch, 2 minor, 3 major
BREAKING=() FEATURES=() FIXES=()
COUNTED=0 IGNORED=0 LINUX=0
while read -r commit; do
    subject="$(git log -1 --format=%s "$commit")"
    if [[ ! "$subject" =~ $SUBJECT ]]; then
        IGNORED=$((IGNORED + 1))
        continue
    fi
    type="${BASH_REMATCH[1]}" scope="${BASH_REMATCH[2]}" bang="${BASH_REMATCH[3]}"
    # Linux work is not in the app's release: no bump, not in the notes. A breaking change too ('!'
    # or the footer): it breaks the Linux version only, which has no release and so nobody to break
    # yet. Revisited when Linux is released (docs/LINUX.md, phase 3).
    if [[ "$scope" == "(linux)" ]]; then
        LINUX=$((LINUX + 1))
        continue
    fi
    COUNTED=$((COUNTED + 1))
    line="- $(capitalise "${BASH_REMATCH[4]}")"
    body="$(git log -1 --format=%b "$commit")"
    if [[ -n "$bang" ]] || grep -Eq '^BREAKING[ -]CHANGE: ' <<<"$body"; then
        BUMP=3
        BREAKING+=("$line")
        continue
    fi
    case "$type" in
        feat) ((BUMP >= 2)) || BUMP=2; FEATURES+=("$line") ;;
        fix|perf) ((BUMP >= 1)) || BUMP=1; FIXES+=("$line") ;;
    esac
done < <(git rev-list --no-merges --reverse "$RANGE")
echo "commits since: $COUNTED conventional, $LINUX linux (left out), $IGNORED ignored" >&2

case "$BUMP" in
    0) echo "nothing to release (no feat, fix, perf or breaking change)" >&2; exit 0 ;;
    1) PATCH=$((PATCH + 1)) ;;
    2) MINOR=$((MINOR + 1)) PATCH=0 ;;
    3) MAJOR=$((MAJOR + 1)) MINOR=0 PATCH=0 ;;
esac
VERSION="$MAJOR.$MINOR.$PATCH"
echo "next version: $VERSION" >&2

if [[ -n "$NOTES_FILE" ]]; then
    # Sections separated by a blank line; empty ones left out. ${a[@]+…}: bash 3.2 and set -u.
    section() {
        local title="$1"
        shift
        (($#)) || return 0
        [[ -s "$NOTES_FILE" ]] && echo >> "$NOTES_FILE"
        { echo "### $title"; echo; printf '%s\n' "$@"; } >> "$NOTES_FILE"
    }
    : > "$NOTES_FILE"
    section "Breaking changes" ${BREAKING[@]+"${BREAKING[@]}"}
    section "New features" ${FEATURES[@]+"${FEATURES[@]}"}
    section "Fixes" ${FIXES[@]+"${FIXES[@]}"}
fi

echo "$VERSION"
