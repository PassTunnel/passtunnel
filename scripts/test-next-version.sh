#!/bin/bash
# Self-test of scripts/next-version.sh: builds a throwaway git repository in a temporary directory
# (empty commits only, no signing, no remote) and checks the version and release notes it picks at
# each step. Runs in CI (ci.yml, "Release scripts") and locally:
#
#   scripts/test-next-version.sh
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/next-version.sh"
REPO="$(mktemp -d)"
trap 'rm -rf "$REPO"' EXIT
cd "$REPO"

FAILED=0
fail() { echo "FAIL: $*" >&2; FAILED=1; }

git init -q -b main
git config user.name alice
git config user.email alice@example.com
git config commit.gpgsign false
git config tag.gpgsign false

# Each commit and merge one second after the one before, so the order of the notes does not depend
# on how many fall into the same second (git orders commits of one range by date).
NOW=1700000000
tick() { NOW=$((NOW + 1)); export GIT_AUTHOR_DATE="$NOW +0000" GIT_COMMITTER_DATE="$NOW +0000"; }

# commit SUBJECT [BODY]
commit() { tick; git commit -q --allow-empty -m "$1" ${2:+-m "$2"}; }

# expect VERSION [REV]: next-version.sh prints VERSION (empty: no release).
expect() {
    local want="$1" got
    shift
    got="$("$SCRIPT" "$@" 2>/dev/null)" || { fail "next-version.sh $* exited non-zero"; return; }
    if [[ "$got" == "$want" ]]; then
        echo "ok: ${want:-no release}${1:+ at $1}"
    else
        fail "expected '${want:-no release}'${1:+ at $1}, got '$got'"
    fi
}

# expect_notes TEXT: the notes next-version.sh writes for HEAD.
expect_notes() {
    local file="$REPO/.git/notes.md" got
    rm -f "$file"
    "$SCRIPT" --notes "$file" >/dev/null 2>&1 || { fail "next-version.sh --notes exited non-zero"; return; }
    got="$(cat "$file" 2>/dev/null || true)"
    if [[ "$got" == "$1" ]]; then
        echo "ok: notes"
    else
        fail "notes differ:"$'\n'"--- expected"$'\n'"$1"$'\n'"--- got"$'\n'"$got"
    fi
}

# No tag at all: counts from 0.0.0.
commit "Initial import"
expect ""
commit "fix: first fix"
expect "0.0.1"
git tag v1.0.0

# Types without a release, and subjects that do not parse, change nothing.
commit "docs: explain the CLI (#2)"
commit "chore(deps): update tooling"
commit "ci: cache the build"
commit "Update README.md"
commit "feat:missing space"
commit "Feat: capital type"
commit "feature: unknown type"
commit "feat(two words): space in scope"
expect ""
if [[ -z "$("$SCRIPT" --notes "$REPO/.git/none.md" 2>/dev/null)" && ! -e "$REPO/.git/none.md" ]]; then
    echo "ok: no notes file without a release"
else
    fail "a notes file was written without a release"
fi

# fix and perf: patch.
commit "fix: reconnect after sleep (#3)"
expect "1.0.1"
commit "perf(core): parse profiles once"
expect "1.0.1"
FIX_REV="$(git rev-parse HEAD)"

# feat: minor; a pre-release tag is not the last release.
commit "feat(cli): add --json to list (#4)"
git tag v1.1.0-rc.1
expect "1.1.0"
expect "1.0.1" "$FIX_REV"
expect_notes "### New features

- Add --json to list (#4)

### Fixes

- Reconnect after sleep (#3)
- Parse profiles once"

# '!': major, listed only under breaking changes.
commit "refactor(config)!: drop the old profile format (#5)"
expect "2.0.0"
expect_notes "### Breaking changes

- Drop the old profile format (#5)

### New features

- Add --json to list (#4)

### Fixes

- Reconnect after sleep (#3)
- Parse profiles once"
git tag v2.0.0

# --ignore-tag TAG with REV = TAG: the version and notes of the release TAG (update-notes.sh).
expect "" v2.0.0
rm -f "$REPO/.git/ignored.md"
got="$("$SCRIPT" --ignore-tag v2.0.0 --notes "$REPO/.git/ignored.md" v2.0.0 2>/dev/null)" || got="exit $?"
if [[ "$got" == "2.0.0" && "$(cat "$REPO/.git/ignored.md" 2>/dev/null)" == "### Breaking changes

- Drop the old profile format (#5)

### New features

- Add --json to list (#4)

### Fixes

- Reconnect after sleep (#3)
- Parse profiles once" ]]; then
    echo "ok: --ignore-tag v2.0.0 gives the release v2.0.0"
else
    fail "--ignore-tag v2.0.0 v2.0.0 gave '$got'"
fi

# A BREAKING CHANGE: footer: major, whatever the type.
commit "chore: rename the settings keys" "Longer explanation.

BREAKING CHANGE: settings from 2.x are not read."
expect "3.0.0"
git tag v3.0.0

# Merge commits are skipped (their subject does not count), the merged commits do.
git switch -q -c side
commit "fix: handle an empty profile list (#7)"
git switch -q main
commit "docs: typo"
git merge -q --no-ff -m "feat!: not counted, this is a merge" side
expect "3.0.1"
expect_notes "### Fixes

- Handle an empty profile list (#7)"

# The highest tag by version is the last release, not the newest one.
git tag v0.9.0
expect "3.0.1"
git tag v3.0.1

# The scope linux (Linux work, no release yet) changes nothing, breaking or not.
commit "feat(linux): add the daemon (#8)"
commit "fix(linux): read the routes from netlink"
commit "perf(linux): start the daemon by socket activation"
commit "fix(linux)!: move the daemon socket (#9)"
commit "refactor(linux): split the daemon" "BREAKING CHANGE: the old socket path is gone."
expect ""
if [[ -z "$("$SCRIPT" --notes "$REPO/.git/linux.md" 2>/dev/null)" && ! -e "$REPO/.git/linux.md" ]]; then
    echo "ok: no notes file for linux commits only"
else
    fail "a notes file was written for linux commits only"
fi

# Mixed with other commits: only those bump the version and are in the notes.
commit "fix(cli): exit with 3 for a missing profile (#10)"
expect "3.0.2"
commit "feat(linux): add the polkit action"
commit "feat: show how long the session has run (#11)"
expect "3.1.0"
expect_notes "### New features

- Show how long the session has run (#11)

### Fixes

- Exit with 3 for a missing profile (#10)"

# Release-As in the message of the merge commit being released (the release pull request dev -> main).
# The last release is v3.0.1; the commits since give 3.1.0 (a feat and a fix).
git switch -q -c dev
commit "fix: keep the window size (#12)"
git switch -q main
NOTES_31="### New features

- Show how long the session has run (#11)

### Fixes

- Exit with 3 for a missing profile (#10)
- Keep the window size (#12)"

# release_merge [PARAGRAPH...]: merges dev into main as a release pull request is merged, the message
# made of "chore: merge dev into main (#13)" and the paragraphs; undo_merge takes the merge back.
release_merge() {
    local args=(-m "chore: merge dev into main (#13)") paragraph
    for paragraph in "$@"; do args+=(-m "$paragraph"); done
    tick
    git merge -q --no-ff "${args[@]}" dev
}
undo_merge() { git reset -q --hard HEAD^; }

# expect_refused NAME [ARG...]: next-version.sh --notes FILE ARG... fails, prints no version, writes no
# notes and names the problem with Release-As on stderr.
expect_refused() {
    local name="$1" file="$REPO/.git/refused.md" err="$REPO/.git/refused.txt" got status=0
    shift
    rm -f "$file"
    got="$("$SCRIPT" --notes "$file" "$@" 2>"$err")" || status=$?
    if ((status == 0)); then
        fail "$name: accepted, printed '$got'"
    elif [[ -n "$got" || -e "$file" ]]; then
        fail "$name: printed '$got' or wrote notes although it failed"
    elif ! grep -q '^error: .*Release-As' "$err"; then
        fail "$name: no error about Release-As (stderr: $(cat "$err"))"
    else
        echo "ok: refused: $name"
    fi
}

# Without the line, nothing changes.
release_merge "Releases 3.1.0."
expect "3.1.0"
expect_notes "$NOTES_31"
undo_merge

# Lower than the computed version (a feat released as a patch): that version, and the same notes,
# the feat under New features.
release_merge "Releases 3.0.2." "Release-As: 3.0.2"
expect "3.0.2"
expect_notes "$NOTES_31"
undo_merge

# Equal to and higher than the computed version.
release_merge "Release-As: 3.1.0"
expect "3.1.0"
undo_merge
release_merge "Releases 4.0.0." "Release-As: 4.0.0"
expect "4.0.0"
undo_merge

# The key in any case, spaces around the colon and the value, the same version twice.
release_merge "Release-as : 3.0.2 " "RELEASE-AS:3.0.2"
expect "3.0.2"
undo_merge

# Not a Release-As line: in the middle of a line, or after other text.
release_merge "Not yet: Release-As: 3.0.2" "- Release-As: 3.0.2"
expect "3.1.0"
undo_merge

# Wrong values, versions not higher than v3.0.1, two different versions.
for value in "v3.0.2" "3.0" "3.0.2-rc.1" "03.0.2" "3.0.2.1" "three" "" "3.0.1" "2.9.9" "3.0.0"; do
    release_merge "Release-As: $value"
    expect_refused "Release-As: '$value'"
    undo_merge
done
release_merge "Release-As: 3.0.2" "Release-As: 3.0.3"
expect_refused "two different Release-As lines"
undo_merge

# expect_warning: next-version.sh warns about a Release-As line that does not count.
expect_warning() {
    local err
    err="$("$SCRIPT" "$@" 2>&1 >/dev/null)" || { fail "next-version.sh $* exited non-zero"; return; }
    if grep -q '^warning: commit .*Release-As' <<<"$err"; then
        echo "ok: warning for a Release-As line that does not count"
    else
        fail "no warning for a Release-As line that does not count"
    fi
}

# Only the merge commit being released counts, not a squash commit on dev (a pull request description
# that became its body): ignored, with a warning, at the merge and at dev itself.
git switch -q dev
commit "fix: keep the window position (#14)" "Release-As: 9.0.0"
git switch -q main
release_merge
expect "3.1.0"
expect_warning
undo_merge
expect "3.1.0" dev
expect_warning dev
git switch -q dev
git reset -q --hard HEAD^
commit "fix: keep the window position (#14)"
git switch -q main
NOTES_31="$NOTES_31
- Keep the window position (#14)"

# A release merge whose release never happened (no tag) does not carry its Release-As over: the next
# release merge gives the computed version (with a warning) unless it has a line of its own.
release_merge "Release-As: 3.0.2"
git switch -q dev
commit "docs: note the window position (#15)"
git switch -q main
release_merge "Releases 3.1.0."
expect "3.1.0"
expect_warning
expect_notes "$NOTES_31"
undo_merge
release_merge "Release-As: 3.0.3"
expect "3.0.3"
expect_notes "$NOTES_31"

# The release 3.0.3 is made: the tag on the merge commit.
git tag v3.0.3
expect "" v3.0.3
# The workflow's re-run (the tag on HEAD is deleted locally and the version computed again).
git tag -d v3.0.3 >/dev/null
expect "3.0.3"
git tag v3.0.3
# update-notes.sh: --ignore-tag v3.0.3 v3.0.3 gives the release v3.0.3 with its notes.
rm -f "$REPO/.git/ignored.md"
got="$("$SCRIPT" --ignore-tag v3.0.3 --notes "$REPO/.git/ignored.md" v3.0.3 2>/dev/null)" || got="exit $?"
if [[ "$got" == "3.0.3" && "$(cat "$REPO/.git/ignored.md" 2>/dev/null)" == "$NOTES_31" ]]; then
    echo "ok: --ignore-tag v3.0.3 gives the overridden release v3.0.3"
else
    fail "--ignore-tag v3.0.3 v3.0.3 gave '$got'"
fi

# After that release, the next one is computed from v3.0.3 again.
git switch -q dev
commit "fix: keep the zoom level (#16)"
git switch -q main
release_merge "Releases 3.0.4."
expect "3.0.4"
expect_notes "### Fixes

- Keep the zoom level (#16)"
undo_merge

# A Release-As with nothing that counts for a release (docs, chore) releases nothing: an error.
git switch -q dev
git reset -q --hard HEAD^
commit "docs: explain the window (#17)"
git switch -q main
release_merge "Release-As: 3.0.4"
expect_refused "Release-As without a commit that counts"
undo_merge
release_merge
expect ""

# Options.
for arg in --bogus no-such-rev --notes --ignore-tag; do
    if "$SCRIPT" "$arg" >/dev/null 2>&1; then
        fail "next-version.sh $arg was accepted"
    else
        echo "ok: next-version.sh $arg refused"
    fi
done

((FAILED == 0)) || { echo "next-version.sh self-test failed" >&2; exit 1; }
echo "next-version.sh self-test passed"
