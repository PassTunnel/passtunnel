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

# commit SUBJECT [BODY]
commit() { git commit -q --allow-empty -m "$1" ${2:+-m "$2"}; }

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

# Options.
for arg in --bogus no-such-rev --notes; do
    if "$SCRIPT" "$arg" >/dev/null 2>&1; then
        fail "next-version.sh $arg was accepted"
    else
        echo "ok: next-version.sh $arg refused"
    fi
done

((FAILED == 0)) || { echo "next-version.sh self-test failed" >&2; exit 1; }
echo "next-version.sh self-test passed"
