#!/bin/bash
# Self-test of scripts/update-notes.sh: builds a throwaway git repository in a temporary directory
# (empty commits only, no signing, no remote) and checks the update notes it writes for a release.
# Runs in CI (ci.yml, "Release scripts") and locally:
#
#   scripts/test-update-notes.sh
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/update-notes.sh"
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

# commit SUBJECT
commit() { git commit -q --allow-empty -m "$1"; }

NOTES="$REPO/.git/notes.md"
ERR="$REPO/.git/stderr.txt"

# expect NAME WANT_STDOUT WANT_WARNING ARG...: update-notes.sh ARG... exits 0 and prints WANT_STDOUT;
# its stderr has a warning containing WANT_WARNING (empty: no warning at all).
expect() {
    local name="$1" want="$2" warning="$3" got
    shift 3
    got="$("$SCRIPT" "$@" 2>"$ERR")" || { fail "$name: exited non-zero: $(cat "$ERR")"; return; }
    if [[ "$got" != "$want" ]]; then
        fail "$name: output differs:"$'\n'"--- expected"$'\n'"$want"$'\n'"--- got"$'\n'"$got"
    elif [[ -z "$warning" ]] && grep -q '^warning:' "$ERR"; then
        fail "$name: unexpected warning: $(cat "$ERR")"
    elif [[ -n "$warning" ]] && ! grep '^warning:' "$ERR" | grep -qF -- "$warning"; then
        fail "$name: no warning about '$warning' (stderr: $(cat "$ERR"))"
    else
        echo "ok: $name"
    fi
}

# v1.0.0 comes from history before Conventional Commits: no notes can be worked out for it.
commit "Initial import"
git tag v1.0.0
commit "feat: add profiles (#1)"
commit "docs: explain profiles"
git tag v1.1.0
commit "fix: reconnect after sleep (#2)"
git tag v1.1.1
commit "feat: add the CLI (#3)"
git tag v1.2.0-rc.1
commit "fix: handle an empty profile list (#4)"

printf '%s\n' "### New features" "" "- Add the CLI (#3)" "" "### Fixes" "" "- Handle an empty profile list (#4)" > "$NOTES"
CURRENT="$(cat "$NOTES")"
V111="## 1.1.1

### Fixes

- Reconnect after sleep (#2)"
V110="## 1.1.0

### New features

- Add profiles (#1)"

# Newest first, the pre-release left out, and the list stops at v1.0.0, which has no notes.
expect "earlier releases, newest first" "## 1.2.0

$CURRENT

$V111

$V110" "v1.0.0" 1.2.0 "$NOTES"

# At most --earlier N of them.
expect "--earlier 1" "## 1.2.0

$CURRENT

$V111" "" --earlier 1 1.2.0 "$NOTES"

# --earlier 0: the notes unchanged, without a heading.
expect "--earlier 0" "$CURRENT" "" --earlier 0 1.2.0 "$NOTES"

# A pre-release: earlier stable releases only, not the earlier release candidate.
expect "pre-release" "## 1.2.0-rc.2

$CURRENT

$V111" "" --earlier 1 1.2.0-rc.2 "$NOTES"

# Only releases lower than VERSION count.
expect "lower versions only" "## 1.1.5

$CURRENT

$V111" "" --earlier 1 1.1.5 "$NOTES"

# --rev: the history of another commit (only v1.1.0 and v1.0.0 are in it).
expect "--rev" "## 1.1.1

$CURRENT

$V110" "v1.0.0" --rev v1.1.0 1.1.1 "$NOTES"

# A re-run of a release whose tag is already at HEAD: its own tag is not an earlier release.
git tag v1.2.0
expect "own tag at HEAD" "## 1.2.0

$CURRENT

$V111

$V110" "v1.0.0" 1.2.0 "$NOTES"

# Versions compare by number: 1.2.0 is lower than 1.10.0 (as text it would not be). Its notes are
# those of this release's commits, the same as NOTES here.
expect "numeric order" "## 1.10.0

$CURRENT

## 1.2.0

$CURRENT" "" --earlier 1 1.10.0 "$NOTES"

# A release made by hand whose commits do not give its version: no notes for it, so none at all
# here (it is the newest earlier release), with a warning.
commit "chore: tidy up"
git tag v1.2.1
commit "fix: keep the window size (#5)"
expect "release without matching commits" "$CURRENT" "v1.2.1" 1.2.2 "$NOTES"

# No earlier release (the first one, or a clone without tags), and an unknown revision.
expect "no earlier release" "$CURRENT" "no release tag before 0.9.0" 0.9.0 "$NOTES"
expect "unknown revision" "$CURRENT" "no-such-rev" --rev no-such-rev 1.2.2 "$NOTES"

# Newest first by version, not by text: 1.10.0 before 1.9.0 (a text sort would put 1.9.0 first and
# then reach 1.8.0, whose commits do not give its version).
commit "feat: add profile groups (#6)"
git tag v1.8.0
commit "feat: sort profile groups (#7)"
git tag v1.9.0
commit "feat: rename profile groups (#8)"
git tag v1.10.0
commit "fix: keep the group order (#9)"
expect "version order" "## 1.10.1

$CURRENT

## 1.10.0

### New features

- Rename profile groups (#8)

## 1.9.0

### New features

- Sort profile groups (#7)" "" --earlier 2 1.10.1 "$NOTES"

# Wrong arguments fail.
: > "$REPO/.git/empty.md"
for args in "1.2.0" "1.2.0 $REPO/.git/missing.md" "1.2.0 $REPO/.git/empty.md" "v1.2.0 $NOTES" \
            "1.2 $NOTES" "--earlier x 1.2.0 $NOTES" "--earlier 100 1.2.0 $NOTES" "--bogus 1.2.0 $NOTES" \
            "1.2.0 $NOTES extra"; do
    # shellcheck disable=SC2086 # split on purpose: the arguments of one case
    if "$SCRIPT" $args >/dev/null 2>&1; then
        fail "update-notes.sh $args was accepted"
    else
        echo "ok: update-notes.sh $args refused"
    fi
done

((FAILED == 0)) || { echo "update-notes.sh self-test failed" >&2; exit 1; }
echo "update-notes.sh self-test passed"
