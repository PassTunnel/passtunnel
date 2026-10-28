#!/bin/bash
# Self-test of swift-retry.sh with fake commands (no Swift needed): a crash of the build system (exit 139,
# "Program crashed" and a swift-build frame) is run once more, and passes or fails with the second run;
# a compile error, a crash without a build-system frame, "Program crashed" with an ordinary exit status
# and an exit of 139 without the report are not run again; the status of the command and its output are
# kept.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RETRY="$ROOT/scripts/swift-retry.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export RUNNER_TEMP="$WORK"

failures=0
pass() { echo "ok: $1"; }
failed() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# A fake command, fake.sh MODE...: it counts its runs in $WORK/count and, on run N, does what the Nth
# word of MODES says. crash: the report of the build system and exit 139; appcrash: a report of our own
# code and exit 139; bare139: exit 139 and no report; error: a compile error and exit 1; softcrash: the
# report but exit 1; ok: success.
cat > "$WORK/fake.sh" <<'FAKE'
#!/bin/bash
count=$(( $(cat "$WORK/count" 2>/dev/null || echo 0) + 1 ))
echo "$count" > "$WORK/count"
read -r -a modes <<< "$MODES"
mode="${modes[$((count - 1))]:-ok}"
case "$mode" in
    crash)
        echo "Compiling something"
        echo "*** Program crashed: Bad pointer dereference at 0xffff002cd756f6fb ***" >&2
        echo "Thread 2 \"DispatchWorker\" crashed:" >&2
        echo "0 discoveredClangToolInfo(...) in swift-package at swift-build/Sources/SWBCore/ToolInfo/ClangToolInfo.swift:132:21" >&2
        exit 139 ;;
    appcrash)
        echo "*** Program crashed: Bad pointer dereference at 0x0 ***" >&2
        echo "0 main in PassTunnelTests at Sources/PassTunnelCore/Thing.swift:10:5" >&2
        exit 139 ;;
    bare139) echo "Segmentation fault"; exit 139 ;;
    error) echo "Sources/X.swift:1:1: error: cannot find 'x' in scope" >&2; exit 1 ;;
    softcrash)
        echo "*** Program crashed: Bad pointer dereference ***" >&2
        echo "0 f in swift-build at swift-build/Sources/SWBCore/X.swift:1:1" >&2
        exit 1 ;;
    ok) echo "Build complete!"; exit 0 ;;
esac
FAKE
chmod +x "$WORK/fake.sh"
export WORK

# check NAME "MODES" EXPECTED_STATUS EXPECTED_RUNS EXPECT_WARNING(yes|no)
check() {
    local name="$1" status=0 runs warned=no
    export MODES="$2"
    rm -f "$WORK/count"
    "$RETRY" "$WORK/fake.sh" > "$WORK/out" 2>&1 || status=$?
    runs="$(cat "$WORK/count")"
    grep -q '^::warning' "$WORK/out" && warned=yes
    if [[ $status -eq $3 && $runs -eq $4 && $warned == "$5" ]]; then
        pass "$name"
    else
        failed "$name: status $status (want $3), runs $runs (want $4), warning $warned (want $5)"
    fi
}

check "a crash of the build system is run once more and passes" "crash ok" 0 2 yes
check "a second crash fails with 139, run no more than twice" "crash crash ok" 139 2 yes
check "a crash and then a compile error fails with 1" "crash error" 1 2 yes
check "success is run once" "ok" 0 1 no
check "a compile error is not run again" "error ok" 1 1 no
check "a crash of our own code is not run again" "appcrash ok" 139 1 no
check "exit 139 without the report is not run again" "bare139 ok" 139 1 no
check "the report with an ordinary exit status is not run again" "softcrash ok" 1 1 no

# The output streams to the caller, and the command's arguments arrive as they are.
export MODES="ok"
rm -f "$WORK/count"
if [[ "$("$RETRY" "$WORK/fake.sh" 2>/dev/null)" == "Build complete!" ]]; then
    pass "the output of the command is passed on"
else
    failed "the output of the command is not passed on"
fi
args="$("$RETRY" printf '%s|' 'a b' c)"
if [[ "$args" == "a b|c|" ]]; then pass "arguments are kept"; else failed "arguments are changed: $args"; fi

# No command is a usage error; no temporary file is left behind.
status=0
"$RETRY" >/dev/null 2>&1 || status=$?
if [[ $status -eq 2 ]]; then pass "no command is refused"; else failed "no command gives $status"; fi
leftover="$(find "$WORK" -name 'swift-retry.*' | wc -l | tr -d ' ')"
if [[ "$leftover" == 0 ]]; then pass "no log is left behind"; else failed "$leftover logs left behind"; fi

if [[ $failures -gt 0 ]]; then
    echo "$failures failed" >&2
    exit 1
fi
echo "all passed"
