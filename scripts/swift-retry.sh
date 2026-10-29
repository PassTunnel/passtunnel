#!/bin/bash
# Runs a command (a `swift build` or `swift test`) and, if the Swift build system itself crashed, once more.
#
#   scripts/swift-retry.sh swift build -c release --product passtunnel
#
# The toolchain's build system (swift-build, run inside swift-package) sometimes segfaults on the Linux
# runners while it plans a build, before any of our code compiles: exit 139 and a crash report whose
# frames name swift-build / SWBCore (https://github.com/PassTunnel/passtunnel/issues/202). A second run
# passes. The command is run again exactly once, and only when both hold:
#
#   - it exited with a signal-like status (128 or more), and
#   - its output has "Program crashed" and a frame of the build system: swift-build, swift-package or
#     an SWB* module (SWBCore, SWBTaskConstruction, ...).
#
# Every other result is returned as it is, so a compile error, a failing test, a crash of a test or of
# our own code (no build-system frame) and a second crash of the build system all fail the step. The
# output (standard error included, merged into standard output) streams to the log as it comes and is
# kept in a temporary file only for the check.
set -uo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: swift-retry.sh command [argument...]" >&2
    exit 2
fi

LOG="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/swift-retry.XXXXXX")"
trap 'rm -f "$LOG"' EXIT

run() {
    local status=0
    "$@" 2>&1 | tee "$LOG" || status=$?
    return "$status"
}

status=0
run "$@" || status=$?

if [[ $status -ge 128 ]] \
    && grep -q 'Program crashed' "$LOG" \
    && grep -Eq 'swift-build|swift-package|SWB[A-Za-z]+' "$LOG"; then
    echo "::warning title=Swift build system crashed::'$1 ${2:-}' exited with $status in the build system; running it once more (issue 202)"
    status=0
    run "$@" || status=$?
fi

exit "$status"
