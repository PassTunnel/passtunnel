#!/usr/bin/env bash
# Prints the statement (line) coverage of our own sources, from the profile `swift test
# --enable-code-coverage` wrote: a Markdown table per target and the TOTAL line. Tests/, .build/ and the
# dependencies are left out. With GITHUB_STEP_SUMMARY set the report is appended to the job summary as
# well. It reports and never fails on the number (see CONTRIBUTING.md, "Tests").
#
#   swift test --enable-code-coverage && scripts/coverage-report.sh
# Extra arguments (such as --build-path) go to the swift commands that locate the profile.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$PWD"

llvm_cov() {
    if [ "$(uname -s)" = Darwin ]; then xcrun llvm-cov "$@"; else llvm-cov "$@"; fi
}

codecov="$(swift test --show-codecov-path "$@")"
profdata="$(dirname "$codecov")/default.profdata"
bin_path="$(swift build --show-bin-path "$@")"
if [ "$(uname -s)" = Darwin ]; then
    binary="$bin_path/PassTunnelPackageTests.xctest/Contents/MacOS/PassTunnelPackageTests"
else
    binary="$bin_path/PassTunnelPackageTests.xctest"
fi
[ -f "$profdata" ] || { echo "no profile at $profdata: run swift test --enable-code-coverage first" >&2; exit 1; }
[ -f "$binary" ] || { echo "no test binary at $binary" >&2; exit 1; }

report="$(
    llvm_cov export -summary-only -instr-profile="$profdata" \
        -ignore-filename-regex='(/Tests/|/\.build/|/checkouts/|/\.swiftpm/)' "$binary" \
        | jq -r --arg root "$root/Sources/" '
            [.data[0].files[]
              | select(.filename | startswith($root))
              | {target: (.filename | ltrimstr($root) | split("/")[0]), lines: .summary.lines}]
            | group_by(.target)
            | map({target: .[0].target, count: (map(.lines.count) | add), covered: (map(.lines.covered) | add)}) as $rows
            | ($rows | map(.count) | add) as $count
            | ($rows | map(.covered) | add) as $covered
            | def pct(c; n): if n == 0 then "n/a" else "\(((c * 10000 / n) | round) / 100)%" end;
              "### Statement coverage\n",
              "| Target | Lines | Covered | Coverage |",
              "|---|---:|---:|---:|",
              ($rows[] | "| \(.target) | \(.count) | \(.covered) | \(pct(.covered; .count)) |"),
              "| **TOTAL** | **\($count)** | **\($covered)** | **\(pct($covered; $count))** |"'
)"

echo "$report"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$report" >>"$GITHUB_STEP_SUMMARY"
fi
