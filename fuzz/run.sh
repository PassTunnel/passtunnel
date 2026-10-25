#!/usr/bin/env bash
# Build the libFuzzer harnesses and run each one for a while. Used by CI and for local runs.
#
#   ./run.sh [seconds] [target]
#
#   seconds   time budget per fuzzer (default 60)
#   target    run only this harness (e.g. FuzzOVPNSanitizer); default: all
#
# Needs the open-source Swift toolchain on PATH (the Xcode toolchain has no libFuzzer runtime on
# macOS). See ../CONTRIBUTING.md, "Fuzzing". Exits non-zero if any harness reports a failure;
# the reproducing input is copied into fuzz/findings/.
set -euo pipefail
cd "$(dirname "$0")"

duration="${1:-60}"
only="${2:-}"

# target : seed-corpus directory
fuzzers=(
    "FuzzOVPNSanitizer:ovpn-sanitizer"
    "FuzzOVPNImport:ovpn-import"
    "FuzzFortiConfig:forti-config"
    "FuzzManagementParser:management-parser"
    "FuzzOTPAuthURI:otpauth-uri"
    "FuzzMCPDecode:mcp-decode"
)

echo "==> swift build (-sanitize=fuzzer,address)"
swift build -c debug -Xswiftc -sanitize=fuzzer,address
bin="$(swift build -c debug --show-bin-path)"

status=0
for pair in "${fuzzers[@]}"; do
    target="${pair%%:*}"
    corpus="${pair##*:}"
    if [[ -n "$only" && "$only" != "$target" ]]; then
        continue
    fi
    echo "::group::$target (${duration}s)"
    # Run against a scratch copy so libFuzzer never writes new units into the tracked seeds.
    work="$(mktemp -d)"
    cp "corpus/$corpus/"* "$work/" 2>/dev/null || true
    if ! "$bin/$target" -max_total_time="$duration" -timeout=25 -rss_limit_mb=2048 \
            -print_final_stats=1 "$work" "corpus/$corpus"; then
        echo "A fuzzer reported a failure in $target"
        mkdir -p findings
        cp crash-* oom-* leak-* timeout-* slow-unit-* findings/ 2>/dev/null || true
        status=1
    fi
    rm -rf "$work"
    echo "::endgroup::"
done
exit "$status"
