#!/usr/bin/env bash
# Regenerate the test-count line of docs/TEST_RESULTS.md from the actual run.
# CI (test-results job) runs this then `git diff --exit-code` — a stale doc
# fails the build instead of drifting silently (TDC-2).
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(cargo test --workspace 2>&1)
total=$(echo "$out" | grep -E "^test result" | awk '{p+=$4} END {print p+0}')
fail=$(echo "$out" | grep -E "^test result" | awk '{f+=$6} END {print f+0}')
today=$(date +%F)

f=docs/TEST_RESULTS.md
# Line 3: "N tests, M failures (`cargo test --workspace`). Clippy clean"
sed -i -E "3s|^[0-9]+ tests, [0-9]+ failures|${total} tests, ${fail} failures|" "$f"
# Line 6: "Generated from the workspace run (DATE); re-run"
sed -i -E "6s|\(20[0-9]{2}-[0-9]{2}-[0-9]{2}\)|(${today})|" "$f"
echo "TEST_RESULTS.md: ${total} tests, ${fail} failures (${today})"
