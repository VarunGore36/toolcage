#!/usr/bin/env bash
# Regenerate the test-count line of docs/TEST_RESULTS.md from the actual run.
# CI (test-results job) runs this then `git diff --exit-code` — a stale doc
# fails the build instead of drifting silently (TDC-2).
set -euo pipefail
cd "$(dirname "$0")/.."

total=$(cargo test --workspace 2>&1 | grep -E "^test result" | awk '{p+=$4} END {print p+0}')
fail=$(cargo test --workspace 2>&1 | grep -E "^test result" | awk '{f+=$6} END {print f+0}')
today=$(date +%F)

f=docs/TEST_RESULTS.md
sed -i -E "s|^[0-9]+ tests, [0-9]+ failures \(cargo test --workspace\)|${total} tests, ${fail} failures (cargo test --workspace)|" "$f"
sed -i -E "s|\(Generated from the workspace run \([0-9-]+\)\; re-run|(Generated from the workspace run (${today}); re-run|" "$f"
echo "TEST_RESULTS.md: ${total} tests, ${fail} failures (${today})"
