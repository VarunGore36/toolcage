#!/bin/bash
# bench v0: policy p99 + audit append eps + CLI run baseline.
# Runs from workbase/. Per plan §11: benchmark harness runs on every merge.
set -euo pipefail

echo "== toolcage bench v0 =="
date -u

echo "== policy decision p99 (target < 5 ms in-process) =="
cargo test -p toolcage-policy --test timing --release -- --nocapture 2>&1 | grep -E "p50|p99|max|test result"

echo "== audit append eps (target >= 10,000/s) =="
cargo test -p toolcage-audit --test throughput --release -- --nocapture 2>&1 | grep -E "audit append|test result"

echo "== CLI run baseline (end-to-end Tier0 exec) =="
cargo build -p toolcage-cli --release -q 2>&1 | tail -1
LOG=/tmp/opencode/tc-bench.jsonl
rm -f "$LOG"
N=200
start=$(date +%s.%N)
for i in $(seq 1 "$N"); do
  ./target/release/toolcage-cli run --policy schemas/policy-v0.yaml --audit "$LOG" -- /bin/true >/dev/null
done
end=$(date +%s.%N)
python3 - "$start" "$end" "$N" "$LOG" <<'PY'
import sys, subprocess
start, end, n, log = float(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
avg_ms = (end - start) * 1000 / n
print(f"cli run: n={n} avg={avg_ms:.1f} ms/call")
subprocess.run(["./target/release/toolcage-cli", "audit", "verify", "--log", log], check=True)
PY
