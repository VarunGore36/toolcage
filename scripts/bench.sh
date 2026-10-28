#!/bin/bash
# bench v0: policy p99 + audit append eps + CLI run baseline.
# Runs from workbase/. Per plan §11: benchmark harness runs on every merge.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== toolcage bench v0 =="
date -u

echo "== policy decision p99 (target < 5 ms in-process) =="
cargo test -p toolcage-policy --test timing --release -- --nocapture 2>&1 | grep -E "p50|p99|max|test result"

echo "== audit append eps (target >= 10,000/s) =="
cargo test -p toolcage-audit --test throughput --release -- --nocapture 2>&1 | grep -E "audit append|test result"

echo "== CLI run baseline (end-to-end Tier0 exec) =="
cargo build -p toolcage-cli --release -q 2>&1 | tail -1
LOG=${TMPDIR:-/tmp}/tc-bench.jsonl
mkdir -p "$(dirname "$LOG")"
rm -f "$LOG"
# Probe run: Tier0 needs unprivileged userns + Landlock (e.g. GitHub's Ubuntu
# 24.04 runners block userns via AppArmor). Skip the baseline there instead of
# failing the job — policy and audit numbers above still measure. Any other
# failure (real CLI regression, broken policy) is reported loud, not silently
# disguised as "Tier0 unavailable".
PROBE_OUT=$(./target/release/toolcage-cli run --policy schemas/policy-v0.yaml --audit "$LOG" -- /bin/true 2>&1) || PROBE_RC=$?
if [ "${PROBE_RC:-0}" -ne 0 ]; then
  if echo "$PROBE_OUT" | grep -qiE "unprivileged|userns|landlock|seccomp|namespace|isolation|AppArmor"; then
    echo "skip: Tier0 exec unavailable on this host (needs unprivileged userns + Landlock) — no run baseline"
    exit 0
  fi
  echo "ERROR: CLI run probe failed (not a Tier0 availability issue):"
  echo "$PROBE_OUT"
  exit 1
fi
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

echo "== Tier 2 warm-claim start latency (target: track p50/p99 by tier) =="
# The claim path (pool pop, workspace attach, VM resume) is measured against a
# mock firecracker API so the number tracks the software's own orchestration on
# every merge. The VM boot/resume itself is firecracker's and is measured live
# on KVM hardware by the same test where the runtime is present (plan §11:
# "treat your own measurements as the only numbers that count").
cargo test -p toolcage-backend-fc --lib bench_tests --release -- --nocapture 2>&1 \
  | grep -E "warm-claim latency|test result"
