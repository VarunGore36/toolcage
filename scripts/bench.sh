#!/bin/bash
# bench v0: policy p99 + audit eps. Run from workbase/.
set -e
echo "== policy decision latency =="
cargo test -p toolcage-policy --release -q 2>&1 | tail -2
python3 - <<'PY'
import time, subprocess, json
# audit append eps via release binary path test
PY
echo "== audit append eps =="
cargo build -p toolcage-cli --release -q
LOG=/tmp/opencode/tc-bench.jsonl
rm -f $LOG
time for i in $(seq 1 500); do ./target/release/toolcage-cli run --policy schemas/policy-v0.yaml --audit $LOG -- /bin/true >/dev/null; done
wc -l $LOG
./target/release/toolcage-cli audit verify --log $LOG
