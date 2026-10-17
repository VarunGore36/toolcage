#!/bin/bash
set -e
echo "== toolcage doctor v0 =="
uname -r
echo "--- /dev/kvm ---"
ls -l /dev/kvm || echo "MISSING: Tier2 needs /dev/kvm"
echo "--- cgroup v2 ---"
[ -f /sys/fs/cgroup/cgroup.controllers ] && cat /sys/fs/cgroup/cgroup.controllers || echo "MISSING cgroup2"
echo "--- landlock ABI ---"
python3 -c "print('check via landlock_create_ruleset(LANDLOCK_CREATE_RULESET_VERSION) — see kernel docs')"
echo "--- tools ---"
which firecracker runsc cargo rustc || true
echo "--- runsc version ---"
runsc --version 2>/dev/null || echo "runsc not available (Tier1 needs runsc)"
