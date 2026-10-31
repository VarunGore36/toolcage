#!/bin/bash
# doctor.sh — the shell-level half of `toolcage doctor`.
#
# The live syscall probes (namespace stack, Landlock ABI, seccomp) are done by
# `toolcage-cli doctor` via NsBackend::probe(), which exercises the real
# clone/landlock_create_ruleset/PR_SET_SECCOMP paths. This script covers what
# a shell can see honestly; it must not pretend to probe a syscall.
set -e
echo "== toolcage doctor (shell half) =="
uname -r
echo "--- /dev/kvm (Tier 2) ---"
if [ -e /dev/kvm ]; then ls -l /dev/kvm; else echo "MISSING: Tier2 needs /dev/kvm"; fi
echo "--- cgroup v2 ---"
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  cat /sys/fs/cgroup/cgroup.controllers
else
  echo "MISSING cgroup2 (Tier 0 wants it; firecracker warns of high restore latency on v1)"
fi
echo "--- tools ---"
which firecracker runsc cargo rustc 2>/dev/null || true
echo "--- runsc version (Tier 1) ---"
runsc --version 2>/dev/null || echo "runsc not available (Tier1 needs runsc)"
echo "--- firecracker version (Tier 2) ---"
firecracker --version 2>/dev/null || echo "firecracker not available (Tier2 needs firecracker + jailer)"
echo "--- live syscall probes ---"
echo "namespace stack / Landlock ABI / seccomp are probed by \`toolcage-cli doctor\`"
echo "(this script cannot call it: that command runs this script)."
