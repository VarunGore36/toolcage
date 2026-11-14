# Backend Tests PR

This PR adds comprehensive tests for all three backend tiers: backend-ns (Tier 0), backend-fc (Tier 2 Firecracker), and backend-gv (Tier 1 gVisor).

## Changes
- backend-ns: cgroup mount/write/write_max tests, seccomp syscall denial tests, exec path tests (exit code, output cap, stderr capture)
- backend-fc: CID allocation tests, vsock UDS path tests, snapshot hash verification, tier2 caps test
- backend-gv: runsc arg structure tests, tier_caps test, tier parsing tests
- backend: tier parsing tests, SessionSpec tests, TierCaps tests
