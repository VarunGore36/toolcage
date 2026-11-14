# Cgroup Enforcement PR

This PR adds cgroup mount, write, and write_max helper functions to the Tier 0 backend-ns crate, wires CPU/memory/pids limits into the exec path, adds cgroup2 unified hierarchy support, and includes comprehensive cgroup isolation tests.

## Changes
- Added cgroup_mount, cgroup_write, cgroup_write_max helper functions
- Wired cpu.max, memory.max, pids.max limits into exec path
- Added memory.oom.group cgroup setting for whole-cgroup OOM kill
- Added cgroup directory cleanup on session destroy
- Added cgroup2 unified hierarchy support
- Added CPU quota (cfs_quota_us) enforcement for hard CPU throttling
- Added memory swap limit enforcement for cgroup v1/v2
- Added 7 cgroup isolation tests
