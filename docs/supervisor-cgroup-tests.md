# Supervisor Cgroup Tests PR

This PR adds comprehensive cgroup isolation tests to the supervisor test suite, covering directory creation, CPU/memory/pids limits, OOM group, cleanup, and audit trail verification.

## Changes
- Added cgroup_dir_created_for_session test
- Added cpu_limit_applied_in_cgroup test
- Added memory_limit_applied_in_cgroup test
- Added process_added_to_cgroup test
- Added cgroup_cleanup_after_session test
- Added cgroup_cleanup_on_destroy test
- Added oom_group_applied_in_cgroup test
- Added audit trail intent and outcome verification
- Added denied exec audit test
