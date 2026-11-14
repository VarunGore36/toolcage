# Capability & Session Spec PR

This project adds the cpu_millis field to SessionSpec in the backend crate, wired from policy limits.cpu_seconds converted to millis. Includes SessionSpec field tests and SessionSpec default/equality tests.

## Changes
- Added cpu_millis field to SessionSpec for cgroup CPU limits
- Wired cpu_millis from policy limits into session spec
- Added tier parsing tests (aliases, case-insensitive, rejects unknown)
- Added TierCaps default/all-true tests
- Added SessionSpec defaults/equality tests
