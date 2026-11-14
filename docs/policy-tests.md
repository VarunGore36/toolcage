# Policy Tests PR

This PR adds comprehensive policy enforcement tests covering exec allowlist denylist bypass fixes, egress limit validation, and path traversal protection.

## Changes
- Added exec allowlist enforcement tests (denylist bypass, version tolerance, untrusted path rejection)
- Added egress limit validation tests (excessive bytes/requests denied, zero means unlimited)
- Added FS path traversal denial tests (null byte, double dotdot, symlink escape, encoded slash)
- Added policy path canonicalization tests (double slash, dot component, trailing slash)
- Added net policy deny tests (unknown host denial, case-insensitive host match, method denial)
