# CLI Tests PR

This PR adds comprehensive CLI integration tests covering egress limits, approval pauses, exit codes, token mint/attenuate, image sign, and client smoke tests.

## Changes
- Added CLI egress limit rejection test
- Added CLI approval pause unknown host denial test
- Added CLI exit code tests (successful run, timeout kill, denied shell, allowed echo)
- Added CLI token mint and attenuate test
- Added CLI image sign test
- Added CLI client smoke tests (Python and TypeScript clients)
