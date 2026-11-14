# Other Crate Tests PR

This PR adds tests for audit, broker, MCP, proxy, guest-agent, and verify crates, covering audit hash determinism, broker credential inject/scrub/rotate, MCP JSON-RPC error handling, proxy budget accumulation, guest-agent id validation, and verify hex parsing.

## Changes
- audit: hash determinism test
- broker: credential inject/scrub/rotate tests, cgroup write tests
- mcp: JSON-RPC error code and response tests
- proxy: budget accumulation test, DNS/metadata blocking tests
- guest-agent: id validation tests
- verify: hex parsing tests
