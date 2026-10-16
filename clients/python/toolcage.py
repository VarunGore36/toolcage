"""toolcage Python client: stdio MCP + CLI wrapper (no secrets cross)."""
import json, subprocess

TOOLS = ["run_command", "read_file", "write_file", "http_fetch"]

class Toolcage:
    def __init__(self, policy, audit, bin="./target/debug/toolcage-cli"):
        self.policy, self.audit, self.bin = policy, audit, bin

    def call(self, name, args):
        assert name in TOOLS, f"unknown tool {name}"
        r = subprocess.run(
            [self.bin, "mcp", "call", "--policy", self.policy,
             "--audit", self.audit, "--name", name,
             "--args-json", json.dumps(args)],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise PermissionError(r.stderr.strip() or "denied")
        return json.loads(r.stdout)

    def run(self, argv):
        return self.call("run_command", {"argv": argv})

    def fetch(self, host, method="GET", path="/"):
        return self.call("http_fetch", {"host": host, "method": method, "path": path})
