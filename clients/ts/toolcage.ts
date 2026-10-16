// toolcage TypeScript client: stdio MCP + CLI wrapper.
import { execFileSync } from "child_process";

export const TOOLS = ["run_command", "read_file", "write_file", "http_fetch"] as const;
export type Tool = typeof TOOLS[number];

export class Toolcage {
  constructor(private policy: string, private audit: string, private bin = "./target/debug/toolcage-cli") {}
  call(name: Tool, args: unknown): unknown {
    try {
      const out = execFileSync(this.bin,
        ["mcp", "call", "--policy", this.policy, "--audit", this.audit,
         "--name", name, "--args-json", JSON.stringify(args)], { encoding: "utf8" });
      return JSON.parse(out);
    } catch (e: any) {
      throw new Error(`denied: ${e.stderr ?? e.message}`);
    }
  }
  run(argv: string[]) { return this.call("run_command", { argv }); }
  fetch(host: string, method = "GET", path = "/") { return this.call("http_fetch", { host, method, path }); }
}
