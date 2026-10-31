// toolcage TypeScript client: stdio MCP + CLI wrapper.
//
// Erasable-only syntax on purpose: it runs under Node's native .ts type
// stripping and Deno as well as a full tsc build (constructor parameter
// properties would need a transform and break the first two).
import { execFileSync } from "child_process";

export const TOOLS = ["run_command", "read_file", "write_file", "http_fetch"] as const;
export type Tool = typeof TOOLS[number];

export class Toolcage {
  private policy: string;
  private audit: string;
  private bin: string;
  constructor(policy: string, audit: string, bin = "./target/debug/toolcage-cli") {
    this.policy = policy;
    this.audit = audit;
    this.bin = bin;
  }
  call(name: Tool, args: unknown): unknown {
    if (!TOOLS.includes(name)) {
      throw new Error(`unknown tool ${name}`);
    }
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
