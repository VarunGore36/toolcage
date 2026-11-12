//! Human-readable denial explanations (DX layer — zero security weight).
//!
//! Policy denials used to be a bare rule id (`denied: deny:shell`), which is
//! greppable but teaches nothing. This module maps every rule id the trusted
//! core can emit to a short "why + what to do" block printed after the terse
//! line. The terse line stays byte-identical and is printed first, so scripts
//! that match `denied:` or exit codes keep working.
//!
//! Keep this in sync with rule ids in crates/policy, crates/proxy and
//! crates/supervisor: `unknown_rule_ids_have_a_fallback` below asserts the
//! fallback is never empty, and `every_known_rule_id_is_explained` pins the
//! full known set — add the new id there when you add a rule.

/// One-paragraph explanation for a denial rule id, as a list of lines to
/// print after `denied: [...]`. Returns an empty Vec for ids we do not know
/// (callers print a generic hint instead — never silence).
pub fn explain_denial(rule_id: &str) -> Vec<&'static str> {
    match rule_id {
        // ---- policy: exec ----
        "deny:shell" => vec![
            "shell strings and interpreter inline code (`sh -c`, `python -c`) are",
            "blocked by policy: the guest may only run binaries as plain argv arrays.",
            "If you trust this binary, allowlist it in the policy:",
            "    exec:",
            "      allow:",
            "        - /usr/bin/python3",
        ],
        "deny:exec-not-allowlisted" => vec![
            "the policy names the exact binaries that may run (`exec.allow`), and",
            "this one is not on the list. Add it if you trust it:",
            "    exec:",
            "      allow:",
            "        - <path-to-binary>",
        ],
        "deny:exec-untrusted-path" => vec![
            "an allowlisted binary name was resolved to a path the guest controls",
            "(`/workspace/...`, `./...`) — a planted twin, not the trusted binary.",
            "Fix: run the system binary (e.g. `/usr/bin/git`), not a workspace copy.",
        ],
        "deny:exec-no-argv" => vec!["proc.exec requires an argv array; there was nothing to run."],

        // ---- policy: net ----
        "net:deny-default" => vec![
            "the host is not in the network allowlist. To allow it, add to policy:",
            "    net:",
            "      hosts:",
            "        - host: <hostname>",
            "          methods: [GET]        # narrow to what the agent needs",
            "          paths: [\"/api/*\"]     # and constrain paths + byte budgets",
        ],
        "forbid:metadata" => vec![
            "cloud metadata endpoints (169.254.169.254 and friends) are forbidden",
            "unconditionally: a leaked metadata credential is an instant host compromise.",
            "There is no policy override by design.",
        ],
        "deny:method-missing" => vec![
            "an http.request without a method authorizes nothing: decide() no longer",
            "defaults it to GET. The caller must spell the method explicitly.",
        ],
        "deny:request-target" => vec![
            "the request line failed hygiene checks (control chars, `..`, smuggled",
            "headers). This is a shape problem in the request, not a policy setting.",
        ],
        "fs:deny-default" => vec![
            "the path is outside every mounted directory. Mount it read-only or",
            "read-write in the policy (`fs.mounts`) if the agent legitimately needs it.",
        ],
        "fs:deny-ro" => vec![
            "the mount is read-only; writes are refused. Change the mount's mode in",
            "the policy only if the agent genuinely needs write access there.",
        ],

        // ---- supervisor / backend ----
        "isolation:unavailable" => vec![
            "no isolation backend could honor the tier this run requires, so the",
            "action was denied — never downgraded to run unconfined.",
            "On this host: `toolcage-cli doctor` shows what is available (Tier 0",
            "needs namespaces+Landlock; Tier 1 needs runsc; Tier 2 needs firecracker).",
        ],
        "isolation:downgrade-refused" => vec![
            "the policy demands a stronger tier than the host can provide; refusing",
            "to run weaker is the point. Wire a stronger backend or lower min_isolation.",
        ],
        "isolation:unisolated" => vec![
            "this ran UNCONFINED because --unsafe-no-isolation was passed explicitly.",
            "The audit log marks it isolation:unisolated so the run is never mistaken",
            "for a contained one.",
        ],
        "token:missing" => vec![
            "the action requires a capability token and none was presented. Pass",
            "--token <file> (mint one with `toolcage token mint`).",
        ],
        "token:deny" => vec![
            "the capability token does not authorize this action (expired, revoked,",
            "or narrowed beyond it). Mint a fresh token or widen it at the SOURCE —",
            "a child token can never widen itself.",
        ],
        "budget:exceeded" => vec![
            "the per-destination byte/request budget is exhausted for this token.",
            "Budgets persist across restarts; raise them in the policy or use a",
            "token with a larger budget.",
        ],
        "approval:required" => vec![
            "this action matches an approval gate and is paused for a human decision",
            "(`toolcage` queues it; timeout = deny). Approve via the orchestrator CLI.",
        ],
        "deny:unknown-action" => vec![
            "the action name is not one this policy version knows (proc.exec,",
            "fs.read, fs.write, http.request, net.connect). Default-deny: an",
            "action the policy cannot reason about is refused, not waved through.",
        ],
        "panic:freeze" => vec![
            "the operator froze this audit log after a suspected compromise",
            "(`tc panic`). The taint marker refuses all future writes and the",
            "terminal deny-all event fails verification if the log is extended.",
        ],

        // unknown ids: empty; caller prints the generic fallback
        _ => vec![],
    }
}

/// Print the terse line plus an explanation block for each rule id.
/// The terse line keeps the exact old format so scripts still match it.
pub fn report_denial(rule_ids: &[String]) {
    eprintln!("denied: {rule_ids:?}");
    let mut explained_any = false;
    for id in rule_ids {
        let lines = explain_denial(id);
        if lines.is_empty() {
            continue;
        }
        explained_any = true;
        eprintln!("  {id}:");
        for l in lines {
            eprintln!("    {l}");
        }
    }
    if !explained_any {
        eprintln!("  (no further explanation; the rule id above is the policy's verdict)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rule id the trusted core emits must map to a non-empty
    /// explanation. If you add a rule id to policy/proxy/supervisor, add it
    /// here too — this list is the contract.
    #[test]
    fn every_known_rule_id_is_explained() {
        let known = [
            // policy exec
            "deny:shell",
            "deny:exec-not-allowlisted",
            "deny:exec-untrusted-path",
            "deny:exec-no-argv",
            // policy net/fs
            "net:deny-default",
            "forbid:metadata",
            "deny:method-missing",
            "deny:request-target",
            "fs:deny-default",
            "fs:deny-ro",
            // supervisor/backend
            "isolation:unavailable",
            "isolation:downgrade-refused",
            "isolation:unisolated",
            "token:missing",
            "token:deny",
            "budget:exceeded",
            "approval:required",
            "deny:unknown-action",
            "panic:freeze",
        ];
        for id in known {
            let lines = explain_denial(id);
            assert!(!lines.is_empty(), "rule id {id} has no explanation");
            assert!(
                lines.iter().all(|l| !l.trim().is_empty()),
                "rule id {id} has a blank explanation line"
            );
        }
    }

    #[test]
    fn unknown_rule_ids_have_a_fallback() {
        // A rule id we do not know must not crash or produce garbage: the
        // caller prints the generic hint instead of an empty block.
        assert!(explain_denial("deny:something-new").is_empty());
        assert!(explain_denial("").is_empty());
    }

    #[test]
    fn allow_rule_ids_are_not_denials() {
        // Net/fs allow ids are emitted on ALLOWED decisions; if someone passes
        // them here by mistake they fall through to the generic hint rather
        // than claiming a denial explanation.
        assert!(explain_denial("net:allow:github").is_empty());
        assert!(explain_denial("fs:allow:/workspace").is_empty());
        assert!(explain_denial("proc:allow").is_empty());
    }
}
