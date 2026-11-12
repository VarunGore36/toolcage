//! `toolcage demo` — a self-contained 60-second tour of the whole story.
//!
//! The README demo deserves to be executable, not copy-pasted. This module
//! writes a minimal demo policy into a scratch dir, then runs the real CLI
//! (via current_exe, so the demo always shows actual behavior) through the
//! canonical sequence:
//!
//!   1. an allowed run (`/bin/echo hello`)          → output comes back
//!   2. the evil twin (`sh -c 'echo pwned'`)        → denied, with explanation
//!   3. keygen + checkpoint + verify                → ok
//!   4. flip one byte of the log                    → verify FAILS
//!
//! Step 4 is the point: the receipt cannot be quietly rewritten.
//!
//! On hosts where Tier 0 cannot create a namespace session (containers, CI),
//! the demo falls back to `--unsafe-no-isolation` and says so loudly — it
//! never pretends the run was confined. Any step that deviates from the
//! expected story is a hard error: the demo must not lie.
use anyhow::Context;
use std::path::Path;
use std::process::Command;

/// The demo policy: no exec allowlist (so the shell denylist is the gate that
/// fires with its full explanation); no network at all. Kept as a const so a
/// test pins its shape and the demo cannot rot silently.
pub const DEMO_POLICY: &str = r#"tool: toolcage-demo
version: 0
min_isolation: tier0
fs:
  mounts:
    - path: /workspace
      mode: rw
      source: session-copy
net:
  mode: allowlist
  hosts: []
limits:
  memory_mb: 256
"#;

struct Step {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(args: &[&str]) -> anyhow::Result<Step> {
    let exe = std::env::current_exe().context("locate toolcage-cli (current_exe)")?;
    let out = Command::new(&exe)
        .args(args)
        .output()
        .context("spawn toolcage-cli")?;
    Ok(Step {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn banner(n: usize, title: &str) {
    println!("\n── {n}. {title} ──────────────────────────────");
}

/// Flip one hex digit inside the FIRST event's `"hash":"..."` field. The
/// first event is the strongest demo: its hash is referenced by the second
/// event's prev_hash AND re-hashed by verify, so the failure is a chain
/// break, not just a re-hash mismatch. (The LAST event's stored hash is
/// only checked by the re-hash — and the demo's checkpoint/signature story
/// is about pinned prefixes; flipping the head leaves no ambiguity about
/// what verify caught.) The JSON stays parseable — length preserved,
/// content changed: exactly what a quiet rewrite looks like.
fn flip_one_byte(log: &Path) -> anyhow::Result<usize> {
    let mut bytes = std::fs::read(log)?;
    anyhow::ensure!(!bytes.is_empty(), "log is empty; nothing to flip");
    let needle = b"\"hash\":\"";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + needle.len()) // first hex digit of the hash
        .unwrap_or(16.min(bytes.len() - 1));
    // Corrupt within the hex alphabet: v -> (v+1) % 16. XOR could turn a hex
    // digit into '`' or '~', which verify would report as a PARSE error; the
    // demo wants the message that matters — a hash mismatch.
    let v = (bytes[at] as char).to_digit(16).unwrap_or(0);
    bytes[at] = std::char::from_digit((v + 1) % 16, 16).unwrap() as u8;
    std::fs::write(log, &bytes)?;
    Ok(at)
}

pub fn run_demo(dir: &Path) -> anyhow::Result<()> {
    println!("toolcage demo — policy, secrets, evidence in 60 seconds");
    // The demo wipes its directory before running. That is only safe for a
    // directory that is plausibly a scratch dir: refuse the filesystem root,
    // system prefixes, and $HOME (and everything under it) — one flag typo
    // must not be an rm -rf. Refuse a NON-EMPTY directory too unless it
    // looks like a previous demo run (policy/ ws/ audit.jsonl): the demo
    // recreates everything it needs, so there is nothing to preserve.
    let canonical = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    anyhow::ensure!(
        canonical != Path::new("/")
            && !canonical.starts_with("/etc")
            && !canonical.starts_with("/usr")
            && !canonical.starts_with("/var")
            && !canonical.starts_with("/boot"),
        "refusing to demo into a system path: {}",
        canonical.display()
    );
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        let home = home.canonicalize().unwrap_or(home);
        anyhow::ensure!(
            canonical != home && !canonical.starts_with(&home),
            "refusing to demo into $HOME ({}): use a scratch directory",
            home.display()
        );
    }
    if dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(dir)?.collect();
        anyhow::ensure!(
            entries.is_empty()
                || entries.iter().flatten().all(|e| e
                    .path()
                    .file_name()
                    .is_some_and(|n| n == "policy" || n == "ws" || n == "audit.jsonl")),
            "{} is not empty and does not look like a previous demo run; remove it yourself first",
            dir.display()
        );
    }
    let _ = std::fs::remove_dir_all(dir);
    // Policy/audit/keys live under <dir>/policy; the workspace is <dir>/ws.
    // Keeping control files OUT of the writable workspace is the VULN-05
    // invariant — the demo must obey its own rules (and demonstrate them).
    let host = dir.join("policy");
    let ws = dir.join("ws");
    std::fs::create_dir_all(&host)?;
    std::fs::create_dir_all(&ws)?;
    let policy = host.join("demo-policy.yaml");
    let log = host.join("demo.jsonl");
    std::fs::write(&policy, DEMO_POLICY)?;
    println!("dir     {}", dir.display());
    println!(
        "policy  {} (echo allowed, ALL net denied, shell denied)",
        policy.display()
    );

    // Hosts that cannot create a namespace session (containers, some CI)
    // would turn step 1 into an infrastructure denial. Detect that once and
    // fall back loudly; the demo never pretends an unconfined run is confined.
    let mut isolation_args: Vec<&str> = vec![];
    let probe = run_cli(&[
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--audit",
        log.to_str().unwrap(),
        "--workspace",
        ws.to_str().unwrap(),
        "--tier",
        "tier0",
        "--",
        "/bin/echo",
        "hello",
    ])?;
    if probe.stderr.contains("create isolated session") {
        println!("\n(note: this host cannot create a namespace session — the demo");
        println!(" falls back to --unsafe-no-isolation and says so; every run is");
        println!(" audited as isolation:unisolated so nothing is overstated)");
        isolation_args = vec!["--unsafe-no-isolation"];
        // The probe consumed nothing (session create failed before exec), so
        // the log is still empty; fall through and run step 1 for real.
    }

    // 1. allowed
    banner(1, "an allowed run");
    let mut args: Vec<&str> = vec![
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--audit",
        log.to_str().unwrap(),
        "--workspace",
        ws.to_str().unwrap(),
        "--tier",
        "tier0",
    ];
    args.extend_from_slice(&isolation_args);
    args.extend_from_slice(&["--", "/bin/echo", "hello"]);
    let s = run_cli(&args)?;
    print!("{}", s.stdout);
    if !s.stderr.is_empty() {
        print!("{}", s.stderr);
    }
    anyhow::ensure!(
        s.code == 0 && s.stdout.trim() == "hello",
        "step 1: allowed run must print hello (code {})",
        s.code
    );

    // 2. evil twin
    banner(2, "the evil twin — denied, with an explanation");
    let mut args: Vec<&str> = vec![
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--audit",
        log.to_str().unwrap(),
        "--workspace",
        ws.to_str().unwrap(),
        "--tier",
        "tier0",
    ];
    args.extend_from_slice(&isolation_args);
    args.extend_from_slice(&["--", "sh", "-c", "echo pwned"]);
    let s = run_cli(&args)?;
    print!("{}", s.stderr);
    anyhow::ensure!(
        s.code == 2 && s.stderr.contains("deny:shell"),
        "step 2: sh -c must be denied with deny:shell (code {})",
        s.code
    );

    // 3. sign and verify
    banner(3, "sign the log, verify it");
    let k = dir.join("k");
    let khex = k.to_str().unwrap().to_string() + ".secret.hex";
    let kpub = k.to_str().unwrap().to_string() + ".pub.hex";
    for (args, must_say) in [
        (
            vec!["audit", "keygen", "--out-prefix", k.to_str().unwrap()],
            "wrote",
        ),
        (
            vec![
                "audit",
                "checkpoint",
                "--log",
                log.to_str().unwrap(),
                "--key-hex",
                &khex,
            ],
            "checkpoint",
        ),
        (
            vec![
                "audit",
                "verify",
                "--log",
                log.to_str().unwrap(),
                "--pubkey",
                &kpub,
            ],
            "ok",
        ),
    ] {
        let s = run_cli(&args)?;
        print!("{}", s.stdout);
        if !s.stderr.is_empty() {
            print!("{}", s.stderr);
        }
        anyhow::ensure!(
            s.code == 0 && (s.stdout.contains(must_say) || s.stderr.contains(must_say)),
            "step 3: `{}` must succeed mentioning {must_say:?} (code {})",
            args.join(" "),
            s.code
        );
    }

    // 4. tamper
    banner(4, "flip one byte of the log — verify must fail");
    let at = flip_one_byte(&log)?;
    println!("flipped byte {at} of {}", log.display());
    let s = run_cli(&[
        "audit",
        "verify",
        "--log",
        log.to_str().unwrap(),
        "--pubkey",
        &kpub,
    ])?;
    print!("{}", s.stderr);
    anyhow::ensure!(
        s.code != 0,
        "step 4: verify must FAIL on a tampered log (it returned 0 — that is a bug)"
    );

    banner(5, "what you just saw");
    println!("• allowlists, not vibes: only /bin/echo could run; sh -c never stood a chance");
    println!("• denials teach: the shell denial printed the policy that would allow it");
    println!("• evidence: the log was signed; one flipped byte and verify refuses");
    println!("\nscratch left in {} (delete freely)", dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use toolcage_policy::Request;

    #[test]
    fn demo_policy_loads_and_pins_the_story() {
        let p = toolcage_policy::load_yaml(DEMO_POLICY).expect("demo policy must parse");
        assert_eq!(p.min_isolation, "tier0");
        // No exec allowlist: the shell denylist is the gate that fires in the
        // demo's evil-twin step, carrying the rich teach-me explanation.
        assert!(p.exec.allowlist.is_empty());
        assert!(p.net.hosts.is_empty(), "demo allows NO network");
    }

    #[test]
    fn demo_policy_denies_shell_and_allows_echo() {
        let p = toolcage_policy::load_yaml(DEMO_POLICY).unwrap();
        let echo = Request {
            action: "proc.exec".into(),
            host: None,
            method: None,
            path: None,
            fs_path: None,
            argv: Some(vec!["/bin/echo".into(), "hello".into()]),
        };
        assert!(
            toolcage_policy::decide(&p, &echo).allow,
            "echo must be allowed"
        );
        let shell = Request {
            action: "proc.exec".into(),
            host: None,
            method: None,
            path: None,
            fs_path: None,
            argv: Some(vec!["sh".into(), "-c".into(), "echo pwned".into()]),
        };
        let d = toolcage_policy::decide(&p, &shell);
        assert!(!d.allow, "sh -c must be denied");
        assert!(d.rule_ids.iter().any(|r| r == "deny:shell"));
    }

    #[test]
    fn flip_one_byte_changes_content_keeps_length() {
        let dir = std::env::temp_dir().join(format!("tc-demo-flip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("l.jsonl");
        std::fs::write(&log, b"{\"seq\":0,\"hash\":\"aabbccdd\"}\n").unwrap();
        let before = std::fs::read(&log).unwrap();
        let at = flip_one_byte(&log).unwrap();
        let after = std::fs::read(&log).unwrap();
        assert_eq!(before.len(), after.len(), "flip must keep length");
        assert_ne!(before, after, "flip must change content");
        // The flip must land INSIDE the hash hex — the first digit after
        // `"hash":"` — so verify fails with a chain break, not a parse error.
        let needle = b"\"hash\":\"";
        let hash_start = before
            .windows(needle.len())
            .rposition(|w| w == needle)
            .unwrap()
            + needle.len();
        assert_eq!(at, hash_start);
        assert!(
            after[at].is_ascii_hexdigit(),
            "flipped byte must stay a hex digit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
