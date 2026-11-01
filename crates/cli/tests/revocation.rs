//! VULN-01, second half: `fetch` had no `--revocation` flag at all and passed
//! an empty RevocationList, so a revoked token kept working on this path while
//! `mcp` refused it. The flag must exist and the revocation must bite BEFORE
//! the dial — including through a multi-hop chain (the signed lineage from
//! the capability fix).

use std::process::Command;

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_toolcage-cli")
}
fn policy() -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/policy-v0.yaml")
        .display()
        .to_string()
}

struct World {
    dir: std::path::PathBuf,
    key: String,
}

fn world(tag: &str) -> World {
    let dir = std::env::temp_dir().join(format!("tc-revoke-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = dir.join("k");
    let st = Command::new(cli())
        .args(["token", "keygen", "--out-prefix", key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    World {
        dir,
        key: format!("{}.key.hex", key.display()),
    }
}

fn run(w: &World, token: &str, host: &str, extra: &[&str]) -> std::process::Output {
    let audit = w.dir.join("a.jsonl");
    let mut args = vec![
        "fetch".to_string(),
        "--policy".to_string(),
        policy(),
        "--audit".to_string(),
        audit.display().to_string(),
        "--host".to_string(),
        host.to_string(),
        "--method".to_string(),
        "GET".to_string(),
        "--path".to_string(),
        // Matches the policy's github rule (/repos/acme/app/**): the policy
        // allows this request, so a denial can only be the token gate.
        "/repos/acme/app/x".to_string(),
        "--token".to_string(),
        token.to_string(),
        "--key-hex".to_string(),
        w.key.clone(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    Command::new(cli()).args(&args).output().unwrap()
}

#[test]
fn fetch_refuses_a_token_whose_root_is_revoked() {
    let w = world("root");
    // Mint a root, and a child delegated from it (the multi-hop case).
    let root = w.dir.join("root.tok");
    let st = Command::new(cli())
        .args([
            "token",
            "mint",
            "--rev",
            "root-1",
            "--out",
            root.to_str().unwrap(),
            "--key-hex",
            &w.key,
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let child = w.dir.join("child.tok");
    let st = Command::new(cli())
        .args([
            "token",
            "attenuate",
            "--parent",
            root.to_str().unwrap(),
            "--rev",
            "child-1",
            "--out",
            child.to_str().unwrap(),
            "--hosts",
            "registry.npmjs.org",
            "--key-hex",
            &w.key,
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );

    // Revoking the ROOT must refuse the root itself...
    let out = run(
        &w,
        root.to_str().unwrap(),
        "github",
        &["--revocation", "root-1"],
    );
    assert!(
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("token:deny"),
        "revoking root-1 must refuse its own token at fetch: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ...and, through the signed lineage, the CHILD presented cold (this is
    // the half the flag alone would not fix).
    let out = run(
        &w,
        child.to_str().unwrap(),
        "registry.npmjs.org",
        &["--revocation", "root-1"],
    );
    assert!(
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("token:deny"),
        "revoking root-1 must refuse the cold child token at fetch: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // An unrelated revocation id must NOT trip the gate: the token is valid
    // and the request proceeds past it (whatever the network then says — the
    // point is the gate did not fire).
    let out = run(
        &w,
        root.to_str().unwrap(),
        "github",
        &["--revocation", "unrelated-9"],
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("token:deny"),
        "an unrelated revocation must not trip the token gate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&w.dir);
}
