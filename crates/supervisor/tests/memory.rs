//! Supervisor idle memory measurement (plan §11: < 100 MB RSS target).

use std::fs::File;
use std::io::Read;

fn current_rss_mb() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        // `/proc/self/statm` fields: size resident shared text lib data dt (in pages).
        let mut f = File::open("/proc/self/statm").ok()?;
        let mut buf = [0u8; 128];
        let n = f.read(&mut buf).ok()?;
        let s = std::str::from_utf8(&buf[..n]).ok()?;
        let resident_pages: u64 = s.split_ascii_whitespace().nth(1)?.parse().ok()?;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return None;
        }
        let rss_bytes = resident_pages.saturating_mul(page_size as u64);
        Some(rss_bytes as f64 / (1024.0 * 1024.0))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[test]
fn supervisor_idle_memory_under_100mb_target() {
    let dir = std::env::temp_dir().join(format!("tc-idle-mem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");

    let sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit,
        session: "idle-mem".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
    };

    // Touch policy decision so the constructed supervisor cannot be dead-code eliminated.
    let dec = sup.check(&toolcage_policy::Request {
        action: "fs.read".into(),
        fs_path: Some("/workspace/readme.md".into()),
        host: None,
        method: None,
        path: None,
        argv: None,
    });
    assert!(dec.allow);

    if let Some(rss_mb) = current_rss_mb() {
        println!(
            "supervisor idle memory: rss={:.2} MB (target < 100 MB)",
            rss_mb
        );
        assert!(
            rss_mb < 100.0,
            "supervisor idle memory exceeded 100 MB target: {:.2} MB",
            rss_mb
        );
    } else {
        eprintln!("skip: /proc/self/statm unavailable on this host");
    }

    drop(sup);
    let _ = std::fs::remove_dir_all(&dir);
}
