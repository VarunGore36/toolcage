//! The golden-image pipeline must produce what the runtime loads:
//! images/build.sh writes manifest.json, `image sign` writes signature.bin,
//! and GoldenImage::load() accepts exactly that pair — with the right key
//! and only the right key.

use std::path::Path;

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_toolcage-cli")
}

#[test]
fn build_sign_load_round_trip() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::temp_dir().join(format!("tc-imgsign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let art = |name: &str, bytes: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    let kernel = art("vmlinux", b"kernel-bytes");
    let rootfs = art("rootfs.ext4", b"rootfs-bytes");
    let snapshot = art("snap.bin", b"snap-bytes");
    let mem = art("mem.bin", b"mem-bytes");
    let out = dir.join("out");

    // 1. Assemble the manifest.
    let st = std::process::Command::new("bash")
        .arg(root.join("images/build.sh"))
        .arg(&out)
        .arg(&kernel)
        .arg(&rootfs)
        .arg(&snapshot)
        .arg(&mem)
        .args(["2", "512"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );

    // 2. Sign it.
    let key = dir.join("k");
    let st = std::process::Command::new(cli())
        .args(["audit", "keygen", "--out-prefix", key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let st = std::process::Command::new(cli())
        .args([
            "image",
            "sign",
            "--dir",
            out.to_str().unwrap(),
            "--key-hex",
            format!("{}.secret.hex", key.display()).as_str(),
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "image sign failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let sig = std::fs::read(out.join("signature.bin")).unwrap();
    assert_eq!(sig.len(), 64, "Ed25519 signatures are 64 bytes");
    let stdout = String::from_utf8_lossy(&st.stdout);
    let pubkey = stdout
        .split("pubkey ")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .expect("image sign prints the pubkey to pin")
        .trim()
        .to_string();

    // 3. The loader accepts the pair with the right key...
    let gi = toolcage_backend_fc::GoldenImage::load(out.to_str().unwrap(), &pubkey)
        .expect("build + sign must produce a loadable golden image");
    assert_eq!(gi.manifest.vcpu_count, 2);
    assert_eq!(gi.manifest.mem_size_mib, 512);

    // ...and refuses any other key (the signature binds the manifest).
    let wrong = "11".repeat(32);
    assert!(
        toolcage_backend_fc::GoldenImage::load(out.to_str().unwrap(), &wrong).is_err(),
        "a foreign key must not verify the image"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
