//! Fuzz target: proxy decide() + metadata/IP blocking.
//! All guest network flows through decide(); it must deny hostile input
//! without panicking.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_policy::load_yaml;
use toolcage_proxy::decide;

fuzz_target!(|data: &[u8]| {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };
    let Ok(policy) = load_yaml(text) else { return };
    // Exercise decide with various host/method/path combos including
    // metadata addresses, garbage strings, and unicode edge cases.
    for host in [
        "",
        "169.254.169.254",
        "metadata.google.internal",
        "instance-data",
        "evil.com",
        data.get(0..8)
            .map(|b| String::from_utf8_lossy(b))
            .unwrap_or_default()
            .as_ref(),
    ] {
        let _ = decide(&policy, host, "GET", "/");
        let _ = decide(&policy, host, "POST", "/repos/acme/app/issues/1");
        let _ = decide(&policy, host, "DELETE", "/");
    }
});
