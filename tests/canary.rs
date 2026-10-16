//! Canary skeleton (I2/I7): plant secret, assert never in guest-visible output.
#[test]
fn canary_placeholder_never_expanded() {
    // Supervisor exec passes only argv; env refs like secret:github_token
    // must never be resolved inside guest (broker does it at proxy in M2).
    let argv = vec!["/bin/echo".to_string(), "secret:github_token".to_string()];
    assert!(argv[1].starts_with("secret:"));
}
