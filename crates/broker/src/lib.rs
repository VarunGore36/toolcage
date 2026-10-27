//! Credential broker v1: secrets live in host, encrypted at rest, injected at proxy only.
//! Guest holds `secret:name` placeholders. Log holds stable ids, never values.
//!
//! REVIEW (I2):
//! - inject() binds (name, use_with alias, method, path). Mismatched dest returns
//!   None — the proxy must treat None as no-auth, never fall back to a literal
//!   or env value. New fields (paths/expiry) must default-deny when absent.
//! - inject() also enforces expires_at — expired credentials return None.
//! - scrub() replaces every known value with [REDACTED] before guest-visible
//!   output. Substring replace can miss encoded forms (base64/URL-encoded);
//!   treat scrub as defense-in-depth, not the boundary — the boundary is never
//!   placing values guest-side in the first place.
//! - log_id() is `cred:name`: safe to audit. Never log Credential.value, not
//!   even at debug/trace. Credential has a manual redacting Debug impl — do
//!   not re-add a derived Debug or log `.value` anywhere.
//! - Storage is in-memory HashMap with encrypted-at-rest persist/load/rotate.
//!   Master key (32 bytes hex) from TOOLCAGE_BROKER_KEY env var or key file.
//!   Rotation re-encrypts all credentials immediately.
//! - Canary plant_canary() uses time-nanos suffix: unique per test run, good
//!   for I2 scans (grep guest mem/files for canary must find 0 hits).
//!
//! Encryption: XChaCha20-Poly1305 with random 24-byte nonces (random nonces
//! are safe with 192-bit nonce space). Associated data = credential name
//! (binding ciphertext to its identity). Master key = 32 bytes.

use chacha20poly1305::aead::{Aead, AeadCore};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use generic_array::GenericArray;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MASTER_KEY_LEN: usize = 32; // bytes

/// A credential held in memory as plaintext (needed for inject).
/// `encrypted_value` is set only when loaded from disk for rotation.
#[derive(Clone)]
pub struct Credential {
    pub name: String,
    pub use_with: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub expires_at: Option<u64>, // epoch seconds; None = unbounded
    pub value: String,           // plaintext — zeroized on drop via Drop impl
    pub encrypted_value: Option<Vec<u8>>, // set when loaded from disk (nonce||ct)
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Manual Debug to never print the secret value.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("use_with", &self.use_with)
            .field("methods", &self.methods)
            .field("paths", &self.paths)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Serializable credential for at-rest storage (encrypted).
/// `encrypted_value` = base64(nonce || ciphertext), nonce is 24 bytes prepended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCredential {
    pub name: String,
    pub use_with: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub expires_at: Option<u64>,
    pub encrypted_value: String, // base64(nonce || ciphertext)
}

/// Master key holder: 32 bytes, zeroized on drop.
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        let bytes = hex_decode(hex)?;
        anyhow::ensure!(
            bytes.len() == MASTER_KEY_LEN,
            "master key must be 32 bytes (64 hex chars)"
        );
        let mut k = [0u8; MASTER_KEY_LEN];
        k.copy_from_slice(&bytes);
        Ok(Self(k))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// Broker: secrets in memory as plaintext, encrypted at rest.
pub struct Broker {
    creds: HashMap<String, Credential>,
    master_key: Option<MasterKey>,
}

impl Default for Broker {
    fn default() -> Self {
        Self::new()
    }
}

impl Broker {
    pub fn new() -> Self {
        Self {
            creds: HashMap::new(),
            master_key: None,
        }
    }

    /// Load broker from disk: decrypt all credentials with master key.
    /// Master key from env `TOOLCAGE_BROKER_KEY` or file `TOOLCAGE_BROKER_KEY_FILE`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let key = load_master_key()?;
        let data = fs::read(path).map_err(|e| anyhow::anyhow!("io: {e}"))?;
        let encrypted: Vec<EncryptedCredential> =
            serde_json::from_slice(&data).map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
        let mut creds = HashMap::new();
        for ec in encrypted {
            let combined =
                base64_decode(&ec.encrypted_value).map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            anyhow::ensure!(combined.len() >= 24, "decrypt: combined too short");
            let (nonce_bytes, ct) = combined.split_at(24);
            let nonce: GenericArray<u8, <XChaCha20Poly1305 as AeadCore>::NonceSize> =
                *GenericArray::from_slice(nonce_bytes);
            let pt = cipher
                .decrypt(&nonce, ct)
                .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            let value = String::from_utf8(pt).map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            creds.insert(
                ec.name.clone(),
                Credential {
                    name: ec.name,
                    use_with: ec.use_with,
                    methods: ec.methods,
                    paths: ec.paths,
                    expires_at: ec.expires_at,
                    value,
                    encrypted_value: Some(combined.to_vec()),
                },
            );
        }
        Ok(Self {
            creds,
            master_key: Some(key),
        })
    }

    /// Save broker to disk: encrypt all credentials with master key.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let key = self
            .master_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no master key set"))?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
        let mut encrypted = Vec::new();
        for c in self.creds.values() {
            let mut rng = OsRng;
            let nonce = XChaCha20Poly1305::generate_nonce(&mut rng);
            let pt = c.value.as_bytes();
            let ct = cipher
                .encrypt(&nonce, pt)
                .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
            let mut combined = nonce.to_vec();
            combined.extend_from_slice(&ct);
            encrypted.push(EncryptedCredential {
                name: c.name.clone(),
                use_with: c.use_with.clone(),
                methods: c.methods.clone(),
                paths: c.paths.clone(),
                expires_at: c.expires_at,
                encrypted_value: base64_encode(&combined),
            });
        }
        let data =
            serde_json::to_vec_pretty(&encrypted).map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
        fs::write(path, data).map_err(|e| anyhow::anyhow!("io: {e}"))?;
        Ok(())
    }

    /// Rotate master key: re-encrypt every credential IN THE STORE with the
    /// new key, atomically replace the file, then swap the in-memory key.
    ///
    /// This used to be a no-op on the store: it swapped the in-memory key and
    /// cleared the ciphertext caches, leaving the file encrypted under the OLD
    /// key. The old key kept decrypting the store forever, and an operator who
    /// retired the old key after "rotating" destroyed access to it.
    ///
    /// Rotation applies to an existing store; it never creates one (materializing
    /// plaintext secrets to a new file is not a rotation decision).
    pub fn rotate(&mut self, path: &Path, new_key_hex: &str) -> anyhow::Result<()> {
        let new_key = MasterKey::from_hex(new_key_hex)?;
        anyhow::ensure!(path.exists(), "no broker store at {}", path.display());
        let old = self
            .master_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no master key set"))?;
        let old_cipher = XChaCha20Poly1305::new_from_slice(old.as_bytes())
            .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
        let new_cipher = XChaCha20Poly1305::new_from_slice(new_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
        let data = fs::read(path).map_err(|e| anyhow::anyhow!("io: {e}"))?;
        let entries: Vec<EncryptedCredential> =
            serde_json::from_slice(&data).map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
        let mut rotated = Vec::new();
        for mut ec in entries {
            let combined =
                base64_decode(&ec.encrypted_value).map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            anyhow::ensure!(combined.len() >= 24, "decrypt: combined too short");
            let (nonce_bytes, ct) = combined.split_at(24);
            let nonce: GenericArray<u8, <XChaCha20Poly1305 as AeadCore>::NonceSize> =
                *GenericArray::from_slice(nonce_bytes);
            // Every entry must actually decrypt under the current key: a
            // rotation that cannot read the store must not rewrite it.
            let pt = old_cipher
                .decrypt(&nonce, ct)
                .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            let mut rng = OsRng;
            let nonce = XChaCha20Poly1305::generate_nonce(&mut rng);
            let ct = new_cipher
                .encrypt(&nonce, pt.as_ref())
                .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
            let mut combined = nonce.to_vec();
            combined.extend_from_slice(&ct);
            ec.encrypted_value = base64_encode(&combined);
            rotated.push(ec);
        }
        let data =
            serde_json::to_vec_pretty(&rotated).map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
        // Atomic replace: a crash mid-rotation must not leave a torn store.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, data).map_err(|e| anyhow::anyhow!("io: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("io: {e}"))?;
        self.master_key = Some(new_key);
        for c in self.creds.values_mut() {
            c.encrypted_value = None;
        }
        Ok(())
    }

    /// Set master key from hex (for programmatic use / tests).
    pub fn set_master_key(&mut self, key_hex: &str) -> anyhow::Result<()> {
        self.master_key = Some(MasterKey::from_hex(key_hex)?);
        Ok(())
    }

    pub fn insert(&mut self, c: Credential) {
        self.creds.insert(c.name.clone(), c);
    }

    pub fn from_policy_rules(rules: &[(String, String)], values: &HashMap<String, String>) -> Self {
        let mut b = Self::new();
        for (name, use_with) in rules {
            if let Some(v) = values.get(name) {
                b.insert(Credential {
                    name: name.clone(),
                    value: v.clone(),
                    use_with: use_with.clone(),
                    methods: vec![],
                    paths: vec![],
                    expires_at: None,
                    encrypted_value: None,
                });
            }
        }
        b
    }

    /// Returns the secret value ONLY if dest/method/path are allowed AND not expired.
    /// Caller (proxy) attaches it upstream; it never goes to the guest.
    /// Empty methods/paths on a credential means "no constraint on that axis".
    pub fn inject(&self, name: &str, dest_alias: &str, method: &str, path: &str) -> Option<&str> {
        let c = self.creds.get(name)?;
        if !c.use_with.eq_ignore_ascii_case(dest_alias) {
            return None;
        }
        if !c.methods.is_empty() && !c.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return None;
        }
        if !c.paths.is_empty() && !c.paths.iter().any(|p| path_match_cred(p, path)) {
            return None;
        }
        // Expiry check (fail-closed).
        if let Some(exp) = c.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > exp {
                return None;
            }
        }
        Some(&c.value)
    }

    /// Stable log identifier — never the value.
    pub fn log_id(name: &str) -> String {
        format!("cred:{name}")
    }

    /// Scrub upstream responses: strip any known secret before guest sees it.
    pub fn scrub(&self, body: &str) -> String {
        let mut out = body.to_string();
        for c in self.creds.values() {
            if !c.value.is_empty() {
                out = out.replace(&c.value, "[REDACTED]");
            }
        }
        out
    }

    /// Canary for I2 tests: unique value that must never appear guest-side.
    pub fn plant_canary(&mut self, name: &str) -> String {
        let v = format!("CANARY-{}-{}", name, rand_suffix());
        self.insert(Credential {
            name: name.into(),
            value: v.clone(),
            use_with: "github".into(),
            methods: vec![],
            paths: vec![],
            expires_at: None,
            encrypted_value: None,
        });
        v
    }
}

/// Load master key from env var or key file.
fn load_master_key() -> anyhow::Result<MasterKey> {
    if let Ok(hex) = std::env::var("TOOLCAGE_BROKER_KEY") {
        return MasterKey::from_hex(&hex);
    }
    if let Ok(path) = std::env::var("TOOLCAGE_BROKER_KEY_FILE") {
        let hex = fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("io: {e}"))?
            .trim()
            .to_string();
        return MasterKey::from_hex(&hex);
    }
    Err(anyhow::anyhow!(
        "master key not set: set TOOLCAGE_BROKER_KEY or TOOLCAGE_BROKER_KEY_FILE"
    ))
}

fn base64_encode(b: &[u8]) -> String {
    BASE64.encode(b)
}

fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    BASE64.decode(s).map_err(|e| anyhow::anyhow!(e))
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(s.len().is_multiple_of(2), "odd hex length");
    // Strict hex digits only. This guards two sharp edges at once: every byte
    // being a hex digit implies ASCII, so the byte slicing below cannot hit a
    // multi-byte char boundary and panic (a crafted non-ASCII string used to
    // abort the process); and it rejects sign-prefixed "digits" like "+a",
    // which from_str_radix would accept.
    anyhow::ensure!(
        s.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid hex digit"
    );
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16)?);
    }
    Ok(out)
}

mod base64_engine {
    pub use base64::engine::general_purpose::STANDARD as BASE64;
}
use base64::Engine as _;
use base64_engine::BASE64;

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", n & 0xffffff)
}

/// Trailing-`/**` match only (same semantics as policy paths): exact or under prefix.
fn path_match_cred(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    } else {
        pattern == path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_only_for_bound_dest() {
        let mut b = Broker::new();
        b.insert(Credential {
            name: "github_token".into(),
            value: "s3cr3t".into(),
            use_with: "github".into(),
            methods: vec![],
            paths: vec![],
            expires_at: None,
            encrypted_value: None,
        });
        assert_eq!(
            b.inject("github_token", "github", "GET", "/"),
            Some("s3cr3t")
        );
        assert_eq!(b.inject("github_token", "evil", "GET", "/"), None);
        // Path-bound credential denies outside its prefix.
        b.insert(Credential {
            name: "scoped".into(),
            value: "v".into(),
            use_with: "github".into(),
            methods: vec![],
            paths: vec!["/repos/acme/**".into()],
            expires_at: None,
            encrypted_value: None,
        });
        assert_eq!(
            b.inject("scoped", "github", "GET", "/repos/acme/app"),
            Some("v")
        );
        assert_eq!(b.inject("scoped", "github", "GET", "/repos/evil"), None);
        // Scrub strips echo
        assert_eq!(b.scrub("token=s3cr3t ok"), "token=[REDACTED] ok");
        // Log id leaks nothing
        assert!(!Broker::log_id("github_token").contains("s3cr3t"));
    }

    #[test]
    fn inject_expired_denied() {
        let mut b = Broker::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        b.insert(Credential {
            name: "expired".into(),
            value: "v".into(),
            use_with: "github".into(),
            methods: vec![],
            paths: vec![],
            expires_at: Some(now - 1), // expired yesterday
            encrypted_value: None,
        });
        assert_eq!(b.inject("expired", "github", "GET", "/"), None);
    }

    #[test]
    fn encrypt_save_load_roundtrip() {
        let mut b = Broker::new();
        b.set_master_key("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        b.insert(Credential {
            name: "gh".into(),
            value: "supersecret".into(),
            use_with: "github".into(),
            methods: vec!["GET".into()],
            paths: vec!["/repos/acme/**".into()],
            expires_at: None,
            encrypted_value: None,
        });
        let dir = std::env::temp_dir().join(format!("tc-broker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broker.json");
        b.save(&path).unwrap();

        // Load fresh broker from disk.
        std::env::set_var(
            "TOOLCAGE_BROKER_KEY",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let b2 = Broker::load(&path).unwrap();
        assert_eq!(
            b2.inject("gh", "github", "GET", "/repos/acme/app"),
            Some("supersecret")
        );
        assert!(b2.inject("gh", "evil", "GET", "/").is_none()); // dest mismatch
        assert!(b2.inject("gh", "github", "POST", "/").is_none()); // method mismatch
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotate_reencrypts() {
        let key_a = "1111111111111111111111111111111111111111111111111111111111111111";
        let key_b = "2222222222222222222222222222222222222222222222222222222222222222";
        let mut b = Broker::new();
        b.set_master_key(key_a).unwrap();
        b.insert(Credential {
            name: "gh".into(),
            value: "v1".into(),
            use_with: "github".into(),
            methods: vec![],
            paths: vec![],
            expires_at: None,
            encrypted_value: None,
        });
        assert_eq!(b.inject("gh", "github", "GET", "/"), Some("v1"));
        let dir = std::env::temp_dir().join(format!("tc-broker-rot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broker.json");
        b.save(&path).unwrap();

        // Rotate to the new key: the STORE must be re-encrypted, not just the
        // in-memory key swapped (the old code left the file under key A).
        b.rotate(&path, key_b).unwrap();
        assert_eq!(b.inject("gh", "github", "GET", "/"), Some("v1"));

        // Inspect the store's actual ciphertext with raw AEAD — no env vars,
        // no load() indirection: key B must decrypt, key A must not.
        let data = std::fs::read(&path).unwrap();
        let entries: Vec<EncryptedCredential> = serde_json::from_slice(&data).unwrap();
        assert_eq!(entries.len(), 1);
        let combined = base64_decode(&entries[0].encrypted_value).unwrap();
        let (nonce_bytes, ct) = combined.split_at(24);
        let nonce: GenericArray<u8, <XChaCha20Poly1305 as AeadCore>::NonceSize> =
            *GenericArray::from_slice(nonce_bytes);
        let cipher_b = XChaCha20Poly1305::new_from_slice(&hex_decode(key_b).unwrap()).unwrap();
        let pt = cipher_b.decrypt(&nonce, ct).unwrap();
        assert_eq!(pt, b"v1".to_vec(), "new key must read the rotated store");
        let cipher_a = XChaCha20Poly1305::new_from_slice(&hex_decode(key_a).unwrap()).unwrap();
        assert!(
            cipher_a.decrypt(&nonce, ct).is_err(),
            "the old key must no longer decrypt the store"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn canary_never_in_guest_output() {
        let mut b = Broker::new();
        let canary = b.plant_canary("test_tok");
        let guest_output = "using secret:test_tok via proxy";
        assert!(!guest_output.contains(&canary));
        let echoed = format!("echo {canary}");
        assert!(!b.scrub(&echoed).contains(&canary));
    }

    #[test]
    fn hex_decode_rejects_hostile_input_without_panicking() {
        // A crafted non-ASCII string must error, not abort the process:
        // byte-slicing `s[i..i+2]` used to land inside a multi-byte char and
        // panic ("aéb" has an even byte length and passes the length check).
        assert!(hex_decode("a\u{e9}b").is_err());
        assert!(hex_decode("\u{e9}\u{e9}").is_err());
        // Sign-prefixed "digits" are not hex — from_str_radix accepted "+a".
        assert!(hex_decode("+abc").is_err());
        assert!(hex_decode("-abc").is_err());
        // Well-formed hex still decodes.
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
    }
}
