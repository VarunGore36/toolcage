//! Egress proxy v1: real dialer with DNS control, metadata blocking, TLS.
//!
//! The proxy is the single egress chokepoint. The guest never dials or
//! resolves DNS. All guest network flows through decide() (policy) then
//! fetch() (real dial).
//!
//! Security properties:
//! - Guest never dials: decide() returns an upstream; the guest string is
//!   only a policy key.
//! - Proxy resolves DNS: guest DNS = exfil channel, so we resolve here and
//!   block metadata/link-local IPs at the socket level.
//! - TLS for https://: native-tls originates the upstream connection.
//! - Budgets enforced per destination: bytes + requests, fail-closed.
//! - No fallback: if the proxy can't dial, the action is denied.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;
use native_tls::{TlsConnector};

use serde::{Deserialize, Serialize};
use toolcage_policy::{Policy, Request};

// Trait object workaround: Rust doesn't allow Box<dyn Read + Write>
// (two non-auto traits). Define a single supertrait instead.
trait IoStream: Read + Write + std::fmt::Debug {}
impl<T: Read + Write + std::fmt::Debug> IoStream for T {}

// Metadata / link-local / loopback ranges that must never be dialed.
// 169.254.0.0/16 is where cloud metadata lives (AWS/Azure/GCP).
// Checked inline in is_blocked_ip().

/// Result of a proxy fetch.
#[derive(Debug)]
pub struct ProxyResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Error from the proxy layer.
#[derive(Debug)]
pub enum ProxyError {
    Policy(String),
    Dns(String),
    BlockedIp(String),
    Connect(String),
    Tls(String),
    Io(String),
    Budget(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Policy(s) => write!(f, "policy: {s}"),
            ProxyError::Dns(s) => write!(f, "dns: {s}"),
            ProxyError::BlockedIp(s) => write!(f, "blocked-ip: {s}"),
            ProxyError::Connect(s) => write!(f, "connect: {s}"),
            ProxyError::Tls(s) => write!(f, "tls: {s}"),
            ProxyError::Io(s) => write!(f, "io: {s}"),
            ProxyError::Budget(s) => write!(f, "budget: {s}"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// alias -> real upstream host. Guest never learns the real hostname/IP.
pub fn alias_map() -> HashMap<String, String> {
    HashMap::from([
        ("github".to_string(), "api.github.com".to_string()),
        ("github.internal".to_string(), "api.github.com".to_string()),
        ("registry".to_string(), "registry.npmjs.org".to_string()),
    ])
}

#[derive(Debug, Clone)]
pub struct ProxyDecision {
    pub allow: bool,
    pub rule_ids: Vec<String>,
    pub reason: String,
    /// Upstream host the proxy will dial (guest never dials directly).
    pub upstream: Option<String>,
}

/// Single choke point for all guest network. Policy + alias + metadata forbid.
pub fn decide(policy: &Policy, alias_or_host: &str, method: &str, path: &str) -> ProxyDecision {
    let aliases = alias_map();
    let key = alias_or_host.to_ascii_lowercase();
    // Resolve alias first: guest uses alias, proxy maps to real host for upstream,
    // but policy is checked against the alias the operator wrote.
    //
    // Look up the guest's alias to get the upstream, then find which operator
    // alias maps to that same upstream for policy checking.
    // E.g. guest uses "github.internal" → upstream "api.github.com" → policy
    // checks against operator alias "github".
    let policy_host = aliases.get(&key)
        .cloned()
        .and_then(|upstream| {
            aliases.iter()
                .find(|(alias, up)| {
                    up.as_str() == upstream.as_str()
                        && policy.net.hosts.iter().any(|h| h.alias.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(alias)))
                })
                .map(|(alias, _)| alias.clone())
        })
        .unwrap_or_else(|| key.clone());
    let req = Request {
        action: "http.request".into(),
        host: Some(policy_host),
        method: Some(method.to_string()),
        path: Some(path.to_string()),
        fs_path: None,
        argv: None,
    };
    let d = toolcage_policy::decide(policy, &req);
    if !d.allow {
        return ProxyDecision { allow: false, rule_ids: d.rule_ids, reason: d.reason, upstream: None };
    }
    let upstream = aliases.get(&key).cloned().unwrap_or(key);
    ProxyDecision { allow: true, rule_ids: d.rule_ids, reason: "proxy allow".into(), upstream: Some(upstream) }
}

/// Resolve a hostname to IPs and reject any that fall in blocked ranges.
fn resolve_allowed_ip(host: &str) -> Result<IpAddr, ProxyError> {
    let addrs: Vec<IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .map_err(|e| ProxyError::Dns(format!("{host}: {e}")))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err(ProxyError::Dns(format!("{host}: no addresses")));
    }
    for addr in &addrs {
        if is_blocked_ip(addr) {
            continue;
        }
        return Ok(*addr);
    }
    Err(ProxyError::BlockedIp(format!("{host}: all resolved IPs are blocked")))
}

fn is_blocked_ip(addr: &IpAddr) -> bool {
    let ip = match addr {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return true, // block IPv6 (no IPv6 metadata route by construction)
    };
    let octets = ip.octets();
    // 169.254.0.0/16 link-local / cloud metadata
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 127.0.0.0/8 loopback
    if octets[0] == 127 {
        return true;
    }
    // 0.0.0.0/8 this network
    if octets[0] == 0 {
        return true;
    }
    // 224.0.0.0/4 multicast
    if octets[0] >= 224 {
        return true;
    }
    false
}

/// Determine default port for a scheme.
fn default_port(host: &str) -> u16 {
    // If host contains a port, use it; else 443 for https-ish, 80 otherwise.
    if host.contains(':') {
        return host.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(443);
    }
    443
}

/// The egress proxy. All guest network flows through here.
pub struct Proxy {
    tls: TlsConnector,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl Proxy {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            tls: TlsConnector::new()?,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
        })
    }

    /// Dial the upstream and perform an HTTP request. Returns status + body.
    /// The caller (supervisor) is responsible for budget checks and credential
    /// injection; this method only does network I/O.
    pub fn fetch(
        &self,
        upstream: &str,
        method: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<ProxyResponse, ProxyError> {
        let port = default_port(upstream);
        let ip = resolve_allowed_ip(upstream)?;
        let socket_addr = std::net::SocketAddr::new(ip, port);

        let stream = TcpStream::connect_timeout(&socket_addr, self.connect_timeout)
            .map_err(|e| ProxyError::Connect(format!("{socket_addr}: {e}")))?;
        stream.set_read_timeout(Some(self.read_timeout)).map_err(|e| ProxyError::Io(e.to_string()))?;
        stream.set_write_timeout(Some(self.read_timeout)).map_err(|e| ProxyError::Io(e.to_string()))?;

        let mut stream: Box<dyn IoStream> = Box::new(stream);
        let use_tls = port == 443 || upstream.ends_with(":443");
        if use_tls {
            let domain = upstream.split(':').next().unwrap_or(upstream);
            let tls_stream = self
                .tls
                .connect(domain, stream)
                .map_err(|e| ProxyError::Tls(e.to_string()))?;
            stream = Box::new(tls_stream);
        }

        // Build HTTP request.
        let mut req = String::new();
        req.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
        req.push_str(&format!("Host: {upstream}\r\n"));
        req.push_str("Connection: close\r\n");
        for (name, value) in headers {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).map_err(|e| ProxyError::Io(e.to_string()))?;
        stream.flush().map_err(|e| ProxyError::Io(e.to_string()))?;

        // Read response until connection close.
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(ProxyError::Io(e.to_string())),
            }
        }

        // Split headers from body.
        let body_start = find_body_start(&buf);
        let body = buf[body_start..].to_vec();

        // Extract status code.
        let status = parse_status(&buf).unwrap_or(0);

        Ok(ProxyResponse { status, body })
    }
}

/// Find the start of the body in an HTTP response (after \r\n\r\n).
fn find_body_start(buf: &[u8]) -> usize {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len())
}

/// Parse the HTTP status code from the response head.
fn parse_status(buf: &[u8]) -> Option<u16> {
    let head = String::from_utf8_lossy(&buf[..buf.len().min(200)]);
    let first_line = head.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Per-destination budgets (M2 damage bound). Returns false when over budget.
///
/// Budgets are persisted to disk so damage bounds survive supervisor
/// restarts. Without a path, budgets are in-memory only (back-compat).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Budgets {
    pub bytes: HashMap<String, u64>,
    pub requests: HashMap<String, u64>,
    #[serde(skip)]
    persist_path: Option<PathBuf>,
}

impl Budgets {
    /// Create budgets with persistence to the given path. Loads existing
    /// state if the file exists, otherwise starts fresh.
    pub fn with_path(path: &Path) -> anyhow::Result<Self> {
        let mut b = Self { bytes: HashMap::new(), requests: HashMap::new(), persist_path: Some(path.to_path_buf()) };
        if path.exists() {
            let data = fs::read(path).map_err(|e| anyhow::anyhow!("io: {e}"))?;
            let saved: Budgets = serde_json::from_slice(&data)
                .map_err(|e| anyhow::anyhow!("deserialize: {e}"))?;
            b.bytes = saved.bytes;
            b.requests = saved.requests;
        }
        Ok(b)
    }

    /// Persist current budget state to disk atomically.
    fn save(&self) -> anyhow::Result<()> {
        let path = self.persist_path.as_ref().ok_or_else(|| anyhow::anyhow!("no persist path"))?;
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("serialize: {e}"))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, data).map_err(|e| anyhow::anyhow!("io: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("io: {e}"))?;
        Ok(())
    }

    pub fn check(&mut self, dest: &str, bytes: u64, max_bytes: u64, max_req: u64) -> bool {
        let b = self.bytes.entry(dest.to_string()).or_insert(0);
        let r = self.requests.entry(dest.to_string()).or_insert(0);
        if *r >= max_req || *b + bytes > max_bytes {
            return false;
        }
        *b += bytes;
        *r += 1;
        // Persist after every successful charge so damage bounds survive restarts.
        if let Some(_path) = &self.persist_path {
            if let Err(e) = self.save() {
                eprintln!("budget persist failed: {e}");
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toolcage_policy::load_yaml;

    fn sample() -> Policy {
        load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
    }

    #[test]
    fn alias_resolves_and_allows() {
        let d = decide(&sample(), "github.internal", "GET", "/repos/acme/app/issues/1");
        assert!(d.allow);
        assert_eq!(d.upstream.as_deref(), Some("api.github.com"));
    }

    #[test]
    fn metadata_has_no_path() {
        for h in ["169.254.169.254", "metadata.google.internal", "instance-data"] {
            let d = decide(&sample(), h, "GET", "/");
            assert!(!d.allow, "{h} must be denied");
        }
    }

    #[test]
    fn raw_unknown_host_denied() {
        let d = decide(&sample(), "evil.example.com", "GET", "/");
        assert!(!d.allow);
    }

    #[test]
    fn budgets_bound_damage() {
        let mut b = Budgets::default();
        assert!(b.check("github", 100, 150, 2));
        assert!(!b.check("github", 100, 150, 2)); // over bytes
    }

    #[test]
    fn blocked_ip_detection() {
        assert!(is_blocked_ip(&"169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip(&"0.0.0.0".parse().unwrap()));
        assert!(!is_blocked_ip(&"1.1.1.1".parse().unwrap()));
        assert!(is_blocked_ip(&"::1".parse().unwrap())); // IPv6 loopback blocked
    }

    #[test]
    fn find_body_start_works() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(find_body_start(resp), 38);
        assert_eq!(&resp[38..], b"hello");
    }

    #[test]
    fn parse_status_works() {
        let resp = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(parse_status(resp), Some(200));
        let resp = b"HTTP/1.1 404 Not Found\r\n\r\n";
        assert_eq!(parse_status(resp), Some(404));
    }
}
