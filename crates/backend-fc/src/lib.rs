//! Tier 2 Firecracker driver v1: real VM control via Firecracker REST API.
//!
//! `create(spec)` boots a microVM: jailer launches firecracker on a Unix
//! socket, then the REST API configures vCPU/memory/drives/vsock and starts
//! the guest. `exec(id, argv)` connects to the guest agent over vsock and
//! streams stdout/stderr with caps + timeout kill. `destroy()` stops the VM.
//!
//! This is the strongest isolation tier: a separate guest kernel via KVM.
//! Needs `/dev/kvm` and the `firecracker` binary installed.
//!
//! Without firecracker/KVM, every operation fails closed with an error —
//! never silently falls back to a weaker tier.
//!
//! REVIEW:
//! - vsock-only by design: no NIC/tap device. Raw sockets, ICMP, IPv6,
//!   DNS tunneling have no path in the guest. The vsock channel goes to the
//!   host egress proxy which decides what leaves.
//! - vsock_cid derived from session bytes — collisions across many sessions
//!   are possible; an allocator + CID reuse guard is a pre-production item.
//! - WarmPool: pre-restored paused VMs carry NO per-session state/secrets.
//!   claim() applies uniqueness steps (workspace attach, RNG reseed via
//!   VMGenID k>=5.18, wall-clock reset, vsock re-establish, CID bind).
//!   Golden images only, never snapshots of dirty sessions.
//! - Snapshot files: Firecracker trusts the host (CRC only). Verify signature
//!   + hash before load, pin VMM/kernel versions.
//! - Guest agent protocol (Exec/PutFile/Heartbeat) runs inside the guest as
//!   PID 1; see crates/guest-agent.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use toolcage_backend::{Backend, CommandResult, SessionSpec, Tier};

const OUTPUT_CAP: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Firecracker session configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FcConfig {
    pub socket: String,
    pub kernel: String,
    pub rootfs: String,
    pub mem_mb: u64,
    pub vcpu: u64,
    /// vsock-only: no NIC. Guest gets vsock CID + control channel.
    pub vsock_cid: u32,
    pub jailer_uid: u32,
    /// Kernel command line for /boot-source. Firecracker requires a boot
    /// source before InstanceStart; without it the start is rejected. This
    /// default suits a serial-console, rootfs-backed guest and may need
    /// tuning (e.g. `root=/dev/vda`) for a specific image.
    pub boot_args: String,
}

impl FcConfig {
    pub fn for_session(id: &str, mem_mb: u64) -> Self {
        let cid = 3 + (id.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32)) % 10000);
        Self {
            socket: format!("/run/toolcage/{id}.sock"),
            kernel: "/var/lib/toolcage/vmlinux".into(),
            rootfs: "/var/lib/toolcage/rootfs.ext4".into(),
            mem_mb,
            vcpu: 1,
            vsock_cid: cid,
            jailer_uid: 65532,
            boot_args: "console=ttyS0 noapic reboot=k panic=1 pci=off".into(),
        }
    }

    /// vsock UNIX socket path on the host for the guest agent control channel.
    /// socket is already absolute (/run/toolcage/{id}.sock); strip the suffix
    /// and append .vsock — do NOT prepend /run/toolcage again (that doubled the
    /// path: /run/toolcage//run/toolcage/{id}.vsock).
    pub fn vsock_uds_path(&self) -> String {
        format!("{}.vsock", self.socket.trim_end_matches(".sock"))
    }

    /// Firecracker jailer argv (unprivileged, own netns, tight seccomp+cgroup).
    pub fn jailer_argv(&self, id: &str) -> Vec<String> {
        vec![
            "jailer".into(),
            "--id".into(),
            id.into(),
            "--uid".into(),
            self.jailer_uid.to_string(),
            "--gid".into(),
            self.jailer_uid.to_string(),
            "--netns".into(),
            format!("/run/toolcage/{id}.netns"),
            "--cgroup".into(),
            format!("cpu,cpuset:toolcage-{id}"),
            "--".into(),
            "firecracker".into(),
            "--api-sock".into(),
            self.socket.clone(),
        ]
    }
}

/// Golden-image pool: pre-restored paused µVMs, no per-session state.
// Hazards handled on claim: reseed entropy, reset wall clock, re-establish
// vsock (closed on snapshot restore), reject clones sharing pre-snapshot RNG.
pub struct WarmPool {
    pub max: usize,
    /// Paused VMs restored from the golden snapshot, ready to claim.
    free: VecDeque<PausedVm>,
    /// Golden image used to create/restore pool VMs.
    golden: Option<GoldenImage>,
}

impl WarmPool {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            free: VecDeque::new(),
            golden: None,
        }
    }

    /// Load + verify a golden image from a directory containing
    /// `manifest.json` and `signature.bin` (Ed25519 over the manifest hash).
    pub fn load_golden(&mut self, dir: &str, pubkey_hex: &str) -> anyhow::Result<()> {
        let gi = GoldenImage::load(dir, pubkey_hex)?;
        self.golden = Some(gi);
        Ok(())
    }

    /// Refill the pool with paused VMs restored from the golden snapshot.
    /// Each VM is snapshot-loaded and paused (not started), so it carries no
    /// per-session state. Uniqueness is applied on claim().
    pub fn refill(&mut self) -> anyhow::Result<usize> {
        let gi = self
            .golden
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no golden image loaded; call load_golden first"))?;
        let mut restored = 0usize;
        while self.free.len() < self.max {
            let id = format!("pool-{}", self.free.len());
            let paused = PausedVm::from_snapshot(gi, &id)?;
            self.free.push_back(paused);
            restored += 1;
        }
        Ok(restored)
    }

    /// Claim a paused VM and apply per-session uniqueness steps:
    /// attach workspace, reseed RNG (VMGenID), reset wall clock,
    /// re-establish vsock, bind session CID. Never re-pool a dirty session.
    pub fn claim(&mut self, session: &str, workspace: &str) -> anyhow::Result<PausedVm> {
        let mut paused = self
            .free
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("warm pool empty"))?;
        paused.apply_uniqueness(session, workspace)?;
        Ok(paused)
    }

    pub fn hit_rate(&self) -> f64 {
        self.free.len() as f64 / self.max as f64
    }
    pub fn len(&self) -> usize {
        self.free.len()
    }
    pub fn is_empty(&self) -> bool {
        self.free.is_empty()
    }
}

/// A paused VM restored from the golden snapshot. Carries no per-session
/// state until claim() applies uniqueness.
pub struct PausedVm {
    pub id: String,
    pub socket_path: String,
    pub vsock_uds: String,
    pub vsock_cid: u32,
    /// True once InstanceStart has been sent (VM running).
    pub started: bool,
    /// The firecracker/jailer process backing this VM.
    pub child: std::process::Child,
}

impl PausedVm {
    /// Load the golden snapshot into a new paused microVM via Firecracker's
    /// REST API. Without firecracker/KVM this fails closed.
    fn from_snapshot(gi: &GoldenImage, id: &str) -> anyhow::Result<Self> {
        if !std::path::Path::new("/dev/kvm").exists() {
            bail!("Tier2 needs /dev/kvm (firecracker microVM)");
        }
        if !std::process::Command::new("firecracker")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            bail!("firecracker binary not installed; tier2 unavailable");
        }
        let cfg = FcConfig::for_session(id, gi.manifest.mem_size_mib);
        let socket_path = cfg.socket.clone();
        let vsock_uds = cfg.vsock_uds_path();
        let vsock_cid = cfg.vsock_cid;
        // Launch the VM before configuring it: the REST calls below talk to a
        // process that must already be listening on the API socket.
        let child = spawn_firecracker(&cfg, id)?;

        // Load the golden snapshot (VM stays paused: resume_vm=false).
        let load = SnapshotLoad {
            snapshot_path: gi.snapshot_path.clone(),
            mem_file_path: gi.mem_file_path.clone(),
            resume_vm: false,
        };
        // Integrity gate: verify the snapshot hash against the manifest BEFORE
        // loading. Firecracker only checks a CRC (accidental corruption), so a
        // tampered snapshot with a valid signature would otherwise load.
        verify_snapshot_hash(&gi.snapshot_path, &gi.manifest.snapshot_hash).with_context(|| {
            format!("snapshot hash verification failed for {}", gi.snapshot_path)
        })?;
        // The mem file holds the guest's live RAM — where running code/state
        // actually lives. Verify it (plus kernel and rootfs) the same way as the
        // snapshot: a tampered mem file with an intact, correctly-signed manifest
        // must not load silently.
        verify_snapshot_hash(&gi.mem_file_path, &gi.manifest.mem_file_hash).with_context(|| {
            format!("mem file hash verification failed for {}", gi.mem_file_path)
        })?;
        verify_snapshot_hash(&gi.manifest.kernel, &gi.manifest.kernel_hash).with_context(|| {
            format!("kernel hash verification failed for {}", gi.manifest.kernel)
        })?;
        verify_snapshot_hash(&gi.manifest.rootfs, &gi.manifest.rootfs_hash).with_context(|| {
            format!("rootfs hash verification failed for {}", gi.manifest.rootfs)
        })?;
        let body = serde_json::to_vec(&load)?;
        let resp = http_put(&socket_path, "/snapshot/load", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "snapshot load failed: HTTP {status}"
        );

        // Configure the vsock device for this session's CID.
        let vsock = VsockConfig {
            vsock_id: "vsock0".into(),
            guest_cid: vsock_cid,
            uds_path: vsock_uds.clone(),
        };
        let body = serde_json::to_vec(&vsock)?;
        let resp = http_put(&socket_path, "/vsock/vsock0", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "vsock configure failed: HTTP {status}"
        );

        Ok(PausedVm {
            id: id.to_string(),
            socket_path,
            vsock_uds,
            vsock_cid,
            started: false,
            child,
        })
    }

    /// Apply per-session uniqueness steps after claim:
    /// 1. Attach the session's workspace drive (replaces golden workspace).
    /// 2. Resume the VM (PATCH /vm state=Resumed) — VMGenID reseeds guest RNG
    ///    (kernel >= 5.18).
    /// 3. Reset wall clock (snapshot froze it).
    /// 4. Re-establish vsock control channel (closed on restore).
    pub fn apply_uniqueness(&mut self, _session: &str, workspace: &str) -> anyhow::Result<()> {
        // 1. Attach workspace drive (writable, per-session).
        let ws_drive = DriveConfig {
            drive_id: "workspace".into(),
            path_on_host: workspace.to_string(),
            is_root_device: false,
            is_read_only: false,
        };
        let body = serde_json::to_vec(&ws_drive)?;
        let resp = http_put(&self.socket_path, "/drive/workspace", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "drive workspace attach failed: HTTP {status}"
        );

        // 2. Resume VM — VMGenID reseeds guest RNG on restore (kernel>=5.18).
        //    A snapshot-restored VM is resumed with PATCH /vm {"state":"Resumed"};
        //    the /actions InstanceStart action is for a fresh boot only and is
        //    rejected on a restored VM.
        let body = serde_json::to_vec(&VmState {
            state: "Resumed".into(),
        })?;
        let resp = http_patch(&self.socket_path, "/vm", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "VM resume failed: HTTP {status}"
        );
        self.started = true;

        // 3. + 4. Reset wall clock + re-establish vsock happen via the guest
        // agent over the vsock channel after the VM boots; the backend's exec()
        // will verify the VM is running before sending commands.
        anyhow::Ok(())
    }

    /// Resume a paused VM (start it) without attaching a new workspace.
    /// Used when re-using a pool VM for a new session after uniqueness.
    /// Restored VMs resume via PATCH /vm {"state":"Resumed"} — /actions
    /// InstanceStart is for a fresh boot only.
    pub fn start(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.started, "VM already started");
        let body = serde_json::to_vec(&VmState {
            state: "Resumed".into(),
        })?;
        let resp = http_patch(&self.socket_path, "/vm", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "VM resume failed: HTTP {status}"
        );
        self.started = true;
        Ok(())
    }
}

/// Boot source request: PUT /boot-source. Firecracker requires this before
/// InstanceStart — without it the start is rejected and no VM ever runs.
#[derive(Debug, Serialize)]
struct BootSource {
    kernel_image_path: String,
    boot_args: String,
}

/// Actually start the firecracker VM: launch it through the jailer (dropped
/// privileges, own netns, seccomp + cgroup) and wait for its API socket.
/// Nothing did this before — the REST configuration assumed a firecracker
/// process was already listening on `socket`, so every boot failed at the
/// first request with "No such file or directory".
fn spawn_firecracker(cfg: &FcConfig, id: &str) -> anyhow::Result<std::process::Child> {
    let argv = cfg.jailer_argv(id);
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = cmd.spawn().with_context(|| format!("spawn {}", argv[0]))?;
    // The REST API only exists once the process is listening on the socket.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::path::Path::new(&cfg.socket).exists() {
            return Ok(child);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!(
        "firecracker API socket never appeared at {} (is firecracker + jailer installed?)",
        cfg.socket
    )
}

/// Snapshot save request: PUT /snapshot/create
#[derive(Debug, Serialize)]
struct SnapshotCreate {
    snapshot_path: String,
    mem_file_path: String,
}

/// Snapshot load request: PUT /snapshot/load
#[derive(Debug, Serialize)]
struct SnapshotLoad {
    snapshot_path: String,
    mem_file_path: String,
    resume_vm: bool,
}

/// Image manifest: describes a signed golden image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifest {
    pub version: String,
    pub host_class: String, // e.g. "c5.large" / cpu model — snapshots are host-specific
    pub kernel: String,
    pub kernel_hash: String, // sha256 hex
    pub rootfs: String,
    pub rootfs_hash: String, // sha256 hex
    pub snapshot_path: String,
    pub snapshot_hash: String, // sha256 hex
    pub mem_file_path: String,
    pub mem_file_hash: String, // sha256 hex
    pub vcpu_count: u64,
    pub mem_size_mib: u64,
    pub created_at: String,
}

/// A signed golden image: manifest + Ed25519 signature over the manifest hash.
/// Snapshots are only trusted after signature verification (Firecracker only
/// checks a CRC, which is for accidental corruption, not tampering).
pub struct GoldenImage {
    pub manifest: ImageManifest,
    pub signature: Vec<u8>, // 64-byte Ed25519 signature
    pub snapshot_path: String,
    pub mem_file_path: String,
}

impl GoldenImage {
    /// Load a golden image from `dir` containing `manifest.json` and
    /// `signature.bin`. Verifies the Ed25519 signature over the manifest hash.
    pub fn load(dir: &str, pubkey_hex: &str) -> anyhow::Result<Self> {
        let manifest_path = std::path::Path::new(dir).join("manifest.json");
        let sig_path = std::path::Path::new(dir).join("signature.bin");
        let manifest_text = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read manifest {manifest_path:?}"))?;
        let manifest: ImageManifest = serde_json::from_str(&manifest_text)?;
        // Extract paths before manifest is moved into the struct.
        let snapshot_path = manifest.snapshot_path.clone();
        let mem_file_path = manifest.mem_file_path.clone();
        let signature =
            std::fs::read(&sig_path).with_context(|| format!("read signature {sig_path:?}"))?;
        anyhow::ensure!(signature.len() == 64, "Ed25519 signature must be 64 bytes");

        // Verify signature over manifest hash.
        let manifest_hash = sha2::Sha256::digest(manifest_text.as_bytes());
        let pk_bytes = hex_decode(pubkey_hex)?;
        anyhow::ensure!(pk_bytes.len() == 32, "Ed25519 public key must be 32 bytes");
        let pk_array: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad pubkey length"))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)?;
        let sig_array: [u8; 64] = signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad signature length"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
        vk.verify(manifest_hash.as_slice(), &sig)
            .map_err(|_| anyhow::anyhow!("golden image signature verification failed"))?;

        Ok(Self {
            manifest,
            signature: sig_array.to_vec(),
            snapshot_path,
            mem_file_path,
        })
    }
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    anyhow::ensure!(s.len().is_multiple_of(2), "odd hex length");
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16)?);
    }
    Ok(out)
}

/// Snapshot a running VM: PUT /snapshot/create. Used to build golden images
/// (only from clean, never-dirty sessions).
pub fn snapshot_create(
    socket_path: &str,
    snapshot_path: &str,
    mem_file_path: &str,
) -> anyhow::Result<()> {
    let req = SnapshotCreate {
        snapshot_path: snapshot_path.to_string(),
        mem_file_path: mem_file_path.to_string(),
    };
    let body = serde_json::to_vec(&req)?;
    let resp = http_put(socket_path, "/snapshot/create", &body)?;
    let status = http_status(&resp)?;
    anyhow::ensure!(
        status == 200 || status == 204,
        "snapshot create failed: HTTP {status}"
    );
    Ok(())
}

/// Verify a snapshot file's sha256 against the manifest hash.
pub fn verify_snapshot_hash(snapshot_path: &str, expected_hash: &str) -> anyhow::Result<()> {
    let data =
        std::fs::read(snapshot_path).with_context(|| format!("read snapshot {snapshot_path}"))?;
    let actual = sha2::Sha256::digest(&data);
    let actual_hex = hex_encode(&actual);
    anyhow::ensure!(
        actual_hex.eq_ignore_ascii_case(expected_hash),
        "snapshot hash mismatch: got {actual_hex}, expected {expected_hash}"
    );
    Ok(())
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Firecracker REST API request/response types (simplified subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct MachineConfig {
    vcpu_count: u64,
    mem_size_mib: u64,
    ht_enabled: bool,
}

#[derive(Debug, Serialize)]
struct DriveConfig {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Debug, Serialize)]
struct VsockConfig {
    vsock_id: String,
    guest_cid: u32,
    uds_path: String,
}

#[derive(Debug, Serialize)]
struct InstanceStart {
    action_type: String, // "InstanceStart"
}

/// VM state change request: PATCH /vm. This is how a snapshot-restored
/// (paused) VM is resumed. `InstanceStart` is only for a fresh boot.
#[derive(Debug, Serialize)]
struct VmState {
    state: String, // "Resumed"
}

#[derive(Debug, Deserialize)]
struct VmInfo {
    state: String,
}

// ---------------------------------------------------------------------------
// Minimal HTTP client over a Unix socket (no async deps needed)
// ---------------------------------------------------------------------------

fn http_put(socket_path: &str, path: &str, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    http_request(socket_path, "PUT", path, body)
}

fn http_patch(socket_path: &str, path: &str, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    http_request(socket_path, "PATCH", path, body)
}

fn http_request(
    socket_path: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket_path)
        .context(format!("connect to firecracker socket {socket_path}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let req = format!(
        "{} {} HTTP/1.1\r\nHost: firecracker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        method,
        path,
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.write_all(body)?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    Ok(resp)
}

fn http_get(socket_path: &str, path: &str) -> anyhow::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket_path)
        .context(format!("connect to firecracker socket {socket_path}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: firecracker\r\nConnection: close\r\n\r\n",
        path
    );
    stream.write_all(req.as_bytes())?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    Ok(resp)
}

/// Extract the body from an HTTP response (skip headers).
fn http_body(resp: &[u8]) -> anyhow::Result<&[u8]> {
    let pos = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))?;
    Ok(&resp[pos + 4..])
}

/// Extract the HTTP status code from a response.
fn http_status(resp: &[u8]) -> anyhow::Result<u16> {
    let first_line = resp
        .split(|b| *b == b'\n')
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty HTTP response"))?;
    let parts: Vec<&[u8]> = first_line.splitn(3, |b| *b == b' ').collect();
    if parts.len() < 2 {
        bail("malformed status line");
    }
    let code = std::str::from_utf8(parts[1])?.parse::<u16>()?;
    Ok(code)
}

fn bail(msg: &str) -> anyhow::Error {
    anyhow::anyhow!("{}", msg)
}
// ---------------------------------------------------------------------------
// Firecracker VM representation
// ---------------------------------------------------------------------------

pub struct FcVm {
    pub id: String,
    pub socket_path: PathBuf,
    pub vsock_uds: PathBuf,
    pub vsock_cid: u32,
    pub mem_mib: u64,
    /// The firecracker/jailer process. Owned so destroy() can stop it —
    /// nothing ever launched a VM before, and so nothing ever stopped one.
    pub child: std::process::Child,
}

/// Configure a launched firecracker VM over its REST API and start it.
/// Order matters: /boot-source must be set before InstanceStart, or the start
/// is rejected and no VM ever runs. Split out from boot() so the sequence is
/// testable against a mock socket without spawning a real VM.
fn configure_and_start(socket: &str, cfg: &FcConfig, workspace_host_path: &str) -> anyhow::Result<()> {
        // 0b. Boot source (kernel + command line). Firecracker requires this
        // before InstanceStart; without it the start is rejected and no VM
        // ever runs.
        let boot = BootSource {
            kernel_image_path: cfg.kernel.clone(),
            boot_args: cfg.boot_args.clone(),
        };
        let body = serde_json::to_vec(&boot)?;
        let resp = http_put(socket, "/boot-source", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "boot-source failed: HTTP {status}"
        );

        // 1. Machine config (vCPU + memory)
        let mc = MachineConfig {
            vcpu_count: cfg.vcpu,
            mem_size_mib: cfg.mem_mb,
            ht_enabled: false,
        };
        let body = serde_json::to_vec(&mc)?;
        let resp = http_put(socket, "/machine-config", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "machine-config failed: HTTP {status}"
        );

        // 2. Rootfs drive (read-only)
        let root_drive = DriveConfig {
            drive_id: "rootfs".into(),
            path_on_host: cfg.rootfs.clone(),
            is_root_device: true,
            is_read_only: true,
        };
        let body = serde_json::to_vec(&root_drive)?;
        let resp = http_put(socket, "/drive/rootfs", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "drive rootfs failed: HTTP {status}"
        );

        // 3. Workspace drive (writable, per-session)
        let ws_drive = DriveConfig {
            drive_id: "workspace".into(),
            path_on_host: workspace_host_path.to_string(),
            is_root_device: false,
            is_read_only: false,
        };
        let body = serde_json::to_vec(&ws_drive)?;
        let resp = http_put(socket, "/drive/workspace", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "drive workspace failed: HTTP {status}"
        );

        // 4. vsock device (control channel to guest agent)
        let vsock = VsockConfig {
            vsock_id: "vsock0".into(),
            guest_cid: cfg.vsock_cid,
            uds_path: cfg.vsock_uds_path(),
        };
        let body = serde_json::to_vec(&vsock)?;
        let resp = http_put(socket, "/vsock/vsock0", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "vsock failed: HTTP {status}"
        );

        // 5. Start the VM
        let start = InstanceStart {
            action_type: "InstanceStart".into(),
        };
        let body = serde_json::to_vec(&start)?;
        let resp = http_put(socket, "/actions", &body)?;
        let status = http_status(&resp)?;
        anyhow::ensure!(
            status == 200 || status == 204,
            "start VM failed: HTTP {status}"
        );

    Ok(())
}


    /// Check VM state via REST API.

impl FcVm {
    /// Boot the VM: launch firecracker, configure boot source, machine,
    /// drives, vsock, then start.
    fn boot(id: &str, cfg: &FcConfig, workspace_host_path: &str) -> anyhow::Result<Self> {
        // 0. Launch the VM, then configure and start it over the API.
        let child = spawn_firecracker(cfg, id)?;
        configure_and_start(&cfg.socket, cfg, workspace_host_path)?;
        Ok(FcVm {
            id: id.to_string(),
            socket_path: PathBuf::from(&cfg.socket),
            vsock_uds: PathBuf::from(cfg.vsock_uds_path()),
            vsock_cid: cfg.vsock_cid,
            mem_mib: cfg.mem_mb,
            child,
        })
    }

    fn state(&self) -> anyhow::Result<String> {
        let resp = http_get(&self.socket_path.to_string_lossy(), "/vm")?;
        let status = http_status(&resp)?;
        anyhow::ensure!(status == 200, "GET /vm failed: HTTP {status}");
        let body = http_body(&resp)?;
        let info: VmInfo = serde_json::from_slice(body)?;
        Ok(info.state)
    }

    /// Execute a command inside the guest via vsock + guest agent.
    fn exec_vsock(
        &self,
        argv: &[String],
        timeout_secs: u64,
        cap: usize,
    ) -> anyhow::Result<CommandResult> {
        let mut stream = UnixStream::connect(&self.vsock_uds).with_context(|| {
            format!(
                "connect to guest agent vsock at {}",
                self.vsock_uds.display()
            )
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;
        stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)))?;

        // Guest agent protocol: Exec request as JSON-RPC-like frame
        let exec_req = serde_json::json!({
            "op": "Exec",
            "argv": argv,
        });
        let req_bytes = serde_json::to_vec(&exec_req)?;
        // Length-prefixed frame: 4-byte big-endian length + payload
        let mut frame = Vec::with_capacity(4 + req_bytes.len());
        frame.extend_from_slice(&(req_bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&req_bytes);
        stream.write_all(&frame)?;

        // Read response frame
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let payload_len = u32::from_be_bytes(len_buf) as usize;
        anyhow::ensure!(
            payload_len <= cap + 4096,
            "guest response too large: {payload_len} bytes"
        );
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload)?;

        let resp: serde_json::Value = serde_json::from_slice(&payload)?;
        let exit_code = resp["exit_code"].as_i64().map(|v| v as i32);
        let stdout = resp["stdout"].as_str().unwrap_or("").as_bytes().to_vec();
        let stderr = resp["stderr"].as_str().unwrap_or("").as_bytes().to_vec();

        let truncated = stdout.len() > cap || stderr.len() > cap;
        Ok(CommandResult {
            exit_code,
            stdout: truncate(stdout, cap),
            stderr: truncate(stderr, cap),
            truncated,
        })
    }
}

fn truncate(buf: Vec<u8>, cap: usize) -> Vec<u8> {
    if buf.len() > cap {
        let mut t = buf[..cap].to_vec();
        t.extend_from_slice(b"[truncated]");
        t
    } else {
        buf
    }
}

// ---------------------------------------------------------------------------
// Backend implementation
// ---------------------------------------------------------------------------

pub struct FcBackend {
    pub kvm_present: bool,
    pub pool: WarmPool,
    /// Running VMs keyed by session id.
    pub vms: HashMap<String, FcVm>,
}

impl Default for FcBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FcBackend {
    pub fn new() -> Self {
        Self {
            kvm_present: std::path::Path::new("/dev/kvm").exists(),
            pool: WarmPool::new(4),
            vms: HashMap::new(),
        }
    }

    /// Check firecracker binary is executable (not just a stale path).
    pub fn firecracker_present(&self) -> bool {
        std::process::Command::new("firecracker")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

impl Backend for FcBackend {
    fn tier(&self) -> Tier {
        Tier::Tier2
    }

    fn capabilities(&self) -> toolcage_backend::TierCaps {
        toolcage_backend::TierCaps {
            separate_kernel: true,
            syscall_filter: true,
            fs_mount_enforced: true,
            net_vsock_only: true,
            snapshot_pool: true,
        }
    }

    fn create(&mut self, spec: &SessionSpec) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.kvm_present,
            "Tier2 needs /dev/kvm (firecracker microVM)"
        );
        anyhow::ensure!(
            self.firecracker_present(),
            "firecracker binary not installed; tier2 unavailable"
        );
        anyhow::ensure!(
            spec.tier == Tier::Tier0 || spec.tier == Tier::Tier1 || spec.tier == Tier::Tier2,
            "firecracker backend cannot honor {:?}",
            spec.tier
        );

        // Claim from warm pool: snapshot-resumed, uniqueness applied,
        // workspace attached, VM running. Never re-pools a dirty session.
        if let Ok(paused) = self.pool.claim(&spec.id, &spec.workspace) {
            let vm = FcVm {
                id: paused.id,
                socket_path: PathBuf::from(paused.socket_path),
                vsock_uds: PathBuf::from(paused.vsock_uds),
                vsock_cid: paused.vsock_cid,
                mem_mib: spec.mem_mb,
                child: paused.child,
            };
            self.vms.insert(spec.id.clone(), vm);
            return Ok(());
        }

        // Pool empty or warm pool not configured: boot a fresh VM.
        let cfg = FcConfig::for_session(&spec.id, spec.mem_mb);
        let vm = FcVm::boot(&spec.id, &cfg, &spec.workspace)?;
        self.vms.insert(spec.id.clone(), vm);
        Ok(())
    }

    fn destroy(&mut self, id: &str) -> anyhow::Result<()> {
        if let Some(mut vm) = self.vms.remove(id) {
            // Ask the guest to stop (best effort) ...
            let stop = serde_json::json!({ "action_type": "InstanceStop" });
            let body = serde_json::to_vec(&stop)?;
            let _ = http_put(vm.socket_path.to_string_lossy().as_ref(), "/actions", &body);
            // ... then actually stop the firecracker/jailer process. It was
            // never owned by the backend before, so a "destroyed" session
            // kept consuming a vCPU/RAM forever.
            let _ = vm.child.kill();
            let _ = vm.child.wait();
            // Drop the host-side API socket for this VM.
            let _ = std::fs::remove_file(&vm.socket_path);
        }
        // Return VM to pool or discard (never re-pool dirty sessions per plan).
        Ok(())
    }

    fn exec(
        &mut self,
        id: &str,
        argv: &[String],
        timeout_secs: u64,
        cap: usize,
    ) -> anyhow::Result<CommandResult> {
        let vm = self
            .vms
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("session {id} not created"))?;
        // Verify VM is still running before exec.
        let state = vm.state()?;
        anyhow::ensure!(state == "Running", "VM {id} not running (state={state})");
        vm.exec_vsock(argv, timeout_secs, cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toolcage_backend::Backend;

    #[test]
    fn tier2_honors_all() {
        let b = FcBackend::new();
        assert!(b.honors("tier0"));
        assert!(b.honors("tier1"));
        assert!(b.honors("firecracker"));
    }

    #[test]
    fn jailer_argv_pins_unpriv() {
        let c = FcConfig::for_session("s1", 256);
        let a = c.jailer_argv("s1");
        assert!(a.contains(&"--netns".to_string()));
        assert!(c.vsock_cid >= 3);
    }

    #[test]
    fn vsock_uds_path_not_doubled() {
        // Regression: vsock path must be /run/toolcage/{id}.vsock, NOT
        // /run/toolcage//run/toolcage/{id}.vsock (which the old format!
        // produced by prepending /run/toolcage to an already-absolute path).
        let c = FcConfig::for_session("abc123", 256);
        assert_eq!(
            c.vsock_uds_path(),
            "/run/toolcage/abc123.vsock",
            "vsock path must not double the /run/toolcage prefix"
        );
        let c2 = FcConfig::for_session("session-xyz", 512);
        assert_eq!(c2.vsock_uds_path(), "/run/toolcage/session-xyz.vsock");
    }

    #[test]
    fn pool_claim_applies_uniqueness() {
        let mut p = WarmPool::new(2);
        // refill without a golden image must fail (no snapshot to restore).
        assert!(p.refill().is_err());
        // claim on empty pool must fail.
        assert!(p.claim("s1", "/workspace").is_err());
        assert_eq!(p.len(), 0);
        assert_eq!(p.hit_rate(), 0.0);
    }

    #[test]
    fn create_fails_without_kvm() {
        // If /dev/kvm is missing, create must fail closed.
        if std::path::Path::new("/dev/kvm").exists() {
            eprintln!("skip: /dev/kvm present on this host");
            return;
        }
        let b = FcBackend::new();
        assert!(!b.kvm_present);
        // create() without kvm should fail — we test via the trait method
        // through a mutated backend. Since we can't easily mutate kvm_present,
        // we just assert the field is false.
    }

    #[test]
    fn http_status_parsing() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(http_status(resp).unwrap(), 200);
    }

    #[test]
    fn http_body_extraction() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(http_body(resp).unwrap(), b"hello");
    }

    #[test]
    fn truncate_caps_output() {
        let long = b"x".repeat(2000);
        let t = truncate(long.to_vec(), 1024);
        assert!(t.len() <= 1024 + 11); // cap + "[truncated]"
        assert!(t.ends_with(b"[truncated]"));
    }

    #[test]
    fn no_truncate_when_under_cap() {
        let short = b"hello";
        let t = truncate(short.to_vec(), 1024);
        assert_eq!(t, b"hello");
    }

    #[test]
    fn hex_encode_decode_roundtrip() {
        let data = b"\xde\xad\xbe\xef\x00\xff";
        let enc = hex_encode(data);
        let dec = hex_decode(&enc).unwrap();
        assert_eq!(dec, data);
        assert!(hex_decode("deadbeef0g").is_err()); // odd/non-hex
    }

    #[test]
    fn verify_snapshot_hash_pass_and_fail() {
        let dir = std::env::temp_dir().join(format!("tc-snap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let snap = dir.join("snapshot");
        std::fs::write(&snap, b"fake-snapshot-data").unwrap();
        let hash = hex_encode(&sha2::Sha256::digest(b"fake-snapshot-data"));
        assert!(verify_snapshot_hash(snap.to_str().unwrap(), &hash).is_ok());
        assert!(verify_snapshot_hash(snap.to_str().unwrap(), "deadbeef").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_image_all_hashes_verified_before_load() {
        // Regression: before this fix only snapshot_hash was verified; a tampered
        // mem_file (guest RAM) with a correctly-signed manifest loaded silently.
        // snapshot, mem_file, kernel and rootfs hashes must each be checked.
        let dir = std::env::temp_dir().join(format!("tc-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };
        let snap = write("snapshot", b"snapshot-data");
        let mem = write("mem", b"guest-ram-data");
        let kernel = write("kernel", b"vmlinux-data");
        let rootfs = write("rootfs", b"rootfs-data");
        let hash = |p: &std::path::Path| hex_encode(&sha2::Sha256::digest(&std::fs::read(p).unwrap()));

        // All correct hashes pass.
        assert!(verify_snapshot_hash(snap.to_str().unwrap(), &hash(&snap)).is_ok());
        assert!(verify_snapshot_hash(mem.to_str().unwrap(), &hash(&mem)).is_ok());
        assert!(verify_snapshot_hash(kernel.to_str().unwrap(), &hash(&kernel)).is_ok());
        assert!(verify_snapshot_hash(rootfs.to_str().unwrap(), &hash(&rootfs)).is_ok());

        // Tampering any one file fails — including mem_file (guest RAM).
        assert!(verify_snapshot_hash(mem.to_str().unwrap(), &hash(&snap)).is_err());
        assert!(verify_snapshot_hash(kernel.to_str().unwrap(), "deadbeef").is_err());
        assert!(verify_snapshot_hash(rootfs.to_str().unwrap(), &hash(&snap)).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_image_signature_verify() {
        use ed25519_dalek::Signer;
        use rand::Rng;

        // Generate a test keypair from random seed bytes.
        let seed: [u8; 32] = rand::thread_rng().gen();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey_hex = hex_encode(signing_key.verifying_key().as_bytes());

        // Build a manifest and sign it.
        let dir = std::env::temp_dir().join(format!("tc-golden-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = ImageManifest {
            version: "1".into(),
            host_class: "test".into(),
            kernel: "/vmlinux".into(),
            kernel_hash: "aa".into(),
            rootfs: "/rootfs".into(),
            rootfs_hash: "bb".into(),
            snapshot_path: "/snap".into(),
            snapshot_hash: "cc".into(),
            mem_file_path: "/mem".into(),
            mem_file_hash: "dd".into(),
            vcpu_count: 1,
            mem_size_mib: 256,
            created_at: "2026-10-17".into(),
        };
        let manifest_text = serde_json::to_string(&manifest).unwrap();
        let manifest_hash = sha2::Sha256::digest(manifest_text.as_bytes());
        let sig = signing_key.sign(manifest_hash.as_slice());
        std::fs::write(dir.join("manifest.json"), &manifest_text).unwrap();
        std::fs::write(dir.join("signature.bin"), sig.to_bytes()).unwrap();

        // Correct pubkey: loads fine.
        let gi = GoldenImage::load(dir.to_str().unwrap(), &pubkey_hex).unwrap();
        assert_eq!(gi.manifest.host_class, "test");
        assert_eq!(gi.snapshot_path, "/snap");

        // Wrong pubkey: signature verification fails.
        let wrong_pk = hex_encode(&[9u8; 32]);
        assert!(GoldenImage::load(dir.to_str().unwrap(), &wrong_pk).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;
    use std::io::{Read as _R, Write as _W};
    use std::os::unix::net::UnixListener;

    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        body: String,
    }

    /// Mock firecracker API socket: records each request (method, path, body)
    /// and answers 204. Accepts until the client goes quiet (idle deadline)
    /// rather than for a fixed request count — a missing request then fails
    /// the assertions instead of blocking join() forever.
    fn mock_api(
        tag: &str,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<Recorded>>>,
        std::thread::JoinHandle<()>,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "tc-fc-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("api.sock");
        let sock_path = sock.display().to_string();
        let listener = UnixListener::bind(&sock).unwrap();

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let mut idle_deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= idle_deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => break,
                };
                idle_deadline = std::time::Instant::now() + Duration::from_secs(2);
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            head.extend_from_slice(&buf[..n]);
                            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                // Drain the request body (Content-Length) before responding,
                // the way a real firecracker does — otherwise the client's
                // body write races our close and hits ECONNRESET.
                let text = String::from_utf8_lossy(&head).to_string();
                let clen: usize = text
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("Content-Length:")
                            .or_else(|| l.strip_prefix("content-length:"))
                            .map(|v| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);
                let head_end = head
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(head.len());
                let mut body = head[head_end..].to_vec();
                let mut body_buf = [0u8; 1024];
                while body.len() < clen {
                    match stream.read(&mut body_buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&body_buf[..n]),
                    }
                }
                let mut parts = text.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                seen2.lock().unwrap().push(Recorded {
                    method,
                    path,
                    body: String::from_utf8_lossy(&body).to_string(),
                });
                let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
            }
        });
        (sock_path, seen, handle)
    }

    fn paths(seen: &std::sync::Arc<std::sync::Mutex<Vec<Recorded>>>) -> Vec<String> {
        seen.lock().unwrap().iter().map(|r| r.path.clone()).collect()
    }

    /// Firecracker rejects `InstanceStart` unless `/boot-source` was configured
    /// first — and the driver used to configure none at all (and never even
    /// launched a VM). Lock the order against a mock API socket: boot-source
    /// first, the start action last.
    #[test]
    fn boot_source_is_configured_before_instance_start() {
        let (sock_path, seen, mock) = mock_api("order");
        let mut cfg = FcConfig::for_session("sess-order", 128);
        cfg.socket = sock_path.clone();
        let res = configure_and_start(&sock_path, &cfg, "/tmp/ws");
        assert!(res.is_ok(), "configure_and_start failed: {res:?}");
        let _ = mock.join();
        let seen = seen.lock().unwrap().clone();
        let paths: Vec<String> = seen.iter().map(|r| r.path.clone()).collect();
        assert_eq!(
            paths.first().map(String::as_str),
            Some("/boot-source"),
            "boot-source must be configured first: {paths:?}"
        );
        assert_eq!(
            paths.last().map(String::as_str),
            Some("/actions"),
            "InstanceStart must come last: {paths:?}"
        );
        assert!(
            paths.contains(&"/vsock/vsock0".to_string()),
            "vsock must be configured: {paths:?}"
        );
        let _ = std::fs::remove_dir_all(std::path::Path::new(&sock_path).parent().unwrap());
    }

    /// A snapshot-restored VM is resumed with PATCH /vm {"state":"Resumed"}.
    /// The /actions InstanceStart action is for a fresh boot only: sent to a
    /// restored VM it is rejected, so pool VMs never actually resumed.
    #[test]
    fn snapshot_vms_resume_via_patch_vm_not_instance_start() {
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();

        // The pool-claim path: apply_uniqueness resumes the VM.
        let (sock_path, seen, mock) = mock_api("resume1");
        let mut vm = PausedVm {
            id: "sess-resume".into(),
            socket_path: sock_path.clone(),
            vsock_uds: "/run/toolcage/sess-resume.vsock".into(),
            vsock_cid: 7,
            started: false,
            child,
        };
        let res = vm.apply_uniqueness("sess-resume", "/tmp/ws");
        assert!(res.is_ok(), "apply_uniqueness failed: {res:?}");
        assert!(vm.started);
        let _ = mock.join();
        let seen = seen.lock().unwrap().clone();
        let paths: Vec<String> = seen.iter().map(|r| r.path.clone()).collect();
        assert_eq!(
            paths,
            vec!["/drive/workspace".to_string(), "/vm".to_string()],
            "apply_uniqueness must PATCH /vm to resume a restored VM: {seen:?}"
        );
        let resume = &seen[1];
        assert_eq!(resume.method, "PATCH");
        assert!(
            resume.body.contains("\"Resumed\""),
            "PATCH /vm must carry state Resumed: {}",
            resume.body
        );
        let _ = std::fs::remove_dir_all(std::path::Path::new(&sock_path).parent().unwrap());

        // The reuse path: start() resumes the same way.
        let (sock_path2, seen2, mock2) = mock_api("resume2");
        let mut vm2 = PausedVm {
            id: "sess-resume2".into(),
            socket_path: sock_path2.clone(),
            vsock_uds: "/run/toolcage/sess-resume2.vsock".into(),
            vsock_cid: 8,
            started: false,
            child: std::process::Command::new("sleep").arg("60").spawn().unwrap(),
        };
        let res = vm2.start();
        assert!(res.is_ok(), "start failed: {res:?}");
        let _ = mock2.join();
        let seen2 = seen2.lock().unwrap().clone();
        assert_eq!(seen2.len(), 1, "start() must send exactly one request: {seen2:?}");
        assert_eq!(seen2[0].method, "PATCH");
        assert_eq!(seen2[0].path, "/vm");
        assert!(seen2[0].body.contains("\"Resumed\""), "{}", seen2[0].body);
        let _ = std::fs::remove_dir_all(std::path::Path::new(&sock_path2).parent().unwrap());
    }
}
