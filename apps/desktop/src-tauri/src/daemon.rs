//! Starting and supervising the privileged `9rai daemon` from the unprivileged GUI.
//!
//! The GUI never edits the hosts file or the trust store itself. It locates the `9rai` CLI,
//! launches `9rai daemon --control-port <port> --token <token>` through the OS elevation
//! prompt, and from then on talks to it *only* through the loopback control channel that
//! `nine_rai_core::proxy::control` serves (`GET /status`, `POST /stop`). That keeps the whole
//! privileged surface in one auditable place and means the desktop app adds no new way to
//! strand the machine: whatever the GUI can do, the CLI can undo.
//!
//! The pairing is persisted to the user's data dir so a GUI restart re-attaches to a daemon
//! that is still up instead of orphaning it with the hosts file hijacked.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use nine_rai_core::appconfig::AppConfig;
use nine_rai_core::cert::{trust, CertStore};
use nine_rai_core::{hosts, paths, Error, Result, Tool};

/// Probe budget. The control channel is loopback: a refused connection returns immediately,
/// so anything slower than this means the daemon is gone or wedged.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long `stop` keeps trying to reach the channel before giving up (covers the small
/// window between "launcher returned" and "daemon bound its control port").
const STOP_ATTEMPTS: Duration = Duration::from_secs(5);
/// How long the daemon may take to come up before we call a silent channel a failure.
const STARTUP_GRACE: Duration = Duration::from_secs(30);
/// Log tail handed to the UI, in bytes read from the end of the file.
const LOG_READ_BYTES: u64 = 64 * 1024;

const SESSION_FILE: &str = "daemon-session.json";
const LOG_FILE: &str = "daemon.log";

/// Everything needed to reach a daemon we started.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    control_port: u16,
    token: String,
}

/// What the UI renders. A flat shape so the frontend stays a `switch` on `state`.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonStatus {
    /// `stopped` | `starting` | `running` | `failed`
    pub state: &'static str,
    pub pid: Option<u32>,
    pub control_port: Option<u16>,
    /// Human-readable explanation for `starting`/`failed`.
    pub detail: Option<String>,
}

impl DaemonStatus {
    fn stopped() -> Self {
        Self {
            state: "stopped",
            pid: None,
            control_port: None,
            detail: None,
        }
    }
}

// ── Discovery and rendering (pure; unit-tested) ──────────────────────────────

pub fn session_path() -> Result<PathBuf> {
    Ok(paths::data_dir()?.join(SESSION_FILE))
}

pub fn log_path() -> Result<PathBuf> {
    Ok(paths::log_dir()?.join(LOG_FILE))
}

/// A per-session bearer token, without pulling an RNG crate: `RandomState` is OS-seeded, and
/// we fold in the pid and wall clock on top. Same construction as the CLI's `random_token`.
fn random_token() -> String {
    let state = RandomState::new();
    let mut out = String::with_capacity(48);
    for i in 0u64..3 {
        let mut h = state.build_hasher();
        h.write_u64(i);
        h.write_u64(std::process::id().into());
        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.write_u128(d.as_nanos());
        }
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// Single-quote a string for `sh`.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Escape a string for the inside of an AppleScript double-quoted literal.
fn as_quote(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', "\\\"")
}

/// The command that launches the daemon with administrator rights.
///
/// Rendered here and nowhere else, as a pure function of its inputs, so the exact argv can be
/// asserted in tests without touching a machine. The daemon runs detached (`&`): the launcher
/// exits as soon as the daemon is started, and liveness is answered by the control channel —
/// not by guessing from process trees across an elevation boundary.
pub fn elevation_argv(cli: &Path, port: u16, token: &str, log: &Path) -> (String, Vec<String>) {
    if cfg!(target_os = "windows") {
        let inner = format!(
            "\"{}\" daemon --control-port {port} --token {token} >> \"{}\" 2>&1",
            cli.display(),
            log.display()
        );
        let script = format!(
            "Start-Process -FilePath 'cmd.exe' -ArgumentList '/C','{}' -Verb RunAs -WindowStyle Hidden",
            inner.replace('\'', "''")
        );
        return (
            "powershell".into(),
            vec!["-NoProfile".into(), "-Command".into(), script],
        );
    }

    let shell = format!(
        "{} daemon --control-port {port} --token {token} >> {} 2>&1 &",
        shq(&cli.to_string_lossy()),
        shq(&log.to_string_lossy())
    );

    if cfg!(target_os = "macos") {
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            as_quote(&shell)
        );
        return ("osascript".into(), vec!["-e".into(), script]);
    }

    // Linux: pkexec is the desktop-standard elevation prompt.
    (
        "pkexec".into(),
        vec!["/bin/sh".into(), "-c".into(), shell.clone()],
    )
}

/// The command that runs a batch of privileged ops through the CLI's hidden `elevated` entry
/// point with OS elevation — the same one-prompt mechanism as the daemon launch, but a
/// one-shot batch (no `&`: the launcher blocks until the ops complete).
pub fn elevated_ops_argv(cli: &Path, ops_b64: &str, log: &Path) -> (String, Vec<String>) {
    if cfg!(target_os = "windows") {
        let inner = format!(
            "\"{}\" elevated --ops {ops_b64} >> \"{}\" 2>&1",
            cli.display(),
            log.display()
        );
        let script = format!(
            "Start-Process -FilePath 'cmd.exe' -ArgumentList '/C','{}' -Verb RunAs -Wait -WindowStyle Hidden",
            inner.replace('\'', "''")
        );
        return (
            "powershell".into(),
            vec!["-NoProfile".into(), "-Command".into(), script],
        );
    }

    let shell = format!(
        "{} elevated --ops {ops_b64} >> {} 2>&1",
        shq(&cli.to_string_lossy()),
        shq(&log.to_string_lossy())
    );

    if cfg!(target_os = "macos") {
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            as_quote(&shell)
        );
        return ("osascript".into(), vec!["-e".into(), script]);
    }

    ("pkexec".into(), vec!["/bin/sh".into(), "-c".into(), shell])
}

/// Minimal standard base64 encoder — the inverse of the CLI's own decoder, kept dependency-free
/// for one call site (the `elevated --ops` payload).
fn b64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Run one privileged batch via the CLI's `elevated` entry point, blocking until it finishes
/// (or the user declines the prompt). Output lands in the shared daemon log, and a failure
/// returns the log tail so the window can show *why*.
pub async fn run_elevated_ops(
    cli: &Path,
    ops: &[nine_rai_core::privilege::PrivOp],
    log: &Path,
) -> Result<()> {
    let encoded = b64_encode(&serde_json::to_vec(ops)?);
    let (program, args) = elevated_ops_argv(cli, &encoded, log);
    log::info!("running privileged batch via {program}");

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|e| Error::io(log, e))?;
    let status = tokio::process::Command::new(&program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            file.try_clone().map_err(|e| Error::io(log, e))?,
        ))
        .stderr(Stdio::from(file))
        .status()
        .await
        .map_err(|e| Error::Elevation(format!("launching `{program}` failed: {e}")))?;

    if status.success() {
        return Ok(());
    }
    let tail = log_tail(log, 8).join("\n");
    Err(Error::Elevation(if tail.is_empty() {
        format!("privileged setup exited with {status}")
    } else {
        format!("privileged setup exited with {status}:\n{tail}")
    }))
}

/// Get the root trusted, preferring the one path that can actually succeed.
///
/// Order matters and is the whole point. Trusting a root for the current user needs no
/// elevation, and because the call runs inside the user's own session macOS can raise its
/// authorization dialog and take the answer — the settings land in the user trust domain, which
/// Security.framework honours for that user's apps. The elevated admin-domain form is tried
/// only as a fallback, and on a GUI-launched batch it is refused before it starts: AppleScript's
/// privileged trampoline has no session to prompt in, so `SecTrustSettingsSetTrustSettings`
/// answers "the authorization was denied since no user interaction was possible" no matter how
/// often it is retried.
///
/// Returns whether the system now trusts us. Never fatal: a machine without OS trust still
/// serves every client that reads `NODE_EXTRA_CA_CERTS`.
pub async fn ensure_ca_trusted(store: &CertStore, log: &Path) -> bool {
    if trust::is_installed(store.fingerprint()) {
        return true;
    }
    let Ok(cert) = store.root_cert_path() else {
        return false;
    };
    let cert = cert.to_string_lossy().to_string();

    note(
        log,
        &["trusting the root CA for this user (macOS will ask for your password)".to_string()],
    );
    for argv in trust::unix_install_user(&cert) {
        log::info!("running {}", argv.display());
        let ran = tokio::process::Command::new(argv.program())
            .args(argv.args())
            .stdin(Stdio::null())
            .output()
            .await;
        match ran {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                log::warn!("{} failed: {stderr}", argv.program());
                note(log, &[format!("trusting the root CA failed: {stderr}")]);
            }
            Err(e) => {
                log::warn!("could not run {}: {e}", argv.program());
                note(log, &[format!("could not run {}: {e}", argv.program())]);
            }
        }
    }

    let trusted = trust::is_installed(store.fingerprint());
    if trusted {
        log::info!("the system now trusts our root CA");
        note(log, &["the system now trusts our root CA".to_string()]);
    } else {
        let remedy = trust::manual_trust_command(&cert);
        log::warn!("the system trust store still does not trust our root; remedy: {remedy}");
        note(
            log,
            &[
                "the system trust store does not trust our root — clients that use it (Chromium, \
and with it the IDE's non-Node requests) will reject our certificates"
                    .to_string(),
                format!("run this in a terminal to fix it: {remedy}"),
            ],
        );
    }
    trusted
}

/// Find the `9rai` CLI.
///
/// Order: an explicit override, then next to the GUI executable (which covers `cargo tauri
/// dev`, where both land in the workspace `target/<profile>/`), then `PATH`.
pub fn locate_cli() -> Result<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["9rai.exe", "9rai"]
    } else {
        &["9rai"]
    };

    if let Some(explicit) = std::env::var_os("NINE_RAI_CLI") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Ok(p);
        }
        return Err(Error::Elevation(format!(
            "NINE_RAI_CLI points at {} which is not a file",
            p.display()
        )));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in names {
                let cand = dir.join(name);
                if cand.is_file() {
                    return Ok(cand);
                }
            }
        }
    }

    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in names {
                let cand = dir.join(name);
                if cand.is_file() {
                    return Ok(cand);
                }
            }
        }
    }

    Err(Error::Elevation(
        "cannot find the `9rai` CLI — build it (`cargo build --release --bin 9rai`) or set NINE_RAI_CLI"
            .into(),
    ))
}

/// A UTC wall-clock stamp for the daemon log. UTC, not local time, so these lines sort next to
/// the daemon's own `tracing` output and the GUI log, which are both UTC.
fn stamp() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Append lines to the shared daemon log, each stamped.
///
/// The GUI's own log lives elsewhere (`~/Library/Logs/...`), but the daemon's stderr lands
/// here — so a failure that is only ever toasted at the window leaves no trace next to the
/// output that explains it. Everything the supervisor decides about a start attempt is
/// therefore written here too. Best-effort: logging must never be why a start fails.
pub fn note(log: &Path, lines: &[String]) {
    use std::io::Write as _;

    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
    else {
        return;
    };
    let stamp = stamp();
    for line in lines {
        let _ = writeln!(file, "[{stamp}] {line}");
    }
}

/// What the GUI knows about the machine at the moment it launches a daemon, as log lines.
///
/// Printed before every start attempt so a failure further down has a labelled starting point:
/// which binary ran (with its build time — a CLI older than the GUI is a bug in itself), how it
/// was elevated, and whether the CA and hosts file were already in the state the daemon is
/// about to put them in.
fn start_banner(
    cli: &Path,
    program: &str,
    port: u16,
    config: &AppConfig,
    store: &CertStore,
) -> Vec<String> {
    let built = std::fs::metadata(cli)
        .and_then(|m| m.modified())
        .map(|t| {
            let secs = t
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or_default();
            time::OffsetDateTime::from_unix_timestamp(secs)
                .map(|t| {
                    format!(
                        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
                        t.year(),
                        u8::from(t.month()),
                        t.day(),
                        t.hour(),
                        t.minute(),
                        t.second()
                    )
                })
                .unwrap_or_else(|_| "?".into())
        })
        .unwrap_or_else(|_| "?".into());

    let hosts_state = match std::fs::read_to_string(paths::hosts_file()) {
        Ok(text) if hosts::is_current(&text, Tool::Kiro.hosts()) => {
            "already redirected".to_string()
        }
        Ok(_) => "clean".to_string(),
        Err(e) => format!("unreadable ({e})"),
    };

    vec![
        "──── start attempt ────".to_string(),
        format!("  cli       {} (built {built})", cli.display()),
        format!("  elevate   {program}"),
        format!("  control   127.0.0.1:{port}"),
        format!(
            "  root CA   {} ({})",
            store.fingerprint(),
            if trust::is_installed(store.fingerprint()) {
                "already trusted"
            } else {
                "not trusted — installing it before launch"
            }
        ),
        format!("  hosts     {hosts_state}"),
        format!(
            "  provider  {} ({} mapping(s), fallback {})",
            config.provider.base_url,
            config.mappings.models.len(),
            config.mappings.default.as_deref().unwrap_or("none")
        ),
    ]
}

/// The last `max_lines` lines of `path`, or an empty list when it does not exist yet.
pub fn log_tail(path: &Path, max_lines: usize) -> Vec<String> {
    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(LOG_READ_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    // When we started reading mid-file the first line is a fragment — drop it.
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let skip = lines.len().saturating_sub(max_lines);
    lines[skip..].iter().map(|s| s.to_string()).collect()
}

/// Pick a free loopback port for the control channel.
fn free_control_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| Error::Elevation(format!("no free loopback port: {e}")))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| Error::Elevation(format!("local_addr: {e}")))
}

// ── Control channel client ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StatusReply {
    #[allow(dead_code)]
    pub ok: bool,
    pub pid: u32,
}

pub struct ControlClient {
    port: u16,
    token: String,
    http: reqwest::Client,
}

impl ControlClient {
    pub fn new(port: u16, token: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(PROBE_TIMEOUT)
            .build()
            .map_err(|e| Error::Elevation(format!("http client: {e}")))?;
        Ok(Self {
            port,
            token: token.into(),
            http,
        })
    }

    /// `Ok(Some(_))` — the daemon answered. `Ok(None)` — nothing is listening. `Err` —
    /// something *is* listening but is not our daemon (e.g. a 401 from another process).
    pub async fn probe(&self) -> Result<Option<StatusReply>> {
        let url = format!("http://127.0.0.1:{}/status", self.port);
        let sent = self.http.get(url).bearer_auth(&self.token).send().await;
        match sent {
            Err(e) if e.is_connect() => Ok(None),
            Err(e) => Err(Error::Elevation(format!("control channel: {e}"))),
            Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => Err(Error::Elevation(
                format!(
                    "port {} is held by a process that rejects our token — is another 9rai daemon running?",
                    self.port
                ),
            )),
            Ok(resp) => resp
                .json::<StatusReply>()
                .await
                .map(Some)
                .map_err(|e| Error::Elevation(format!("control channel reply: {e}"))),
        }
    }

    pub async fn stop(&self) -> Result<()> {
        let url = format!("http://127.0.0.1:{}/stop", self.port);
        self.http
            .post(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| Error::Elevation(format!("control channel: {e}")))?;
        Ok(())
    }
}

// ── Supervisor ───────────────────────────────────────────────────────────────

pub struct Supervisor {
    /// The elevation launcher while its prompt is still open. Once it exits, liveness is the
    /// control channel's answer, not this handle.
    launcher: Option<Child>,
    session: Option<Session>,
    started_at: Option<Instant>,
    /// Set once the control channel has answered for the current session; distinguishes
    /// "still coming up" from "never came up".
    ever_ready: bool,
    /// Last failure worth showing the user, kept until the next start.
    sticky_error: Option<String>,
}

impl Supervisor {
    /// Re-attach to a daemon recorded by an earlier GUI run, if any.
    pub fn load() -> Self {
        let session = session_path()
            .ok()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<Session>(&bytes).ok());
        Self {
            launcher: None,
            session,
            started_at: None,
            ever_ready: false,
            sticky_error: None,
        }
    }

    pub async fn start(&mut self) -> Result<DaemonStatus> {
        let current = self.status().await;
        if current.state == "running" {
            return Ok(current);
        }

        let config = AppConfig::load()?;
        if config.provider.api_key.is_empty() {
            return Err(Error::Elevation(
                "no provider configured — set the provider endpoint and API key first".into(),
            ));
        }
        if config.mappings.is_empty() {
            return Err(Error::Elevation(
                "no model mappings — map at least one Kiro model (or set a fallback)".into(),
            ));
        }

        let cli = locate_cli()?;
        // Make sure the root CA exists before we elevate: the daemon installs it into the
        // trust store during startup, and generating it here keeps that step predictable.
        let store = CertStore::load_or_create()?;

        let port = free_control_port()?;
        let token = random_token();
        let log = log_path()?;
        if let Some(dir) = log.parent() {
            paths::ensure_dir(dir)?;
            // Pre-create as the user so the root daemon appends to a user-owned file.
            if !log.exists() {
                paths::write_private(&log, b"")?;
            }
        }

        let session = Session {
            control_port: port,
            token: token.clone(),
        };
        let session_file = session_path()?;
        paths::write_private(&session_file, &serde_json::to_vec(&session)?)?;

        let (program, args) = elevation_argv(&cli, port, &token, &log);
        log::info!(
            "launching 9rai daemon: {} (control port {port})",
            cli.display()
        );
        note(&log, &start_banner(&cli, &program, port, &config, &store));

        // The root has to be trusted before the daemon is launched, and by a path that can
        // actually prompt — see `ensure_ca_trusted`. Not fatal either way.
        ensure_ca_trusted(&store, &log).await;

        let log_handle = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .map_err(|e| Error::io(&log, e))?;

        let child = Command::new(&program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                log_handle.try_clone().map_err(|e| Error::io(&log, e))?,
            ))
            .stderr(Stdio::from(log_handle))
            .spawn()
            .map_err(|e| {
                let msg = format!("launching `{program}` for elevation failed: {e}");
                note(&log, &[format!("start failed: {msg}")]);
                Error::Elevation(msg)
            })?;

        self.launcher = Some(child);
        self.session = Some(session);
        self.started_at = Some(Instant::now());
        self.ever_ready = false;
        self.sticky_error = None;
        Ok(self.status().await)
    }

    pub async fn stop(&mut self) -> Result<DaemonStatus> {
        let Some(session) = self.session.clone() else {
            // No daemon we know of — which is exactly the state a crashed one leaves behind,
            // hosts file and all. Stop has to be able to get the machine out of it.
            self.restore_if_stranded().await;
            let mut status = DaemonStatus::stopped();
            status.detail = self.sticky_error.take();
            return Ok(status);
        };
        let client = ControlClient::new(session.control_port, session.token.clone())?;

        // A session left over from an earlier run (or a crash) with nothing listening: there is
        // nothing to stop, and the retry loop below would just stall the UI. Only skip when we
        // are *not* inside a startup window, where "not listening yet" is expected.
        let starting = self
            .started_at
            .map(|t| t.elapsed() < STARTUP_GRACE)
            .unwrap_or(false);
        if !starting {
            if let Ok(None) = client.probe().await {
                self.clear_session();
                self.session = None;
                self.restore_if_stranded().await;
                let mut status = DaemonStatus::stopped();
                status.detail = self.sticky_error.take();
                return Ok(status);
            }
        }

        // Ask politely, retrying across the startup window: `POST /stop` is what restores the
        // hosts file, so this is the only path that tears the machine back down cleanly.
        let deadline = Instant::now() + STOP_ATTEMPTS;
        let mut stopped = false;
        loop {
            match client.stop().await {
                Ok(()) => {
                    stopped = true;
                    break;
                }
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(e) => {
                    if let Ok(path) = log_path() {
                        note(&path, &[format!("stop failed: {e}")]);
                    }
                    log::error!("stop failed: {e}");
                    self.sticky_error = Some(e.to_string());
                    break;
                }
            }
        }

        if stopped {
            // Wait for the channel to go quiet before declaring the daemon gone.
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                match client.probe().await {
                    Ok(None) => break,
                    _ => tokio::time::sleep(Duration::from_millis(150)).await,
                }
            }
        }

        // Cancel a prompt still waiting for authorization, if any.
        if let Some(mut child) = self.launcher.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Only forget the session once we are sure nothing is listening: a stale token would
        // leave a running daemon impossible to stop from the GUI.
        let listenable = matches!(client.probe().await, Ok(Some(_)) | Err(_));
        if !listenable {
            self.clear_session();
        }
        self.session = None;
        self.started_at = None;

        self.restore_if_stranded().await;

        let mut status = self.status().await;
        if let Some(detail) = self.sticky_error.take() {
            status.detail = Some(detail);
        }
        Ok(status)
    }

    /// Put `/etc/hosts` back if the daemon did not.
    ///
    /// A daemon that exits normally restores the file itself, so this is a no-op on every
    /// ordinary stop — it exists for the one that was SIGKILLed, crashed, or outlived a GUI
    /// restart. Left alone, that machine keeps resolving the IDE's endpoints to a loopback
    /// port with nothing behind it while the window calmly reports "stopped": the two most
    /// misleading facts we could show together.
    ///
    /// A shutting-down daemon restores the file a moment after its control channel goes quiet,
    /// so wait for that before concluding anything — asking for a password we do not need is
    /// its own kind of bug.
    async fn restore_if_stranded(&mut self) {
        for _ in 0..20 {
            match nine_rai_core::session::hosts_are_redirected() {
                Ok(false) => return,
                Ok(true) => tokio::time::sleep(Duration::from_millis(250)).await,
                Err(e) => {
                    log::warn!("cannot read the hosts file: {e}");
                    return;
                }
            }
        }

        let Ok(log) = log_path() else { return };
        log::warn!("the hosts file is still redirected; restoring it");
        note(
            &log,
            &[
                "the daemon went away without restoring the hosts file; restoring it now"
                    .to_string(),
            ],
        );

        let restore = async {
            let cli = locate_cli()?;
            let ops = nine_rai_core::session::disable_ops()?;
            run_elevated_ops(&cli, &ops, &log).await
        };
        if let Err(e) = restore.await {
            log::error!("failed to restore the hosts file: {e}");
            note(&log, &[format!("failed to restore the hosts file: {e}")]);
            self.sticky_error = Some(format!(
                "the proxy is stopped, but your hosts file is still redirected and could not be \
restored ({e}) — the IDE will not reach its endpoints until it is"
            ));
        } else {
            note(&log, &["hosts file restored".to_string()]);
        }
    }

    pub async fn status(&mut self) -> DaemonStatus {
        // Reap the launcher, if it already exited.
        if let Some(child) = self.launcher.as_mut() {
            match child.try_wait() {
                Ok(Some(exit)) => {
                    self.launcher = None;
                    if !exit.success() && !self.ever_ready {
                        let path = log_path().unwrap_or_default();
                        // The note carries the reason only: the tail is already in the file
                        // right above it, and copying it back in would double every line.
                        note(
                            &path,
                            &[format!(
                                "start failed: the elevation launcher exited {exit} — the \
authorization prompt was refused, or the daemon died before it could serve its control channel"
                            )],
                        );
                        log::error!("start failed: launcher exited {exit}");
                        let tail = log_tail(&path, 8).join("\n");
                        self.sticky_error = Some(format!(
                            "authorization was refused or the daemon failed to start (launcher exit {exit}){}",
                            if tail.is_empty() {
                                String::new()
                            } else {
                                format!(":\n{tail}")
                            }
                        ));
                        self.clear_session();
                        self.session = None;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    self.launcher = None;
                    log::warn!("launcher try_wait failed: {e}");
                }
            }
        }

        let Some(session) = self.session.clone() else {
            if let Some(detail) = self.sticky_error.clone() {
                return DaemonStatus {
                    state: "failed",
                    pid: None,
                    control_port: None,
                    detail: Some(detail),
                };
            }
            return DaemonStatus::stopped();
        };

        let Ok(client) = ControlClient::new(session.control_port, session.token.clone()) else {
            return DaemonStatus {
                state: "failed",
                pid: None,
                control_port: Some(session.control_port),
                detail: Some("cannot build the control-channel client".into()),
            };
        };
        match client.probe().await {
            Ok(Some(reply)) => {
                if !self.ever_ready {
                    if let Ok(path) = log_path() {
                        note(
                            &path,
                            &[format!(
                                "daemon ready: pid {} answering on 127.0.0.1:{}",
                                reply.pid, session.control_port
                            )],
                        );
                    }
                    log::info!("daemon ready (pid {})", reply.pid);
                }
                self.ever_ready = true;
                DaemonStatus {
                    state: "running",
                    pid: Some(reply.pid),
                    control_port: Some(session.control_port),
                    detail: None,
                }
            }
            Ok(None) => {
                let age = self.started_at.map(|t| t.elapsed()).unwrap_or_default();
                if age > STARTUP_GRACE && !self.ever_ready {
                    // Silent past the grace window and nothing is listening: the session file
                    // is stale (e.g. the daemon was killed), so stop pretending we can reach it.
                    let path = log_path().unwrap_or_default();
                    note(
                        &path,
                        &[format!(
                            "start failed: nothing answered 127.0.0.1:{} within {}s — the daemon \
exited during startup (its own error is above) or never got past the authorization prompt",
                            session.control_port,
                            STARTUP_GRACE.as_secs()
                        )],
                    );
                    log::error!(
                        "start failed: control channel on port {} stayed silent for {}s",
                        session.control_port,
                        STARTUP_GRACE.as_secs()
                    );
                    let tail = log_tail(&path, 8).join("\n");
                    self.clear_session();
                    self.session = None;
                    return DaemonStatus {
                        state: "failed",
                        pid: None,
                        control_port: None,
                        detail: Some(format!(
                            "the daemon never answered its control channel{}",
                            if tail.is_empty() {
                                String::new()
                            } else {
                                format!(":\n{tail}")
                            }
                        )),
                    };
                }
                DaemonStatus {
                    state: "starting",
                    pid: None,
                    control_port: Some(session.control_port),
                    detail: Some(
                        "waiting for the system authorization prompt and daemon startup…".into(),
                    ),
                }
            }
            Err(e) => {
                let path = log_path().unwrap_or_default();
                note(&path, &[format!("start failed: {e}")]);
                log::error!("control channel error: {e}");
                let tail = log_tail(&path, 8).join("\n");
                self.sticky_error = Some(e.to_string());
                DaemonStatus {
                    state: "failed",
                    pid: None,
                    control_port: Some(session.control_port),
                    detail: Some(format!(
                        "{e}{}",
                        if tail.is_empty() {
                            String::new()
                        } else {
                            format!("\n{tail}")
                        }
                    )),
                }
            }
        }
    }

    fn clear_session(&self) {
        if let Ok(path) = session_path() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_attempt_is_described_before_anything_launches() {
        use crate::test_home::ScratchHome;

        let (_home, dir) = ScratchHome::new("banner");
        let config = AppConfig::load().expect("a fresh config");
        let store = CertStore::load_or_create().expect("mint a root CA");

        // The banner has to answer "which binary, elevated how, and what state was the machine
        // in" without anyone re-running the failure.
        let text =
            start_banner(Path::new("/tmp/9rai"), "osascript", 54321, &config, &store).join("\n");
        assert!(text.contains("start attempt"), "{text}");
        assert!(text.contains("/tmp/9rai"), "{text}");
        assert!(text.contains("osascript"), "{text}");
        assert!(text.contains("127.0.0.1:54321"), "{text}");
        assert!(text.contains(store.fingerprint()), "{text}");
        assert!(text.contains("hosts"), "{text}");

        // Notes are stamped and appended, so a second attempt never overwrites the first.
        let log = dir.join("daemon.log");
        note(&log, &["start failed: the launcher exited 1".into()]);
        note(&log, &["start failed: nothing answered".into()]);
        let written = std::fs::read_to_string(&log).expect("the note was written");
        assert_eq!(written.lines().count(), 2, "{written}");
        for line in written.lines() {
            assert!(line.starts_with('['), "every line carries a stamp: {line}");
            assert!(line.contains("Z] start failed: "), "{line}");
        }

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shell_quoting_survives_spaces_and_quotes() {
        assert_eq!(shq("/Users/a b/9rai"), "'/Users/a b/9rai'");
        assert_eq!(shq("it's"), r"'it'\''s'");
    }

    #[test]
    fn applescript_escaping_covers_backslash_and_quote() {
        assert_eq!(as_quote(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn b64_matches_the_standard_alphabet() {
        assert_eq!(b64_encode(b"9rai"), "OXJhaQ==");
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"\xff\xff\xff"), "////");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_elevated_ops_is_one_elevated_foreground_batch() {
        let (program, args) = elevated_ops_argv(
            Path::new("/Applications/9rai.app/Contents/MacOS/9rai"),
            "OXJhaQ==",
            Path::new("/Users/a b/Library/Application Support/9rai/logs/daemon.log"),
        );
        assert_eq!(program, "osascript");
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "-e");
        let script = &args[1];
        assert!(
            script.contains("elevated --ops OXJhaQ=="),
            "script: {script}"
        );
        assert!(script.ends_with("with administrator privileges"));
        assert!(script.contains("'/Users/a b/Library/Application Support/9rai/logs/daemon.log'"));
        // A one-shot batch runs in the foreground — no `&` backgrounding.
        assert!(!script.ends_with("&\" with administrator privileges"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_is_one_elevated_osascript() {
        let (program, args) = elevation_argv(
            Path::new("/Applications/9rai.app/Contents/MacOS/9rai"),
            41234,
            "abc123",
            Path::new("/Users/a b/Library/Application Support/9rai/logs/daemon.log"),
        );
        assert_eq!(program, "osascript");
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "-e");
        let script = &args[1];
        assert!(script.starts_with("do shell script \""));
        assert!(script.ends_with("with administrator privileges"));
        assert!(script.contains("--control-port 41234"));
        assert!(script.contains("--token abc123"));
        // Paths with spaces must stay single-quoted for the shell that osascript spawns.
        assert!(script.contains("'/Users/a b/Library/Application Support/9rai/logs/daemon.log'"));
    }

    /// The client half of the control protocol, exercised against the real server the daemon
    /// runs — token auth, the status payload, and the stop signal.
    #[tokio::test]
    async fn control_client_talks_to_the_real_control_server() {
        use std::sync::Arc;

        nine_rai_core::proxy::init_crypto();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(nine_rai_core::proxy::control::serve_control(
            listener,
            Arc::from("t0ken"),
            stop_tx,
        ));

        let client = ControlClient::new(port, "t0ken").unwrap();
        let reply = client.probe().await.unwrap().expect("daemon answers");
        assert_eq!(reply.pid, std::process::id());

        let stranger = ControlClient::new(port, "wrong").unwrap();
        assert!(
            stranger.probe().await.is_err(),
            "a wrong token must not authorize"
        );

        client.stop().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), stop_rx.changed())
            .await
            .expect("stop must be signalled")
            .expect("watch channel alive");
        assert!(*stop_rx.borrow());
    }

    #[tokio::test]
    async fn probe_reports_none_when_nothing_listens() {
        nine_rai_core::proxy::init_crypto();
        let port = free_control_port().unwrap();
        let client = ControlClient::new(port, "t0ken").unwrap();
        assert!(client.probe().await.unwrap().is_none());
    }

    /// A cancelled elevation prompt (or a daemon that dies on startup) must surface as a
    /// diagnosable failure — and must not leave a pairing behind that later reads as "running".
    #[tokio::test]
    async fn a_refused_authorization_surfaces_as_failed() {
        let (_home, dir) = crate::test_home::ScratchHome::new("refused");

        // A launcher that dies immediately stands in for a refused osascript prompt.
        let launcher = Command::new("/bin/sh")
            .args(["-c", "exit 1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut supervisor = Supervisor {
            launcher: Some(launcher),
            session: Some(Session {
                control_port: free_control_port().unwrap(),
                token: "t0ken".into(),
            }),
            started_at: Some(Instant::now()),
            ever_ready: false,
            sticky_error: None,
        };

        tokio::time::sleep(Duration::from_millis(100)).await;
        let status = supervisor.status().await;
        assert_eq!(status.state, "failed");
        let detail = status.detail.expect("a failure must explain itself");
        assert!(detail.contains("authorization"), "detail was: {detail}");
        assert!(
            supervisor.session.is_none(),
            "the dead pairing must be dropped"
        );

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_tail_reads_the_end_of_the_file() {
        let dir = std::env::temp_dir().join(format!("9rai-logtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.log");
        let body: String = (0..50).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&path, body).unwrap();

        let tail = log_tail(&path, 5);
        assert_eq!(
            tail,
            vec!["line 45", "line 46", "line 47", "line 48", "line 49"]
        );

        assert!(log_tail(&dir.join("absent.log"), 5).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
