//! Headless driver for the 9rai MITM engine.
//!
//! Everything the GUI can do is reachable here, so the whole system stays scriptable and
//! measurable without a desktop session — which is what the evaluation harness needs.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use nine_rai_core::eventstream::testing::decode_stream;
use nine_rai_core::translate::{to_chat_request, SseReader, StreamState};
use nine_rai_core::types::{cw, openai};

#[derive(Parser)]
#[command(name = "9rai", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert a captured CodeWhisperer request body into the OpenAI request we would send.
    Request {
        /// Captured Kiro request body (JSON).
        #[arg(long)]
        input: PathBuf,
        /// Provider model to target.
        #[arg(long, default_value = "test-model")]
        model: String,
    },
    /// Convert a captured OpenAI SSE transcript into the EventStream bytes Kiro would receive.
    Response {
        /// Captured `text/event-stream` transcript.
        #[arg(long)]
        input: PathBuf,
        /// Where to write the binary stream.
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "test-model")]
        model: String,
    },
    /// Decode an EventStream file and print one line per frame. Exits non-zero if malformed.
    Verify {
        #[arg(long)]
        input: PathBuf,
    },
    /// Root CA management.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Show or set the provider configuration and model mappings.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Run the interception proxy: set up CA + hosts, serve until Ctrl-C, then restore.
    ///
    /// Must run with privileges (root on macOS to bind :443; Administrator on Windows for the
    /// trust store and hosts file).
    Daemon {
        /// Also serve the GUI control channel (status/stop) on 127.0.0.1:<port>.
        #[arg(long)]
        control_port: Option<u16>,
        /// Bearer token for the control channel. A random one is generated per session if
        /// omitted and printed to stderr.
        #[arg(long)]
        token: Option<String>,
    },
    /// Internal: run a base64-encoded batch of privileged operations. Invoked by the elevated
    /// helper; not intended for direct use.
    #[command(hide = true)]
    Elevated {
        #[arg(long)]
        ops: String,
    },
    /// Measure the engine's hot paths (for the feasibility evaluation).
    Bench {
        /// Iterations per measured operation.
        #[arg(long, default_value_t = 1000)]
        iterations: u32,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the current configuration (the API key is redacted).
    Show,
    /// Set the provider endpoint and key.
    SetProvider {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        api_key: String,
    },
    /// Map a Kiro model id to a provider model.
    Map {
        #[arg(long)]
        kiro_model: String,
        #[arg(long)]
        provider_model: String,
    },
    /// Set the fallback provider model for any unmapped Kiro model.
    SetDefault {
        #[arg(long)]
        provider_model: String,
    },
}

#[derive(Subcommand)]
enum CaAction {
    /// Ensure the root CA exists and print its location and fingerprint.
    Init,
    /// Mint a leaf for a domain and write cert + key PEM (for offline inspection).
    Leaf {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Report whether the root CA is trusted by this machine's store.
    Status,
}

fn main() -> Result<()> {
    use std::io::IsTerminal as _;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        // `9rai daemon` runs with its output redirected into `daemon.log`, which the GUI shows
        // verbatim in its log panel: colour escapes would land there as `[2m[0m` litter. Keep
        // them for a human at a terminal only.
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    match Cli::parse().command {
        Command::Request { input, model } => {
            let raw =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let request: cw::Request =
                serde_json::from_slice(&raw).context("parsing CodeWhisperer body")?;
            let out = to_chat_request(&request, model)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }

        Command::Response {
            input,
            output,
            model,
        } => {
            let raw =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;

            let mut reader = SseReader::new();
            let mut state = StreamState::new(model, None);
            let mut frames: Vec<Vec<u8>> = Vec::new();

            for payload in reader.push(&raw) {
                if let Ok(chunk) = serde_json::from_str::<openai::StreamChunk>(&payload) {
                    frames.extend(state.on_chunk(&chunk));
                }
            }
            if let Some(payload) = reader.flush() {
                if let Ok(chunk) = serde_json::from_str::<openai::StreamChunk>(&payload) {
                    frames.extend(state.on_chunk(&chunk));
                }
            }
            frames.extend(state.finish());

            let bytes = frames.concat();
            std::fs::write(&output, &bytes)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!("{} frames, {} bytes", frames.len(), bytes.len());
        }

        Command::Verify { input } => {
            let raw =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            for frame in decode_stream(&raw) {
                println!(
                    "{:<10} {:<24} {}",
                    frame.message_type(),
                    frame.event_type(),
                    serde_json::to_string(&frame.json())?
                );
            }
        }

        Command::Ca { action } => run_ca(action)?,

        Command::Config { action } => run_config(action)?,

        Command::Daemon {
            control_port,
            token,
        } => run_daemon(control_port, token)?,

        Command::Elevated { ops } => run_elevated(&ops)?,

        Command::Bench { iterations } => run_bench(iterations)?,
    }

    Ok(())
}

fn run_bench(iterations: u32) -> Result<()> {
    use nine_rai_core::cert::gen;
    use nine_rai_core::translate::{SseReader, StreamState};
    use nine_rai_core::types::openai;
    use std::time::Instant;

    let n = iterations.max(1);
    println!("iterations: {n}\n");

    // 1. Root CA generation (one-off cost, done once per install).
    let t = Instant::now();
    let root = gen::generate_root()?;
    println!("root CA generation (P-256): {:?}", t.elapsed());

    // 2. Leaf mint — the cost paid inside the TLS SNI callback. This is the headline number:
    //    it is what makes ECDSA viable where RSA-2048 would not be.
    let issuer = gen::load_issuer(&root.cert_pem, &root.key_pem)?;
    let t = Instant::now();
    for i in 0..n {
        let domain = format!("host{i}.us-east-1.kiro.dev");
        std::hint::black_box(gen::generate_leaf(&domain, &issuer)?);
    }
    let per_leaf = t.elapsed() / n;
    println!("leaf mint (P-256), mean of {n}: {per_leaf:?}");

    // 3. Response translation throughput: SSE chunk -> EventStream frames.
    let chunk = br#"data: {"choices":[{"delta":{"content":"the quick brown fox jumps"}}]}"#;
    let t = Instant::now();
    let mut total_bytes = 0usize;
    for _ in 0..n {
        let mut reader = SseReader::new();
        let mut state = StreamState::new("bench-model", None);
        let mut out = 0usize;
        for payload in reader.push(chunk) {
            if let Ok(c) = serde_json::from_str::<openai::StreamChunk>(&payload) {
                for f in state.on_chunk(&c) {
                    out += f.len();
                }
            }
        }
        for f in state.finish() {
            out += f.len();
        }
        total_bytes += out;
    }
    let elapsed = t.elapsed();
    let per_chunk = elapsed / n;
    let mb_per_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    println!("response translation, mean of {n}: {per_chunk:?} per turn ({mb_per_s:.1} MiB/s out)");

    Ok(())
}

fn run_config(action: ConfigAction) -> Result<()> {
    use nine_rai_core::appconfig::AppConfig;

    let mut config = AppConfig::load()?;
    match action {
        ConfigAction::Show => {
            let mut shown = config.clone();
            if !shown.provider.api_key.is_empty() {
                shown.provider.api_key = "***redacted***".into();
            }
            println!("{}", serde_json::to_string_pretty(&shown)?);
            println!("(config file: {})", AppConfig::path()?.display());
        }
        ConfigAction::SetProvider { base_url, api_key } => {
            config.provider.base_url = base_url;
            config.provider.api_key = api_key;
            config.save()?;
            println!("provider updated");
        }
        ConfigAction::Map {
            kiro_model,
            provider_model,
        } => {
            config.mappings.models.insert(kiro_model, provider_model);
            config.save()?;
            println!("mapping added");
        }
        ConfigAction::SetDefault { provider_model } => {
            config.mappings.default = Some(provider_model);
            config.save()?;
            println!("default model set");
        }
    }
    Ok(())
}

fn run_daemon(control_port: Option<u16>, token: Option<String>) -> Result<()> {
    use nine_rai_core::appconfig::AppConfig;
    use nine_rai_core::cert::CertStore;
    use nine_rai_core::privilege::{DirectExecutor, Privileged};
    use nine_rai_core::provider::Provider;
    use nine_rai_core::proxy::{init_crypto, ProxyServer};
    use nine_rai_core::session;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    let config = AppConfig::load()?;
    if config.provider.api_key.is_empty() {
        anyhow::bail!("no provider configured — run `9rai config set-provider` first");
    }
    if config.mappings.is_empty() {
        anyhow::bail!("no model mappings — run `9rai config map` first");
    }

    init_crypto();
    let store = Arc::new(CertStore::load_or_create()?);
    let provider = Provider::new(config.provider.clone())?;

    // This process is already elevated (it must be, to bind :443 / edit the trust store), so we
    // apply the privileged batch directly rather than spawning a helper.
    //
    // The banner below is what a post-mortem starts from: the GUI launches this process
    // detached behind an authorization prompt, so its stderr in `daemon.log` is the only
    // account of what the daemon saw at startup.
    let executor = DirectExecutor;
    tracing::info!(
        binary = %std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "?".into()),
        fingerprint = store.fingerprint(),
        ca_trusted = nine_rai_core::cert::trust::is_installed(store.fingerprint()),
        control_port = ?control_port,
        "daemon starting: applying the privileged batch"
    );
    ensure_ca_trusted(&executor, &store);
    if let Err(e) = executor.run(&session::enable_ops(&store)?) {
        tracing::error!(
            error = %e,
            "enabling interception failed — hosts file and trust store are unchanged"
        );
        return Err(anyhow::Error::new(e).context("enabling interception"));
    }
    // Applying the hosts file is not the same as the resolver honouring it.
    if let Err(e) = ensure_resolver_sees_hijack(&executor) {
        // Leave the machine as we found it: a hosts file we cannot make effective is worse
        // than none, because `9rai ca status` and the GUI would both claim interception is on.
        if let Err(restore) = executor.run(&session::disable_ops()?) {
            tracing::error!(error = %restore, "failed to restore the hosts file after a failed start");
        }
        return Err(e);
    }

    tracing::info!(
        fingerprint = store.fingerprint(),
        "interception enabled"
    );
    eprintln!(
        "interception enabled; CA fingerprint {}",
        store.fingerprint()
    );

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async {
        let server = ProxyServer::new(provider, config.mappings.clone(), store.clone())?;

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        if let Some(port) = control_port {
            let token: Arc<str> = match token {
                Some(t) => t.into(),
                None => random_token().into(),
            };
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .map_err(|e| {
                    nine_rai_core::Error::Provider(format!("binding control port {port}: {e}"))
                })?;
            eprintln!("control channel on 127.0.0.1:{port} (bearer token: {token})");
            tokio::spawn(nine_rai_core::proxy::control::serve_control(
                listener, token, stop_tx,
            ));
        }

        let shutdown = async move {
            let mut stop_rx = stop_rx;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = stop_rx.changed() => {}
            }
            eprintln!("\nshutting down…");
        };
        server.serve(shutdown).await
    });

    // Always restore the hosts file, even if serving failed. A SIGKILL still strands the
    // hijack — cover that with `9rai daemon` refusing to start over a stale block, and by the
    // eventual GUI watchdog; a signal handler cannot outlive SIGKILL by definition.
    if let Err(e) = executor.run(&session::disable_ops()?) {
        tracing::error!(error = %e, "failed to restore the hosts file");
        eprintln!("warning: failed to restore hosts file: {e}");
    } else {
        tracing::info!("interception disabled; hosts file restored");
        eprintln!("interception disabled; hosts file restored");
    }

    result.map_err(Into::into)
}

/// Get the root into the system trust store if it is not there — and never fail over it.
///
/// Writing trust settings needs an authorization that can prompt, and the session a
/// GUI-launched daemon runs in has no way to show one: macOS answers "the authorization was
/// denied since no user interaction was possible". A machine in that state is still fully
/// usable — every client that reads `NODE_EXTRA_CA_CERTS` works — so refusing to start would
/// take away a working setup over a nicety. What it must not do is stay quiet: without the
/// trust store, Chromium and anything else built on Security.framework goes on rejecting our
/// leaves, and the IDE reports its own opaque error. So: try, verify, and print the one command
/// that does work, which is the same command from a terminal where the prompt can appear.
fn ensure_ca_trusted(
    executor: &impl nine_rai_core::privilege::Privileged,
    store: &nine_rai_core::cert::CertStore,
) {
    use nine_rai_core::cert::trust;
    use nine_rai_core::privilege::PrivOp;

    // macOS trust settings are per-user, and this process is root on someone else's behalf.
    // It cannot see the user-domain settings the desktop session writes, so it would report a
    // trusted machine as untrusted — and its only available remedy, the admin domain, is the
    // one write a session with no authorization prompt can never perform. Leave both to the
    // session that can, rather than failing an install on every start and crying wolf in the
    // log about a trust store that is actually fine.
    if nine_rai_core::paths::gui_user_uid().is_some() {
        tracing::info!(
            "root cannot see per-user trust settings; leaving the trust store to the desktop session"
        );
        return;
    }
    if trust::is_installed(store.fingerprint()) {
        return;
    }
    let Ok(cert) = store.root_cert_path() else {
        return;
    };

    if let Err(e) = executor.run(&[PrivOp::InstallCa { cert: cert.clone() }]) {
        tracing::warn!(error = %e, "installing the root CA into the system trust store failed");
    }
    if trust::is_installed(store.fingerprint()) {
        tracing::info!("the system trust store now trusts our root");
        return;
    }

    tracing::warn!(
        remedy = %trust::manual_trust_command(&cert.to_string_lossy()),
        "the system trust store does not trust our root — Node clients still work through \
NODE_EXTRA_CA_CERTS, but anything using the OS trust store (Chromium, and with it an IDE's \
non-Node requests) will reject our certificates until the remedy is run in a terminal"
    );
}

/// Confirm the system resolver now sends the hijacked hosts to us, repairing it once if not.
///
/// On macOS a flush purges the DNS cache without re-reading `/etc/hosts`, so a stop-then-start
/// can leave the resolver serving the real AWS addresses while every step of the enable batch
/// reports success — the proxy then waits for connections that never come. Restarting the
/// resolver makes it read the file afresh.
fn ensure_resolver_sees_hijack(executor: &impl nine_rai_core::privilege::Privileged) -> Result<()> {
    use nine_rai_core::privilege::PrivOp;

    let stale = nine_rai_core::session::hosts_not_hijacked();
    if stale.is_empty() {
        return Ok(());
    }

    tracing::warn!(
        hosts = ?stale,
        "the system resolver has not picked up the new hosts file; restarting the resolver"
    );
    executor
        .run(&[PrivOp::ReloadResolver])
        .context("reloading the system resolver")?;

    // The resolver is restarted by the service manager; give it a moment to come back and
    // read the file, re-checking rather than guessing at a fixed delay.
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let stale = nine_rai_core::session::hosts_not_hijacked();
        if stale.is_empty() {
            tracing::info!("the system resolver picked up the hosts change after a restart");
            return Ok(());
        }
    }

    let stale = nine_rai_core::session::hosts_not_hijacked();
    tracing::error!(
        hosts = ?stale,
        "the system resolver still sends these hosts to the real service"
    );
    anyhow::bail!(
        "the hosts file was applied, but the system resolver still sends {} to the real \
service — the IDE would never reach this proxy",
        stale.join(", ")
    )
}

/// A per-session control token without pulling a RNG crate: `RandomState` is seeded by the OS
/// per process, and we fold in pid + wall time for good measure.
fn random_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut out = String::with_capacity(64);
    for i in 0u64..4 {
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

fn run_elevated(encoded: &str) -> Result<()> {
    use nine_rai_core::privilege::{self, DirectExecutor, PrivOp, Privileged};

    // The GUI passes a base64-encoded JSON array of ops so a single elevation covers the batch.
    let json = base64_decode(encoded).context("decoding elevated ops")?;
    let ops: Vec<PrivOp> = serde_json::from_slice(&json).context("parsing elevated ops")?;
    // We are running with admin rights on behalf of whoever invoked us — only execute the
    // exact op shapes the app itself can produce.
    privilege::validate(&ops).context("rejected a suspicious elevated batch")?;
    DirectExecutor.run(&ops)?;
    Ok(())
}

/// Minimal standard base64 decoder (avoids pulling a crate for one call site).
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [255u8; 256];
    for (i, &b) in TABLE.iter().enumerate() {
        rev[b as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &b in input.trim().as_bytes() {
        if b == b'=' {
            break;
        }
        let v = rev[b as usize];
        anyhow::ensure!(v != 255, "invalid base64");
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

fn run_ca(action: CaAction) -> Result<()> {
    use nine_rai_core::cert::{trust, CertStore};

    match action {
        CaAction::Init => {
            let store = CertStore::load_or_create()?;
            println!("cert: {}", store.root_cert_path()?.display());
            println!("fingerprint (SHA-1): {}", store.fingerprint());
        }
        CaAction::Leaf { domain, out_dir } => {
            let store = CertStore::load_or_create()?;
            // certified_key mints and caches; re-derive the PEM for inspection.
            let issuer = nine_rai_core::cert::gen::load_issuer(
                store.root_cert_pem(),
                &std::fs::read_to_string(nine_rai_core::paths::root_ca_key()?)?,
            )?;
            let leaf = nine_rai_core::cert::gen::generate_leaf(&domain, &issuer)?;
            std::fs::create_dir_all(&out_dir)?;
            let cert_path = out_dir.join(format!("{domain}.crt"));
            let key_path = out_dir.join(format!("{domain}.key"));
            std::fs::write(&cert_path, &leaf.cert_pem)?;
            std::fs::write(&key_path, &leaf.key_pem)?;
            println!("{}", cert_path.display());
            println!("{}", key_path.display());
        }
        CaAction::Status => {
            let store = CertStore::load_or_create()?;
            let trusted = trust::is_installed(store.fingerprint());
            println!(
                "fingerprint {} — {}",
                store.fingerprint(),
                if trusted { "TRUSTED" } else { "not trusted" }
            );
        }
    }
    Ok(())
}
