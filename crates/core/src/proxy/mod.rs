//! The local TLS server: accept loop, request routing, health probe, and port preflight.

pub mod body;
pub mod control;
pub mod intercept;
pub mod passthrough;
pub mod preflight;
pub mod route;
pub mod sni;

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

use crate::cert::CertStore;
use crate::config::LISTEN_PORT;
use crate::dns::DnsResolver;
use crate::mapping::ModelMap;
use crate::provider::Provider;
use crate::proxy::body::{full, BoxBody};
use crate::proxy::route::{classify, Decision};
use crate::proxy::sni::SniResolver;
use crate::{Error, Result};

/// Requests bodies above this are refused rather than buffered — the reference has no cap.
const MAX_BODY: usize = 32 * 1024 * 1024;

/// Install the process-wide rustls crypto provider. Must run once before any TLS work, because
/// reqwest uses `rustls-no-provider` and never installs a default.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Everything a request handler needs, shared across connections.
pub struct Shared {
    pub provider: Provider,
    pub map: ModelMap,
    pub dns: DnsResolver,
    pub upstream_tls: Arc<rustls::ClientConfig>,
    /// Almost always 443; overridable so tests can point passthrough at a local mock upstream.
    pub upstream_port: u16,
}

pub struct ProxyServer {
    provider: Provider,
    map: ModelMap,
    cert_store: Arc<CertStore>,
    dns: DnsResolver,
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
    upstream_port: u16,
}

impl ProxyServer {
    pub fn new(provider: Provider, map: ModelMap, cert_store: Arc<CertStore>) -> Result<Self> {
        Ok(Self {
            provider,
            map,
            cert_store,
            dns: DnsResolver::new()?,
            upstream_tls: None,
            upstream_port: 443,
        })
    }

    /// Test hook: trust this TLS config for upstreams instead of the public webpki roots.
    pub fn with_upstream_tls(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.upstream_tls = Some(config);
        self
    }

    /// Test hook: dial upstreams on this port instead of 443.
    pub fn with_upstream_port(mut self, port: u16) -> Self {
        self.upstream_port = port;
        self
    }

    /// Test hook: seed DNS answers so passthrough never touches the network.
    pub fn dns(&self) -> &DnsResolver {
        &self.dns
    }

    fn tls_config(&self) -> Arc<rustls::ServerConfig> {
        let resolver = Arc::new(SniResolver::new(self.cert_store.clone()));
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        // Offer both so a client's ALPN choice is honored on the intercept path too.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Bind port 443 on both loopback stacks and serve until `shutdown` resolves.
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let listeners = preflight::bind_loopback(LISTEN_PORT).await?;
        self.serve_many(listeners, shutdown).await
    }

    /// Serve on an already-bound listener. Lets tests and benchmarks run on an ephemeral port
    /// without the privilege that binding 443 would need.
    pub async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        self.serve_many(vec![listener], shutdown).await
    }

    async fn serve_many(
        self,
        listeners: Vec<TcpListener>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        let tls_config = self.tls_config();
        let shared = Arc::new(Shared {
            provider: self.provider,
            map: self.map,
            dns: self.dns,
            upstream_tls: self
                .upstream_tls
                .unwrap_or_else(passthrough::upstream_tls_config),
            upstream_port: self.upstream_port,
        });

        // Fan the one-shot shutdown future out to every listener task via a watch channel.
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown.await;
            let _ = stop_tx.send(true);
        });

        let mut tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            tracing::info!(addr = ?listener.local_addr().ok(), "proxy listening");
            let tls_config = tls_config.clone();
            let shared = shared.clone();
            let mut stop = stop_rx.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.changed() => break,
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((tcp, peer)) => {
                                    let tls_config = tls_config.clone();
                                    let shared = shared.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = serve_conn(tls_config, shared, tcp).await {
                                            log_connection_error(peer, &e);
                                        }
                                    });
                                }
                                Err(e) => tracing::warn!(error = %e, "accept failed"),
                            }
                        }
                    }
                }
            }));
        }
        for task in tasks {
            let _ = task.await;
        }
        tracing::info!("shutdown signalled");
        Ok(())
    }
}

/// Say what a dead connection actually means, because the two cases look identical in a log
/// and lead opposite ways.
///
/// A client that distrusts our root ends the handshake with a fatal alert naming the reason —
/// that one is ours to fix, and it is the only thing the IDE will ever show as a generic
/// internal error. A handshake that simply hits EOF is a client that connected and walked away:
/// a port prober or health check, of which a developer machine has several, each arriving on a
/// metronome. Reporting those as a trust problem buries the real one.
fn log_connection_error(peer: std::net::SocketAddr, e: &Error) {
    let text = e.to_string();
    if !text.contains("tls accept") {
        tracing::debug!(%peer, error = %text, "connection ended");
        return;
    }

    let lower = text.to_ascii_lowercase();
    if lower.contains("unknownca")
        || lower.contains("unknown_ca")
        || lower.contains("badcertificate")
        || lower.contains("certificateunknown")
        || lower.contains("decryptionerror")
    {
        // Deliberately no verdict on *why*: a client reaches our root through the OS trust
        // store, through NODE_EXTRA_CA_CERTS, or not at all if it carries its own bundled
        // roots. Naming one of those as the cause sends people to fix what is already fine.
        tracing::warn!(
            %peer,
            error = %text,
            "the client rejected our certificate — it reached none of our trust paths. Check \
        `9rai ca status` for the system store; a process started before the proxy was enabled has \
        neither that nor NODE_EXTRA_CA_CERTS and needs restarting"
        );
    } else if lower.contains("eof") {
        tracing::debug!(
            %peer,
            error = %text,
            "client closed before completing the handshake (port probe or health check)"
        );
    } else {
        tracing::warn!(%peer, error = %text, "TLS handshake failed");
    }
}

async fn serve_conn(
    tls_config: Arc<rustls::ServerConfig>,
    shared: Arc<Shared>,
    tcp: tokio::net::TcpStream,
) -> Result<()> {
    tcp.set_nodelay(true).ok();

    // Read the ClientHello before finishing the handshake, purely so a failure can name the
    // host the client was asking for. "Someone rejected our certificate" is a dead end; "the
    // client asking for q.us-east-1.amazonaws.com rejected it" points straight at the process.
    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp)
        .await
        .map_err(|e| Error::Provider(format!("tls accept: {e}")))?;
    let sni = start
        .client_hello()
        .server_name()
        .map(str::to_string)
        .unwrap_or_else(|| "no SNI".to_string());

    let tls = start
        .into_stream(tls_config)
        .await
        .map_err(|e| Error::Provider(format!("tls accept for {sni}: {e}")))?;
    let io = TokioIo::new(tls);

    let service = service_fn(move |req: Request<Incoming>| {
        let shared = shared.clone();
        async move { Ok::<_, Infallible>(route_request(shared, req).await) }
    });

    ServerBuilder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await
        .map_err(|e| Error::Provider(format!("serve connection: {e}")))
}

/// Route one request, always returning a response (errors become a 502 body).
async fn route_request(shared: Arc<Shared>, req: Request<Incoming>) -> Response<BoxBody> {
    // Enough of the request to answer "did the IDE reach us, and what did we do with it" from
    // the log alone — the question every report of "the proxy is up but nothing works" asks.
    let started = std::time::Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    match try_route(shared, req).await {
        Ok(resp) => {
            tracing::info!(
                %method,
                %host,
                %path,
                status = resp.status().as_u16(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "request handled"
            );
            resp
        }
        Err(e) => {
            tracing::warn!(%method, %host, %path, error = %e, "request failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("9rai proxy error: {e}")))
                .expect("static builder")
        }
    }
}

async fn try_route(shared: Arc<Shared>, req: Request<Incoming>) -> Result<Response<BoxBody>> {
    let (parts, body) = req.into_parts();

    let host = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| parts.uri.host().map(str::to_string))
        .unwrap_or_default();
    // Routing decisions use the bare path — a query string must not defeat the health probe
    // or the chat-request match.
    let path = parts.uri.path().to_string();
    let amz_target = parts
        .headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let bytes = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| Error::Provider("request body exceeded limit".into()))?
        .to_bytes();

    let decision = classify(&host, &path, amz_target.as_deref(), &bytes, &shared.map);
    match &decision {
        Decision::Health => {}
        Decision::Intercept { model } => tracing::info!(
            %host,
            %path,
            target = amz_target.as_deref().unwrap_or("-"),
            bytes = bytes.len(),
            provider_model = %model,
            "intercepting chat turn"
        ),
        // Why a turn was *not* intercepted is the more valuable line of the two: an unmapped
        // model id or an unexpected path both look like "the proxy did nothing".
        Decision::Passthrough => tracing::info!(
            %host,
            %path,
            target = amz_target.as_deref().unwrap_or("-"),
            bytes = bytes.len(),
            "passing through untouched (not a mapped chat turn)"
        ),
    }

    match decision {
        Decision::Health => Ok(health_response()),
        Decision::Intercept { model } => {
            intercept::intercept(&shared.provider, &model, &bytes).await
        }
        Decision::Passthrough => {
            let upstream = rebuild_request(&parts, &host, bytes)?;
            passthrough::passthrough(
                &shared.dns,
                shared.upstream_tls.clone(),
                &host,
                shared.upstream_port,
                upstream,
            )
            .await
        }
    }
}

fn rebuild_request(
    parts: &hyper::http::request::Parts,
    host: &str,
    bytes: Bytes,
) -> Result<Request<Full<Bytes>>> {
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    // Absolute-form URI gives both the h1 and h2 clients an authority to work from.
    let uri: hyper::Uri = format!("https://{host}{path}")
        .parse()
        .map_err(|e| Error::Provider(format!("rebuild uri: {e}")))?;

    let mut builder = Request::builder().method(parts.method.clone()).uri(uri);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(bytes))
        .map_err(|e| Error::Provider(format!("rebuild request: {e}")))
}

fn health_response() -> Response<BoxBody> {
    let pid = std::process::id();
    let body = serde_json::json!({ "ok": true, "pid": pid }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full(body))
        .expect("static builder")
}
