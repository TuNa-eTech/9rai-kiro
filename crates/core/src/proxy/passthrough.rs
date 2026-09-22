//! Forward a request to the real upstream, unmodified.
//!
//! Unlike the reference — which disables certificate verification everywhere — we resolve the
//! true IP, set SNI to the real hostname, and verify against the webpki roots. There is no
//! reason to skip verification once we are talking to the genuine host, and doing so closes a
//! hole in the original. ALPN is read from the live connection rather than a throwaway probe.

use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::dns::DnsResolver;
use crate::proxy::body::{box_body, BoxBody};
use crate::{Error, Result};

/// Headers that must not cross a connection boundary, in either direction. Applies to the
/// relayed response too — forwarding `transfer-encoding` would fight hyper's re-framing.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

/// Build the client TLS config once; it is cloned per connection.
pub fn upstream_tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

pub async fn passthrough(
    dns: &DnsResolver,
    tls: Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
    req: Request<Full<Bytes>>,
) -> Result<Response<BoxBody>> {
    let tcp = connect_any(dns.resolve(host).await?.iter().copied(), host, port).await?;
    tcp.set_nodelay(true).ok();

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| Error::Provider(format!("invalid server name {host}: {e}")))?;
    let tls_stream = TlsConnector::from(tls)
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Provider(format!("tls to {host}: {e}")))?;

    let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = TokioIo::new(tls_stream);

    if is_h2 {
        forward_h2(io, host, req).await
    } else {
        forward_h1(io, host, req).await
    }
}

/// Try each resolved address in order; only fail when every one refuses us.
async fn connect_any(
    ips: impl Iterator<Item = IpAddr>,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    let mut last_err: Option<std::io::Error> = None;
    let mut tried = 0usize;
    for ip in ips {
        tried += 1;
        match TcpStream::connect((ip, port)).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => {
                tracing::debug!(%host, %ip, error = %e, "upstream connect failed; trying next");
                last_err = Some(e);
            }
        }
    }
    match last_err {
        Some(e) => Err(Error::Provider(format!(
            "connect {host}:{port} failed for all {tried} address(es), last: {e}"
        ))),
        None => Err(Error::Provider(format!("no address for {host}"))),
    }
}

fn sanitize(req: &mut Request<Full<Bytes>>, host: &str) {
    let headers = req.headers_mut();
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    // The body is fully buffered; let hyper compute framing instead of trusting whatever
    // the client sent.
    headers.remove(hyper::header::CONTENT_LENGTH);
    if let Ok(value) = host.parse() {
        headers.insert(hyper::header::HOST, value);
    }
}

async fn forward_h1<S>(
    io: TokioIo<S>,
    host: &str,
    mut req: Request<Full<Bytes>>,
) -> Result<Response<BoxBody>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    sanitize(&mut req, host);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| Error::Provider(format!("http1 handshake: {e}")))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "upstream http1 connection closed");
        }
    });
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Provider(format!("http1 request: {e}")))?;
    Ok(relay_response(resp))
}

async fn forward_h2<S>(
    io: TokioIo<S>,
    host: &str,
    mut req: Request<Full<Bytes>>,
) -> Result<Response<BoxBody>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    sanitize(&mut req, host);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .map_err(|e| Error::Provider(format!("http2 handshake: {e}")))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "upstream http2 connection closed");
        }
    });
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Provider(format!("http2 request: {e}")))?;
    Ok(relay_response(resp))
}

fn relay_response(resp: Response<Incoming>) -> Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    for name in HOP_BY_HOP {
        parts.headers.remove(*name);
    }
    let boxed = box_body(body.map_err(|e| Error::Provider(format!("upstream body: {e}"))));
    Response::from_parts(parts, boxed)
}
