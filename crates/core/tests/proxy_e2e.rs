//! End-to-end proxy tests against a mock Kiro client and mock upstreams — no real network.
//!
//! Proves the M3/M4 paths in-process: TLS termination with a minted leaf, request
//! classification, intercept translation against a mock OpenAI provider, and byte-relay
//! passthrough against a mock TLS upstream over both HTTP/1.1 and HTTP/2.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nine_rai_core::cert::CertStore;
use nine_rai_core::eventstream::testing::decode_stream;
use nine_rai_core::mapping::ModelMap;
use nine_rai_core::provider::{Provider, ProviderConfig};
use nine_rai_core::proxy::{init_crypto, ProxyServer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const KIRO_HOST: &str = "codewhisperer.us-east-1.amazonaws.com";
const UPSTREAM_MARKER: &[u8] = b"upstream-real-response";

/// Serves a single pre-minted leaf regardless of SNI (the mock upstream side).
#[derive(Debug)]
struct OneCert(Arc<CertifiedKey>);

impl ResolvesServerCert for OneCert {
    fn resolve(&self, _: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn client_tls_trusting(root_pem: &str, h2_only: bool) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(root_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = if h2_only {
        vec![b"h2".to_vec()]
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    Arc::new(config)
}

/// A mock OpenAI endpoint that replies with a fixed SSE transcript (plain HTTP).
async fn start_mock_provider() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let service = service_fn(|_req: Request<Incoming>| async {
                    let sse = concat!(
                        "data: {\"model\":\"mock\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n",
                        "data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n",
                        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n",
                        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n",
                        "data: [DONE]\n",
                    );
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .header("content-type", "text/event-stream")
                            .body(Full::new(Bytes::from(sse)))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    format!("http://{addr}")
}

/// A mock *upstream* (the "real AWS"): TLS with a cert from its own CA, speaks h1 or h2,
/// answers every request with a marker body.
async fn start_mock_upstream(h2_only: bool) -> (u16, String) {
    let ca = CertStore::ephemeral().unwrap();
    let root_pem = ca.root_cert_pem().to_string();
    let leaf = ca.certified_key(KIRO_HOST).unwrap();

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneCert(leaf)));
    config.alpn_protocols = if h2_only {
        vec![b"h2".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let service = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .header("content-type", "text/plain")
                            .header("x-mock", "yes")
                            .body(Full::new(Bytes::from_static(UPSTREAM_MARKER)))
                            .unwrap(),
                    )
                });
                if h2_only {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                }
            });
        }
    });

    (port, root_pem)
}

fn test_map() -> ModelMap {
    ModelMap {
        models: HashMap::from([("auto".to_string(), "mock".to_string())]),
        default: None,
    }
}

/// Bring up the proxy on an ephemeral port; returns the address and the proxy's root CA PEM.
async fn start_proxy(provider_base: String) -> (std::net::SocketAddr, String) {
    let store = Arc::new(CertStore::ephemeral().unwrap());
    let root_pem = store.root_cert_pem().to_string();
    let provider = Provider::new(ProviderConfig {
        base_url: provider_base,
        api_key: "test-key".into(),
    })
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = ProxyServer::new(provider, test_map(), store).unwrap();

    tokio::spawn(async move {
        server
            .serve_on(listener, std::future::pending::<()>())
            .await
            .unwrap();
    });

    (addr, root_pem)
}

/// Proxy with passthrough redirected to the given mock upstream (TLS config + DNS seed).
async fn start_proxy_with_upstream(
    provider_base: String,
    upstream_port: u16,
    upstream_root: &str,
) -> (std::net::SocketAddr, String) {
    let store = Arc::new(CertStore::ephemeral().unwrap());
    let root_pem = store.root_cert_pem().to_string();
    let provider = Provider::new(ProviderConfig {
        base_url: provider_base,
        api_key: "test-key".into(),
    })
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = ProxyServer::new(provider, test_map(), store)
        .unwrap()
        .with_upstream_tls(client_tls_trusting(upstream_root, false))
        .with_upstream_port(upstream_port);
    server
        .dns()
        .seed(KIRO_HOST, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);

    tokio::spawn(async move {
        server
            .serve_on(listener, std::future::pending::<()>())
            .await
            .unwrap();
    });

    (addr, root_pem)
}

/// An HTTP/1.1 TLS client trusting our root, pinning SNI to `KIRO_HOST`.
async fn kiro_client_h1(
    addr: std::net::SocketAddr,
    root_pem: &str,
) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
    let connector = TlsConnector::from(client_tls_trusting(root_pem, false));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(KIRO_HOST).unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();

    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

/// An HTTP/2 TLS client — the dialect modern Electron-based clients may negotiate.
async fn kiro_client_h2(
    addr: std::net::SocketAddr,
    root_pem: &str,
) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    let connector = TlsConnector::from(client_tls_trusting(root_pem, true));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(KIRO_HOST).unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

fn kiro_body(model: &str) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "conversationState": {
                "conversationId": "conv-test-1",
                "currentMessage": { "userInputMessage": { "content": "hi", "modelId": model } },
                "history": []
            }
        }))
        .unwrap(),
    )
}

fn assert_eventstream_response(body: Bytes) -> Vec<String> {
    let frames = decode_stream(&body);
    let kinds: Vec<String> = frames.iter().map(|f| f.event_type().to_string()).collect();
    assert_eq!(kinds.first().map(String::as_str), Some("initial-response"));
    assert_eq!(kinds.last().map(String::as_str), Some("messageStopEvent"));
    kinds
}

#[tokio::test]
async fn health_endpoint_answers_over_tls() {
    init_crypto();
    let (addr, root_pem) = start_proxy("http://127.0.0.1:1".into()).await;
    let mut sender = kiro_client_h1(addr, &root_pem).await;

    let req = Request::builder()
        .method("GET")
        .uri("/_mitm_health")
        .header("host", KIRO_HOST)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
}

#[tokio::test]
async fn health_endpoint_tolerates_a_query_string() {
    init_crypto();
    let (addr, root_pem) = start_proxy("http://127.0.0.1:1".into()).await;
    let mut sender = kiro_client_h1(addr, &root_pem).await;

    let req = Request::builder()
        .method("GET")
        .uri("/_mitm_health?probe=1")
        .header("host", KIRO_HOST)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn mapped_chat_turn_is_translated_end_to_end() {
    init_crypto();
    let provider_base = start_mock_provider().await;
    let (addr, root_pem) = start_proxy(provider_base).await;
    let mut sender = kiro_client_h1(addr, &root_pem).await;

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", KIRO_HOST)
        .header(
            "x-amz-target",
            "KiroRuntimeService.GenerateAssistantResponse",
        )
        .body(Full::new(kiro_body("auto")))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/vnd.amazon.eventstream"
    );

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let frames = decode_stream(&body);
    let kinds: Vec<&str> = frames.iter().map(|f| f.event_type()).collect();
    assert_eq!(kinds.first(), Some(&"initial-response"));
    assert_eq!(kinds.last(), Some(&"messageStopEvent"));

    // The conversation id from the request is echoed back.
    assert_eq!(frames[0].json()["conversationId"], "conv-test-1");

    let text: String = frames
        .iter()
        .filter(|f| f.event_type() == "assistantResponseEvent")
        .map(|f| f.json()["content"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(text, "Hello world");

    let usage = frames
        .iter()
        .find(|f| f.event_type() == "usageEvent")
        .expect("usage must be reported even though it arrives after finish_reason");
    assert_eq!(usage.json()["inputTokens"], 5);
}

#[tokio::test]
async fn intercept_works_for_an_http2_client() {
    init_crypto();
    let provider_base = start_mock_provider().await;
    let (addr, root_pem) = start_proxy(provider_base).await;
    let mut sender = kiro_client_h2(addr, &root_pem).await;

    // h2 needs an absolute-form URI for :authority.
    let req = Request::builder()
        .method("POST")
        .uri(format!("https://{KIRO_HOST}/"))
        .header(
            "x-amz-target",
            "KiroRuntimeService.GenerateAssistantResponse",
        )
        .body(Full::new(kiro_body("auto")))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eventstream_response(body);
}

#[tokio::test]
async fn passthrough_relays_an_unmapped_chat_turn_over_http1() {
    init_crypto();
    let (upstream_port, upstream_root) = start_mock_upstream(false).await;
    let (addr, root_pem) =
        start_proxy_with_upstream("http://127.0.0.1:1".into(), upstream_port, &upstream_root).await;
    let mut sender = kiro_client_h1(addr, &root_pem).await;

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", KIRO_HOST)
        .header(
            "x-amz-target",
            "KiroRuntimeService.GenerateAssistantResponse",
        )
        .body(Full::new(kiro_body("some-unmapped-model")))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-mock").unwrap(), "yes");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        body.as_ref(),
        UPSTREAM_MARKER,
        "passthrough must relay bytes untouched"
    );
}

#[tokio::test]
async fn passthrough_relays_a_non_chat_request_over_http2_upstream() {
    init_crypto();
    let (upstream_port, upstream_root) = start_mock_upstream(true).await;
    let (addr, root_pem) =
        start_proxy_with_upstream("http://127.0.0.1:1".into(), upstream_port, &upstream_root).await;
    let mut sender = kiro_client_h1(addr, &root_pem).await;

    let req = Request::builder()
        .method("GET")
        .uri("/telemetry")
        .header("host", KIRO_HOST)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), UPSTREAM_MARKER);
}
