//! Loopback control channel for the desktop GUI: status + stop behind a bearer token.
//!
//! The unprivileged GUI spawns `9rai daemon --control-port <p> --token <t>` and talks to the
//! privileged daemon only through this server. Bound to 127.0.0.1 by the caller; every request
//! needs the per-session token, because POST /stop can take the proxy (and with it the hosts
//! redirection lifecycle) down.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::Result;

type ControlBody = Full<Bytes>;

/// Serve until `stop` is signalled (or the process exits). An authorized `POST /stop` flips
/// `stop`, which both ends this server and shuts the proxy down via the daemon's wiring.
pub async fn serve_control(
    listener: TcpListener,
    token: Arc<str>,
    stop: watch::Sender<bool>,
) -> Result<()> {
    let mut stop_rx = stop.subscribe();
    loop {
        tokio::select! {
            _ = stop_rx.changed() => return Ok(()),
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "control accept failed");
                        continue;
                    }
                };
                let token = token.clone();
                let stop = stop.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let token = token.clone();
                        let stop = stop.clone();
                        async move { Ok::<_, Infallible>(handle(&token, &stop, req)) }
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .await
                    {
                        tracing::debug!(%peer, error = %e, "control connection ended");
                    }
                });
            }
        }
    }
}

fn handle(
    token: &Arc<str>,
    stop: &watch::Sender<bool>,
    req: Request<Incoming>,
) -> Response<ControlBody> {
    let authorized = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == token.as_ref());
    if !authorized {
        return text(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/status") => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "pid": std::process::id(),
            }),
        ),
        (&Method::POST, "/stop") => {
            let _ = stop.send(true);
            json(StatusCode::OK, serde_json::json!({ "stopping": true }))
        }
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

fn json(status: StatusCode, value: serde_json::Value) -> Response<ControlBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("static builder")
}

fn text(status: StatusCode, message: &str) -> Response<ControlBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(message.to_string())))
        .expect("static builder")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start() -> (u16, watch::Receiver<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop_tx, stop_rx) = watch::channel(false);
        tokio::spawn(serve_control(listener, Arc::from("s3cret"), stop_tx));
        (port, stop_rx)
    }

    async fn request(port: u16, method: &str, path: &str, auth: Option<&str>) -> (u16, String) {
        let mut status = 0u16;
        let mut body = String::new();
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let auth_header = auth
            .map(|t| format!("authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n{auth_header}connection: close\r\n\r\n"
        );
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf);
        if let Some((head, tail)) = raw.split_once("\r\n\r\n") {
            status = head
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            body = tail.to_string();
        }
        (status, body)
    }

    #[tokio::test]
    async fn status_requires_the_bearer_token() {
        let (port, _rx) = start().await;
        let (status, _) = request(port, "GET", "/status", None).await;
        assert_eq!(status, 401);
        let (status, _) = request(port, "GET", "/status", Some("wrong")).await;
        assert_eq!(status, 401);
        let (status, body) = request(port, "GET", "/status", Some("s3cret")).await;
        assert_eq!(status, 200);
        assert!(body.contains("\"ok\":true"), "got {body}");
    }

    #[tokio::test]
    async fn stop_flips_the_watch_channel() {
        let (port, mut rx) = start().await;
        assert!(!*rx.borrow());
        let (status, _) = request(port, "POST", "/stop", Some("s3cret")).await;
        assert_eq!(status, 200);
        rx.changed().await.unwrap();
        assert!(*rx.borrow());
    }
}
