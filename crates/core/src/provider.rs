//! The user's own OpenAI-compatible endpoint.

use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::types::openai::ChatRequest;
use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Endpoint root, e.g. `https://api.openai.com/v1`.
    pub base_url: String,
    pub api_key: String,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com/v1".into(),
            api_key: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Provider {
    config: ProviderConfig,
    http: reqwest::Client,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            // No overall timeout: a long agentic turn can legitimately stream for minutes.
            // The connect phase is what we want bounded.
            .connect_timeout(std::time::Duration::from_secs(20))
            .build()?;
        Ok(Self { config, http })
    }

    fn endpoint(&self) -> String {
        format!(
            "{}/chat/completions",
            self.config.base_url.trim_end_matches('/')
        )
    }

    /// Open the upstream stream.
    ///
    /// A non-2xx response is surfaced here, before any bytes reach the client. The reference
    /// implementation never checks the status, so an upstream 429 reaches the IDE as a
    /// well-formed but completely empty answer.
    pub async fn stream(
        &self,
        request: &ChatRequest,
    ) -> Result<impl Stream<Item = Result<bytes::Bytes>> + Unpin> {
        let response = self
            .http
            .post(self.endpoint())
            .bearer_auth(&self.config.api_key)
            .json(request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let detail: String = body.chars().take(500).collect();
            return Err(Error::Provider(format!(
                "upstream returned {status}: {detail}"
            )));
        }

        Ok(response
            .bytes_stream()
            .map(|chunk| chunk.map_err(Error::from))
            .boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::openai::{ChatMessage, ChatRequest, Role, StreamOptions};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    fn request() -> ChatRequest {
        ChatRequest {
            model: "mock".into(),
            messages: vec![ChatMessage::text(Role::User, "hi")],
            stream: true,
            stream_options: Some(StreamOptions {
                include_usage: true,
            }),
            tools: Vec::new(),
            tool_choice: None,
        }
    }

    /// A one-shot mock provider: replies with `status` and `body`, and hands the captured
    /// request JSON back over the returned channel.
    async fn mock_provider(
        status: u16,
        body: String,
    ) -> (String, tokio::sync::oneshot::Receiver<serde_json::Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                let tx = tx.lock().unwrap().take();
                let body = body.clone();
                async move {
                    let bytes = req.into_body().collect().await.unwrap().to_bytes();
                    if let Some(tx) = tx {
                        let _ = tx.send(serde_json::from_slice(&bytes).unwrap_or_default());
                    }
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(status)
                            .body(Full::new(bytes::Bytes::from(body)))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), service)
                .await;
        });
        (format!("http://{addr}"), rx)
    }

    #[tokio::test]
    async fn a_non_success_status_is_an_error_before_any_bytes_stream() {
        // FIX(5): the reference forwards the upstream status blindly, so a 429 reaches the
        // IDE as a well-formed but empty answer.
        crate::proxy::init_crypto();
        let (base_url, _rx) = mock_provider(429, "rate limited".into()).await;
        let provider = Provider::new(ProviderConfig {
            base_url,
            api_key: "k".into(),
        })
        .unwrap();
        let result = provider.stream(&request()).await;
        let err = match result {
            Ok(_) => panic!("a 429 must not produce a stream"),
            Err(e) => e,
        };
        let text = err.to_string();
        assert!(
            text.contains("429"),
            "expected the status in the error: {text}"
        );
        assert!(
            text.contains("rate limited"),
            "expected the body detail: {text}"
        );
    }

    #[tokio::test]
    async fn a_successful_request_asks_for_stream_usage_and_yields_the_body() {
        crate::proxy::init_crypto();
        let sse = "data: {\"choices\":[]}\n\ndata: [DONE]\n";
        let (base_url, rx) = mock_provider(200, sse.to_string()).await;
        let provider = Provider::new(ProviderConfig {
            base_url,
            api_key: "k".into(),
        })
        .unwrap();

        let mut stream = provider.stream(&request()).await.unwrap();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(String::from_utf8(body).unwrap(), sse);

        // stream_options.include_usage must be on the wire — without it providers omit usage
        // and the usage-event fix would never fire.
        let sent = rx.await.expect("request was captured");
        assert_eq!(sent["stream"], true);
        assert_eq!(sent["stream_options"]["include_usage"], true);
        assert_eq!(sent["model"], "mock");
    }
}
