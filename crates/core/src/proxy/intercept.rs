//! The interception path: translate a Kiro chat turn, call the provider, stream the reply back
//! as an AWS EventStream.

use bytes::Bytes;
use futures_util::StreamExt;
use hyper::body::Frame;
use hyper::{Response, StatusCode};

use crate::eventstream::{self, CONTENT_TYPE};
use crate::provider::Provider;
use crate::proxy::body::{box_body, full, BoxBody};
use crate::translate::{to_chat_request, SseReader, StreamState};
use crate::types::{cw, openai};
use crate::Result;

/// Depth of the frame channel between the upstream reader task and the response body.
const CHANNEL_DEPTH: usize = 32;

pub async fn intercept(provider: &Provider, model: &str, body: &[u8]) -> Result<Response<BoxBody>> {
    // Classification already confirmed this parses; this is belt-and-braces.
    let request: cw::Request = serde_json::from_slice(body)?;
    let chat = to_chat_request(&request, model)?;
    let conversation_id = request.conversation_state.conversation_id.clone();

    let upstream = match provider.stream(&chat).await {
        Ok(s) => s,
        Err(e) => {
            // The client is told inside the stream, as an exception frame — but that frame is
            // opaque to everything except the IDE, and the response itself is a healthy 200.
            // Without this line a provider outage reads as a perfectly successful request in
            // the log, which is the most expensive kind of silence.
            tracing::warn!(
                provider_model = %model,
                error = %e,
                "the provider call failed; returning an exception frame to the client"
            );
            // Pre-stream failure (e.g. a non-2xx upstream). Deliver a well-formed stream
            // carrying an exception frame, rather than raw bytes that fail the client's CRC.
            let mut out = eventstream::initial_response(conversation_id.as_deref().unwrap_or(""));
            out.extend(eventstream::error_frame("UpstreamError", &e.to_string()));
            return Ok(eventstream_response(full(out)));
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(CHANNEL_DEPTH);
    let model = model.to_string();

    tokio::spawn(async move {
        let mut upstream = upstream;
        let mut reader = SseReader::new();
        let mut state = StreamState::new(model, conversation_id.as_deref());

        loop {
            tokio::select! {
                // The response body owns the receiver; when Kiro aborts, the receiver is
                // dropped and `closed()` resolves. Without this arm a hung or silent provider
                // would pin the upstream connection (and its spend) indefinitely.
                _ = tx.closed() => return,
                chunk = upstream.next() => match chunk {
                    Some(Ok(bytes)) => {
                        for payload in reader.push(&bytes) {
                            if !feed(&mut state, &payload, &tx).await {
                                return;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "the provider stream failed mid-response");
                        let frame = eventstream::error_frame("UpstreamError", &e.to_string());
                        let _ = tx.send(Ok(Bytes::from(frame))).await;
                        return;
                    }
                    None => break,
                },
            }
        }
        if let Some(payload) = reader.flush() {
            if !feed(&mut state, &payload, &tx).await {
                return;
            }
        }
        for frame in state.finish() {
            if tx.send(Ok(Bytes::from(frame))).await.is_err() {
                return;
            }
        }
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    let body = http_body_util::StreamBody::new(stream.map(|res| res.map(Frame::data)));
    Ok(eventstream_response(box_body(body)))
}

/// Feed one SSE payload into the translator. Returns false when the client has gone away.
async fn feed(
    state: &mut StreamState,
    payload: &str,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes>>,
) -> bool {
    let Ok(chunk) = serde_json::from_str::<openai::StreamChunk>(payload) else {
        // Tolerate (and surface) malformed lines rather than aborting the whole stream.
        tracing::debug!(len = payload.len(), "skipping malformed SSE payload");
        return true;
    };
    for frame in state.on_chunk(&chunk) {
        if tx.send(Ok(Bytes::from(frame))).await.is_err() {
            return false;
        }
    }
    true
}

fn eventstream_response(body: BoxBody) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, CONTENT_TYPE)
        .header(hyper::header::CACHE_CONTROL, "no-cache")
        .body(body)
        .expect("static response builder cannot fail")
}
