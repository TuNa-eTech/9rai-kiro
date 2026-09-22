//! Golden fixture + independent-decoder validation.
//!
//! `fixtures/resp.sse` is a captured-style OpenAI transcript (text, a `<think>` block split
//! across chunks, a tool call with fragmented arguments, usage after finish_reason). Two
//! properties are asserted:
//!
//! 1. Our pipeline output is byte-identical to the committed golden `fixtures/out.bin`.
//!    Regenerate with: `cargo run -p nine-rai-cli -- response --input fixtures/resp.sse
//!    --output fixtures/out.bin --model gpt-4o` and review the diff before committing.
//! 2. The same output decodes cleanly under `aws-smithy-eventstream` — AWS's own
//!    implementation — not just our in-house decoder.

use aws_smithy_eventstream::frame::read_message_from;
use nine_rai_core::translate::{SseReader, StreamState};
use nine_rai_core::types::openai::StreamChunk;

fn fixtures() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn produce(sse: &str, model: &str) -> Vec<u8> {
    let mut reader = SseReader::new();
    let mut state = StreamState::new(model, None);
    let mut out: Vec<u8> = Vec::new();
    for payload in reader.push(sse.as_bytes()) {
        if let Ok(chunk) = serde_json::from_str::<StreamChunk>(&payload) {
            for frame in state.on_chunk(&chunk) {
                out.extend_from_slice(&frame);
            }
        }
    }
    if let Some(payload) = reader.flush() {
        if let Ok(chunk) = serde_json::from_str::<StreamChunk>(&payload) {
            for frame in state.on_chunk(&chunk) {
                out.extend_from_slice(&frame);
            }
        }
    }
    for frame in state.finish() {
        out.extend_from_slice(&frame);
    }
    out
}

fn event_types(bytes: &[u8]) -> Vec<String> {
    let mut rest = bytes;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let msg = read_message_from(&mut rest).expect("smithy decoder must accept the frame");
        let event = msg
            .headers()
            .iter()
            .find(|h| h.name().as_str() == ":event-type")
            .map(|h| {
                h.value()
                    .as_string()
                    .expect(":event-type must be a string header")
                    .as_str()
                    .to_string()
            })
            .unwrap_or_else(|| "<none>".to_string());
        out.push(event);
    }
    out
}

#[test]
fn pipeline_output_matches_the_committed_golden() {
    let sse = std::fs::read_to_string(fixtures().join("resp.sse")).unwrap();
    let golden = std::fs::read(fixtures().join("out.bin")).unwrap();
    let produced = produce(&sse, "gpt-4o");
    assert_eq!(
        produced, golden,
        "pipeline output drifted from fixtures/out.bin — if this is deliberate, regenerate the \
         golden and review the byte diff"
    );
}

#[test]
fn pipeline_output_decodes_under_aws_smithy_eventstream() {
    let sse = std::fs::read_to_string(fixtures().join("resp.sse")).unwrap();
    let produced = produce(&sse, "gpt-4o");
    let kinds = event_types(&produced);
    assert_eq!(
        kinds,
        [
            "initial-response",
            // The <think> tag straddles two chunks: reasoning + visible text per chunk.
            "reasoningContentEvent",
            "assistantResponseEvent",
            "reasoningContentEvent",
            "assistantResponseEvent",
            // tool init + two argument fragments
            "toolUseEvent",
            "toolUseEvent",
            "toolUseEvent",
            // stop:true for the tool, then usage (FIX 3: emitted even though it arrived
            // after finish_reason), then the terminal frame (FIX 1).
            "toolUseEvent",
            "usageEvent",
            "messageStopEvent",
        ],
        "unexpected frame sequence"
    );
}
