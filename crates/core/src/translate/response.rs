//! OpenAI stream chunks -> AWS EventStream frames.
//!
//! Frame payload key order is chosen to match the JS reference byte-for-byte, so golden-file
//! parity tests can compare raw output. Deviations from that reference are deliberate and
//! marked `FIX(n)`, keyed to the defect table in the project plan.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::eventstream::{self, event};
use crate::translate::thinking::ThinkingSplitter;
use crate::types::openai;

#[derive(Serialize)]
struct ContentPayload<'a> {
    content: &'a str,
    #[serde(rename = "modelId")]
    model_id: &'a str,
}

#[derive(Serialize)]
struct ToolInitPayload<'a> {
    name: &'a str,
    #[serde(rename = "toolUseId")]
    tool_use_id: &'a str,
}

#[derive(Serialize)]
struct ToolInputPayload<'a> {
    input: &'a str,
    name: &'a str,
    #[serde(rename = "toolUseId")]
    tool_use_id: &'a str,
}

#[derive(Serialize)]
struct ToolStopPayload<'a> {
    name: &'a str,
    stop: bool,
    #[serde(rename = "toolUseId")]
    tool_use_id: &'a str,
}

#[derive(Serialize)]
struct UsagePayload {
    #[serde(rename = "inputTokens")]
    input_tokens: u64,
    #[serde(rename = "outputTokens")]
    output_tokens: u64,
}

#[derive(Debug, Default, Clone)]
struct ToolMeta {
    id: String,
    name: String,
}

pub struct StreamState {
    model_id: String,
    /// Echoed in the `initial-response` frame. The JS reference always sends an empty string;
    /// we echo the conversation id Kiro sent so multi-turn bookkeeping on newer builds has a
    /// real value to match against.
    conversation_id: String,
    /// Keyed by the OpenAI delta index. A BTreeMap keeps terminal frames in numeric order —
    /// FIX(2): the reference sorts stringified indices, so index 10 precedes index 2.
    tools: BTreeMap<usize, ToolMeta>,
    has_tool_calls: bool,
    usage: Option<openai::Usage>,
    thinking: ThinkingSplitter,
    initial_sent: bool,
    finished: bool,
}

impl StreamState {
    /// `model_id` is echoed back to Kiro; seed it with the mapped model name.
    /// `conversation_id` should be the id from the incoming request, when present.
    pub fn new(model_id: impl Into<String>, conversation_id: Option<&str>) -> Self {
        Self {
            model_id: model_id.into(),
            conversation_id: conversation_id.unwrap_or_default().to_string(),
            tools: BTreeMap::new(),
            has_tool_calls: false,
            usage: None,
            thinking: ThinkingSplitter::new(),
            initial_sent: false,
            finished: false,
        }
    }

    /// Every stream opens with `initial-response`; emit it lazily so it precedes real output.
    fn emit(&mut self, out: &mut Vec<Vec<u8>>, frame: Vec<u8>) {
        if !self.initial_sent {
            self.initial_sent = true;
            out.push(eventstream::initial_response(&self.conversation_id));
        }
        out.push(frame);
    }

    fn emit_content(&mut self, out: &mut Vec<Vec<u8>>, kind: &str, text: &str) {
        if text.is_empty() {
            return;
        }
        let payload = ContentPayload {
            content: text,
            model_id: &self.model_id,
        };
        // Serialization of a plain struct of strings cannot fail.
        let frame = eventstream::json_frame(kind, &payload).expect("content payload is encodable");
        self.emit(out, frame);
    }

    /// Feed one parsed chunk.
    pub fn on_chunk(&mut self, chunk: &openai::StreamChunk) -> Vec<Vec<u8>> {
        let mut out = Vec::new();

        if self.model_id.is_empty() {
            if let Some(m) = &chunk.model {
                self.model_id = m.clone();
            }
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
        }

        for choice in &chunk.choices {
            for tc in &choice.delta.tool_calls {
                self.has_tool_calls = true;
                let func = tc.function.as_ref();

                if let Some(id) = &tc.id {
                    let entry = self.tools.entry(tc.index).or_default();
                    if entry.id.is_empty() {
                        entry.id = id.clone();
                    }
                }
                if let Some(name) = func.and_then(|f| f.name.as_ref()) {
                    let entry = self.tools.entry(tc.index).or_default();
                    if entry.name.is_empty() {
                        entry.name = name.clone();
                        let meta = entry.clone();
                        let frame = eventstream::json_frame(
                            event::TOOL_USE,
                            &ToolInitPayload {
                                name: &meta.name,
                                tool_use_id: &meta.id,
                            },
                        )
                        .expect("tool init payload is encodable");
                        self.emit(&mut out, frame);
                    }
                }

                if let Some(args) = func.and_then(|f| f.arguments.as_ref()) {
                    if !args.is_empty() {
                        let meta = self.tools.get(&tc.index).cloned().unwrap_or_default();
                        // Fragments are forwarded raw; the consumer concatenates then parses.
                        let frame = eventstream::json_frame(
                            event::TOOL_USE,
                            &ToolInputPayload {
                                input: args,
                                name: &meta.name,
                                tool_use_id: &meta.id,
                            },
                        )
                        .expect("tool input payload is encodable");
                        self.emit(&mut out, frame);
                    }
                }
            }

            if let Some(reasoning) = &choice.delta.reasoning_content {
                self.emit_content(&mut out, event::REASONING_CONTENT, &reasoning.clone());
            }

            if let Some(content) = &choice.delta.content {
                let split = self.thinking.push(content);
                self.emit_content(&mut out, event::REASONING_CONTENT, &split.reasoning.clone());
                self.emit_content(&mut out, event::ASSISTANT_RESPONSE, &split.text.clone());
            }

            if choice.finish_reason.is_some() {
                // FIX(3): do NOT close the stream here. Providers routinely send usage in a
                // chunk *after* finish_reason; the reference short-circuits and loses it.
                self.finished = true;
            }
        }

        out
    }

    /// Close the stream. Must be called exactly once, at end of the upstream byte stream.
    pub fn finish(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();

        let tail = self.thinking.flush();
        self.emit_content(&mut out, event::REASONING_CONTENT, &tail.reasoning.clone());
        self.emit_content(&mut out, event::ASSISTANT_RESPONSE, &tail.text.clone());

        if self.has_tool_calls {
            for meta in self.tools.values().cloned().collect::<Vec<_>>() {
                let frame = eventstream::json_frame(
                    event::TOOL_USE,
                    &ToolStopPayload {
                        name: &meta.name,
                        stop: true,
                        tool_use_id: &meta.id,
                    },
                )
                .expect("tool stop payload is encodable");
                self.emit(&mut out, frame);
            }
        }

        if let Some(usage) = self.usage {
            let frame = eventstream::json_frame(
                event::USAGE,
                &UsagePayload {
                    input_tokens: usage.prompt_tokens,
                    output_tokens: usage.completion_tokens,
                },
            )
            .expect("usage payload is encodable");
            self.emit(&mut out, frame);
        }

        // FIX(1): the reference omits this for tool-call responses and after a thinking
        // flush, leaving the client waiting on a stream that never formally ends.
        let stop = eventstream::frame(event::MESSAGE_STOP, b"{}", "application/json");
        self.emit(&mut out, stop);

        out
    }

    /// Whether the upstream signalled `finish_reason` before the stream ended.
    pub fn saw_finish(&self) -> bool {
        self.finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventstream::testing::decode_all;

    fn chunk(json: serde_json::Value) -> openai::StreamChunk {
        serde_json::from_value(json).expect("chunk fixture must parse")
    }

    /// Run a whole stream and return `(event_type, payload_json)` pairs.
    fn run(chunks: Vec<serde_json::Value>) -> Vec<(String, serde_json::Value)> {
        let mut state = StreamState::new("test-model", None);
        let mut frames = Vec::new();
        for c in chunks {
            frames.extend(state.on_chunk(&chunk(c)));
        }
        frames.extend(state.finish());
        decode_all(&frames.concat())
    }

    #[test]
    fn text_stream_opens_with_initial_response_and_ends_with_message_stop() {
        let got = run(vec![
            serde_json::json!({"choices":[{"delta":{"content":"hi"}}]}),
            serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}]}),
        ]);
        let kinds: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "initial-response",
                "assistantResponseEvent",
                "messageStopEvent"
            ]
        );
        assert_eq!(got[1].1["content"], "hi");
        assert_eq!(got[1].1["modelId"], "test-model");
    }

    #[test]
    fn tool_call_stream_still_terminates_with_message_stop() {
        // FIX(1): the JS reference emits the tool stop frame and then nothing.
        let got = run(vec![
            serde_json::json!({"choices":[{"delta":{"tool_calls":[
                {"index":0,"id":"t1","function":{"name":"read","arguments":""}}
            ]}}]}),
            serde_json::json!({"choices":[{"delta":{"tool_calls":[
                {"index":0,"function":{"arguments":"{\"p\":1}"}}
            ]}}]}),
            serde_json::json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
        ]);
        let kinds: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "initial-response",
                "toolUseEvent",
                "toolUseEvent",
                "toolUseEvent",
                "messageStopEvent"
            ]
        );
        assert_eq!(got[1].1["name"], "read");
        assert_eq!(got[1].1["toolUseId"], "t1");
        // Argument fragments are forwarded raw, not accumulated.
        assert_eq!(got[2].1["input"], "{\"p\":1}");
        assert_eq!(got[3].1["stop"], true);
    }

    #[test]
    fn terminal_tool_frames_are_ordered_numerically() {
        // FIX(2): lexicographic key sort would place index 10 before index 2.
        let mut chunks = Vec::new();
        for i in [2usize, 10, 1] {
            chunks.push(serde_json::json!({"choices":[{"delta":{"tool_calls":[
                {"index": i, "id": format!("t{i}"), "function":{"name": format!("f{i}")}}
            ]}}]}));
        }
        let got = run(chunks);
        let stops: Vec<&str> = got
            .iter()
            .filter(|(k, v)| k == "toolUseEvent" && v.get("stop").is_some())
            .map(|(_, v)| v["toolUseId"].as_str().unwrap())
            .collect();
        assert_eq!(stops, ["t1", "t2", "t10"]);
    }

    #[test]
    fn usage_arriving_after_finish_reason_is_still_reported() {
        // FIX(3): the reference closes at finish_reason and drops this chunk entirely.
        let got = run(vec![
            serde_json::json!({"choices":[{"delta":{"content":"x"}}]}),
            serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}]}),
            serde_json::json!({"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}),
        ]);
        let usage = got
            .iter()
            .find(|(k, _)| k == "usageEvent")
            .expect("usageEvent must be emitted");
        assert_eq!(usage.1["inputTokens"], 7);
        assert_eq!(usage.1["outputTokens"], 3);
        // It must precede the terminal frame, which the client treats as end-of-stream.
        let kinds: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds.last(), Some(&"messageStopEvent"));
    }

    #[test]
    fn thinking_blocks_are_routed_to_the_reasoning_channel() {
        let got = run(vec![
            serde_json::json!({"choices":[{"delta":{"content":"a<think>why"}}]}),
            serde_json::json!({"choices":[{"delta":{"content":"</think>b"}}]}),
        ]);
        let reasoning: String = got
            .iter()
            .filter(|(k, _)| k == "reasoningContentEvent")
            .map(|(_, v)| v["content"].as_str().unwrap())
            .collect();
        let text: String = got
            .iter()
            .filter(|(k, _)| k == "assistantResponseEvent")
            .map(|(_, v)| v["content"].as_str().unwrap())
            .collect();
        assert_eq!(reasoning, "why");
        assert_eq!(text, "ab");
    }

    #[test]
    fn native_reasoning_content_is_forwarded() {
        let got = run(vec![serde_json::json!({
            "choices":[{"delta":{"reasoning_content":"deliberating"}}]
        })]);
        assert_eq!(got[1].0, "reasoningContentEvent");
        assert_eq!(got[1].1["content"], "deliberating");
    }

    #[test]
    fn initial_response_echoes_the_request_conversation_id() {
        let mut state = StreamState::new("m", Some("conv-123"));
        let frames = state.on_chunk(&chunk(
            serde_json::json!({"choices":[{"delta":{"content":"x"}}]}),
        ));
        let decoded = decode_all(&frames.concat());
        assert_eq!(decoded[0].1["conversationId"], "conv-123");
    }

    #[test]
    fn an_empty_stream_still_produces_a_well_formed_terminal_pair() {
        let got = run(vec![]);
        let kinds: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds, ["initial-response", "messageStopEvent"]);
    }
}
