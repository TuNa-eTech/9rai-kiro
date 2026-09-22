//! AWS EventStream (Smithy) binary framing — encode side.
//!
//! Kiro's SDK decodes the response with `SmithyMessageDecoderStream`, which rejects anything
//! that is not a well-formed frame, so we have to produce the exact wire format rather than
//! SSE. Frame layout, all integers big-endian:
//!
//! ```text
//! [totalLen u32][headersLen u32][preludeCrc u32][headers..][payload..][messageCrc u32]
//! ```
//!
//! `preludeCrc` covers the first 8 bytes; `messageCrc` covers everything before itself.

use bytes::{BufMut, BytesMut};

pub const CONTENT_TYPE: &str = "application/vnd.amazon.eventstream";

const JSON: &str = "application/json";
const AMZ_JSON_1_0: &str = "application/x-amz-json-1.0";

/// Header value type tag for a UTF-8 string, per the EventStream spec.
const HEADER_TYPE_STRING: u8 = 7;

fn crc32(bytes: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(bytes);
    h.finalize()
}

fn encode_header(out: &mut BytesMut, name: &str, value: &str) {
    let name = name.as_bytes();
    let value = value.as_bytes();
    debug_assert!(name.len() <= u8::MAX as usize);
    debug_assert!(value.len() <= u16::MAX as usize);

    out.put_u8(name.len() as u8);
    out.put_slice(name);
    out.put_u8(HEADER_TYPE_STRING);
    out.put_u16(value.len() as u16);
    out.put_slice(value);
}

/// Build one frame. `payload` is the already-serialized JSON body.
///
/// The three `:`-prefixed system headers are mandatory — the Smithy decoder errors out
/// without them even though the payload would parse fine.
pub fn frame(event_type: &str, payload: &[u8], content_type: &str) -> Vec<u8> {
    let mut headers = BytesMut::new();
    encode_header(&mut headers, ":message-type", "event");
    encode_header(&mut headers, ":event-type", event_type);
    encode_header(&mut headers, ":content-type", content_type);

    assemble(&headers, payload)
}

/// Wrap an already-encoded header block and payload in the prelude/CRC envelope.
fn assemble(headers: &[u8], payload: &[u8]) -> Vec<u8> {
    let headers_len = headers.len();
    let total_len = 4 + 4 + 4 + headers_len + payload.len() + 4;

    let mut buf = BytesMut::with_capacity(total_len);
    buf.put_u32(total_len as u32);
    buf.put_u32(headers_len as u32);
    buf.put_u32(crc32(&buf[..8]));
    buf.put_slice(headers);
    buf.put_slice(payload);

    let message_crc = crc32(&buf[..total_len - 4]);
    buf.put_u32(message_crc);

    buf.to_vec()
}

/// Frame carrying a JSON-serializable payload.
pub fn json_frame<T: serde::Serialize>(event_type: &str, payload: &T) -> crate::Result<Vec<u8>> {
    let body = serde_json::to_vec(payload)?;
    Ok(frame(event_type, &body, JSON))
}

/// Every real Kiro Runtime stream opens with this frame; the decoder expects it first.
pub fn initial_response(conversation_id: &str) -> Vec<u8> {
    let body = serde_json::json!({ "conversationId": conversation_id });
    frame(
        "initial-response",
        &serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
        AMZ_JSON_1_0,
    )
}

/// Signal a mid-stream failure.
///
/// The reference implementation appends a raw JSON error object into the binary stream, which
/// always fails the client's prelude-CRC check and surfaces as a decode error rather than the
/// actual problem. A framed `exception` message is what the decoder actually dispatches on.
pub fn error_frame(code: &str, message: &str) -> Vec<u8> {
    let payload = serde_json::json!({ "message": message });
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

    let mut headers = BytesMut::new();
    encode_header(&mut headers, ":message-type", "exception");
    encode_header(&mut headers, ":exception-type", code);
    encode_header(&mut headers, ":content-type", JSON);

    assemble(&headers, &body)
}

/// Event names Kiro's decoder dispatches on.
pub mod event {
    pub const ASSISTANT_RESPONSE: &str = "assistantResponseEvent";
    pub const REASONING_CONTENT: &str = "reasoningContentEvent";
    pub const TOOL_USE: &str = "toolUseEvent";
    pub const USAGE: &str = "usageEvent";
    pub const MESSAGE_STOP: &str = "messageStopEvent";
}

/// A spec-faithful decoder, used by tests across the crate and by the CLI's verify command.
///
/// This is deliberately an independent re-implementation rather than shared code with the
/// encoder: a decoder built from the same helpers would agree with an encoder that is wrong.
pub mod testing {
    use std::collections::BTreeMap;

    use super::{crc32, HEADER_TYPE_STRING};

    #[derive(Debug, Clone)]
    pub struct DecodedFrame {
        pub headers: BTreeMap<String, String>,
        pub payload: Vec<u8>,
    }

    impl DecodedFrame {
        pub fn event_type(&self) -> &str {
            self.headers
                .get(":event-type")
                .or_else(|| self.headers.get(":exception-type"))
                .map(String::as_str)
                .unwrap_or_default()
        }

        pub fn message_type(&self) -> &str {
            self.headers
                .get(":message-type")
                .map(String::as_str)
                .unwrap_or_default()
        }

        pub fn json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.payload).unwrap_or(serde_json::Value::Null)
        }
    }

    /// Decode one frame, validating both CRCs. Returns the frame and its total length.
    pub fn decode_frame(buf: &[u8]) -> Result<(DecodedFrame, usize), String> {
        if buf.len() < 16 {
            return Err(format!(
                "frame shorter than the 16-byte minimum: {}",
                buf.len()
            ));
        }
        let total_len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        let headers_len = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as usize;
        let prelude_crc = u32::from_be_bytes(buf[8..12].try_into().unwrap());

        if total_len > buf.len() {
            return Err(format!(
                "totalLen {total_len} exceeds the {} bytes available",
                buf.len()
            ));
        }
        if headers_len > total_len - 16 {
            return Err(format!(
                "headersLen {headers_len} does not fit in totalLen {total_len}"
            ));
        }
        if prelude_crc != crc32(&buf[..8]) {
            return Err("prelude CRC mismatch".into());
        }
        let message_crc = u32::from_be_bytes(buf[total_len - 4..total_len].try_into().unwrap());
        if message_crc != crc32(&buf[..total_len - 4]) {
            return Err("message CRC mismatch".into());
        }

        let mut headers = BTreeMap::new();
        let headers_end = 12 + headers_len;
        let mut cur = 12;
        while cur < headers_end {
            let name_len = buf[cur] as usize;
            cur += 1;
            let name = String::from_utf8_lossy(&buf[cur..cur + name_len]).into_owned();
            cur += name_len;
            if buf[cur] != HEADER_TYPE_STRING {
                return Err(format!("header {name} has non-string type {}", buf[cur]));
            }
            cur += 1;
            let value_len = u16::from_be_bytes(buf[cur..cur + 2].try_into().unwrap()) as usize;
            cur += 2;
            let value = String::from_utf8_lossy(&buf[cur..cur + value_len]).into_owned();
            cur += value_len;
            if headers.insert(name.clone(), value).is_some() {
                return Err(format!("duplicate header {name}"));
            }
        }

        Ok((
            DecodedFrame {
                headers,
                payload: buf[headers_end..total_len - 4].to_vec(),
            },
            total_len,
        ))
    }

    /// Decode a whole stream, panicking on the first malformed frame.
    pub fn decode_stream(mut buf: &[u8]) -> Vec<DecodedFrame> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            let (frame, len) = decode_frame(buf).expect("stream must decode");
            out.push(frame);
            buf = &buf[len..];
        }
        out
    }

    /// Convenience view used by translation tests: `(event type, payload as JSON)`.
    pub fn decode_all(buf: &[u8]) -> Vec<(String, serde_json::Value)> {
        decode_stream(buf)
            .into_iter()
            .map(|f| (f.event_type().to_string(), f.json()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{decode_frame, decode_stream};
    use super::*;

    fn decode(buf: &[u8]) -> (String, Vec<u8>) {
        let (frame, len) = decode_frame(buf).expect("frame must decode");
        assert_eq!(len, buf.len(), "totalLen must cover the whole frame");
        (frame.event_type().to_string(), frame.payload)
    }

    #[test]
    fn frame_roundtrips_through_a_spec_decoder() {
        let f = frame(event::ASSISTANT_RESPONSE, br#"{"content":"hi"}"#, JSON);
        let (event_type, payload) = decode(&f);
        assert_eq!(event_type, event::ASSISTANT_RESPONSE);
        assert_eq!(payload, br#"{"content":"hi"}"#);
    }

    #[test]
    fn initial_response_carries_the_amz_json_content_type() {
        let f = initial_response("");
        let (event_type, payload) = decode(&f);
        assert_eq!(event_type, "initial-response");
        assert!(String::from_utf8_lossy(&payload).contains("conversationId"));
        assert!(
            f.windows(AMZ_JSON_1_0.len())
                .any(|w| w == AMZ_JSON_1_0.as_bytes()),
            "must advertise x-amz-json-1.0"
        );
    }

    #[test]
    fn empty_payload_is_still_a_valid_frame() {
        let f = frame(event::MESSAGE_STOP, b"{}", JSON);
        let (event_type, payload) = decode(&f);
        assert_eq!(event_type, event::MESSAGE_STOP);
        assert_eq!(payload, b"{}");
    }

    #[test]
    fn error_frame_is_framed_as_an_exception_not_raw_json() {
        let f = error_frame("UpstreamError", "provider returned 429");
        let decoded = decode_stream(&f);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].message_type(), "exception");
        assert_eq!(decoded[0].event_type(), "UpstreamError");
        assert_eq!(decoded[0].json()["message"], "provider returned 429");
    }

    #[test]
    fn concatenated_frames_decode_back_in_order() {
        let mut stream = Vec::new();
        stream.extend(initial_response(""));
        stream.extend(frame(
            event::ASSISTANT_RESPONSE,
            br#"{"content":"a"}"#,
            JSON,
        ));
        stream.extend(frame(event::MESSAGE_STOP, b"{}", JSON));

        let kinds: Vec<String> = decode_stream(&stream)
            .iter()
            .map(|f| f.event_type().to_string())
            .collect();
        assert_eq!(
            kinds,
            [
                "initial-response",
                event::ASSISTANT_RESPONSE,
                event::MESSAGE_STOP
            ]
        );
    }

    #[test]
    fn a_corrupted_byte_is_rejected_by_the_crc_check() {
        let mut f = frame(event::ASSISTANT_RESPONSE, br#"{"content":"a"}"#, JSON);
        let last = f.len() - 5;
        f[last] ^= 0xff;
        assert!(decode_frame(&f).is_err());
    }
}
