//! Incremental `text/event-stream` reader.
//!
//! Bytes are buffered until a line is complete, so a multi-byte character split across two
//! network reads cannot be corrupted. Only `data:` lines carry payloads; `[DONE]` is a sentinel,
//! not a payload, and is never treated as a terminator (the byte stream ending is).

#[derive(Debug, Default)]
pub struct SseReader {
    buf: Vec<u8>,
}

fn payload(raw: &[u8]) -> Option<String> {
    let line = String::from_utf8_lossy(raw);
    let rest = line.trim().strip_prefix("data:")?.trim();
    (!rest.is_empty() && rest != "[DONE]").then(|| rest.to_string())
}

impl SseReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw bytes; returns the payloads of every line that completed.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=nl).collect();
            if let Some(p) = payload(&line[..nl]) {
                out.push(p);
            }
        }
        out
    }

    /// A final line with no trailing newline is still a valid event.
    pub fn flush(&mut self) -> Option<String> {
        let rest = std::mem::take(&mut self.buf);
        payload(&rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_complete_lines_and_skips_non_data() {
        let mut r = SseReader::new();
        let got = r.push(b": comment\ndata: {\"a\":1}\n\ndata: [DONE]\n");
        assert_eq!(got, vec![r#"{"a":1}"#]);
    }

    #[test]
    fn carries_a_partial_line_across_reads() {
        let mut r = SseReader::new();
        assert!(r.push(b"data: {\"a\":").is_empty());
        assert_eq!(r.push(b"1}\n"), vec![r#"{"a":1}"#]);
    }

    #[test]
    fn tolerates_crlf_framing() {
        let mut r = SseReader::new();
        assert_eq!(r.push(b"data: x\r\n"), vec!["x"]);
    }

    #[test]
    fn emits_a_trailing_unterminated_line_on_flush() {
        let mut r = SseReader::new();
        assert!(r.push(b"data: tail").is_empty());
        assert_eq!(r.flush().as_deref(), Some("tail"));
    }

    #[test]
    fn survives_a_multibyte_char_split_across_reads() {
        let text = "data: \"chào\"\n";
        let bytes = text.as_bytes();
        // Cut inside the two-byte 'à'.
        let cut = text.find('à').unwrap() + 1;
        let mut r = SseReader::new();
        assert!(r.push(&bytes[..cut]).is_empty());
        assert_eq!(r.push(&bytes[cut..]), vec!["\"chào\""]);
    }
}
