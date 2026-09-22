//! Property tests for the incremental SSE reader: no matter where the byte stream is cut
//! into chunks, the emitted payload sequence is identical.

use nine_rai_core::translate::SseReader;
use proptest::prelude::*;

/// A transcript exercising comments, blank lines, multibyte UTF-8, [DONE], and a trailing
/// line without a newline.
const TRANSCRIPT: &[u8] =
    b": comment\ndata: {\"a\":1}\n\ndata: \"ch\xc3\xa0o\"\r\ndata: [DONE]\ndata: tail";

fn run_all(chunks: &[&[u8]]) -> Vec<String> {
    let mut reader = SseReader::new();
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend(reader.push(chunk));
    }
    out.extend(reader.flush());
    out
}

proptest! {
    /// Splitting the same transcript at arbitrary byte offsets must not change the payloads.
    #[test]
    fn arbitrary_chunking_preserves_payloads(mut cuts in prop::collection::vec(0usize..=TRANSCRIPT.len(), 0..64)) {
        cuts.sort_unstable();
        cuts.dedup();

        let mut chunks: Vec<&[u8]> = Vec::new();
        let mut prev = 0usize;
        for cut in cuts {
            chunks.push(&TRANSCRIPT[prev..cut]);
            prev = cut;
        }
        chunks.push(&TRANSCRIPT[prev..]);

        prop_assert_eq!(run_all(&chunks), run_all(&[TRANSCRIPT]));
    }
}
