//! Splits `<thinking>` / `<think>` blocks out of a token stream into a separate reasoning
//! channel, tolerating tags that straddle chunk boundaries.
//!
//! The JS reference only buffers once a *complete* opening tag has been seen, so a chunk ending
//! mid-tag (`"…<thin"`) leaks the fragment as visible assistant text. It also trims and
//! concatenates the text around a block, silently welding words together. This implementation
//! holds back any suffix that could still grow into a tag, and never rewrites the text it emits.

/// Opening tag paired with the closing tag it requires.
const TAGS: [(&str, &str); 2] = [("<thinking>", "</thinking>"), ("<think>", "</think>")];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Split {
    pub reasoning: String,
    pub text: String,
}

impl Split {
    pub fn is_empty(&self) -> bool {
        self.reasoning.is_empty() && self.text.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct ThinkingSplitter {
    /// Text we cannot classify yet: either inside an open block, or a possible partial tag.
    pending: String,
    /// `Some(close_tag)` while inside a block.
    close: Option<&'static str>,
}

/// Length of the longest suffix of `hay` that is a *proper* prefix of one of `tags`.
/// That suffix must be held back — the next chunk may complete it into a real tag.
fn holdback(hay: &str, tags: &[&str]) -> usize {
    let limit = tags
        .iter()
        .map(|t| t.len())
        .max()
        .unwrap_or(0)
        .saturating_sub(1)
        .min(hay.len());

    (1..=limit)
        .rev()
        .filter(|n| hay.is_char_boundary(hay.len() - n))
        .find(|&n| {
            let suffix = &hay.as_bytes()[hay.len() - n..];
            tags.iter()
                .any(|t| t.len() > n && t.as_bytes().starts_with(suffix))
        })
        .unwrap_or(0)
}

impl ThinkingSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one delta. Returns whatever became unambiguous as a result.
    pub fn push(&mut self, input: &str) -> Split {
        self.pending.push_str(input);
        let mut out = Split::default();

        loop {
            // Tags are ASCII, so ASCII-lowercasing preserves byte indices exactly.
            let lower = self.pending.to_ascii_lowercase();

            match self.close {
                Some(close) => match lower.find(close) {
                    Some(idx) => {
                        out.reasoning.push_str(&self.pending[..idx]);
                        self.pending.drain(..idx + close.len());
                        self.close = None;
                    }
                    None => {
                        let keep = holdback(&lower, &[close]);
                        let upto = self.pending.len() - keep;
                        out.reasoning.push_str(&self.pending[..upto]);
                        self.pending.drain(..upto);
                        return out;
                    }
                },
                None => {
                    let found = TAGS
                        .iter()
                        .filter_map(|(open, close)| lower.find(open).map(|i| (i, *open, *close)))
                        .min_by_key(|(i, _, _)| *i);

                    match found {
                        Some((idx, open, close)) => {
                            out.text.push_str(&self.pending[..idx]);
                            self.pending.drain(..idx + open.len());
                            self.close = Some(close);
                        }
                        None => {
                            let opens: Vec<&str> = TAGS.iter().map(|(o, _)| *o).collect();
                            let keep = holdback(&lower, &opens);
                            let upto = self.pending.len() - keep;
                            out.text.push_str(&self.pending[..upto]);
                            self.pending.drain(..upto);
                            return out;
                        }
                    }
                }
            }
        }
    }

    /// Drain anything still held at end of stream. An unterminated block is reasoning; a
    /// dangling tag-lookalike was never a tag, so it is ordinary text.
    pub fn flush(&mut self) -> Split {
        let rest = std::mem::take(&mut self.pending);
        if self.close.take().is_some() {
            Split {
                reasoning: rest,
                text: String::new(),
            }
        } else {
            Split {
                reasoning: String::new(),
                text: rest,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a whole string one chunk at a time and collect the totals.
    fn split_chunks(chunks: &[&str]) -> Split {
        let mut s = ThinkingSplitter::new();
        let mut total = Split::default();
        for c in chunks {
            let part = s.push(c);
            total.reasoning.push_str(&part.reasoning);
            total.text.push_str(&part.text);
        }
        let tail = s.flush();
        total.reasoning.push_str(&tail.reasoning);
        total.text.push_str(&tail.text);
        total
    }

    #[test]
    fn passes_plain_text_through_untouched() {
        let out = split_chunks(&["hello world"]);
        assert_eq!(out.text, "hello world");
        assert!(out.reasoning.is_empty());
    }

    #[test]
    fn separates_a_complete_block() {
        let out = split_chunks(&["a<thinking>why</thinking>b"]);
        assert_eq!(out.reasoning, "why");
        assert_eq!(out.text, "ab");
    }

    #[test]
    fn supports_the_short_tag_spelling() {
        let out = split_chunks(&["<think>hm</think>done"]);
        assert_eq!(out.reasoning, "hm");
        assert_eq!(out.text, "done");
    }

    #[test]
    fn keeps_every_block_not_just_the_first() {
        // The JS reference discards the second block's reasoning entirely.
        let out = split_chunks(&["<think>one</think>mid<think>two</think>end"]);
        assert_eq!(out.reasoning, "onetwo");
        assert_eq!(out.text, "midend");
    }

    #[test]
    fn a_tag_split_across_chunks_is_not_leaked_as_text() {
        // This is the JS bug: "<thin" does not match the regex and gets emitted as content.
        let out = split_chunks(&["a<thin", "king>why</thin", "king>b"]);
        assert_eq!(out.reasoning, "why");
        assert_eq!(out.text, "ab");
    }

    #[test]
    fn an_unterminated_block_becomes_reasoning_at_eof() {
        let out = split_chunks(&["a<thinking>dangling"]);
        assert_eq!(out.reasoning, "dangling");
        assert_eq!(out.text, "a");
    }

    #[test]
    fn a_dangling_lookalike_stays_text() {
        let out = split_chunks(&["2 < 3 and x<thi"]);
        assert_eq!(out.text, "2 < 3 and x<thi");
        assert!(out.reasoning.is_empty());
    }

    #[test]
    fn does_not_weld_words_around_a_block() {
        // JS trims both sides and concatenates, producing "beforeafter".
        let out = split_chunks(&["before <think>x</think> after"]);
        assert_eq!(out.text, "before  after");
    }

    #[test]
    fn result_is_independent_of_chunk_boundaries() {
        let full = "aa<thinking>rr</thinking>bb<think>ss</think>cc";
        let expected = split_chunks(&[full]);
        for cut in 1..full.len() {
            if !full.is_char_boundary(cut) {
                continue;
            }
            let got = split_chunks(&[&full[..cut], &full[cut..]]);
            assert_eq!(got, expected, "mismatch when split at {cut}");
        }
    }

    #[test]
    fn handles_multibyte_text_around_tags() {
        let out = split_chunks(&["xin chào <think>suy nghĩ</think> bạn"]);
        assert_eq!(out.reasoning, "suy nghĩ");
        assert_eq!(out.text, "xin chào  bạn");
    }
}
