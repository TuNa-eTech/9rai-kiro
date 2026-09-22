//! Hosts-file editing as pure string transforms.
//!
//! The reference implementation appends bare `127.0.0.1 <host>` lines and later removes them by
//! substring line-filtering, which silently deletes any unrelated user line that happens to
//! mention the host. We instead own a single delimited block and never touch anything outside it,
//! so [`apply`] and [`strip`] are exact inverses on the user's own content.

use std::fmt::Write as _;

const BEGIN: &str = "# BEGIN 9rai";
const END: &str = "# END 9rai";

/// Remove our managed block (and the blank line that padded it) from `existing`.
pub fn strip(existing: &str) -> String {
    let Some(start) = existing.find(BEGIN) else {
        return existing.to_string();
    };
    // Everything from BEGIN through the line containing END.
    let after_start = &existing[start..];
    let end_rel = match after_start.find(END) {
        Some(i) => i + END.len(),
        None => after_start.len(), // truncated block: drop to EOF
    };
    let block_end = start + end_rel;

    let mut head = existing[..start].to_string();
    // Drop one trailing newline we inserted before the block.
    if head.ends_with('\n') {
        head.pop();
        if head.ends_with('\r') {
            head.pop();
        }
    }

    let mut tail = existing[block_end..].to_string();
    // Consume the newline that terminated the END line.
    if let Some(rest) = tail.strip_prefix('\n') {
        tail = rest.to_string();
    } else if let Some(rest) = tail.strip_prefix("\r\n") {
        tail = rest.to_string();
    }

    match (head.is_empty(), tail.is_empty()) {
        (true, _) => tail,
        (_, true) => {
            if head.ends_with('\n') {
                head
            } else {
                head.push('\n');
                head
            }
        }
        _ => format!("{head}\n{tail}"),
    }
}

/// Replace (or insert) our managed block so it maps every `host` to loopback. Passing an empty
/// `hosts` is equivalent to [`strip`]. Existing 9rai blocks are always replaced, never stacked.
pub fn apply(existing: &str, hosts: &[&str]) -> String {
    let base = strip(existing);
    if hosts.is_empty() {
        return base;
    }

    let mut block = String::new();
    let _ = writeln!(block, "{BEGIN}");
    let _ = writeln!(
        block,
        "# Managed by 9rai. Do not edit; removed automatically when interception stops."
    );
    for host in hosts {
        let _ = writeln!(block, "127.0.0.1\t{host}");
        // Kiro's SDK may resolve AAAA first; map v6 loopback too so it cannot slip past us.
        let _ = writeln!(block, "::1\t{host}");
    }
    let _ = write!(block, "{END}");

    let trimmed = base.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        format!("{block}\n")
    } else {
        format!("{trimmed}\n\n{block}\n")
    }
}

/// Is our managed block present at all, whatever it currently maps?
///
/// Distinct from [`is_current`]: this answers "did somebody leave the machine redirected",
/// which is the question after a daemon dies without restoring anything.
pub fn is_applied(existing: &str) -> bool {
    existing.contains(BEGIN)
}

/// Does the file already map exactly `hosts` (and nothing stale)?
pub fn is_current(existing: &str, hosts: &[&str]) -> bool {
    apply(existing, hosts) == ensure_trailing_newline(existing)
}

fn ensure_trailing_newline(s: &str) -> String {
    if s.is_empty() || s.ends_with('\n') {
        s.to_string()
    } else {
        format!("{s}\n")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_leftover_block_is_detectable_even_when_it_maps_nothing_we_recognise() {
        let clean = "127.0.0.1 localhost\n";
        assert!(!super::is_applied(clean));
        let applied = super::apply(clean, &["example.test"]);
        assert!(super::is_applied(&applied));
        assert!(!super::is_applied(&super::strip(&applied)));
    }

    use super::*;

    const HOSTS: [&str; 2] = ["runtime.us-east-1.kiro.dev", "q.us-east-1.amazonaws.com"];

    #[test]
    fn apply_then_strip_restores_the_original_content() {
        let original = "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n";
        let applied = apply(original, &HOSTS);
        assert!(applied.contains(BEGIN) && applied.contains(END));
        assert!(applied.contains("::1\truntime.us-east-1.kiro.dev"));
        assert_eq!(strip(&applied), original);
    }

    #[test]
    fn reapplying_replaces_rather_than_stacks_blocks() {
        let once = apply("base\n", &HOSTS);
        let twice = apply(&once, &["api2.cursor.sh"]);
        assert_eq!(twice.matches(BEGIN).count(), 1);
        assert!(twice.contains("api2.cursor.sh"));
        assert!(!twice.contains("kiro.dev"));
    }

    #[test]
    fn strip_leaves_unrelated_lines_that_merely_mention_a_host() {
        // The exact case the substring-deletion bug destroys.
        let user_line = "# note about runtime.us-east-1.kiro.dev for later\n";
        let file = format!("{user_line}{}", apply("", &HOSTS));
        let stripped = strip(&file);
        assert!(stripped.contains(user_line.trim_end()));
        assert!(!stripped.contains(BEGIN));
    }

    #[test]
    fn empty_hosts_is_a_strip() {
        let applied = apply("base\n", &HOSTS);
        assert_eq!(apply(&applied, &[]), "base\n");
    }

    #[test]
    fn strip_is_a_noop_without_a_block() {
        assert_eq!(strip("nothing here\n"), "nothing here\n");
    }

    #[test]
    fn is_current_detects_matching_and_stale_state() {
        let applied = apply("base\n", &HOSTS);
        assert!(is_current(&applied, &HOSTS));
        assert!(!is_current(&applied, &["api2.cursor.sh"]));
        assert!(!is_current("base\n", &HOSTS));
    }

    #[test]
    fn handles_a_block_left_truncated_by_a_crash() {
        // END never got written (process killed mid-write).
        let truncated = format!("base\n\n{BEGIN}\n127.0.0.1\tkiro.dev\n");
        let recovered = strip(&truncated);
        assert_eq!(recovered, "base\n");
    }
}
