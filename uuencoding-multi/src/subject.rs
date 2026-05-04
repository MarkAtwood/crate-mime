use std::sync::OnceLock;

use regex::Regex;

use crate::SubjectParts;

// ---------------------------------------------------------------------------
// Compiled-once regex patterns
// ---------------------------------------------------------------------------
//
// Pattern priority (most specific first):
//   1. Parenthesised fraction:  (03/17)
//   2. Bracketed fraction:      [2/4]   — only when both sides are digits
//   3. English "part N/M":      Part 3/17
//   4. English "part N of M":   Part 03 of 17 / part3of17
//   5. Dash-separated fraction: - 03/17
//
// All patterns are compiled once into a static array via `OnceLock`.

struct Pattern {
    re: Regex,
}

fn patterns() -> &'static [Pattern; 5] {
    static PATTERNS: OnceLock<[Pattern; 5]> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            // 1. Parenthesised fraction: (03/17) or ( 3 / 17 )
            Pattern {
                re: Regex::new(r"\(\s*(\d{1,6})\s*/\s*(\d{1,6})\s*\)").unwrap(),
            },
            // 2. Bracketed fraction: [2/4] — require digit on both sides so
            //    [BINARY] is not matched.
            Pattern {
                re: Regex::new(r"\[\s*(\d{1,6})\s*/\s*(\d{1,6})\s*\]").unwrap(),
            },
            // 3. English "Part N/M" (case-insensitive via (?i))
            Pattern {
                re: Regex::new(r"(?i)\bpart\s+(\d{1,6})\s*/\s*(\d{1,6})\b").unwrap(),
            },
            // 4. English "Part N of M" / "Part3of17" (case-insensitive)
            Pattern {
                re: Regex::new(r"(?i)\bpart\s*(\d{1,6})\s*of\s*(\d{1,6})\b").unwrap(),
            },
            // 5. Dash-separated fraction: " - 03/17"
            Pattern {
                re: Regex::new(r"\s+-\s+(\d{1,6})\s*/\s*(\d{1,6})\b").unwrap(),
            },
        ]
    })
}

// Matches a yEnc marker at a word boundary (case-insensitive).
fn yenc_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\byenc\b").unwrap())
}

// Strips common reply/forward prefixes (case-insensitive) repeatedly.
fn strip_prefixes(s: &str) -> &str {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)^(re|fwd?)\s*:\s*").unwrap());

    let mut cur = s;
    loop {
        let stripped = re.find(cur).map(|m| &cur[m.end()..]).unwrap_or(cur);
        if stripped.len() == cur.len() {
            break;
        }
        cur = stripped;
    }
    cur
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a multi-part Usenet/email subject line.
///
/// Recognises five marker formats (in priority order):
/// 1. Parenthesised fraction: `(03/17)` or `( 3 / 17 )`
/// 2. Bracketed fraction: `[2/4]` (only when both sides are digits)
/// 3. English "Part N/M" (case-insensitive)
/// 4. English "Part N of M" / `part3of17` (case-insensitive)
/// 5. Dash-separated fraction: ` - 03/17`
///
/// Leading `Re:`, `Fwd:`, and `Fw:` prefixes are stripped before matching
/// (repeatedly, to handle nested re-forwards). The extracted part marker is
/// removed from the subject to produce `base_subject`.
///
/// # Return value
///
/// Returns `None` only when:
/// - `subject` is empty, or
/// - `subject` contains a `yEnc` marker (those posts use a distinct encoding
///   that is explicitly out of scope for this crate).
///
/// Otherwise returns `Some(SubjectParts)`. When no part-marker pattern
/// matches, `part_index` and `part_total` are both `None` and `base_subject`
/// is the prefix-stripped, trimmed input.
///
/// # Never panics
///
/// This function never panics on any input, including strings containing
/// arbitrary Unicode code points.
///
/// # Examples
///
/// ```
/// use uuencoding_multi::parse_subject;
///
/// // Parenthesised fraction — the most common Usenet format.
/// let sp = parse_subject("bigfile.rar (2/5)").unwrap();
/// assert_eq!(sp.part_index, Some(2));
/// assert_eq!(sp.part_total, Some(5));
/// assert_eq!(sp.base_subject, "bigfile.rar");
/// ```
///
/// ```
/// use uuencoding_multi::parse_subject;
///
/// // Re: prefix is stripped before matching.
/// let sp = parse_subject("Re: archive.tar.gz (03/17)").unwrap();
/// assert_eq!(sp.part_index, Some(3));
/// assert_eq!(sp.part_total, Some(17));
/// ```
///
/// ```
/// use uuencoding_multi::parse_subject;
///
/// // yEnc subject → None (out of scope for this crate).
/// assert!(parse_subject("\"file.nfo\" yEnc (1/3)").is_none());
/// ```
///
/// ```
/// use uuencoding_multi::parse_subject;
///
/// // Empty input → None.
/// assert!(parse_subject("").is_none());
/// ```
///
/// ```
/// use uuencoding_multi::parse_subject;
///
/// // No marker → Some with None fields and subject preserved.
/// let sp = parse_subject("just a plain subject").unwrap();
/// assert_eq!(sp.part_index, None);
/// assert_eq!(sp.part_total, None);
/// assert_eq!(sp.base_subject, "just a plain subject");
/// ```
pub fn parse_subject(subject: &str) -> Option<SubjectParts> {
    if subject.is_empty() {
        return None;
    }

    // yEnc posts are out of scope.
    if yenc_re().is_match(subject) {
        return None;
    }

    let stripped = strip_prefixes(subject).trim();

    for pat in patterns() {
        if let Some(caps) = pat.re.captures(stripped) {
            // Capture group 1 is always the part index.
            let part_index: u32 = caps[1].parse().ok()?;
            // Capture group 2 is always the total (all five patterns have it).
            let part_total: u32 = caps[2].parse().ok()?;

            // Build base_subject: remove the matched span from `stripped`.
            let m = caps.get(0).unwrap();
            let before = stripped[..m.start()].trim_end();
            let after = stripped[m.end()..].trim_start();

            let raw = if before.is_empty() {
                after.to_string()
            } else if after.is_empty() {
                before.to_string()
            } else {
                format!("{} {}", before, after)
            };

            // Strip trailing " -" artifact (e.g. "filename.tar.gz -").
            let base_subject = raw
                .trim_end_matches(|c: char| c == '-' || c.is_whitespace())
                .trim()
                .to_string();

            return Some(SubjectParts {
                base_subject,
                part_index: Some(part_index),
                part_total: Some(part_total),
            });
        }
    }

    // No marker found.
    Some(SubjectParts {
        base_subject: stripped.to_string(),
        part_index: None,
        part_total: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(subject: &str) -> SubjectParts {
        parse_subject(subject).unwrap()
    }

    // ------------------------------------------------------------------
    // Pattern 1 — parenthesised fraction
    // ------------------------------------------------------------------

    #[test]
    fn paren_fraction_basic() {
        let p = parts("bigfile.rar (1/5)");
        assert_eq!(p.part_index, Some(1));
        assert_eq!(p.part_total, Some(5));
        assert_eq!(p.base_subject, "bigfile.rar");
    }

    #[test]
    fn paren_fraction_leading_zero() {
        let p = parts("filename.tar.gz (03/17)");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(17));
        assert_eq!(p.base_subject, "filename.tar.gz");
    }

    #[test]
    fn paren_fraction_spaces_inside() {
        let p = parts("file.zip ( 2 / 7 )");
        assert_eq!(p.part_index, Some(2));
        assert_eq!(p.part_total, Some(7));
    }

    // ------------------------------------------------------------------
    // Pattern 2 — bracketed fraction
    // ------------------------------------------------------------------

    #[test]
    fn bracket_fraction_basic() {
        let p = parts("image.jpg [2/4]");
        assert_eq!(p.part_index, Some(2));
        assert_eq!(p.part_total, Some(4));
        assert_eq!(p.base_subject, "image.jpg");
    }

    #[test]
    fn bracket_fraction_not_binary_tag() {
        // [BINARY] must NOT be parsed as a fraction.
        let p = parts("[BINARY] filename - Part 3 of 12");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(12));
    }

    // ------------------------------------------------------------------
    // Pattern 3 — "Part N/M"
    // ------------------------------------------------------------------

    #[test]
    fn part_slash_basic() {
        let p = parts("file.zip Part 3/17");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(17));
    }

    #[test]
    fn part_slash_lowercase() {
        let p = parts("file.tar.gz part 2/5");
        assert_eq!(p.part_index, Some(2));
        assert_eq!(p.part_total, Some(5));
    }

    // ------------------------------------------------------------------
    // Pattern 4 — "Part N of M"
    // ------------------------------------------------------------------

    #[test]
    fn part_of_with_spaces() {
        let p = parts("file.zip Part 03 of 17");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(17));
    }

    #[test]
    fn part_of_no_spaces() {
        let p = parts("archive.tar.gz part3of17");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(17));
    }

    #[test]
    fn binary_tag_part_of() {
        let p = parts("[BINARY] filename - Part 3 of 12");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(12));
    }

    // ------------------------------------------------------------------
    // Pattern 5 — dash-separated fraction
    // ------------------------------------------------------------------

    #[test]
    fn dash_fraction() {
        let p = parts("filename.tar.gz - 03/17");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(17));
        assert_eq!(p.base_subject, "filename.tar.gz");
    }

    // ------------------------------------------------------------------
    // Part 0 (TOC)
    // ------------------------------------------------------------------

    #[test]
    fn part_zero_toc() {
        let p = parts("filename.tar.gz (00/17)");
        assert_eq!(p.part_index, Some(0));
        assert_eq!(p.part_total, Some(17));
    }

    // ------------------------------------------------------------------
    // yEnc → None
    // ------------------------------------------------------------------

    #[test]
    fn yenc_returns_none() {
        assert!(parse_subject("\"file.nfo\" yEnc (1/3)").is_none());
    }

    #[test]
    fn yenc_uppercase_returns_none() {
        assert!(parse_subject("\"file.nfo\" YENC (1/3)").is_none());
    }

    // ------------------------------------------------------------------
    // No marker
    // ------------------------------------------------------------------

    #[test]
    fn no_marker_returns_some_none_fields() {
        let p = parts("plain subject");
        assert_eq!(p.base_subject, "plain subject");
        assert_eq!(p.part_index, None);
        assert_eq!(p.part_total, None);
    }

    // ------------------------------------------------------------------
    // Empty input → None
    // ------------------------------------------------------------------

    #[test]
    fn empty_returns_none() {
        assert!(parse_subject("").is_none());
    }

    // ------------------------------------------------------------------
    // Re: / Fwd: prefix stripping
    // ------------------------------------------------------------------

    #[test]
    fn re_prefix_stripped() {
        let p = parts("Re: filename.tar.gz (03/17)");
        assert_eq!(p.part_index, Some(3));
        assert_eq!(p.part_total, Some(17));
    }

    #[test]
    fn fwd_prefix_stripped() {
        let p = parts("Fwd: filename.tar.gz (03/17)");
        assert_eq!(p.part_index, Some(3));
    }

    #[test]
    fn fw_prefix_stripped() {
        let p = parts("Fw: filename.tar.gz (03/17)");
        assert_eq!(p.part_index, Some(3));
    }

    #[test]
    fn nested_re_prefix_stripped() {
        let p = parts("Re: Re: filename.tar.gz (03/17)");
        assert_eq!(p.part_index, Some(3));
    }

    // ------------------------------------------------------------------
    // Unicode stem — must not panic
    // ------------------------------------------------------------------

    #[test]
    fn unicode_stem_no_panic() {
        let p = parts("日本語ファイル (1/3)");
        assert_eq!(p.part_index, Some(1));
        assert_eq!(p.part_total, Some(3));
        assert!(p.base_subject.contains('日'));
    }

    // ------------------------------------------------------------------
    // base_subject trimming
    // ------------------------------------------------------------------

    #[test]
    fn base_subject_trailing_dash_stripped() {
        // Pattern 5 leaves no artifact here; verify general trimming.
        let p = parts("myfile.bin (2/5)");
        assert!(!p.base_subject.ends_with('-'));
        assert!(!p.base_subject.ends_with(' '));
    }
}
