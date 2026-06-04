use std::sync::OnceLock;

use regex::Regex;

/// Fields extracted from a parsed Usenet/email subject line.
///
/// Returned by [`parse_subject`]. The `base_subject` field can be used as a
/// stable grouping key across parts of the same series.
///
/// # Field invariants
///
/// - `part_total` is always `Some` when `part_index` is `Some`, because every
///   supported marker format includes the total count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectParts {
    /// The subject with all `Re:`/`Fwd:` prefixes and the part-number marker stripped.
    /// Never empty; [`parse_subject`] returns `None` rather than returning an empty
    /// `base_subject`.
    pub base_subject: String,
    /// 1-based part number extracted from the marker. `Some(0)` indicates a
    /// TOC post (e.g. `(00/17)`). `None` when no recognised marker was found.
    pub part_index: Option<u32>,
    /// Total number of parts as declared in the subject marker.
    /// Always `Some` when `part_index` is `Some`; `None` otherwise.
    pub part_total: Option<u32>,
}

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
                re: Regex::new(r"\([ \t]*([0-9]{1,6})[ \t]*/[ \t]*([0-9]{1,6})[ \t]*\)").unwrap(),
            },
            // 2. Bracketed fraction: [2/4] — require digit on both sides so
            //    [BINARY] is not matched.
            Pattern {
                re: Regex::new(r"\[[ \t]*([0-9]{1,6})[ \t]*/[ \t]*([0-9]{1,6})[ \t]*\]").unwrap(),
            },
            // 3. English "Part N/M" (case-insensitive)
            Pattern {
                re: Regex::new(r"(?i)\bpart[ \t]+([0-9]{1,6})[ \t]*/[ \t]*([0-9]{1,6})\b").unwrap(),
            },
            // 4. English "Part N of M" / "Part3of17" (case-insensitive)
            Pattern {
                re: Regex::new(r"(?i)\bpart[ \t]*([0-9]{1,6})[ \t]*of[ \t]*([0-9]{1,6})\b")
                    .unwrap(),
            },
            // 5. Dash-separated fraction: " - 03/17"
            Pattern {
                re: Regex::new(r"[ \t]+-[ \t]+([0-9]{1,6})[ \t]*/[ \t]*([0-9]{1,6})\b").unwrap(),
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
    let re = RE.get_or_init(|| Regex::new(r"(?i)^(re|fwd?)[ \t]*:[ \t]*").unwrap());

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
/// # First-match-wins
///
/// The five patterns are tried in the priority order listed above. The first
/// pattern that matches wins; no attempt is made to find a "better" match
/// further along. If a subject line contains multiple markers
/// (e.g. `"file (1/3) [2/4]"`), only the first one matched — the
/// parenthesised fraction in that example — is used and the rest are left in
/// `base_subject`.
///
/// # Return value
///
/// Returns `None` only when:
/// - `subject` is empty, or
/// - `subject` contains a `yEnc` marker (those posts use a distinct encoding
///   that is explicitly out of scope for this crate), or
/// - the entire input is consumed by the part-marker pattern, leaving no
///   base subject (e.g. `"(1/3)"` with nothing else). The invariant that
///   `base_subject` is never empty must hold whenever `Some` is returned.
///
/// Otherwise returns `Some(SubjectParts)`. When no part-marker pattern
/// matches, `part_index` and `part_total` are both `None` and `base_subject`
/// is the prefix-stripped, trimmed input.
///
/// # Zero totals
///
/// A subject like `"file.bin (3/0)"` produces `part_total = Some(0)`. This is
/// nonsensical but is passed through verbatim since the crate cannot know
/// whether the source is malformed or intentional. Callers that pass
/// `part_total` directly to [`PartCollection::with_total`][crate::PartCollection::with_total]
/// should validate that the total is non-zero before doing so.
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

    let stripped = strip_prefixes(subject).trim();

    if stripped.is_empty() {
        return None;
    }

    // yEnc posts are out of scope. Check after prefix stripping for
    // consistency — patterns are also matched against `stripped`.
    if yenc_re().is_match(stripped) {
        return None;
    }

    for (pat_idx, pat) in patterns().iter().enumerate() {
        if let Some(caps) = pat.re.captures(stripped) {
            // Capture group 1 is always the part index.
            // Use `continue` (not `?`) so that a failed parse on one pattern
            // does not exit the function — we try the remaining patterns instead.
            // In practice the regex limits captures to 6 digits (max 999999),
            // which is always within u32 range, so parse failure is impossible
            // with current regexes.
            let part_index: u32 = match caps[1].parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            // Capture group 2 is always the total (all five patterns have it).
            let part_total: u32 = match caps[2].parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

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

            // Strip trailing " -" artifact only when pattern 5 (dash-separated
            // fraction) matched. Pattern 5 matches " - 03/17"; removing it can
            // leave a trailing " -" or bare "-" artifact. Other patterns do not
            // produce this artifact, and unconditional stripping would corrupt
            // filenames that legitimately end in a dash.
            let base_subject = if pat_idx == 4 {
                raw.trim_end_matches(|c: char| c == '-' || c.is_whitespace())
                    .trim()
                    .to_string()
            } else {
                raw
            };

            // Invariant: base_subject must not be empty. A subject that
            // consists solely of a part marker (e.g. "(1/3)") has no
            // meaningful base; treat it as non-parseable.
            if base_subject.is_empty() {
                return None;
            }

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

    #[test]
    fn yenc_after_re_prefix_returns_none() {
        // yEnc check must apply after prefix stripping so Re:-prefixed yEnc
        // subjects are still filtered.
        assert!(parse_subject("Re: \"file.nfo\" yEnc (1/3)").is_none());
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
    // Bare marker (entire input is the marker) → None
    // Invariant: base_subject must never be empty.
    // ------------------------------------------------------------------

    #[test]
    fn bare_paren_marker_returns_none() {
        assert!(parse_subject("(1/3)").is_none());
    }

    #[test]
    fn bare_paren_marker_with_spaces_returns_none() {
        assert!(parse_subject("  (1/3)  ").is_none());
    }

    #[test]
    fn bare_bracket_marker_returns_none() {
        assert!(parse_subject("[2/4]").is_none());
    }

    /// A subject that is entirely a "Part N of M" or "Part N/M" marker with no
    /// surrounding text strips to empty after removing the marker.
    /// Invariant: base_subject must never be empty → returns None.
    #[test]
    fn bare_part_marker_only_returns_none() {
        assert!(parse_subject("Part 1 of 3").is_none());
        assert!(parse_subject("Part 1/3").is_none());
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
    fn base_subject_trailing_dash_stripped_for_pattern5() {
        // Pattern 5 (dash-separated fraction) can leave a trailing " -"
        // artifact after the marker is removed. Only pattern 5 trims this.
        let p = parts("filename.tar.gz - 03/17");
        assert!(!p.base_subject.ends_with('-'));
    }

    #[test]
    fn base_subject_trailing_dash_preserved_for_other_patterns() {
        // A filename ending in a dash must NOT have it stripped when matched
        // by patterns other than pattern 5.
        let p = parts("my-file- (1/3)");
        assert_eq!(p.base_subject, "my-file-");
        assert_eq!(p.part_index, Some(1));
    }

    // ------------------------------------------------------------------
    // All-prefix input stripped to empty → None
    // Invariant: base_subject must never be empty.
    // ------------------------------------------------------------------

    #[test]
    fn parse_subject_returns_none_for_all_prefix_input() {
        assert!(parse_subject("Re: ").is_none());
        assert!(parse_subject("Fwd: Re: ").is_none());
        assert!(parse_subject("   ").is_none());
    }
}
