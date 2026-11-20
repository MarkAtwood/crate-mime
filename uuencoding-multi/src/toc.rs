//! Parser for multi-part UUencode table-of-contents (TOC) bodies.
//!
//! TOC posts (typically numbered part 0) list the files contained in a
//! multi-part series, along with optional size information and part ranges.
//! This module provides a best-effort parser that tolerates varied formatting
//! and non-UTF-8 byte sequences.

use std::ops::RangeInclusive;
use std::sync::OnceLock;

use regex::Regex;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One entry in a table-of-contents post.
///
/// A TOC entry describes a single file within a multi-part series. Not all
/// fields are present in every TOC format; `size_bytes` and `parts` are
/// `None` when the corresponding information was absent from the line.
///
/// # Example
///
/// ```
/// use uuencoding_multi::parse_toc;
///
/// let body = b"archive.tar.gz   1234567 bytes   parts 1-8\n";
/// let toc = parse_toc(body).unwrap();
/// let entry = &toc.entries[0];
/// assert_eq!(entry.filename, "archive.tar.gz");
/// assert_eq!(entry.size_bytes, Some(1_234_567));
/// assert_eq!(entry.parts, Some(1..=8));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TocEntry {
    /// Filename as it appears in the TOC line.
    pub filename: String,
    /// Declared file size in bytes, if present. KB and MB values are
    /// converted to bytes (1 KB = 1 024 bytes, 1 MB = 1 048 576 bytes).
    pub size_bytes: Option<u64>,
    /// Which parts carry this file, if a range was specified. The range is
    /// inclusive on both ends (`lo..=hi`). Inverted ranges (`lo > hi`) are
    /// silently discarded and produce `None`.
    pub parts: Option<RangeInclusive<u32>>,
}

/// Result of parsing a TOC body.
///
/// `entries` may be a strict subset of the lines in the body: lines that do
/// not look like TOC entries (plain text, comments, blank lines) are silently
/// skipped. Inspect `raw_text` for the original body when debugging partial
/// results.
///
/// # Example
///
/// ```
/// use uuencoding_multi::parse_toc;
///
/// let body = b"# TOC\nfile.bin (512 bytes)\n";
/// let toc = parse_toc(body).unwrap();
/// assert_eq!(toc.entries.len(), 1);
/// assert!(toc.raw_text.contains("# TOC"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToc {
    /// Successfully parsed entries; may be a strict subset of all lines.
    pub entries: Vec<TocEntry>,
    /// Full body text kept verbatim for diagnostic use when parsing is partial.
    /// Non-UTF-8 bytes are replaced with the Unicode replacement character
    /// (`U+FFFD`) via lossy conversion.
    pub raw_text: String,
}

// ---------------------------------------------------------------------------
// Compiled-once regex patterns
// ---------------------------------------------------------------------------

/// Format 1: `filename.tar.gz   1234567 bytes   parts 1-8`
/// Filename is the first whitespace-delimited token; size and "parts N-M" can
/// appear in either order after it.
fn re_format1() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Captures: 1=filename, rest parsed manually for size/parts.
        Regex::new(r"(?i)^([^ \t\r\n]+)[ \t]+(.+)$").unwrap()
    })
}

/// Format 3 prefix: `01-08  filename.tar.gz  1234 KB`
/// The line starts with a zero-padded (or plain) part range.
fn re_format3_prefix() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^([0-9]{1,6})-([0-9]{1,6})[ \t]+([^ \t\r\n]+)[ \t]*(.*)$").unwrap()
    })
}

/// Format 2: `filename.tar.gz (1234567 bytes)` — parenthesised size.
fn re_format2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^([^ \t\r\n]+)[ \t]*\([ \t]*([0-9][0-9,]*(?:\.[0-9]+)?)[ \t]*(bytes?|b|kb|mb)[ \t]*\)[ \t]*$",
        )
            .unwrap()
    })
}

/// Size token: a number (digits, optionally comma-grouped, optionally with a
/// decimal fraction) followed by a unit.
///
/// The number must not be preceded by a word character, `.` or `,`, so that
/// the regex cannot start matching in the middle of `1.5` or `1,234,567`
/// (the `regex` crate has no look-behind, hence the explicit prefix group).
/// The captured number is validated by [`parse_size`].
fn re_size_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[^\w.,])([0-9][0-9,]*(?:\.[0-9]+)?)[ \t]*(bytes?|b|kb|mb)\b").unwrap()
    })
}

/// "parts N-M" token.
fn re_parts_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bparts?[ \t]+([0-9]{1,6})-([0-9]{1,6})\b").unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a size number + unit string to bytes.
///
/// `number` is plain digits (`1234567`), comma-grouped digits with groups of
/// three (`1,234,567`), either optionally followed by a decimal fraction
/// (`1.5`). KB and MB fractions are rounded down to whole bytes
/// (`1.5 KB` = 1536). Returns `None` — never a wrong number — when the
/// number is malformed (`1,23`, `1,2345`, `1.`), when a byte count has a
/// non-zero fraction, or when the result would overflow `u64`.
fn parse_size(number: &str, unit: &str) -> Option<u64> {
    let mult: u128 = match unit.to_lowercase().trim_end_matches('s') {
        "byte" | "b" => 1,
        "kb" => 1024,
        "mb" => 1024 * 1024,
        _ => return None,
    };

    let (int_part, frac_part) = match number.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (number, None),
    };

    let int_digits: String = if int_part.contains(',') {
        let mut groups = int_part.split(',');
        let first = groups.next()?;
        let first_ok = (1..=3).contains(&first.len());
        let all_ok = first_ok && groups.all(|g| g.len() == 3);
        if !all_ok {
            return None;
        }
        int_part.chars().filter(|&c| c != ',').collect()
    } else {
        int_part.to_string()
    };
    if int_digits.is_empty() || !int_digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let int_value: u128 = int_digits.parse().ok()?;
    let mut bytes = int_value.checked_mul(mult)?;

    if let Some(frac) = frac_part {
        // 30 digits keep `frac_value * mult` well inside u128.
        if frac.is_empty() || frac.len() > 30 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let frac_value: u128 = frac.parse().ok()?;
        let scale = 10u128.checked_pow(u32::try_from(frac.len()).ok()?)?;
        let frac_scaled = frac_value * mult;
        if mult == 1 && frac_scaled % scale != 0 {
            return None; // fractional number of bytes
        }
        bytes = bytes.checked_add(frac_scaled / scale)?;
    }

    u64::try_from(bytes).ok()
}

/// Try to extract a size value from an arbitrary text fragment.
fn extract_size(text: &str) -> Option<u64> {
    let caps = re_size_token().captures(text)?;
    parse_size(&caps[1], &caps[2])
}

/// Try to extract a part range from an arbitrary text fragment.
fn extract_parts(text: &str) -> Option<RangeInclusive<u32>> {
    let caps = re_parts_token().captures(text)?;
    let lo: u32 = caps[1].parse().ok()?;
    let hi: u32 = caps[2].parse().ok()?;
    if lo <= hi {
        Some(lo..=hi)
    } else {
        None
    }
}

/// Attempt to parse a single TOC line into a [`TocEntry`].
///
/// Returns `None` if the line doesn't look like a TOC entry at all.
fn parse_line(line: &str) -> Option<TocEntry> {
    let line = line.trim();

    // Skip blank lines and comments.
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Format 3: line starts with a part range, e.g. "01-08  filename  1234 KB"
    if let Some(caps) = re_format3_prefix().captures(line) {
        let lo: u32 = caps[1].parse().ok()?;
        let hi: u32 = caps[2].parse().ok()?;
        let filename = caps[3].to_string();
        let remainder = &caps[4];
        let size_bytes = extract_size(remainder);
        // Validate the range is sensible and the filename looks real.
        if lo > hi || !looks_like_filename(&filename) {
            return None;
        }
        return Some(TocEntry {
            filename,
            size_bytes,
            parts: Some(lo..=hi),
        });
    }

    // Format 2: "filename (1234567 bytes)"
    if let Some(caps) = re_format2().captures(line) {
        let filename = caps[1].to_string();
        if !looks_like_filename(&filename) {
            return None;
        }
        // The size is this format's only content: skip the line when the
        // number is malformed or overflows, rather than return an empty entry.
        let size_bytes = Some(parse_size(&caps[2], &caps[3])?);
        return Some(TocEntry {
            filename,
            size_bytes,
            parts: None,
        });
    }

    // Format 1 (and fallback): "filename  size_with_unit  [parts N-M]"
    // The filename is the first non-whitespace token; the rest is parsed for
    // size and parts tokens in any order.
    if let Some(caps) = re_format1().captures(line) {
        let filename = caps[1].to_string();
        let remainder = &caps[2];

        if !looks_like_filename(&filename) {
            return None;
        }

        let size_bytes = extract_size(remainder);
        let parts = extract_parts(remainder);

        // A line only qualifies if it yields at least a size or a parts range
        // — otherwise almost any two-token line would be accepted.
        if size_bytes.is_none() && parts.is_none() {
            return None;
        }

        return Some(TocEntry {
            filename,
            size_bytes,
            parts,
        });
    }

    None
}

/// Heuristic gate: a bare word like `"garbage"` or `"just"` should not be
/// treated as a filename.
///
/// We require either:
/// - a path separator (`/` or `\`), which strongly implies a path, or
/// - a `.` whose extension part (the text after the last `.`) contains at
///   least one alphabetic character — this rejects bare decimal numbers like
///   `"1.5"` or `"3.14"` while accepting `"file.bin"`, `"1.txt"`,
///   `"archive.tar.gz"`, and Unicode filenames like `"日本語.tar.gz"`.
///
/// **Known limitation**: a string like `"foo.123"` (digits-only extension)
/// is rejected. This is intentional: pure-numeric extensions are rare in
/// real-world UU archive filenames and are more likely to be numeric tokens.
fn looks_like_filename(s: &str) -> bool {
    // A path separator is strong evidence of a filename, but a bare separator
    // alone (e.g. "/" or "\") is not valid. Require at least one non-separator,
    // non-whitespace character alongside the separator.
    if s.contains('/') || s.contains('\\') {
        return s
            .chars()
            .any(|c| c != '/' && c != '\\' && !c.is_whitespace());
    }
    if let Some(dot_pos) = s.rfind('.') {
        let ext = &s[dot_pos + 1..];
        return ext.chars().any(|c| c.is_alphabetic());
    }
    false
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Best-effort parse of a UUencode multi-part TOC body.
///
/// The input is treated as a sequence of lines. Each line is independently
/// attempted against three recognised TOC formats (in priority order):
///
/// 1. **Part-range prefix**: `01-08  filename.tar.gz  1234 KB`
/// 2. **Parenthesised size**: `filename.tar.gz (1234567 bytes)`
/// 3. **Inline size/parts**: `filename.tar.gz   1234567 bytes   parts 1-8`
///
/// Lines that match none of these formats (comments starting with `#`, blank
/// lines, plain prose) are silently ignored. This makes the parser tolerant
/// of the varied free-form headers that real TOC posts contain.
///
/// # Return value
///
/// Returns `None` if no lines at all parse as TOC entries.
/// Returns `Some(ParsedToc)` with partial `entries` if at least one line
/// parses; unparseable lines are omitted without error.
///
/// # Format notes
///
/// - Size units `bytes`/`b`, `KB`, and `MB` are recognised case-insensitively.
///   KB and MB are converted to bytes using powers of 1 024.
/// - Size numbers may be comma-grouped (`1,234,567 bytes`) and may have a
///   decimal fraction (`1.5 MB`; KB/MB fractions round down to whole bytes).
///   A malformed number (e.g. `1,23 MB`) yields no size rather than a wrong
///   one.
/// - Part ranges use an inclusive dash notation (`N-M`). Inverted ranges
///   where `N > M` are rejected and produce `None` for that field.
/// - Non-UTF-8 bytes in `body_bytes` are replaced via lossy conversion and
///   preserved verbatim in [`ParsedToc::raw_text`].
///
/// # Never panics
///
/// This function never panics on any input, including empty slices and
/// byte sequences that are not valid UTF-8.
///
/// # Examples
///
/// ```
/// use uuencoding_multi::parse_toc;
///
/// let body = b"archive.tar.gz   1234567 bytes   parts 1-8\n";
/// let toc = parse_toc(body).expect("should parse");
/// assert_eq!(toc.entries.len(), 1);
/// assert_eq!(toc.entries[0].filename, "archive.tar.gz");
/// assert_eq!(toc.entries[0].size_bytes, Some(1_234_567));
/// assert_eq!(toc.entries[0].parts, Some(1..=8));
/// ```
///
/// ```
/// use uuencoding_multi::parse_toc;
///
/// // Body with no recognisable TOC lines → None.
/// assert!(parse_toc(b"just plain text\n").is_none());
/// ```
///
/// ```
/// use uuencoding_multi::parse_toc;
///
/// // Empty input → None.
/// assert!(parse_toc(b"").is_none());
/// ```
pub fn parse_toc(body_bytes: &[u8]) -> Option<ParsedToc> {
    let raw_text = String::from_utf8_lossy(body_bytes).into_owned();

    let entries: Vec<TocEntry> = raw_text.lines().filter_map(parse_line).collect();

    if entries.is_empty() {
        None
    } else {
        Some(ParsedToc { entries, raw_text })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Full TOC with all three formats present
    // ------------------------------------------------------------------

    #[test]
    fn full_toc_three_formats() {
        let body = b"# TOC\nfilename.tar.gz   1234567 bytes   parts 1-8\nother.zip   512 KB\nsome.bin (99 bytes)\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries.len(), 3);

        let e0 = &toc.entries[0];
        assert_eq!(e0.filename, "filename.tar.gz");
        assert_eq!(e0.size_bytes, Some(1234567));
        assert_eq!(e0.parts, Some(1..=8));

        let e1 = &toc.entries[1];
        assert_eq!(e1.filename, "other.zip");
        assert_eq!(e1.size_bytes, Some(512 * 1024));
        assert_eq!(e1.parts, None);

        let e2 = &toc.entries[2];
        assert_eq!(e2.filename, "some.bin");
        assert_eq!(e2.size_bytes, Some(99));
        assert_eq!(e2.parts, None);
    }

    // ------------------------------------------------------------------
    // Unparseable lines mixed in — no panic, still get 1 entry
    // ------------------------------------------------------------------

    #[test]
    fn garbage_lines_mixed_in() {
        let body = b"garbage\nfile.txt   100 bytes\ngibberish here\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries.len(), 1);
        assert_eq!(toc.entries[0].filename, "file.txt");
        assert_eq!(toc.entries[0].size_bytes, Some(100));
    }

    // ------------------------------------------------------------------
    // Not a TOC → None
    // ------------------------------------------------------------------

    #[test]
    fn not_a_toc_returns_none() {
        let body = b"just plain text body\nno entries at all\n";
        assert!(parse_toc(body).is_none());
    }

    // ------------------------------------------------------------------
    // UTF-8 filename
    // ------------------------------------------------------------------

    #[test]
    fn utf8_filename_no_panic() {
        let body = "日本語.tar.gz   100 bytes\n".as_bytes();
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries.len(), 1);
        assert_eq!(toc.entries[0].filename, "日本語.tar.gz");
    }

    // ------------------------------------------------------------------
    // Part range formats
    // ------------------------------------------------------------------

    #[test]
    fn parts_token_format1() {
        let body = b"file.tar.gz   100 bytes   parts 2-5\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].parts, Some(2..=5));
    }

    #[test]
    fn parts_prefix_format3() {
        let body = b"02-05  file.tar.gz  100 bytes\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].filename, "file.tar.gz");
        assert_eq!(toc.entries[0].parts, Some(2..=5));
        assert_eq!(toc.entries[0].size_bytes, Some(100));
    }

    // ------------------------------------------------------------------
    // Size unit parsing
    // ------------------------------------------------------------------

    #[test]
    fn size_kb() {
        let body = b"archive.zip   1 KB\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].size_bytes, Some(1024));
    }

    #[test]
    fn size_mb() {
        let body = b"archive.zip   2 MB\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].size_bytes, Some(2 * 1024 * 1024));
    }

    #[test]
    fn size_bare_b_unit() {
        let body = b"file.bin   512 B\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].size_bytes, Some(512));
    }

    // ------------------------------------------------------------------
    // Non-UTF-8 input — must not panic
    // ------------------------------------------------------------------

    #[test]
    fn non_utf8_no_panic() {
        // Embed an invalid UTF-8 sequence followed by a valid TOC line.
        let mut body = vec![0xFF, 0xFE, b'\n'];
        body.extend_from_slice(b"file.tar.gz   100 bytes\n");
        // May or may not produce an entry depending on lossy conversion, but
        // must never panic.
        let _ = parse_toc(&body);
    }

    // ------------------------------------------------------------------
    // Comment-only body → None
    // ------------------------------------------------------------------

    #[test]
    fn comment_only_returns_none() {
        let body = b"# just a comment\n# another comment\n";
        assert!(parse_toc(body).is_none());
    }

    // ------------------------------------------------------------------
    // Empty input → None
    // ------------------------------------------------------------------

    #[test]
    fn empty_input_returns_none() {
        assert!(parse_toc(b"").is_none());
    }

    // ------------------------------------------------------------------
    // raw_text is preserved verbatim
    // ------------------------------------------------------------------

    #[test]
    fn raw_text_preserved() {
        let body = b"# TOC\nfile.tar.gz   100 bytes\n";
        let toc = parse_toc(body).expect("should parse");
        assert!(toc.raw_text.contains("# TOC"));
        assert!(toc.raw_text.contains("file.tar.gz"));
    }

    // ------------------------------------------------------------------
    // Format 2 parenthesised size — various units
    // ------------------------------------------------------------------

    #[test]
    fn format2_kb() {
        let body = b"file.tar.gz (1024 KB)\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].size_bytes, Some(1024 * 1024));
    }

    // ------------------------------------------------------------------
    // Part range where lo > hi is ignored (invalid range)
    // ------------------------------------------------------------------

    #[test]
    fn inverted_parts_range_format1_ignored() {
        // "parts 8-1" is nonsensical — should still parse the entry but
        // produce no parts range.
        let body = b"file.tar.gz   100 bytes   parts 8-1\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].parts, None);
    }

    // ------------------------------------------------------------------
    // Plural "parts" keyword
    // ------------------------------------------------------------------

    #[test]
    fn plural_parts_keyword() {
        let body = b"file.tar.gz   100 bytes   parts 3-6\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].parts, Some(3..=6));
    }

    // ------------------------------------------------------------------
    // Singular "part" keyword
    // ------------------------------------------------------------------

    #[test]
    fn singular_part_keyword() {
        let body = b"file.tar.gz   100 bytes   part 3-6\n";
        let toc = parse_toc(body).expect("should parse");
        assert_eq!(toc.entries[0].parts, Some(3..=6));
    }

    // ------------------------------------------------------------------
    // looks_like_filename — path separator branch
    // ------------------------------------------------------------------

    /// Strings containing '/' or '\' are unconditionally accepted as filenames
    /// regardless of whether they have an extension, because a path separator
    /// is strong evidence of an actual path.
    #[test]
    fn looks_like_filename_path_separator() {
        assert!(looks_like_filename("some/path/file.rar"));
        assert!(looks_like_filename("/absolute/path"));
        // Backslash path (Windows-style) is also accepted.
        assert!(looks_like_filename("some\\path\\file.rar"));
    }

    #[test]
    fn looks_like_filename_bare_separator_rejected() {
        // Bare separators without any content are not valid filenames.
        assert!(
            !looks_like_filename("/"),
            "bare '/' must not be accepted as a filename"
        );
        assert!(
            !looks_like_filename("\\"),
            "bare '\\' must not be accepted as a filename"
        );
        assert!(
            !looks_like_filename("/ "),
            "separator with only whitespace must not be accepted"
        );
    }

    // ------------------------------------------------------------------
    // looks_like_filename — decimal numbers are not filenames (592.9)
    // ------------------------------------------------------------------

    /// Bare decimal numbers like "1.5" or "3.14" must not be accepted as
    /// filenames; their extension is digits-only.
    #[test]
    fn decimal_number_is_not_a_filename() {
        assert!(
            !looks_like_filename("1.5"),
            "\"1.5\" must not be treated as a filename"
        );
        assert!(
            !looks_like_filename("3.14"),
            "\"3.14\" must not be treated as a filename"
        );
        // Sanity-check: real filenames still pass.
        assert!(looks_like_filename("file.bin"));
        assert!(looks_like_filename("archive.tar.gz"));
        assert!(looks_like_filename("1.txt"));
    }

    // ------------------------------------------------------------------
    // Decimal and comma-grouped sizes (regression: "1.5 MB" was read as
    // 5 MB and "1,234,567 bytes" as 567).
    // ------------------------------------------------------------------

    fn size_of(line: &str) -> Option<u64> {
        parse_toc(line.as_bytes()).and_then(|t| t.entries.first().and_then(|e| e.size_bytes))
    }

    #[test]
    fn size_decimal_mb() {
        // 1.5 * 1_048_576 = 1_572_864
        assert_eq!(size_of("file.bin 1.5 MB\n"), Some(1_572_864));
        assert_eq!(size_of("file.bin (1.5 MB)\n"), Some(1_572_864));
        assert_eq!(size_of("01-03 file.bin 1.5 MB\n"), Some(1_572_864));
    }

    #[test]
    fn size_decimal_kb_rounds_down() {
        // 2.25 * 1024 = 2304 exactly; 0.001 * 1024 = 1.024 -> 1
        assert_eq!(size_of("file.bin 2.25 KB\n"), Some(2304));
        assert_eq!(size_of("file.bin 0.001 KB\n"), Some(1));
    }

    #[test]
    fn size_comma_grouped() {
        assert_eq!(size_of("file.bin 1,234,567 bytes\n"), Some(1_234_567));
        assert_eq!(size_of("file.bin (1,234,567 bytes)\n"), Some(1_234_567));
        assert_eq!(size_of("file.bin 1,234.5 KB\n"), Some(1_264_128));
    }

    #[test]
    fn size_malformed_numbers_yield_no_size() {
        for line in [
            "file.bin 1,23 MB parts 1-2\n",
            "file.bin 1,2345 bytes parts 1-2\n",
            "file.bin 1.5.3 MB parts 1-2\n",
            "file.bin 1.5 bytes parts 1-2\n",
            "file.bin v1.5 MB parts 1-2\n",
            "file.bin x5 MB parts 1-2\n",
        ] {
            let toc = parse_toc(line.as_bytes()).expect("parts range still parses");
            assert_eq!(toc.entries[0].size_bytes, None, "{line:?}");
            assert_eq!(toc.entries[0].parts, Some(1..=2), "{line:?}");
        }
        // Integral "bytes" with a zero fraction is still a whole number.
        assert_eq!(size_of("file.bin 12.0 bytes\n"), Some(12));
        // Parenthesised form: a malformed size skips the line entirely.
        assert!(parse_toc(b"file.bin (1,23 MB)\n").is_none());
    }
}
