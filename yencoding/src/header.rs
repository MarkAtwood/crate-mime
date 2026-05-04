//! Parser for yEnc header lines: `=ybegin`, `=ypart`, `=yend`.
//!
//! yEnc headers are key=value pairs on a single line, space-separated, with
//! the `name=` field always last (it extends to end-of-line and may contain
//! spaces). Field order is not specified by the yEnc "spec" (a website
//! document, not an RFC), so parsers must tolerate any order. Unknown fields
//! are silently skipped — future extensions must not break existing decoders.

use crate::error::YencError;

/// Parsed fields from a `=ybegin` line.
#[derive(Debug, Default)]
pub(crate) struct YbeginFields {
    /// Total size of the complete file in bytes (`size=`).
    pub size: Option<u64>,
    /// Encoded line length (`line=`). Informational; not used for decoding.
    pub line_length: Option<u8>,
    /// Part number within a multi-part series (`part=`). Absent on single-part.
    pub part: Option<u32>,
    /// Total number of parts in the series (`total=`). Absent on single-part.
    pub total: Option<u32>,
    /// Filename (`name=`). Extends to end of line; may contain spaces.
    pub name: Option<String>,
}

/// Parsed fields from a `=ypart` line.
#[derive(Debug, Default)]
pub(crate) struct YpartFields {
    /// 1-based byte offset of the first byte in this part (`begin=`).
    pub begin: Option<u64>,
    /// 1-based byte offset of the last byte in this part (`end=`).
    pub end: Option<u64>,
}

/// Parsed fields from a `=yend` line.
#[derive(Debug, Default)]
pub(crate) struct YendFields {
    /// Size of the decoded payload of this part (`size=`).
    pub size: Option<u64>,
    /// Per-part CRC32 (`pcrc32=`). Used for multi-part verification.
    pub pcrc32: Option<u32>,
    /// Whole-file CRC32 (`crc32=`). Used for single-part verification, and
    /// optionally present on the last part of a multi-part article.
    pub crc32: Option<u32>,
}

/// Parse a `=ybegin ...` line.
///
/// `line` should be stripped of its leading `=ybegin` keyword and any
/// surrounding whitespace; it is the key=value payload that follows.
pub(crate) fn parse_ybegin(payload: &str) -> Result<YbeginFields, YencError> {
    let mut f = YbeginFields::default();

    // `name=` must be handled specially: it consumes the rest of the line.
    // Find it first so we can split the line correctly.
    if let Some(name_pos) = find_name_param(payload) {
        // Everything before `name=` is the regular key=value pairs.
        let before_name = payload[..name_pos].trim();
        parse_kv_pairs(before_name, &mut f)?;
        // The value of `name=` is everything after `name=`.
        let name_start = name_pos + "name=".len();
        f.name = Some(
            payload[name_start..]
                .trim_end_matches(['\r', '\n'])
                .to_string(),
        );
    } else {
        parse_kv_pairs(payload, &mut f)?;
    }

    Ok(f)
}

/// Parse a `=ypart ...` line payload.
pub(crate) fn parse_ypart(payload: &str) -> Result<YpartFields, YencError> {
    let mut f = YpartFields::default();
    for (key, val) in kv_iter(payload) {
        match key {
            "begin" => {
                f.begin = Some(parse_u64(val, "begin")?);
            }
            "end" => {
                f.end = Some(parse_u64(val, "end")?);
            }
            _ => {} // unknown fields silently skipped
        }
    }
    Ok(f)
}

/// Parse a `=yend ...` line payload.
pub(crate) fn parse_yend(payload: &str) -> Result<YendFields, YencError> {
    let mut f = YendFields::default();
    for (key, val) in kv_iter(payload) {
        match key {
            "size" => {
                f.size = Some(parse_u64(val, "size")?);
            }
            "pcrc32" => {
                f.pcrc32 = Some(parse_crc32(val, "pcrc32")?);
            }
            "crc32" => {
                f.crc32 = Some(parse_crc32(val, "crc32")?);
            }
            _ => {}
        }
    }
    Ok(f)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the byte position of `name=` in a ybegin payload, handling it as a
/// special last-field (value extends to EOL, may contain spaces).
fn find_name_param(payload: &str) -> Option<usize> {
    // Walk through space-delimited tokens looking for one that starts with
    // "name=". Once found, return its start position within `payload`.
    // We look for " name=" or beginning-of-string "name=" to avoid matching
    // a hypothetical "xname=" token.
    if payload.starts_with("name=") {
        return Some(0);
    }
    // Find " name=" — a space followed by "name=".
    let needle = " name=";
    payload.find(needle).map(|pos| pos + 1) // +1 to skip the leading space
}

/// Apply parsed key=value tokens (excluding `name=`) to a `YbeginFields`.
fn parse_kv_pairs(s: &str, f: &mut YbeginFields) -> Result<(), YencError> {
    for (key, val) in kv_iter(s) {
        match key {
            "size" => f.size = Some(parse_u64(val, "size")?),
            "line" => {
                // line= is u16 in some encoders, but we store as u8 (0–255).
                // Values > 255 are clamped to 255; they are informational only.
                let n: u64 = parse_u64(val, "line")?;
                f.line_length = Some(n.min(255) as u8);
            }
            "part" => f.part = Some(parse_u32(val, "part")?),
            "total" => f.total = Some(parse_u32(val, "total")?),
            _ => {} // unknown fields silently skipped
        }
    }
    Ok(())
}

/// Iterator over `key=value` pairs in a space-delimited header payload.
/// Stops before any token that starts with `name=` (handled separately).
/// Skips tokens that don't contain `=` (malformed, ignored).
fn kv_iter(s: &str) -> impl Iterator<Item = (&str, &str)> {
    s.split_ascii_whitespace()
        .take_while(|tok| !tok.starts_with("name="))
        .filter_map(|tok| {
            let eq = tok.find('=')?;
            Some((&tok[..eq], &tok[eq + 1..]))
        })
}

fn parse_u64(s: &str, field: &str) -> Result<u64, YencError> {
    s.parse::<u64>().map_err(|_| YencError::InvalidHeader {
        field: field.to_string(),
    })
}

fn parse_u32(s: &str, field: &str) -> Result<u32, YencError> {
    s.parse::<u32>().map_err(|_| YencError::InvalidHeader {
        field: field.to_string(),
    })
}

fn parse_crc32(s: &str, field: &str) -> Result<u32, YencError> {
    u32::from_str_radix(s, 16).map_err(|_| YencError::InvalidHeader {
        field: field.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // =ybegin parsing
    // -----------------------------------------------------------------------

    #[test]
    fn ybegin_single_part() {
        // Oracle: from single_part.yenc fixture
        // =ybegin line=128 size=64 name=test.bin
        let f = parse_ybegin("line=128 size=64 name=test.bin").unwrap();
        assert_eq!(f.line_length, Some(128));
        assert_eq!(f.size, Some(64));
        assert_eq!(f.name.as_deref(), Some("test.bin"));
        assert!(f.part.is_none());
        assert!(f.total.is_none());
    }

    #[test]
    fn ybegin_multi_part() {
        // Oracle: from multi_part_1.yenc fixture
        // =ybegin part=1 total=2 line=128 size=128 name=test.bin
        let f = parse_ybegin("part=1 total=2 line=128 size=128 name=test.bin").unwrap();
        assert_eq!(f.part, Some(1));
        assert_eq!(f.total, Some(2));
        assert_eq!(f.line_length, Some(128));
        assert_eq!(f.size, Some(128));
        assert_eq!(f.name.as_deref(), Some("test.bin"));
    }

    #[test]
    fn ybegin_name_with_spaces() {
        // Filename may contain spaces — name= must extend to EOL.
        let f = parse_ybegin("size=100 name=my cool file.bin").unwrap();
        assert_eq!(f.name.as_deref(), Some("my cool file.bin"));
        assert_eq!(f.size, Some(100));
    }

    #[test]
    fn ybegin_unknown_fields_ignored() {
        // Future extensions: skip gracefully.
        let f = parse_ybegin("line=128 size=64 newfield=42 name=test.bin").unwrap();
        assert_eq!(f.size, Some(64));
        assert_eq!(f.name.as_deref(), Some("test.bin"));
    }

    #[test]
    fn ybegin_field_order_independent() {
        // The yEnc "spec" says field order is not guaranteed for fields before
        // name=. The name= field is always last (it extends to EOL).
        // We test different orderings of the pre-name fields.
        let a = parse_ybegin("size=10 line=128 name=f.bin").unwrap();
        let b = parse_ybegin("line=128 size=10 name=f.bin").unwrap();
        assert_eq!(a.name, b.name);
        assert_eq!(a.size, b.size);
        assert_eq!(a.line_length, b.line_length);
    }

    #[test]
    fn ybegin_invalid_size_is_error() {
        let err = parse_ybegin("size=notanumber name=f.bin").unwrap_err();
        assert!(matches!(err, YencError::InvalidHeader { field } if field == "size"));
    }

    // -----------------------------------------------------------------------
    // =ypart parsing
    // -----------------------------------------------------------------------

    #[test]
    fn ypart_basic() {
        // Oracle: from multi_part_1.yenc fixture
        // =ypart begin=1 end=64
        let f = parse_ypart("begin=1 end=64").unwrap();
        assert_eq!(f.begin, Some(1));
        assert_eq!(f.end, Some(64));
    }

    #[test]
    fn ypart_unknown_fields_ignored() {
        let f = parse_ypart("begin=1 end=64 extra=99").unwrap();
        assert_eq!(f.begin, Some(1));
        assert_eq!(f.end, Some(64));
    }

    // -----------------------------------------------------------------------
    // =yend parsing
    // -----------------------------------------------------------------------

    #[test]
    fn yend_single_part() {
        // Oracle: from single_part.yenc fixture
        // =yend size=64 crc32=100ece8c
        let f = parse_yend("size=64 crc32=100ece8c").unwrap();
        assert_eq!(f.size, Some(64));
        assert_eq!(f.crc32, Some(0x100e_ce8c));
        assert!(f.pcrc32.is_none());
    }

    #[test]
    fn yend_multi_part() {
        // Oracle: from multi_part_1.yenc fixture
        // =yend size=64 part=1 pcrc32=100ece8c crc32=24650d57
        let f = parse_yend("size=64 part=1 pcrc32=100ece8c crc32=24650d57").unwrap();
        assert_eq!(f.size, Some(64));
        assert_eq!(f.pcrc32, Some(0x100e_ce8c));
        assert_eq!(f.crc32, Some(0x2465_0d57));
    }

    #[test]
    fn yend_invalid_crc_is_error() {
        let err = parse_yend("size=64 crc32=GGGGGGGG").unwrap_err();
        assert!(matches!(err, YencError::InvalidHeader { field } if field == "crc32"));
    }
}
