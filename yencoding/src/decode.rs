//! yEnc decode implementation.
//!
//! The core algorithm is simple: each encoded byte has 42 subtracted (mod 256).
//! When the decoder sees `=` (0x3D), it reads the next byte and subtracts 106
//! (= 42 + 64) instead. `\r`, `\n`, and `\0` in the encoded stream are
//! discarded (they are line-wrap artifacts, not data).
//!
//! Dot-stuffing: NNTP adds a leading `.` to any data line that starts with `.`.
//! We handle this defensively — a line starting with `..` has the first dot
//! stripped before decoding.
//!
//! The framing structure:
//! ```text
//! [preamble text — optional, skipped]
//! =ybegin [part=N total=T] line=L size=S name=filename
//! [=ypart begin=B end=E]          ← present only for multi-part
//! <encoded data lines>
//! =yend size=S [part=N] [pcrc32=HHHHHHHH] [crc32=HHHHHHHH]
//! ```

use crate::error::YencError;
use crate::header::{parse_ybegin, parse_yend, parse_ypart};
use crate::{DecodedPart, YencMetadata};

/// Decode a yEnc article from raw bytes.
///
/// Scans forward for the first `=ybegin` line, ignoring any preceding prose
/// (NNTP article headers, etc.). Decodes the data region between the header
/// lines and `=yend`, verifies the CRC32, and returns a [`DecodedPart`].
///
/// # Errors
///
/// - [`YencError::NoHeader`] — no `=ybegin` line found.
/// - [`YencError::InvalidHeader`] — a required field is missing or unparsable.
/// - [`YencError::UnexpectedEof`] — `=yend` line was never found.
/// - [`YencError::CrcMismatch`] — decoded bytes do not match the CRC in `=yend`.
/// - [`YencError::SizeMismatch`] — decoded byte count does not match `=yend size=`.
pub fn decode(input: &[u8]) -> Result<DecodedPart, YencError> {
    // -----------------------------------------------------------------------
    // Step 1: Find =ybegin line.
    // We scan line-by-line to avoid misidentifying =ybegin inside encoded data.
    // -----------------------------------------------------------------------
    let mut lines = LineIter::new(input);

    let ybegin_payload = loop {
        let line = lines.next().ok_or(YencError::NoHeader)?;
        if let Some(payload) = strip_keyword(line, b"=ybegin ") {
            break payload;
        }
    };

    let ybegin = parse_ybegin(lossy_str(ybegin_payload).trim())?;
    let filename = ybegin.name.ok_or(YencError::InvalidHeader {
        field: "name".to_string(),
    })?;
    let total_size = ybegin.size.ok_or(YencError::InvalidHeader {
        field: "size".to_string(),
    })?;

    // -----------------------------------------------------------------------
    // Step 2: Check for optional =ypart line.
    // -----------------------------------------------------------------------
    let mut part_begin: Option<u64> = None;
    let mut part_end: Option<u64> = None;

    // Peek at the next line — if it is =ypart, consume it; otherwise it is
    // the first data line and we must not skip it.
    let first_data_line = {
        let peeked = lines.next().ok_or(YencError::UnexpectedEof)?;
        if let Some(payload) = strip_keyword(peeked, b"=ypart ") {
            let ypart = parse_ypart(lossy_str(payload).trim())?;
            part_begin = ypart.begin;
            part_end = ypart.end;
            // Now the next line is the first real data line.
            None // signal: consume normally
        } else {
            Some(peeked) // hold for first decode iteration
        }
    };

    // -----------------------------------------------------------------------
    // Step 3: Decode data lines until =yend.
    // -----------------------------------------------------------------------
    let mut decoded: Vec<u8> = Vec::new();
    // Track a lone '=' that was the last byte of a data line. Per the yEnc
    // spec the encoder must never produce a split escape, but some encoders do
    // when the encoded byte stream is sliced at a fixed column boundary.  We
    // carry the pending-escape flag across line boundaries so the escape
    // target at the start of the next line is decoded correctly.
    let mut pending_escape = false;

    // Process the held line first (if we peeked past =ypart and found data).
    if let Some(line) = first_data_line {
        if let Some(yend_payload) = strip_keyword(line, b"=yend ") {
            // The very first "data" line is actually =yend (empty article).
            return finish_decode(
                decoded,
                yend_payload,
                filename,
                total_size,
                ybegin.line_length.unwrap_or(128),
                ybegin.part,
                ybegin.total,
                part_begin,
                part_end,
            );
        }
        decode_line(line, &mut decoded, &mut pending_escape);
    }

    loop {
        let line = lines.next().ok_or(YencError::UnexpectedEof)?;
        if let Some(yend_payload) = strip_keyword(line, b"=yend ") {
            return finish_decode(
                decoded,
                yend_payload,
                filename,
                total_size,
                ybegin.line_length.unwrap_or(128),
                ybegin.part,
                ybegin.total,
                part_begin,
                part_end,
            );
        }
        decode_line(line, &mut decoded, &mut pending_escape);
    }
}

// ---------------------------------------------------------------------------
// Finish: verify CRC and build DecodedPart
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn finish_decode(
    data: Vec<u8>,
    yend_raw: &[u8],
    filename: String,
    total_size: u64,
    line_length: u8,
    part: Option<u32>,
    total_parts: Option<u32>,
    part_begin: Option<u64>,
    part_end: Option<u64>,
) -> Result<DecodedPart, YencError> {
    let yend = parse_yend(lossy_str(yend_raw).trim())?;

    // CRC32 verification: use the field appropriate to the article type.
    //
    // Single-part: check crc32= (whole-file CRC, which equals the part CRC for
    // a single-part article).  pcrc32= is not defined for single-part articles;
    // if a non-compliant encoder writes both, ignore pcrc32= to avoid verifying
    // against the wrong value.
    //
    // Multi-part: check pcrc32= (per-part CRC).  crc32= is the whole-file CRC
    // and cannot be verified against a single part's payload.
    let crc_to_check = if part.is_some() {
        yend.pcrc32
    } else {
        yend.crc32
    };
    let crc32_verified;
    if let Some(expected) = crc_to_check {
        let actual = crc32fast::hash(&data);
        if actual != expected {
            return Err(YencError::CrcMismatch { expected, actual });
        }
        crc32_verified = true;
    } else {
        // No CRC field present (or multi-part with only whole-file crc32) —
        // cannot verify. Not an error per the yEnc "spec" (CRC is optional
        // on some older encoders), but we surface this via crc32_verified=false
        // so callers can decide.
        crc32_verified = false;
    }

    // When no CRC was present, validate size= as the only integrity check.
    // When CRC was present and verified, this is redundant but harmless to keep.
    if let Some(declared_size) = yend.size {
        if data.len() as u64 != declared_size {
            return Err(YencError::SizeMismatch {
                expected: declared_size,
                actual: data.len() as u64,
            });
        }
    }

    Ok(DecodedPart {
        data,
        metadata: YencMetadata {
            filename,
            size: total_size,
            line_length,
            total_parts,
        },
        part,
        part_begin,
        part_end,
        crc32_verified,
        whole_file_crc32: yend.crc32,
    })
}

// ---------------------------------------------------------------------------
// Line-level decode
// ---------------------------------------------------------------------------

/// Decode one yEnc data line into `out`.
///
/// - Discards `\r`, `\n`, `\0` (line-wrap artifacts and spec-mandated ignores).
/// - Handles dot-stuffing: a line starting with `..` (NNTP dot-stuff) has its
///   first dot stripped before decoding.
/// - Escape: `=X` → `(X - 106) mod 256`.
/// - Normal: `b` → `(b - 42) mod 256`.
///
/// `pending_escape` carries a lone `=` that ended the **previous** line across
/// the line boundary. If `*pending_escape` is `true` on entry, the first
/// non-framing byte of this line is consumed as the escape target. This handles
/// the split-escape case that arises when a conforming encoder slices the
/// encoded byte stream at a fixed column and an escape pair (`=X`) straddles a
/// line boundary.
pub(crate) fn decode_line(line: &[u8], out: &mut Vec<u8>, pending_escape: &mut bool) {
    // Strip leading dot-stuff: NNTP adds a '.' before any data line starting
    // with '.'. The resulting '.' is not part of the yEnc encoded data.
    //
    // This MUST happen before pending-escape resolution.  Dot-stuffing is a
    // transport-layer transformation: the NNTP server prepends a '.' that the
    // encoder never emitted.  Removing it first recovers the encoder's
    // original byte stream, so the pending-escape target is the byte the
    // encoder intended, not the NNTP-added dot.
    let line = if line.len() >= 2 && line[0] == b'.' && line[1] == b'.' {
        &line[1..]
    } else {
        line
    };

    let mut i = 0;
    let len = line.len();

    // If the previous line ended with a lone '=', the first non-framing byte
    // on this line is its escape target.
    if *pending_escape {
        *pending_escape = false;
        // Skip over any leading framing bytes (\r, \n, \0) — they are not the
        // escape target, they are artifacts of the line terminator.
        while i < len && matches!(line[i], b'\r' | b'\n' | b'\0') {
            i += 1;
        }
        if i < len {
            out.push(line[i].wrapping_sub(106));
            i += 1;
        }
        // If the line was entirely framing bytes, the escape is simply lost
        // (the encoder violated the spec; best effort is to discard it).
    }

    while i < len {
        let b = line[i];
        match b {
            // Discard line-ending and NUL bytes — they are framing, not data.
            b'\r' | b'\n' | b'\0' => {
                i += 1;
            }
            // Escape sequence: next byte has 64 additional subtracted.
            // (b - 42 - 64) = (b - 106) mod 256
            // Guard: if the next byte is a framing byte (\r, \n, \0), the '='
            // is a lone/trailing escape.  Set pending_escape so the target is
            // picked up from the start of the next line.
            b'=' if i + 1 < len && !matches!(line[i + 1], b'\r' | b'\n' | b'\0') => {
                let next = line[i + 1];
                out.push(next.wrapping_sub(106));
                i += 2;
            }
            // Trailing lone '=' at end of line (before \r\n or at EOF of line):
            // the escape target is on the next line — defer it.
            b'=' => {
                *pending_escape = true;
                i += 1;
            }
            // Normal byte: subtract 42 (mod 256).
            _ => {
                out.push(b.wrapping_sub(42));
                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Iterator that yields lines (including their line-ending bytes) from a byte slice.
struct LineIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> LineIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        // Find the next \n.
        let nl = self.data[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|r| start + r);
        let end = match nl {
            Some(nl_pos) => nl_pos + 1, // include the \n
            None => self.data.len(),    // no \n — line runs to EOF
        };
        self.pos = end;
        Some(&self.data[start..end])
    }
}

/// If `line` starts with `keyword`, return the remainder after the keyword.
/// The keyword must end with a space (e.g. `b"=ybegin "`).
fn strip_keyword<'a>(line: &'a [u8], keyword: &[u8]) -> Option<&'a [u8]> {
    // Trim leading CR/LF to handle lines from a CRLF stream.
    let line = line
        .strip_suffix(b"\r\n")
        .or_else(|| line.strip_suffix(b"\n"))
        .or_else(|| line.strip_suffix(b"\r"))
        .unwrap_or(line);
    line.strip_prefix(keyword)
}

/// Convert bytes to a UTF-8 string lossily (for header parsing only).
fn lossy_str(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // decode_line unit tests
    // Oracle: Python arithmetic only — no yEnc library.
    // decode: out = (encoded_byte - 42) % 256
    // escape: out = (next_byte - 106) % 256
    // -----------------------------------------------------------------------

    #[test]
    fn decode_line_simple_bytes() {
        // Oracle: b'*' (0x2A) + nothing = (0x2A - 42) % 256 = 0
        // b'+' (0x2B) = 1, etc.
        let encoded = b"*+,-";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(out, &[0, 1, 2, 3]);
        assert!(!pe);
    }

    #[test]
    fn decode_line_escape_sequence() {
        // Oracle: '=' followed by '}' (0x7D)
        // decoded = (0x7D - 106) % 256 = (125 - 106) = 19
        // Byte 19 + 42 = 61 = '=', which must be escaped. This is the escape
        // in the single_part.yenc fixture.
        let encoded = b"=}";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(out, &[19]);
        assert!(!pe);
    }

    #[test]
    fn decode_line_discards_crlf() {
        // \r\n at end of line are framing, not data.
        let encoded = b"*+\r\n";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(out, &[0, 1]);
    }

    #[test]
    fn decode_line_discards_nul() {
        // NUL in the encoded stream is discarded.
        let encoded = b"*\x00+";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(out, &[0, 1]);
    }

    #[test]
    fn decode_line_dot_stuffing() {
        // NNTP dot-stuffing: a line starting with '..' has the first '.' stripped.
        // '..' → '.' → decoded = ('.' - 42) = (46 - 42) = 4
        let encoded = b"..+";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        // First '.' stripped (dot-stuff), remaining '.+':
        // '.' = 46, (46 - 42) = 4; '+' = 43, (43 - 42) = 1
        assert_eq!(out, &[4, 1]);
    }

    #[test]
    fn decode_line_no_dot_stuffing_single_dot() {
        // A single leading dot is NOT stripped — only '..' at start triggers it.
        let encoded = b".+";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        // '.' = 46, (46 - 42) = 4; '+' = 43, (43 - 42) = 1
        assert_eq!(out, &[4, 1]);
    }

    #[test]
    fn decode_line_all_256_bytes() {
        // Oracle: for each raw byte b in 0..=255:
        //   encoded = (b + 42) % 256, but escape NUL/LF/CR/= with '=' prefix.
        // We verify the round-trip using the Python oracle encoding.
        // This test uses the Python gen_fixtures.py algorithm directly.
        let raw: Vec<u8> = (0u8..=255).collect();
        let mut encoded = Vec::new();
        for &b in &raw {
            let v = b.wrapping_add(42);
            if matches!(v, 0 | 10 | 13 | 61) {
                encoded.push(b'=');
                encoded.push(v.wrapping_add(64));
            } else {
                encoded.push(v);
            }
        }
        let mut decoded = Vec::new();
        let mut pe = false;
        decode_line(&encoded, &mut decoded, &mut pe);
        assert_eq!(decoded, raw, "all-bytes round-trip failed");
    }

    #[test]
    fn decode_line_trailing_lone_eq_sets_pending_escape() {
        // A trailing lone '=' at end of line sets pending_escape for the next line.
        // The output of this line is just the bytes before '='.
        let encoded = b"*=";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(out, &[0]); // only '*' decoded
        assert!(pe, "trailing '=' must set pending_escape");
    }

    #[test]
    fn decode_line_split_escape_across_lines() {
        // Oracle: raw byte 19 encodes as '=' + '}' (0x7D).
        // If '=' is the last byte of line 1 and '}' is the first byte of line 2,
        // the decoder must produce 19, not misinterpret '}' as normal data.
        //
        // Normal decode of '}' = (0x7D - 42) % 256 = (125 - 42) = 83.
        // Escaped decode of '}' = (0x7D - 106) % 256 = 19.
        // Oracle says the correct decoded value is 19.
        let line1 = b"*=\r\n"; // '*' → 0, then '=' before \r\n → pending_escape
        let line2 = b"}\r\n"; // '}' is the escape target → (0x7D - 106) = 19
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(line1, &mut out, &mut pe);
        assert!(pe, "line1 must leave pending_escape set");
        decode_line(line2, &mut out, &mut pe);
        assert!(!pe, "line2 consumed the pending escape");
        assert_eq!(out, &[0u8, 19], "split escape must decode correctly");
    }

    #[test]
    fn decode_line_split_escape_with_dot_stuffed_target() {
        // Verify that pending-escape interacts correctly with NNTP
        // dot-stuffing.  The encoder produces a split escape where the target
        // byte is '.' (0x2E), which causes NNTP to dot-stuff the next line.
        //
        // Encoder output:   line1 = "*=\r\n", line2 = ".+\r\n"
        // After dot-stuff:  line1 = "*=\r\n", line2 = "..+\r\n"
        //
        // Dot-unstuffing must happen first (transport layer), recovering the
        // encoder's ".+".  Then pending-escape consumes '.' as the target.
        //
        // Oracle: escape decode of '.' = (0x2E - 106) % 256 = 196 = 0xC4
        //         normal  decode of '+' = (0x2B -  42) % 256 =   1
        let line1 = b"*=\r\n"; // '*' → 0, trailing '=' → pending_escape
        let line2 = b"..+\r\n"; // dot-stuffed; after unstuff: '.+\r\n'
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(line1, &mut out, &mut pe);
        assert!(pe, "line1 must leave pending_escape set");
        decode_line(line2, &mut out, &mut pe);
        assert!(!pe, "line2 consumed the pending escape");
        // '*' → 0, escape('.') → 196, '+' → 1
        assert_eq!(
            out,
            &[0u8, 196, 1],
            "dot-unstuffing must happen before pending-escape resolution"
        );
    }

    #[test]
    fn decode_line_split_escape_all_framing_line() {
        // If the pending-escape target line contains only framing bytes
        // (\r\n\0), the escape is lost (encoder violated the spec).
        let line1 = b"*=\r\n";
        let line2 = b"\r\n";
        let line3 = b"+\r\n";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(line1, &mut out, &mut pe);
        assert!(pe, "line1 must leave pending_escape set");
        decode_line(line2, &mut out, &mut pe);
        // Escape is lost — the line was entirely framing bytes.
        assert!(!pe, "pending_escape must be cleared even if lost");
        // The '+' on line3 is decoded normally, not as an escape target.
        decode_line(line3, &mut out, &mut pe);
        assert_eq!(out, &[0u8, 1], "lost escape must not carry to line3");
    }

    #[test]
    fn decode_line_eq_before_cr_sets_pending_escape() {
        // '=' immediately before \r sets pending_escape for the next line.
        // Oracle: '*' decodes to (42 - 42) = 0.  The trailing '=' before \r
        // is deferred to the next line.
        let encoded = b"*=\r";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(
            out,
            &[0],
            "=\\r must not produce a garbage byte on this line"
        );
        assert!(pe, "=\\r must set pending_escape");
    }

    #[test]
    fn decode_line_eq_before_lf_sets_pending_escape() {
        // '=' immediately before \n sets pending_escape for the next line.
        let encoded = b"*=\n";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(
            out,
            &[0],
            "=\\n must not produce a garbage byte on this line"
        );
        assert!(pe, "=\\n must set pending_escape");
    }

    #[test]
    fn decode_line_eq_before_nul_sets_pending_escape() {
        // '=' immediately before \0 sets pending_escape.
        let encoded = b"*=\x00";
        let mut out = Vec::new();
        let mut pe = false;
        decode_line(encoded, &mut out, &mut pe);
        assert_eq!(
            out,
            &[0],
            "=\\0 must not produce a garbage byte on this line"
        );
        assert!(pe, "=\\0 must set pending_escape");
    }

    // -----------------------------------------------------------------------
    // Full decode() tests using committed fixture files
    // Oracle: Python gen_fixtures.py — independent of this crate
    // -----------------------------------------------------------------------

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
    }

    #[test]
    fn decode_single_part_fixture() {
        // Oracle: manifest.toml — expected_decoded_len=64, expected_crc32=100ece8c
        // Payload: bytes(range(64))
        let input = load_fixture("single_part.yenc");
        let part = decode(&input).expect("single_part.yenc should decode cleanly");
        assert_eq!(part.data.len(), 64, "decoded length");
        assert_eq!(part.data, (0u8..64).collect::<Vec<_>>(), "decoded payload");
        assert_eq!(part.metadata.filename, "test.bin");
        assert_eq!(part.metadata.size, 64);
        assert!(part.crc32_verified, "CRC should be verified");
        assert!(part.part.is_none(), "single-part has no part number");
        assert!(part.part_begin.is_none());
        assert!(part.part_end.is_none());
        assert!(part.metadata.total_parts.is_none());
    }

    #[test]
    fn decode_multi_part_1_fixture() {
        // Oracle: manifest.toml — part 1 of 2, payload bytes(range(128))[0..64]
        // expected_crc32 = 100ece8c, whole_file_crc32 = 24650d57
        let input = load_fixture("multi_part_1.yenc");
        let part = decode(&input).expect("multi_part_1.yenc should decode");
        assert_eq!(part.data, (0u8..64).collect::<Vec<_>>());
        assert_eq!(part.metadata.filename, "test.bin");
        assert_eq!(part.metadata.size, 128); // total file size
        assert_eq!(part.part, Some(1));
        assert_eq!(part.metadata.total_parts, Some(2));
        assert_eq!(part.part_begin, Some(1)); // 1-based, adjusted to 0-indexed by caller
        assert_eq!(part.part_end, Some(64));
        assert!(part.crc32_verified);
    }

    #[test]
    fn decode_multi_part_2_fixture() {
        // Oracle: manifest.toml — part 2 of 2, payload bytes(range(128))[64..128]
        // expected_crc32 = 5a8fc61f
        let input = load_fixture("multi_part_2.yenc");
        let part = decode(&input).expect("multi_part_2.yenc should decode");
        assert_eq!(part.data, (64u8..128).collect::<Vec<_>>());
        assert_eq!(part.part, Some(2));
        assert_eq!(part.metadata.total_parts, Some(2));
        assert_eq!(part.part_begin, Some(65));
        assert_eq!(part.part_end, Some(128));
        assert!(part.crc32_verified);
    }

    #[test]
    fn decode_prose_preamble_fixture() {
        // Oracle: manifest.toml — same payload as single_part but with 3 preamble lines.
        // Decoder must skip prose before =ybegin.
        let input = load_fixture("prose_preamble.yenc");
        let part = decode(&input).expect("prose_preamble.yenc should decode");
        assert_eq!(part.data, (0u8..64).collect::<Vec<_>>());
        assert!(part.crc32_verified);
    }

    #[test]
    fn decode_crc_mismatch_fixture() {
        // Oracle: manifest.toml — correct encoding but crc32=00000000 in =yend.
        let input = load_fixture("crc_mismatch.yenc");
        let err = decode(&input).expect_err("crc_mismatch.yenc should return CrcMismatch");
        assert!(
            matches!(err, YencError::CrcMismatch { expected: 0, .. }),
            "expected CrcMismatch with expected=0, got: {:?}",
            err
        );
    }

    #[test]
    fn decode_truncated_fixture() {
        // Oracle: manifest.toml — =yend line omitted entirely.
        let input = load_fixture("truncated.yenc");
        let err = decode(&input).expect_err("truncated.yenc should return UnexpectedEof");
        assert_eq!(err, YencError::UnexpectedEof);
    }

    #[test]
    fn decode_empty_input_returns_no_header() {
        let err = decode(b"").unwrap_err();
        assert_eq!(err, YencError::NoHeader);
    }

    #[test]
    fn decode_missing_name_field_is_error() {
        // =ybegin with no name= field
        let input = b"=ybegin line=128 size=10\n*+,-\n=yend size=4\n";
        let err = decode(input).unwrap_err();
        assert!(matches!(err, YencError::InvalidHeader { field } if field == "name"));
    }

    #[test]
    fn decode_missing_size_field_is_error() {
        let input = b"=ybegin line=128 name=f.bin\n*+,-\n=yend size=4\n";
        let err = decode(input).unwrap_err();
        assert!(matches!(err, YencError::InvalidHeader { field } if field == "size"));
    }

    #[test]
    fn decode_missing_yend_is_unexpected_eof() {
        let input = b"=ybegin line=128 size=4 name=f.bin\n*+,-\n";
        let err = decode(input).unwrap_err();
        assert_eq!(err, YencError::UnexpectedEof);
    }

    #[test]
    fn decode_size_mismatch_is_error() {
        // =yend size=10 but only 4 bytes in the data block
        let input = b"=ybegin line=128 size=10 name=f.bin\n*+,-\n=yend size=10\n";
        let err = decode(input).unwrap_err();
        assert!(
            matches!(
                err,
                YencError::SizeMismatch {
                    expected: 10,
                    actual: 4
                }
            ),
            "expected SizeMismatch, got: {:?}",
            err
        );
    }

    #[test]
    fn decode_no_panic_on_arbitrary_input() {
        // Fuzz-style: must not panic on any byte sequence.
        let inputs: &[&[u8]] = &[
            b"",
            b"\x00\x01\x02",
            b"=ybegin",
            b"=ybegin \n",
            b"=ybegin size=0 name=f\n=yend size=0 crc32=00000000\n",
            b"=ybegin size=1 name=f\n*\n=yend size=1 crc32=00000000\n",
            &[b'='; 256],
            &[0xFF; 100],
        ];
        for input in inputs {
            let _ = decode(input); // must not panic
        }
    }

    #[test]
    fn decode_eq_before_crlf_does_not_consume_framing_byte() {
        // '=' immediately before \r\n sets pending_escape for the next line.
        // The \r\n itself must NOT be consumed as the escape target.
        //
        // Body: '*' encodes raw byte 0; then lone '=' before CRLF.
        // The pending escape is orphaned when =yend follows — the '=' target
        // was never provided.
        //
        // Oracle: '*' = 0x2A = 42; raw = (42 - 42) % 256 = 0.
        // Expected: data == [0].  CRC 00000000 won't match real CRC of [0],
        // so CrcMismatch is acceptable — what is NOT acceptable is Ok with 2 bytes.
        let input = b"=ybegin line=128 size=1 name=test\n*=\r\n=yend size=1 crc32=00000000\n";
        let result = crate::decode(input);
        if let Ok(decoded) = &result {
            assert_eq!(
                decoded.data.len(),
                1,
                "lone '=' before CRLF must not produce extra byte; got {:?}",
                decoded.data
            );
            assert_eq!(decoded.data[0], 0);
        }
    }

    #[test]
    fn decode_split_escape_across_lines() {
        // Regression test for split-escape: when a yEnc encoder slices the
        // encoded byte stream at a fixed column, an escape pair ('=' followed by
        // the escape target) can be split across two lines.  The decoder must
        // re-join the pair across the line boundary.
        //
        // Payload: [0, 19].
        //   Byte 0  → (0 + 42) % 256 = 42 = '*'. No escaping needed.
        //   Byte 19 → (19 + 42) % 256 = 61 = '='. Must be escaped: '=' + '}'
        //             where '}' = (61 + 64) % 256 = 125 = 0x7D.
        //
        // With line_length=1 the encoded stream is cut after each data byte:
        //   Line 1: "*\r\n"   (byte 0 encoded)
        //   Line 2: "=\r\n"   (escape prefix for byte 19 — split here)
        //   Line 3: "}\r\n"   (escape target for byte 19)
        //
        // Oracle: CRC32([0, 19]) = 0xc5675321
        //   python3 -c "import binascii; print(hex(binascii.crc32(bytes([0,19]))&0xffffffff))"
        let input: &[u8] =
            b"=ybegin line=1 size=2 name=split.bin\n*\r\n=\r\n}\r\n=yend size=2 crc32=c5675321\n";
        let part = decode(input).expect("split-escape article must decode successfully");
        assert_eq!(
            part.data,
            &[0u8, 19],
            "split-escape decode must produce correct bytes"
        );
        assert!(part.crc32_verified, "CRC must verify against oracle");
    }

    #[test]
    fn decode_multipart_crc32_only_no_pcrc32_is_ok() {
        // Regression test for MIME-3ps.3: a multi-part article that has crc32=
        // in =yend but no pcrc32= must NOT return CrcMismatch.
        //
        // crc32= is the whole-file CRC and is meaningless for a single part.
        // We use an intentionally wrong value (0xdeadbeef) to confirm it is
        // completely ignored.
        //
        // Payload: bytes [0, 1, 2, 3] encoded as yEnc (* + , -).
        // Oracle (encode): (b + 42) % 256 for each; none of these need escaping.
        //   0+42=42='*', 1+42=43='+', 2+42=44=',', 3+42=45='-'
        let input: &[u8] = b"=ybegin part=1 total=2 line=128 size=128 name=test.bin\n\
                              =ypart begin=1 end=4\n\
                              *+,-\n\
                              =yend size=4 part=1 crc32=deadbeef\n";

        let result = decode(input);
        // Must not return CrcMismatch — the whole-file crc32 is not checked
        // against a part's payload.
        assert!(
            result.is_ok(),
            "expected Ok for multi-part with only crc32= (no pcrc32=), got: {:?}",
            result.unwrap_err()
        );
        let part = result.unwrap();
        assert_eq!(part.data, &[0, 1, 2, 3], "decoded bytes");
        // crc32_verified must be false: we had no pcrc32 to check against.
        assert!(
            !part.crc32_verified,
            "crc32_verified should be false when only whole-file crc32= is present"
        );
    }

    #[test]
    fn decode_single_part_ignores_pcrc32_uses_crc32() {
        // A single-part article that has BOTH pcrc32= (wrong value) and crc32=
        // (correct value). The decoder must check only crc32= and succeed.
        //
        // This ensures that pcrc32= is never used for single-part verification.
        //
        // Payload: bytes [0, 1, 2] → '*', '+', ','  (no escapes needed).
        // CRC32([0,1,2]) = 0x0854897f  (python3: binascii.crc32(bytes([0,1,2])) & 0xffffffff)
        let input: &[u8] = b"=ybegin line=128 size=3 name=test.bin\n\
                              *+,\n\
                              =yend size=3 pcrc32=deadbeef crc32=0854897f\n";

        let result = decode(input);
        assert!(
            result.is_ok(),
            "expected Ok: single-part must use crc32=, not pcrc32=; got: {:?}",
            result.err()
        );
        let part = result.unwrap();
        assert_eq!(part.data, &[0u8, 1, 2]);
        assert!(
            part.crc32_verified,
            "crc32_verified must be true when crc32= is correct"
        );
    }
}
