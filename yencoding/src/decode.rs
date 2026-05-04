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
        decode_line(line, &mut decoded);
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
        decode_line(line, &mut decoded);
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

    // CRC32 verification: prefer pcrc32 (per-part) for multi-part articles,
    // fall back to crc32 for single-part.
    let crc32_verified;
    if let Some(expected) = yend.pcrc32.or(yend.crc32) {
        let actual = crc32fast::hash(&data);
        if actual != expected {
            return Err(YencError::CrcMismatch { expected, actual });
        }
        crc32_verified = true;
    } else {
        // No CRC field present — cannot verify. Not an error per the yEnc
        // "spec" (CRC is optional on some older encoders), but we surface this
        // via crc32_verified=false so callers can decide.
        crc32_verified = false;
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
pub(crate) fn decode_line(line: &[u8], out: &mut Vec<u8>) {
    // Strip leading dot-stuff: NNTP adds a '.' before any data line starting
    // with '.'. The resulting '.' is not part of the yEnc encoded data.
    let line = if line.len() >= 2 && line[0] == b'.' && line[1] == b'.' {
        &line[1..]
    } else {
        line
    };

    let mut i = 0;
    let len = line.len();
    while i < len {
        let b = line[i];
        match b {
            // Discard line-ending and NUL bytes — they are framing, not data.
            b'\r' | b'\n' | b'\0' => {
                i += 1;
            }
            // Escape sequence: next byte has 64 additional subtracted.
            // (b - 42 - 64) = (b - 106) mod 256
            b'=' if i + 1 < len => {
                let next = line[i + 1];
                out.push(next.wrapping_sub(106));
                i += 2;
            }
            // Trailing lone '=' at end of line: discard. Per spec the encoder
            // must not produce this, but we handle it defensively.
            b'=' => {
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
        decode_line(encoded, &mut out);
        assert_eq!(out, &[0, 1, 2, 3]);
    }

    #[test]
    fn decode_line_escape_sequence() {
        // Oracle: '=' followed by '}' (0x7D)
        // decoded = (0x7D - 106) % 256 = (125 - 106) = 19
        // Byte 19 + 42 = 61 = '=', which must be escaped. This is the escape
        // in the single_part.yenc fixture.
        let encoded = b"=}";
        let mut out = Vec::new();
        decode_line(encoded, &mut out);
        assert_eq!(out, &[19]);
    }

    #[test]
    fn decode_line_discards_crlf() {
        // \r\n at end of line are framing, not data.
        let encoded = b"*+\r\n";
        let mut out = Vec::new();
        decode_line(encoded, &mut out);
        assert_eq!(out, &[0, 1]);
    }

    #[test]
    fn decode_line_discards_nul() {
        // NUL in the encoded stream is discarded.
        let encoded = b"*\x00+";
        let mut out = Vec::new();
        decode_line(encoded, &mut out);
        assert_eq!(out, &[0, 1]);
    }

    #[test]
    fn decode_line_dot_stuffing() {
        // NNTP dot-stuffing: a line starting with '..' has the first '.' stripped.
        // '..' → '.' → decoded = ('.' - 42) = (46 - 42) = 4
        let encoded = b"..+";
        let mut out = Vec::new();
        decode_line(encoded, &mut out);
        // First '.' stripped (dot-stuff), remaining '.+':
        // '.' = 46, (46 - 42) = 4; '+' = 43, (43 - 42) = 1
        assert_eq!(out, &[4, 1]);
    }

    #[test]
    fn decode_line_no_dot_stuffing_single_dot() {
        // A single leading dot is NOT stripped — only '..' at start triggers it.
        let encoded = b".+";
        let mut out = Vec::new();
        decode_line(encoded, &mut out);
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
        decode_line(&encoded, &mut decoded);
        assert_eq!(decoded, raw, "all-bytes round-trip failed");
    }

    #[test]
    fn decode_line_trailing_lone_eq_discarded() {
        // A trailing lone '=' at end of line (malformed — encoder shouldn't
        // produce this) is discarded rather than panicking.
        let encoded = b"*=";
        let mut out = Vec::new();
        decode_line(encoded, &mut out); // must not panic
        assert_eq!(out, &[0]); // only '*' decoded
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
}
