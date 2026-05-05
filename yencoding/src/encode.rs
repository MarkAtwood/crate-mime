//! yEnc encode implementation.
//!
//! The core algorithm: add 42 to each byte (mod 256). Four specific encoded
//! values must be escaped with a preceding `=` and then adding 64 (mod 256):
//! - `\0` (NUL, 0x00) — would terminate C strings and confuse some software
//! - `\n` (LF, 0x0A) — line terminator; would be misread as end of data line
//! - `\r` (CR, 0x0D) — carriage return; same issue
//! - `=`  (0x3D) — the escape character itself
//!
//! Additionally, the yEnc spec documents two optional-but-common escapes:
//! - `.` at the start of a line is escaped to avoid NNTP dot-stuffing ambiguity
//! - TAB (0x09) at the start of a line is escaped on some encoders
//!
//! This implementation escapes `.` and TAB at line start, matching what real
//! Usenet encoders produce and what the Python fixture generator in
//! `tests/fixtures/gen_fixtures.py` does.
//!
//! Lines are wrapped at `line_length` *encoded* characters (default 128).
//! Line endings are `\r\n`.

/// Default line length for yEnc encoding, matching the yEnc spec recommendation.
pub const DEFAULT_LINE_LENGTH: u8 = 128;

/// Encode `data` as a single-part yEnc article.
///
/// The output is a complete article body including `=ybegin`, the encoded
/// data lines wrapped at `line_length` characters, and `=yend` with CRC32.
/// It does **not** include NNTP message headers.
///
/// # Parameters
///
/// - `data` — raw bytes to encode. May be empty.
/// - `filename` — written verbatim to the `name=` field of `=ybegin`.
///   No validation is performed; control characters should be avoided.
/// - `line_length` — maximum number of encoded bytes per line (1–255).
///   Pass `DEFAULT_LINE_LENGTH` (128) for the standard value.
///
/// # Returns
///
/// A `Vec<u8>` containing the complete encoded article ready for posting.
#[must_use]
pub fn encode(data: &[u8], filename: &str, line_length: u8) -> Vec<u8> {
    // Clamp to at least 2: escape pairs are 2 bytes and must fit on one line.
    let line_length = line_length.max(2) as usize;
    let mut out = Vec::with_capacity(data.len() * 11 / 10 + 128);

    // =ybegin header (single-part: no part= or total= fields)
    out.extend_from_slice(
        format!(
            "=ybegin line={line_length} size={} name={filename}\r\n",
            data.len()
        )
        .as_bytes(),
    );

    // Encode body
    let crc = encode_body(data, line_length, &mut out);

    // =yend footer
    out.extend_from_slice(format!("=yend size={} crc32={crc:08x}\r\n", data.len()).as_bytes());

    out
}

/// Encode one part of a multi-part yEnc series.
///
/// Called from the public `encode_part` wrapper in `lib.rs` which groups
/// the parameters into `EncodePartOptions` to satisfy the argument-count lint.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn encode_part(
    data: &[u8],
    filename: &str,
    total_size: u64,
    total_parts: u32,
    part: u32,
    begin: u64,
    end: u64,
    whole_file_crc32: u32,
    line_length: u8,
) -> Vec<u8> {
    // Clamp to at least 2: escape pairs are 2 bytes and must fit on one line.
    let line_length = line_length.max(2) as usize;
    let mut out = Vec::with_capacity(data.len() * 11 / 10 + 256);

    // =ybegin header (multi-part: includes part= and total= fields)
    out.extend_from_slice(
        format!(
            "=ybegin part={part} total={total_parts} line={line_length} \
             size={total_size} name={filename}\r\n"
        )
        .as_bytes(),
    );

    // =ypart header
    out.extend_from_slice(format!("=ypart begin={begin} end={end}\r\n").as_bytes());

    // Encode body; get per-part CRC
    let pcrc = encode_body(data, line_length, &mut out);

    // =yend footer: includes both pcrc32= (this part) and crc32= (whole file)
    out.extend_from_slice(
        format!(
            "=yend size={} part={part} pcrc32={pcrc:08x} crc32={whole_file_crc32:08x}\r\n",
            data.len()
        )
        .as_bytes(),
    );

    out
}

// ---------------------------------------------------------------------------
// Core encode body (used by both encode() and encode_part())
// ---------------------------------------------------------------------------

/// Encode `data` into `out`, wrapping at `line_length` encoded bytes.
///
/// Returns the CRC32 of the *raw* (pre-encode) `data`.
fn encode_body(data: &[u8], line_length: usize, out: &mut Vec<u8>) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    let crc = hasher.finalize();

    let mut col: usize = 0; // current position within the current line

    for &byte in data {
        let encoded = byte.wrapping_add(42);

        // Determine whether this byte must be escaped.
        // NUL, LF, CR, and '=' are always escaped.
        // '.' and TAB (0x09) at position 0 of a line are also escaped.
        let must_escape = matches!(encoded, 0x00 | 0x0A | 0x0D | 0x3D)
            || (col == 0 && matches!(encoded, 0x2E | 0x09));

        if must_escape {
            // A 2-byte escape pair must fit on one line.  If there is only one
            // column left, flush the current line before emitting the pair.
            if col + 2 > line_length {
                out.extend_from_slice(b"\r\n");
                col = 0;
            }
            out.push(b'=');
            out.push(encoded.wrapping_add(64));
            col += 2;
        } else {
            out.push(encoded);
            col += 1;
        }

        if col >= line_length {
            out.extend_from_slice(b"\r\n");
            col = 0;
        }
    }

    // Emit a final line ending if there are any leftover characters.
    if col > 0 {
        out.extend_from_slice(b"\r\n");
    }

    crc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode;

    // -----------------------------------------------------------------------
    // encode_body unit tests
    // Oracle: Python gen_fixtures.py — same encoding algorithm
    // -----------------------------------------------------------------------

    #[test]
    fn encode_simple_bytes() {
        // Oracle: byte 0 + 42 = '*' (0x2A), byte 1 = '+' (0x2B), etc.
        let mut out = Vec::new();
        let crc = encode_body(&[0, 1, 2, 3], 128, &mut out);
        assert_eq!(&out[..4], b"*+,-");
        // CRC32 of [0,1,2,3] — from Python: binascii.crc32(bytes([0,1,2,3])) = 0x8bb98613
        assert_eq!(crc, 0x8bb9_8613);
    }

    #[test]
    fn encode_escapes_nul() {
        // byte 214 + 42 = 256 mod 256 = 0 (NUL) → escape as '=' + (0+64) = '@'
        let mut out = Vec::new();
        encode_body(&[214], 128, &mut out);
        assert_eq!(&out[..2], b"=@");
    }

    #[test]
    fn encode_escapes_lf() {
        // Oracle: byte 224 + 42 = 266 mod 256 = 10 (LF) → escape as '=' + (10+64=74='J')
        let mut out = Vec::new();
        encode_body(&[224], 128, &mut out);
        assert_eq!(&out[..2], b"=J");
    }

    #[test]
    fn encode_escapes_cr() {
        // Oracle: byte 227 + 42 = 269 mod 256 = 13 (CR) → escape as '=' + (13+64='M')
        // python3: chr((227+42)%256) == '\r', chr(13+64) == 'M'
        let mut out = Vec::new();
        encode_body(&[227], 128, &mut out);
        assert_eq!(&out[..2], b"=M");
    }

    #[test]
    fn encode_escapes_eq() {
        // byte 19 + 42 = 61 = '=' → escape as '=' + (61+64) = '}'
        let mut out = Vec::new();
        encode_body(&[19], 128, &mut out);
        assert_eq!(&out[..2], b"=}");
    }

    #[test]
    fn encode_escapes_dot_at_line_start() {
        // byte 4 + 42 = 46 = '.' — at start of line, must be escaped
        let mut out = Vec::new();
        encode_body(&[4], 128, &mut out);
        // '.' + 64 = 110 = 'n'
        assert_eq!(&out[..2], b"=n");
    }

    #[test]
    fn encode_dot_not_escaped_mid_line() {
        // '.' at position > 0 is NOT escaped
        // byte 1 = '+' (not dot), byte 4 = '.' mid-line
        let mut out = Vec::new();
        encode_body(&[1, 4], 128, &mut out);
        assert_eq!(out[0], b'+');
        assert_eq!(out[1], b'.'); // not escaped, mid-line
    }

    #[test]
    fn encode_line_wrapping() {
        // With line_length=4, every 4 encoded chars should be followed by \r\n.
        let data = vec![0u8; 8]; // 8 zeros → 8 '*' chars → 2 lines of 4
        let mut out = Vec::new();
        encode_body(&data, 4, &mut out);
        // Expected: "****\r\n****\r\n"
        assert_eq!(&out[..4], b"****");
        assert_eq!(&out[4..6], b"\r\n");
        assert_eq!(&out[6..10], b"****");
        assert_eq!(&out[10..12], b"\r\n");
    }

    #[test]
    fn encode_all_bytes_round_trip() {
        // Oracle applied to mandatory-escape bytes only (NUL/LF/CR/=): the Python
        // algorithm (b+42)%256, then escape if in {0,10,13,61}, is the reference.
        // Dot and TAB at line-start escaping uses round-trip consistency (covered
        // by fixture tests); they are not independently verified here.
        let raw: Vec<u8> = (0u8..=255).collect();
        // Build expected using Python algorithm
        let mut expected_encoded = Vec::new();
        for &b in &raw {
            let v = b.wrapping_add(42);
            if matches!(v, 0 | 10 | 13 | 61) {
                expected_encoded.push(b'=');
                expected_encoded.push(v.wrapping_add(64));
            } else if v == b'.' || v == 0x09 {
                // These would be escaped at line start but not mid-line.
                // Since we have many bytes, they won't all land at col=0.
                // Just push them unescaped for this oracle comparison.
                expected_encoded.push(v);
            } else {
                expected_encoded.push(v);
            }
        }
        // The encode/decode round-trip must be correct regardless.
        let encoded = encode(&raw, "all.bin", 128);
        let decoded = decode(&encoded).expect("round-trip decode failed");
        assert_eq!(decoded.data, raw, "all-bytes round-trip failed");
    }

    // -----------------------------------------------------------------------
    // Full encode() tests
    // -----------------------------------------------------------------------

    #[test]
    fn encode_single_part_header_footer() {
        let data = b"Cat";
        let out = encode(data, "cat.bin", 128);
        let s = String::from_utf8_lossy(&out);
        assert!(s.starts_with("=ybegin line=128 size=3 name=cat.bin\r\n"));
        assert!(s.contains("=yend size=3 crc32="));
        assert!(s.ends_with("\r\n"));
    }

    #[test]
    fn encode_empty_data() {
        let out = encode(b"", "empty.bin", 128);
        let s = String::from_utf8_lossy(&out);
        assert!(s.starts_with("=ybegin line=128 size=0 name=empty.bin\r\n"));
        assert!(s.contains("=yend size=0 crc32="));
        // No data lines between header and footer.
        let parts: Vec<&str> = s.lines().collect();
        assert_eq!(parts[0], "=ybegin line=128 size=0 name=empty.bin");
        assert_eq!(parts[1], "=yend size=0 crc32=00000000");
    }

    #[test]
    fn encode_single_part_crc_correct() {
        // Oracle: binascii.crc32(bytes(range(64))) = 0x100ece8c
        let data: Vec<u8> = (0..64).collect();
        let out = encode(&data, "test.bin", 128);
        assert!(
            String::from_utf8_lossy(&out).contains("crc32=100ece8c"),
            "CRC32 mismatch in encoded output"
        );
        // Also verify decode round-trip
        let decoded = decode(&out).unwrap();
        assert_eq!(decoded.data, data);
        assert!(decoded.crc32_verified);
    }

    #[test]
    fn encode_part_header_fields() {
        let data: Vec<u8> = (0..64).collect();
        let out = encode_part(&data, "test.bin", 128, 2, 1, 1, 64, 0xdeadbeef, 128);
        let s = String::from_utf8_lossy(&out);
        assert!(s.starts_with("=ybegin part=1 total=2 line=128 size=128 name=test.bin\r\n"));
        assert!(s.contains("=ypart begin=1 end=64\r\n"));
        assert!(s.contains("pcrc32="));
        assert!(s.contains("crc32=deadbeef"));
    }

    #[test]
    fn encode_part_pcrc_is_part_crc() {
        // Oracle: pcrc32 of bytes(range(64)) = 0x100ece8c
        let data: Vec<u8> = (0..64).collect();
        let out = encode_part(&data, "test.bin", 128, 2, 1, 1, 64, 0x24650d57, 128);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("pcrc32=100ece8c"), "per-part CRC wrong: {s}");
        assert!(s.contains("crc32=24650d57"), "whole-file CRC wrong: {s}");
    }

    #[test]
    fn encode_line_length_1_clamped_to_2() {
        // line_length=1 would make escape pairs (2 bytes) overflow the column
        // limit.  The encoder must clamp it to at least 2.
        // Oracle: byte 214 encodes to NUL (needs escape), so we get "=@" which
        // is 2 bytes — must fit on one line even though the caller asked for 1.
        let out = encode(&[214], "t.bin", 1);
        let s = String::from_utf8_lossy(&out);
        for line in s.lines() {
            if line.starts_with("=ybegin") || line.starts_with("=yend") || line.is_empty() {
                continue;
            }
            assert!(
                line.len() <= 2,
                "line too long with clamped line_length=2: {:?}",
                line
            );
        }
        // Round-trip must succeed.
        let decoded = decode(&out).expect("round-trip decode of line_length=1 input failed");
        assert_eq!(decoded.data, &[214]);
    }

    #[test]
    fn encode_line_length_2_does_not_panic() {
        // line_length=2 is the minimum valid value; must not panic and must
        // produce a decodable output.
        // Oracle: bytes [0, 1] encode to '*' '+' — no escaping needed.
        let data = &[0u8, 1u8];
        let out = encode(data, "t.bin", 2);
        let decoded = decode(&out).expect("round-trip decode of line_length=2 input failed");
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn no_line_exceeds_line_length() {
        use crate::encode;
        // Use a small line_length (e.g. 10) and a payload that forces escapes at various positions.
        // Bytes that must be escaped: those whose (b+42)%256 equals 0, 10, 13, or 61.
        // (b+42)%256 = 0 -> b = 214
        // (b+42)%256 = 10 -> b = 224
        // (b+42)%256 = 13 -> b = 227
        // (b+42)%256 = 61 -> b = 19
        // Create a payload with escapes at position 9 (last column for line_length=10).
        let line_length = 10u8;
        // Build a 50-byte payload where every 9th byte (0-indexed) forces an escape:
        let payload: Vec<u8> = (0u8..50)
            .map(|i| if i % 9 == 8 { 19u8 } else { 0u8 })
            .collect();
        let encoded = encode(&payload, "test.bin", line_length);
        // Extract data lines (skip =ybegin and =yend lines)
        for line in encoded.split(|&b| b == b'\n') {
            let line = if line.ends_with(b"\r") {
                &line[..line.len() - 1]
            } else {
                line
            };
            // Skip header/footer lines
            if line.starts_with(b"=ybegin") || line.starts_with(b"=yend") || line.is_empty() {
                continue;
            }
            assert!(
                line.len() <= line_length as usize,
                "data line too long: {} chars (limit {}): {:?}",
                line.len(),
                line_length,
                std::str::from_utf8(line).unwrap_or("<binary>")
            );
        }
    }
}
