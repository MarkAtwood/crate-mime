use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use crate::{
    error::ParseError,
    message::DecodedBodyValue,
    part::{ParsedPart, TransferEncoding},
};

/// Decode the body of a parsed part.
///
/// Performs transfer-encoding decode (Base64, Quoted-Printable, or identity),
/// optional byte-length truncation, and charset conversion to UTF-8 via
/// `encoding_rs`.
///
/// `max_bytes` limits the number of transfer-decoded bytes before charset
/// conversion.
///
/// Returns `Err(ParseError::InvalidRange)` when `part.body_range` is out of
/// bounds for `raw`.
pub fn decode_body_value(
    raw: &[u8],
    part: &ParsedPart,
    max_bytes: Option<usize>,
) -> Result<DecodedBodyValue, ParseError> {
    let (offset_u32, length_u32) = part.body_range;
    let offset = offset_u32 as usize;
    let length = length_u32 as usize;
    let end = offset.checked_add(length).ok_or(ParseError::InvalidRange {
        offset: offset_u32,
        length: length_u32,
        available: raw.len(),
    })?;
    if end > raw.len() {
        return Err(ParseError::InvalidRange {
            offset: offset_u32,
            length: length_u32,
            available: raw.len(),
        });
    }
    let body_bytes = &raw[offset..end];

    // Step 1: transfer-decode, pre-truncating input to avoid decoding more
    // than needed.  Each path sets a `*_was_limited` flag when input was cut
    // short, so Step 2 knows whether additional content exists beyond the limit.
    let mut is_encoding_problem = false;
    let mut input_was_limited = false;
    let decoded: Vec<u8> = match part.transfer_encoding {
        TransferEncoding::Base64 => {
            // Limit base64 input to avoid allocating a full decode buffer when
            // only a preview (max_bytes) is needed.  3 decoded bytes = 4 base64
            // chars; round up to the next multiple of 4 so the STANDARD (padded)
            // engine never receives a partial group, which would be a spurious
            // decode error.
            let max_b64_chars = max_bytes
                .map(|n| n.saturating_mul(4).div_ceil(3).next_multiple_of(4))
                .unwrap_or(usize::MAX);

            // Strip CR/LF line wrapping, collect up to max_b64_chars bytes,
            // and detect truncation — all in a single pass.
            let mut stripped = Vec::with_capacity(max_b64_chars.min(body_bytes.len()));
            for &b in body_bytes {
                if b == b'\r' || b == b'\n' {
                    continue;
                }
                if stripped.len() >= max_b64_chars {
                    input_was_limited = true;
                    break;
                }
                stripped.push(b);
            }
            match BASE64_STANDARD.decode(&stripped) {
                Ok(v) => v,
                Err(_) => {
                    is_encoding_problem = true;
                    Vec::new()
                }
            }
        }
        TransferEncoding::QuotedPrintable => {
            // Pre-truncate the QP input when only a preview is needed.
            // Decoded bytes ≤ encoded bytes always (=XX is 3 encoded → 1 decoded;
            // soft-line-break =\r\n is 3 encoded → 0 decoded).  A 4× multiplier
            // comfortably bounds the worst case of all-=XX content.  Truncation
            // mid-escape is handled gracefully by Robust mode.
            let qp_input = max_bytes.map_or(body_bytes, |n| {
                let limit = n.saturating_mul(4).min(body_bytes.len());
                input_was_limited = limit < body_bytes.len();
                &body_bytes[..limit]
            });
            match quoted_printable::decode(qp_input, quoted_printable::ParseMode::Robust) {
                Ok(v) => v,
                Err(_) => {
                    is_encoding_problem = true;
                    qp_input.to_vec()
                }
            }
        }
        TransferEncoding::UUEncode => decode_uuencode(
            body_bytes,
            max_bytes,
            &mut is_encoding_problem,
            &mut input_was_limited,
        ),
        TransferEncoding::Identity
        | TransferEncoding::SevenBit
        | TransferEncoding::EightBit
        | TransferEncoding::Binary => {
            // Slice to max_bytes before allocating to avoid copying the full body.
            let truncated = max_bytes.map_or(body_bytes, |n| {
                let limit = n.min(body_bytes.len());
                input_was_limited = limit < body_bytes.len();
                &body_bytes[..limit]
            });
            truncated.to_vec()
        }
    };

    // Step 2: apply max_bytes truncation on the decoded bytes and determine
    // is_truncated.  All three encoding paths pre-truncate their input and
    // record the result via `input_was_limited`, so the logic here is
    // symmetric: either the decoded output itself exceeded max_bytes (possible
    // for Base64 or QP, where the input limit is an approximation),
    // or the input path was cut short.
    let (truncated_bytes, is_truncated) = match max_bytes {
        Some(n) if decoded.len() > n => (decoded[..n].to_vec(), true),
        _ => (decoded, input_was_limited),
    };

    // Step 3: charset conversion to UTF-8 via encoding_rs.
    // Practical default: UTF-8 is more permissive than RFC 2045 §5.2 (us-ascii)
    // but avoids false is_encoding_problem flags on modern charsetless text.
    let charset = part.charset.as_deref().unwrap_or("utf-8");
    let enc = encoding_rs::Encoding::for_label(charset.as_bytes()).unwrap_or(encoding_rs::UTF_8);
    let (cow, _, had_errors) = enc.decode(&truncated_bytes);
    is_encoding_problem |= had_errors;

    // Step 4: encoding_rs guarantees valid UTF-8 output.  Any truncation that
    // cut through a multi-byte source sequence causes encoding_rs to emit a
    // replacement character and set had_errors, which we already capture in
    // is_encoding_problem above.
    let value = cow.into_owned();

    Ok(DecodedBodyValue {
        value,
        is_truncated,
        is_encoding_problem,
    })
}

/// Decode a UUencoded body using the `uuencoding` crate.
///
/// Delegates to [`uuencoding::decode`], which handles `begin`/`end` framing,
/// CRLF stripping, space/backtick zero-value handling, and partial-result
/// tolerance. This replaces a duplicate in-crate implementation and ensures
/// all UU edge-case fixes in the `uuencoding` crate apply here automatically.
///
/// - Respects `max_bytes`; sets `*input_was_limited` when the decoded output
///   was truncated to the limit.
/// - Sets `*is_encoding_problem` when the block is missing a `begin` line,
///   is a `begin-base64` block, or the decoded result was truncated (i.e.
///   the `end` line was absent or a data line was malformed).
fn decode_uuencode(
    body: &[u8],
    max_bytes: Option<usize>,
    is_encoding_problem: &mut bool,
    input_was_limited: &mut bool,
) -> Vec<u8> {
    // Use decode_limited so that decoding halts as soon as max_bytes decoded
    // bytes have been produced.  Note: input is still split into lines up-front
    // (O(input)), but data decoding stops at max_bytes.
    match uuencoding::decode_limited(body, max_bytes) {
        Err(_) => {
            *is_encoding_problem = true;
            Vec::new()
        }
        Ok(block) => {
            if block.is_truncated {
                // was_limit_hit is set by decode_limited() when max_bytes
                // caused the early stop.  Absent that, the block was genuinely
                // truncated (missing end line, bad data byte, etc.).
                if block.was_limit_hit {
                    *input_was_limited = true;
                } else {
                    *is_encoding_problem = true;
                }
            }
            block.data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part::{ParsedPart, TransferEncoding};

    /// Build a synthetic raw buffer with `body_bytes` appended after a fake
    /// header block, and return a matching `ParsedPart`.
    fn make_part(
        body_bytes: &[u8],
        transfer_encoding: TransferEncoding,
        charset: Option<&str>,
    ) -> (Vec<u8>, ParsedPart) {
        let prefix = b"fake-header: x\r\n\r\n";
        let mut raw: Vec<u8> = prefix.to_vec();
        let offset = raw.len();
        raw.extend_from_slice(body_bytes);
        let length = body_bytes.len();

        let part = ParsedPart {
            part_id: "1".to_owned(),
            content_type: "text/plain".to_owned(),
            charset: charset.map(str::to_owned),
            transfer_encoding,
            disposition: None,
            filename: None,
            cid: None,
            header_range: (0u32, offset as u32),
            body_range: (offset as u32, length as u32),
            children: vec![],
            is_encoding_problem: false,
        };
        (raw, part)
    }

    #[test]
    fn test_base64_body() {
        // Oracle: base64("Hello, World!") == "SGVsbG8sIFdvcmxkIQ=="
        let b64 = b"SGVsbG8sIFdvcmxkIQ==";
        let (raw, part) = make_part(b64, TransferEncoding::Base64, Some("utf-8"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "Hello, World!");
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_quoted_printable_body() {
        // Oracle: QP encoding of "café" in UTF-8 is "caf=C3=A9"
        let qp = b"caf=C3=A9";
        let (raw, part) = make_part(qp, TransferEncoding::QuotedPrintable, Some("utf-8"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "caf\u{e9}"); // "café"
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_latin1_charset() {
        // Oracle: latin-1 byte 0xE9 is 'é' (U+00E9)
        let latin1 = b"\xe9";
        let (raw, part) = make_part(latin1, TransferEncoding::Identity, Some("iso-8859-1"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "\u{e9}"); // "é"
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_max_bytes_truncation() {
        // Body = "Hello, World!" (13 bytes), max_bytes = 5 → "Hello"
        let body = b"Hello, World!";
        let (raw, part) = make_part(body, TransferEncoding::Identity, Some("utf-8"));
        let result = decode_body_value(&raw, &part, Some(5)).unwrap();
        assert_eq!(result.value, "Hello");
        assert!(result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_base64_is_truncated_multiple_of_3() {
        // Oracle: base64("Hello, World!") == "SGVsbG8sIFdvcmxkIQ=="
        // "Hello, World!" is 13 bytes. For max_bytes that are multiples of 3
        // AND less than 13, the body is truncated and is_truncated must be true.
        // For max_bytes = 13 (exact body length), is_truncated must be false.
        let b64 = b"SGVsbG8sIFdvcmxkIQ==";
        let (raw, part) = make_part(b64, TransferEncoding::Base64, Some("utf-8"));

        // max_bytes = 3: multiple of 3, body is 13 bytes, must be truncated
        let result = decode_body_value(&raw, &part, Some(3)).unwrap();
        assert!(
            result.is_truncated,
            "max_bytes=3 (multiple of 3) on 13-byte body: is_truncated must be true"
        );

        // max_bytes = 6: multiple of 3, body is 13 bytes, must be truncated
        let result = decode_body_value(&raw, &part, Some(6)).unwrap();
        assert!(
            result.is_truncated,
            "max_bytes=6 (multiple of 3) on 13-byte body: is_truncated must be true"
        );

        // max_bytes = 9: multiple of 3, body is 13 bytes, must be truncated
        let result = decode_body_value(&raw, &part, Some(9)).unwrap();
        assert!(
            result.is_truncated,
            "max_bytes=9 (multiple of 3) on 13-byte body: is_truncated must be true"
        );

        // max_bytes = 13: exact body length — NOT truncated
        let result = decode_body_value(&raw, &part, Some(13)).unwrap();
        assert!(
            !result.is_truncated,
            "max_bytes=13 (exact body length): is_truncated must be false"
        );
    }

    #[test]
    fn test_base64_max_bytes_non_multiple_of_4() {
        // Oracle: base64("Hello, World!") == "SGVsbG8sIFdvcmxkIQ=="
        // "Hello, World!" is 13 bytes.  For each max_bytes from 1..=10 the
        // pre-truncation of the base64 input must be a multiple of 4 so the
        // STANDARD (padded) engine does not reject it with a spurious error.
        let b64 = b"SGVsbG8sIFdvcmxkIQ==";
        let (raw, part) = make_part(b64, TransferEncoding::Base64, Some("utf-8"));
        for n in 1usize..=10 {
            let result = decode_body_value(&raw, &part, Some(n)).unwrap();
            assert!(
                !result.is_encoding_problem,
                "max_bytes={n}: unexpected encoding problem (base64 pre-truncation not a multiple of 4?)"
            );
            assert!(
                !result.value.is_empty(),
                "max_bytes={n}: expected non-empty result"
            );
        }
    }

    // -----------------------------------------------------------------------
    // UUencode tests
    //
    // All UU-encoded byte strings are from the Python 3.12 `uu` / `binascii`
    // stdlib modules — the independent oracle.  No expected value comes from
    // this crate.  Python commands are cited inline.
    // -----------------------------------------------------------------------

    #[test]
    fn test_uuencode_hello_world() {
        // Oracle (Python 3.12):
        //   import uu, io
        //   buf = io.BytesIO()
        //   uu.encode(io.BytesIO(b"Hello, World!"), buf, "test.txt", mode=0o644)
        //   print(repr(buf.getvalue()))
        //   → b'begin 644 test.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n'
        //
        // Expected decoded bytes (hex 48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21):
        // "Hello, World!" in ASCII.
        let uu_body = b"begin 644 test.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, Some("utf-8"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "Hello, World!");
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_hello() {
        // Oracle (Python 3.12):
        //   import uu, io
        //   buf = io.BytesIO()
        //   uu.encode(io.BytesIO(b"Hello"), buf, "hello.txt", mode=0o644)
        //   print(repr(buf.getvalue()))
        //   → b'begin 644 hello.txt\n%2&5L;&\\ \n \nend\n'
        //
        // Expected decoded bytes (hex 48 65 6c 6c 6f): "Hello".
        let uu_body = b"begin 644 hello.txt\n%2&5L;&\\ \n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, Some("utf-8"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "Hello");
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_empty() {
        // Oracle (Python 3.12):
        //   import uu, io
        //   buf = io.BytesIO()
        //   uu.encode(io.BytesIO(b""), buf, "empty.txt", mode=0o644)
        //   print(repr(buf.getvalue()))
        //   → b'begin 644 empty.txt\n \nend\n'
        //
        // A single space line means 0 decoded bytes (end marker).
        let uu_body = b"begin 644 empty.txt\n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, Some("utf-8"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "");
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_crlf_line_endings() {
        // Same data as test_uuencode_hello_world but with CRLF line endings.
        // UU is commonly CRLF-terminated in email.  Only CR/LF is stripped;
        // trailing spaces (= encoding padding) must be preserved.
        // Oracle: same expected bytes as the LF-only version.
        let uu_body = b"begin 644 test.txt\r\n-2&5L;&\\L(%=O<FQD(0  \r\n \r\nend\r\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, Some("utf-8"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "Hello, World!");
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_content_before_begin_skipped() {
        // Content before the "begin NNN filename" line must be silently skipped.
        // Oracle: same expected bytes as test_uuencode_hello_world.
        let uu_body =
            b"Some MIME preamble\r\nMore garbage\r\nbegin 644 test.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, Some("utf-8"));
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value, "Hello, World!");
        assert!(!result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_max_bytes_truncation() {
        // Oracle: UU-encoded "Hello, World!" → 13 decoded bytes.
        // max_bytes = 5 should yield "Hello" and set is_truncated.
        let uu_body = b"begin 644 test.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, Some("utf-8"));
        let result = decode_body_value(&raw, &part, Some(5)).unwrap();
        assert_eq!(result.value, "Hello");
        assert!(result.is_truncated);
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_no_begin_line_is_encoding_problem() {
        // A body with no "begin" line is malformed.
        // Expected: empty output with is_encoding_problem set.
        let uu_body = b"this has no begin line\njust garbage\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, None);
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert!(result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_null_byte_in_encoded_payload_no_panic() {
        // Regression test for MIME-gcz.1: a 0x00 byte in the encoded payload
        // must not panic.
        //
        // Mechanism: in uuencoding/src/decode_line.rs, data bytes go through
        // decode_byte(), which rejects anything outside 0x20..=0x5F or 0x60.
        // A 0x00 byte in a data position returns Err(InvalidChar), which causes
        // the block to be returned with is_truncated=true and whatever bytes
        // were decoded before the error.  wrapping_sub(32) applies only to the
        // length byte (line[0]), not the data payload.
        //
        // The key invariant is no panic regardless of the error path taken.
        // is_encoding_problem will be true because is_truncated is true.
        let uu_body = b"begin 644 f\n#\x00\x00\x00\x00\n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, None);
        let _result = decode_body_value(&raw, &part, None).unwrap();
    }

    #[test]
    fn test_uuencode_backtick_end_marker() {
        // A backtick-only line is an alternative end marker (used by some mailers).
        // Oracle (Python 3.12):
        //   import binascii
        //   print(repr(binascii.b2a_uu(b"Hi")))
        //   → b'"2&D \n'
        //
        // Replace the standard space end-marker with a backtick; decoder must stop.
        // Expected decoded bytes: b"Hi" (0x48 0x69).
        let uu_body = b"begin 644 hi.txt\n\"2&D \n`\nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, None);
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert_eq!(result.value.as_bytes(), b"Hi");
        assert!(!result.is_encoding_problem);
    }

    #[test]
    fn test_uuencode_full_45_byte_line() {
        // Oracle (Python 3.12):
        //   import binascii
        //   print(repr(binascii.b2a_uu(bytes(range(45)))))
        //   → b'M  $" P0%!@<("0H+# T.#Q 1$A,4%187&!D:&QP=\'A\\@(2(C)"4F)R@I*BLL\n'
        //
        // 'M' = 77, (77-32)&63 = 45 bytes per line.
        // Decoded: bytes 0x00..0x2C (0 through 44).
        let uu_body =
            b"begin 644 test.bin\nM  $\" P0%!@<(\"0H+# T.#Q 1$A,4%187&!D:&QP=\'A\\@(2(C)\"4F)R@I*BLL\n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, None);
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert!(!result.is_encoding_problem, "unexpected encoding problem");
        let decoded = result.value.as_bytes();
        assert_eq!(decoded.len(), 45, "expected 45 decoded bytes");
        for (i, &b) in decoded.iter().enumerate() {
            assert_eq!(
                b, i as u8,
                "decoded[{i}] = {b:#04x}, expected {:#04x}",
                i as u8
            );
        }
    }

    #[test]
    fn test_uuencode_two_line_decode() {
        // Oracle (Python 3.12):
        //   import binascii
        //   print(repr(binascii.b2a_uu(bytes(range(45)))))
        //   → b'M  $" P0%!@<("0H+# T.#Q 1$A,4%187&!D:&QP=\'A\\@(2(C)"4F)R@I*BLL\n'
        //   print(repr(binascii.b2a_uu(bytes(range(45, 48)))))
        //   → b'#+2XO\n'
        //
        // Two-line decode: bytes 0..47.
        let uu_body = b"begin 644 test48.bin\n\
M  $\" P0%!@<(\"0H+# T.#Q 1$A,4%187&!D:&QP=\'A\\@(2(C)\"4F)R@I*BLL\n\
#+2XO\n \nend\n";
        let (raw, part) = make_part(uu_body, TransferEncoding::UUEncode, None);
        let result = decode_body_value(&raw, &part, None).unwrap();
        assert!(!result.is_encoding_problem, "unexpected encoding problem");
        let decoded = result.value.as_bytes();
        assert_eq!(decoded.len(), 48, "expected 48 decoded bytes");
        for (i, &b) in decoded.iter().enumerate() {
            assert_eq!(
                b, i as u8,
                "decoded[{i}] = {b:#04x}, expected {:#04x}",
                i as u8
            );
        }
    }
}
