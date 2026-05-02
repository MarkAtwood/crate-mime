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

    // Step 1: transfer-decode.
    let mut is_encoding_problem = false;
    let mut b64_input_was_limited = false;
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
            let mut stripped = Vec::new();
            for &b in body_bytes {
                if b == b'\r' || b == b'\n' {
                    continue;
                }
                if stripped.len() >= max_b64_chars {
                    b64_input_was_limited = true;
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
        TransferEncoding::Identity
        | TransferEncoding::SevenBit
        | TransferEncoding::EightBit
        | TransferEncoding::Binary => {
            // Slice to max_bytes before allocating to avoid copying the full body.
            let truncated =
                max_bytes.map_or(body_bytes, |n| &body_bytes[..n.min(body_bytes.len())]);
            truncated.to_vec()
        }
    };

    // Step 2: apply max_bytes truncation on the transfer-decoded bytes.
    // (The identity path already truncated above; this handles Base64/QP.)
    let (truncated_bytes, is_truncated) = match max_bytes {
        Some(n) if decoded.len() > n => (decoded[..n].to_vec(), true),
        Some(_) if b64_input_was_limited => (decoded, true),
        _ => {
            let is_truncated = matches!(
                part.transfer_encoding,
                TransferEncoding::Identity
                    | TransferEncoding::SevenBit
                    | TransferEncoding::EightBit
                    | TransferEncoding::Binary
            ) && max_bytes.is_some_and(|n| length > n);
            (decoded, is_truncated)
        }
    };

    // Step 3: charset conversion to UTF-8 via encoding_rs.
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
}
