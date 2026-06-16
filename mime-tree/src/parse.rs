use mail_parser::{
    Encoding, HeaderValue, Message, MessageParser, MessagePart, MimeHeaders, PartType,
};

use crate::{
    error::ParseError,
    message::{DecodedBodyValue, ParsedMessage},
    part::{ParsedHeader, ParsedPart, TransferEncoding},
    walk,
};

/// Parse raw RFC 5322 bytes into a `ParsedMessage`.
///
/// Returns `Err(ParseError::EmptyInput)` for empty input and
/// `Err(ParseError::NoHeaders)` when mail-parser cannot find any headers.
/// All other malformed input produces a best-effort `ParsedMessage` with
/// `warnings` populated.
#[must_use = "the parsed message must be used"]
pub fn parse(raw: &[u8]) -> Result<ParsedMessage, ParseError> {
    if raw.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    let message = MessageParser::default()
        .parse(raw)
        .ok_or(ParseError::NoHeaders)?;

    let mut warnings: Vec<String> = Vec::new();

    // Extract top-level headers from parts[0].
    let headers = message
        .parts
        .first()
        .map(|p| extract_headers(p, raw))
        .unwrap_or_default();

    // Build the part tree.
    let part_index = build_root(&message, 0, &mut warnings).ok_or(ParseError::NoHeaders)?;

    // Compute RFC 8621 §4.1.4 body-view lists from the parsed part tree.
    let body = walk::compute_body_structure(&part_index);

    // Compute preview: first 256 decoded characters from the first text_body part.
    // We decode up to 1024 bytes (not 256) because worst-case UTF-8 uses 4 bytes
    // per character, so 1024 bytes guarantees at least 256 characters.
    let preview = body.text_body.first().and_then(|id| {
        let part = part_index.find_by_id(id)?;
        let decoded = crate::decode::decode_body_value(raw, part, Some(1024)).ok()?;
        let s: String = decoded.value.chars().take(256).collect();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    });

    Ok(ParsedMessage {
        part_index,
        text_body: body.text_body,
        html_body: body.html_body,
        attachments: body.attachments,
        headers,
        preview,
        warnings,
    })
}

/// Decode the body of a parsed part.
///
/// Slices `raw[part.body_range]`, applies transfer-encoding decode
/// (Base64, QP, UUencode, or identity), then charset-converts the
/// result to UTF-8.
///
/// # `max_bytes`
///
/// * `None` — decode the full body.  There is no implicit size limit.
/// * `Some(n)` — decode at most `n` bytes of the **transfer-decoded**
///   output.  [`DecodedBodyValue::is_truncated`] is set to `true` when
///   the full body exceeds this limit.  The truncation point may fall
///   mid-codepoint after charset conversion, in which case
///   [`DecodedBodyValue::is_encoding_problem`] is also set.
///
/// # Errors
///
/// Returns [`ParseError::InvalidRange`] when `part.body_range` is out
/// of bounds for `raw`.
#[must_use = "the decoded body value must be used"]
pub fn decode_body_value(
    raw: &[u8],
    part: &ParsedPart,
    max_bytes: Option<usize>,
) -> Result<DecodedBodyValue, ParseError> {
    crate::decode::decode_body_value(raw, part, max_bytes)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract `ParsedHeader` values from a part's header list.
///
/// For headers whose value mail-parser parses as plain text (Subject,
/// Comments, Content-Description, and any unstructured header), the decoded
/// string from `h.value` is used directly.  mail-parser decodes RFC 2047
/// encoded-words during its own parse phase, so the `Text` variant already
/// contains the final Unicode string.
///
/// For headers whose value is a `TextList` (e.g. References, Keywords), the
/// list elements are joined with ", " after trimming each item.
///
/// For all other header types (Address, DateTime, ContentType, Received) the
/// raw bytes are sliced from `raw` as before, because those values are not
/// encoded-word fields and the structured `HeaderValue` variants would require
/// lossy reconstruction.
fn extract_headers(part: &MessagePart<'_>, raw: &[u8]) -> Vec<ParsedHeader> {
    part.headers
        .iter()
        .map(|h| {
            let name = h.name.as_str().to_owned();

            // Always capture the raw bytes of the header field value from the
            // original message. These bytes are faithful to the wire format
            // and preserve non-UTF-8 bytes that `from_utf8_lossy` would
            // replace with U+FFFD.
            let raw_value = raw
                .get(h.offset_start as usize..h.offset_end as usize)
                .unwrap_or_default()
                .to_vec();

            let value = match &h.value {
                // mail-parser has already decoded any RFC 2047 encoded-words
                // into this Cow<str>; use it directly.
                HeaderValue::Text(s) => s.as_ref().trim().to_owned(),
                // TextList: join with comma+space (e.g. References, Keywords).
                HeaderValue::TextList(list) => list
                    .iter()
                    .map(|s| s.as_ref().trim())
                    .collect::<Vec<_>>()
                    .join(", "),
                // All other variants (Address, DateTime, ContentType, Received,
                // Empty): fall back to lossy UTF-8 for the `value` string.
                _ => String::from_utf8_lossy(raw_value.trim_ascii()).into_owned(),
            };
            ParsedHeader {
                name,
                value,
                raw_value,
            }
        })
        .collect()
}

/// Build a `ParsedPart` for `parts[part_idx]`, assigning it the given `part_id`.
///
/// Returns `None` when `part_idx` is out of range in `message.parts`; the
/// caller logs a warning and skips the missing child.
///
/// For the root call (part_idx = 0) we use the dedicated `build_root` entry
/// point which handles the special IMAP ID assignment for the root part.
fn build_part(
    message: &Message<'_>,
    part_idx: u32,
    part_id: String,
    warnings: &mut Vec<String>,
) -> Option<ParsedPart> {
    let part = match message.parts.get(part_idx as usize) {
        Some(p) => p,
        None => {
            warnings.push(format!("part {part_id}: index {part_idx} out of range"));
            return None;
        }
    };

    if part.is_encoding_problem {
        warnings.push(format!("part {part_id}: encoding problem"));
    }

    let header_range = (
        part.offset_header,
        part.offset_body.saturating_sub(part.offset_header),
    );
    let body_range = (
        part.offset_body,
        part.offset_end.saturating_sub(part.offset_body),
    );

    let raw_ct = part.content_type();
    let content_type = raw_ct
        .map(|ct| {
            let subtype = ct.subtype().unwrap_or("plain");
            format!("{}/{}", ct.ctype(), subtype)
        })
        .unwrap_or_else(|| "text/plain".to_owned());

    let charset = raw_ct
        .and_then(|ct| ct.attribute("charset"))
        .map(str::to_owned)
        .or_else(|| {
            if raw_ct.is_none() {
                Some("us-ascii".to_owned())
            } else {
                None
            }
        });

    let transfer_encoding = map_encoding(part, warnings);

    let disposition = part.content_disposition().map(|cd| cd.ctype().to_owned());

    let filename = part.attachment_name().map(str::to_owned);

    let cid = part.content_id().map(str::to_owned);

    let children = match &part.body {
        PartType::Multipart(child_ids) => child_ids
            .iter()
            .enumerate()
            .filter_map(|(n, &child_idx)| {
                let child_id = if part_id.is_empty() {
                    (n + 1).to_string()
                } else {
                    format!("{}.{}", part_id, n + 1)
                };
                build_part(message, child_idx, child_id, warnings)
            })
            .collect(),
        PartType::Message(_nested) => {
            // message/rfc822 is intentionally treated as an opaque leaf.
            // Its raw bytes are accessible via body_range; callers that need
            // the inner structure should pass those bytes to parse() themselves.
            // See crate invariant: callers handle recursion, not this crate.
            vec![]
        }
        _ => vec![],
    };

    Some(ParsedPart {
        part_id,
        content_type,
        charset,
        transfer_encoding,
        disposition,
        filename,
        cid,
        header_range,
        body_range,
        children,
        is_encoding_problem: part.is_encoding_problem,
    })
}

/// Entry point for the root part (parts[0]).
///
/// Returns `None` when `parts[part_idx]` does not exist.
///
/// IMAP part-ID rules:
/// - If the root is multipart, it acts as an envelope container; its body
///   children receive IDs `"1"`, `"2"`, ... and the root itself gets `""`.
/// - If the root is a single-part leaf (or a nested `message/rfc822`), the
///   body is accessible as `"1"`.
fn build_root(
    message: &Message<'_>,
    part_idx: u32,
    warnings: &mut Vec<String>,
) -> Option<ParsedPart> {
    let is_multipart = message
        .parts
        .get(part_idx as usize)
        .is_some_and(|p| matches!(p.body, PartType::Multipart(_)));

    let root_id = if is_multipart {
        String::new()
    } else {
        "1".to_owned()
    };

    build_part(message, part_idx, root_id, warnings)
}

/// Map a mail-parser `Encoding` (and optional CTE string) to `TransferEncoding`.
///
/// Pushes a warning to `warnings` when the CTE token is non-empty and not one
/// of the values recognised by this crate.  RFC 2045 §6.4 permits x-token
/// CTE values; the conventional UUencode spellings are handled explicitly and
/// do not produce a warning.
fn map_encoding(part: &MessagePart<'_>, warnings: &mut Vec<String>) -> TransferEncoding {
    match part.encoding {
        Encoding::Base64 => TransferEncoding::Base64,
        Encoding::QuotedPrintable => TransferEncoding::QuotedPrintable,
        Encoding::None => {
            // Check the raw CTE header string for well-known values.
            match part.content_transfer_encoding() {
                Some(s) if s.eq_ignore_ascii_case("7bit") => TransferEncoding::SevenBit,
                Some(s) if s.eq_ignore_ascii_case("8bit") => TransferEncoding::EightBit,
                Some(s) if s.eq_ignore_ascii_case("binary") => TransferEncoding::Binary,
                Some(s)
                    if s.eq_ignore_ascii_case("x-uuencode")
                        || s.eq_ignore_ascii_case("x-uue")
                        || s.eq_ignore_ascii_case("uuencode") =>
                {
                    TransferEncoding::UUEncode
                }
                Some(s) if !s.is_empty() => {
                    warnings.push(format!("Unknown Content-Transfer-Encoding: {s}"));
                    TransferEncoding::Identity
                }
                _ => TransferEncoding::Identity,
            }
        }
    }
}
