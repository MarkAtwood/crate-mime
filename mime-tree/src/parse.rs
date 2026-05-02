use mail_parser::{Encoding, Message, MessageParser, MessagePart, MimeHeaders, PartType};

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
    let preview = body.text_body.first().and_then(|id| {
        let part = part_index.find_by_id(id)?;
        let decoded = crate::decode::decode_body_value(raw, part, Some(256)).ok()?;
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
/// Transfer-encoding decode and charset conversion are performed on demand.
/// See [`crate::decode::decode_body_value`] for the full algorithm.
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
/// Each header's raw value bytes are sliced from `raw` using the offsets
/// stored by mail-parser, then decoded as lossy UTF-8 and trimmed.
fn extract_headers(part: &MessagePart<'_>, raw: &[u8]) -> Vec<ParsedHeader> {
    part.headers
        .iter()
        .map(|h| {
            let name = h.name.as_str().to_owned();
            let value = raw
                .get(h.offset_start as usize..h.offset_end as usize)
                .map(|bytes| String::from_utf8_lossy(bytes).trim().to_owned())
                .unwrap_or_default();
            ParsedHeader { name, value }
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

    let no_content_type = part.content_type().is_none();
    let content_type = part
        .content_type()
        .map(|ct| {
            let subtype = ct.subtype().unwrap_or("plain");
            format!("{}/{}", ct.ctype(), subtype)
        })
        .unwrap_or_else(|| "text/plain".to_owned());

    let charset = part
        .content_type()
        .and_then(|ct| ct.attribute("charset"))
        .map(str::to_owned)
        .or_else(|| {
            if no_content_type {
                Some("us-ascii".to_owned())
            } else {
                None
            }
        });

    let transfer_encoding = map_encoding(part);

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
fn map_encoding(part: &MessagePart<'_>) -> TransferEncoding {
    match part.encoding {
        Encoding::Base64 => TransferEncoding::Base64,
        Encoding::QuotedPrintable => TransferEncoding::QuotedPrintable,
        Encoding::None => {
            // Check the raw CTE header string for 7bit / 8bit / binary.
            match part.content_transfer_encoding() {
                Some(s) if s.eq_ignore_ascii_case("7bit") => TransferEncoding::SevenBit,
                Some(s) if s.eq_ignore_ascii_case("8bit") => TransferEncoding::EightBit,
                Some(s) if s.eq_ignore_ascii_case("binary") => TransferEncoding::Binary,
                _ => TransferEncoding::Identity,
            }
        }
    }
}
