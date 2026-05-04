//! Inline UUencode scanner for MIME body parts.
//!
//! # What is inline UUencode?
//!
//! UUencode (Unix-to-Unix encoding) predates MIME by over a decade.  Before
//! MIME standardised `Content-Transfer-Encoding` in 1992, UUencode was the
//! dominant way to send binary attachments over 7-bit text networks (Usenet,
//! early SMTP).  A UU block looks like:
//!
//! ```text
//! begin 644 filename.bin
//! M<encoded data lines>
//! `
//! end
//! ```
//!
//! # Why this appears in practice
//!
//! Many mail archives and mailing-list digests from the 1990s and early 2000s
//! contain messages where binary files were embedded as literal UU blocks
//! inside `text/plain` bodies — no `Content-Transfer-Encoding` header, no
//! MIME multipart wrapper.  Modern mail clients also sometimes produce hybrid
//! messages: a MIME-structured outer shell with an inner `text/plain` part
//! that still contains legacy inline UU attachments.
//!
//! # This module vs. `parse()` / `decode_body_value()`
//!
//! [`parse()`][crate::parse] and [`decode_body_value()`][crate::decode_body_value]
//! handle the RFC 2045 `Content-Transfer-Encoding: x-uuencode` case — a part
//! whose *entire body* is one UU-encoded blob declared via a MIME header.
//!
//! [`scan_inline_uuencode()`] is completely separate and opt-in.  It operates
//! on the raw bytes of a part's body (typically a `text/plain` part) and
//! searches for one or more `begin … end` UU blocks embedded anywhere within
//! the body text.  It does **not** call `parse()` or `decode_body_value()`
//! internally, and it does not modify the [`ParsedPart`][crate::ParsedPart] tree.
//!
//! Callers decide when to invoke this scanner.  A reasonable heuristic is to
//! call it on any `text/plain` leaf part whose decoded text contains the
//! literal string `"begin "`.

use crate::part::ParsedPart;

/// A single UU-encoded binary block found inside a part body.
///
/// All byte offsets are **absolute** — they are in the same coordinate space
/// as `ParsedPart::body_range` and the `raw` buffer passed to
/// [`scan_inline_uuencode()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineUUBlock {
    /// Byte offset of the `begin NNN filename` line within `raw`.
    ///
    /// Slicing `raw[begin_offset .. begin_offset + begin_length]` yields the
    /// complete UU block from the `begin` line through the `end` line
    /// (inclusive).
    pub begin_offset: u32,

    /// Byte length of the entire UU block: from the start of the `begin` line
    /// through the end of the `end` line (inclusive of its newline).
    pub begin_length: u32,

    /// File permission mode parsed from the `begin` line, e.g. `0o644`.
    pub mode: u32,

    /// Filename parsed verbatim from the `begin` line.
    pub filename: String,

    /// Decoded binary content.  Empty if `is_encoding_problem` is true and
    /// no bytes could be decoded, or if the encoded payload was genuinely
    /// empty (backtick-only lines).
    pub data: Vec<u8>,

    /// True if any decoding error was encountered (unknown/malformed line
    /// length byte, wrong number of encoded characters, missing `end` line).
    /// A partial decode may still be present in `data`.
    pub is_encoding_problem: bool,
}

/// Scan a MIME part's body for inline UU-encoded blocks.
///
/// Slices `raw` using `part.body_range` to obtain the body bytes, then scans
/// for one or more `begin NNN filename` / `end` UU blocks embedded anywhere
/// in the body text.  Returns one [`InlineUUBlock`] per block found.
///
/// # Parameters
///
/// * `raw`  — the full raw message bytes (same buffer you passed to
///   [`parse()`][crate::parse]).
/// * `part` — a [`ParsedPart`][crate::ParsedPart] from the parsed tree.
///   Only `part.body_range` is used to locate the relevant slice of `raw`.
///
/// # Return value
///
/// An empty `Vec` when:
/// - the body contains no `begin … end` blocks,
/// - `part.body_range` is out of bounds for `raw`.
///
/// Otherwise, one entry per block found, in the order they appear in the body.
///
/// # Notes
///
/// * This function does **not** call `decode_body_value()` internally.  It
///   works directly on the raw bytes of the body without any
///   transfer-encoding decode or charset conversion.
/// * Byte offsets in the returned [`InlineUUBlock`]s are absolute — they are
///   relative to the start of `raw`, matching the coordinate space of
///   `part.body_range`.
/// * No panic occurs on any input (malformed, truncated, or adversarial).
///
/// # Example
///
/// ```rust
/// use mime_tree::{parse, scan_inline_uuencode};
///
/// // A text/plain message with an inline UU block.
/// // Oracle: Python `binascii.b2a_uu(b"Hello")` == b'%2&5L;&\\ \n'
/// let raw: &[u8] = b"Content-Type: text/plain\r\n\r\nbegin 644 hello.txt\n%2&5L;&\\ \nend\n";
/// let msg = parse(raw).unwrap();
/// let part = msg.part_index.find_by_id("1").unwrap();
///
/// let blocks = scan_inline_uuencode(raw, part);
/// assert_eq!(blocks.len(), 1);
/// assert_eq!(blocks[0].mode, 0o644);
/// assert_eq!(blocks[0].filename, "hello.txt");
/// assert_eq!(blocks[0].data, b"Hello");
/// assert!(!blocks[0].is_encoding_problem);
/// ```
pub fn scan_inline_uuencode(raw: &[u8], part: &ParsedPart) -> Vec<InlineUUBlock> {
    let (offset_u32, length_u32) = part.body_range;
    let offset = offset_u32 as usize;
    let length = length_u32 as usize;

    // Defensive: body_range out of bounds → empty result, no panic.
    let end = match offset.checked_add(length) {
        Some(e) if e <= raw.len() => e,
        _ => return Vec::new(),
    };
    let body = &raw[offset..end];

    scan_body(body, offset_u32)
}

/// Core scanner: operates on a body slice and returns blocks with absolute
/// offsets (body_base_offset added to every relative position).
fn scan_body(body: &[u8], body_base_offset: u32) -> Vec<InlineUUBlock> {
    let mut blocks = Vec::new();
    let mut pos = 0usize;

    while pos < body.len() {
        // Find next line.
        let line_start = pos;
        let line_end = next_line_end(body, pos);
        let line = &body[line_start..line_end];
        pos = line_end;

        // Try to parse a "begin NNN filename" line.
        if let Some((mode, filename)) = parse_begin_line(line) {
            let block_start_abs =
                body_base_offset.saturating_add(u32::try_from(line_start).unwrap_or(u32::MAX));

            // Decode the UU data lines until "end" or end of body.
            let (data, is_encoding_problem, block_body_end_rel) = decode_uu_block(body, pos);

            // block_body_end_rel is the position in body after consuming through 'end\n'
            // (or end of body if 'end' was missing).
            let block_end = block_body_end_rel;
            pos = block_end;

            // begin_length: from start of 'begin' line to end of 'end' line.
            let block_len_usize = block_end.saturating_sub(line_start);
            let block_len = u32::try_from(block_len_usize).unwrap_or(u32::MAX);

            blocks.push(InlineUUBlock {
                begin_offset: block_start_abs,
                begin_length: block_len,
                mode,
                filename,
                data,
                is_encoding_problem,
            });
        }
        // else: not a begin line, advance to next line (pos already advanced above)
    }

    blocks
}

/// Decode UU data lines starting at `pos` within `body`.
///
/// Returns `(decoded_bytes, is_encoding_problem, new_pos)` where `new_pos`
/// is the position in `body` after consuming through the `end` line (or end
/// of body if no `end` was found).
fn decode_uu_block(body: &[u8], start_pos: usize) -> (Vec<u8>, bool, usize) {
    let mut data: Vec<u8> = Vec::new();
    let mut is_encoding_problem = false;
    let mut pos = start_pos;
    let mut found_end = false;

    while pos < body.len() {
        let line_start = pos;
        let line_end = next_line_end(body, pos);
        let raw_line = &body[line_start..line_end];
        pos = line_end;

        // Strip CRLF and trailing spaces/tabs.
        let line = strip_line_endings(raw_line);

        // Empty line: skip (shouldn't happen normally but be defensive).
        if line.is_empty() {
            continue;
        }

        // Check for "end" terminator.
        if line == b"end" {
            found_end = true;
            break;
        }

        // Check for backtick-only line (empty data marker, may precede "end").
        if line == b"`" {
            // This is a valid zero-length data line; continue to look for "end".
            continue;
        }

        // Decode a UU data line.
        // First byte: length field.
        let length_char = line[0];
        let byte_count = ((length_char as u32).wrapping_sub(32)) & 0x3F;

        if byte_count == 0 {
            // Zero-length line (space or backtick as length byte); continue looking for "end".
            continue;
        }

        let encoded = &line[1..];

        // Decode groups of 4 characters → 3 bytes.
        let mut decoded_line: Vec<u8> = Vec::with_capacity(byte_count as usize);
        let mut i = 0usize;

        // We process ceil(byte_count / 3) groups of 4 encoded chars.
        let groups_needed = (byte_count as usize).div_ceil(3);

        for _ in 0..groups_needed {
            // Read up to 4 chars, padding with 0x20 (space = 0) if the line is short.
            let c0 = encoded_val(encoded, i);
            let c1 = encoded_val(encoded, i + 1);
            let c2 = encoded_val(encoded, i + 2);
            let c3 = encoded_val(encoded, i + 3);
            i += 4;

            decoded_line.push((c0 << 2) | (c1 >> 4));
            decoded_line.push(((c1 & 0x0F) << 4) | (c2 >> 2));
            decoded_line.push(((c2 & 0x03) << 6) | c3);
        }

        // Truncate to the declared byte_count.
        decoded_line.truncate(byte_count as usize);

        // Validate: encoded must have enough characters to cover byte_count bytes.
        // Each group of 4 encoded chars yields 3 decoded bytes.  The last group
        // may have trailing spaces stripped (they encode as 0), so we only need
        // enough chars to cover the first ceil(byte_count/3)-1 full groups plus
        // at least 1 char from the final group.
        //
        // Minimum encoded chars needed = (byte_count - 1) / 3 * 4 + 1
        // (We need at least 1 char from the last group to decode the first byte of it.)
        let min_encoded_len = if byte_count == 0 {
            0
        } else {
            ((byte_count as usize - 1) / 3) * 4 + 1
        };
        if encoded.len() < min_encoded_len {
            is_encoding_problem = true;
        }

        data.extend_from_slice(&decoded_line);
    }

    if !found_end {
        is_encoding_problem = true;
    }

    (data, is_encoding_problem, pos)
}

/// Return the 6-bit UU value for the character at `encoded[idx]`,
/// or 0 if `idx` is out of bounds (padding).
#[inline]
fn encoded_val(encoded: &[u8], idx: usize) -> u8 {
    if idx < encoded.len() {
        ((encoded[idx] as u32).wrapping_sub(32) & 0x3F) as u8
    } else {
        0
    }
}

/// Return the end position of the current line (past the newline character(s)).
///
/// Handles both `\n` and `\r\n`.  If no newline is found, returns `body.len()`
/// (the line runs to end of body).
fn next_line_end(body: &[u8], start: usize) -> usize {
    let slice = &body[start..];
    if let Some(nl) = slice.iter().position(|&b| b == b'\n') {
        start + nl + 1
    } else {
        body.len()
    }
}

/// Strip trailing `\r`, `\n`, space, and tab from a raw line slice.
fn strip_line_endings(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\r' | b'\n' | b' ' | b'\t') {
        end -= 1;
    }
    &line[..end]
}

/// Parse a `begin NNN filename` line.
///
/// Returns `Some((mode, filename))` on success, `None` if the line is not a
/// valid begin line.
///
/// The mode must be 1–4 octal digits.  The filename may contain spaces.
fn parse_begin_line(line: &[u8]) -> Option<(u32, String)> {
    // Strip trailing CRLF/spaces for comparison.
    let line = strip_line_endings(line);

    // Must start with "begin ".
    let rest = line.strip_prefix(b"begin ")?;

    // Parse octal mode: one or more octal digits followed by a space.
    let space_pos = rest.iter().position(|&b| b == b' ')?;
    let mode_bytes = &rest[..space_pos];
    if mode_bytes.is_empty() || mode_bytes.len() > 7 {
        return None;
    }
    // All mode bytes must be ASCII octal digits.
    if !mode_bytes.iter().all(|&b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    let mode_str = std::str::from_utf8(mode_bytes).ok()?;
    let mode = u32::from_str_radix(mode_str, 8).ok()?;

    // Everything after the space is the filename (may contain spaces).
    let filename_bytes = &rest[space_pos + 1..];
    if filename_bytes.is_empty() {
        return None;
    }
    let filename = String::from_utf8_lossy(filename_bytes).into_owned();

    Some((mode, filename))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part::{ParsedPart, TransferEncoding};

    /// Build a synthetic raw buffer: `prefix || body_bytes`, returning the
    /// buffer and a `ParsedPart` whose `body_range` points at `body_bytes`.
    fn make_part(prefix: &[u8], body_bytes: &[u8]) -> (Vec<u8>, ParsedPart) {
        let mut raw = prefix.to_vec();
        let body_offset = raw.len();
        raw.extend_from_slice(body_bytes);

        let part = ParsedPart {
            part_id: "1".to_owned(),
            content_type: "text/plain".to_owned(),
            charset: Some("utf-8".to_owned()),
            transfer_encoding: TransferEncoding::Identity,
            disposition: None,
            filename: None,
            cid: None,
            header_range: (0u32, body_offset as u32),
            body_range: (body_offset as u32, body_bytes.len() as u32),
            children: vec![],
            is_encoding_problem: false,
        };
        (raw, part)
    }

    // -----------------------------------------------------------------------
    // TV1: single block, "Hello"
    // Oracle: python3 -c "import binascii; print(binascii.b2a_uu(b'Hello'))"
    // -> b'%2&5L;&\\ \n'
    // -----------------------------------------------------------------------
    #[test]
    fn test_single_block_hello() {
        // body hex: 626567696e203634342068656c6c6f2e7478740a253226354c3b265c200a656e640a
        let body =
            hex_bytes("626567696e203634342068656c6c6f2e7478740a253226354c3b265c200a656e640a");
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 1, "expected 1 block");

        let b = &blocks[0];
        assert_eq!(b.mode, 0o644);
        assert_eq!(b.filename, "hello.txt");
        // expected decoded: 48656c6c6f = "Hello"
        assert_eq!(b.data, hex_bytes("48656c6c6f"));
        assert!(!b.is_encoding_problem);
        // begin_offset = 0 (no prefix), begin_length = body.len() = 34
        assert_eq!(b.begin_offset, 0);
        assert_eq!(b.begin_length, body.len() as u32);
        // Verify by slicing raw
        let sliced = &raw[b.begin_offset as usize..(b.begin_offset + b.begin_length) as usize];
        assert_eq!(sliced, body.as_slice());
    }

    // -----------------------------------------------------------------------
    // TV2: two blocks with interleaved text
    // Oracle: python3 -c "import binascii; print(binascii.b2a_uu(b'The quick brown fox'))"
    // -> b'3 5&AE(\'%U:6-K(&)R;W=N(&9O>  \n'  (no, let's use the generated hex)
    // -----------------------------------------------------------------------
    #[test]
    fn test_two_blocks() {
        // full_body_hex from oracle output
        let body = hex_bytes(
            "626567696e203634342068656c6c6f2e7478740a253226354c3b265c200a656e\
             640a536f6d65207465787420696e206265747765656e0a626567696e20363030\
             20666f782e62696e0a3335264145282725553a362d4b282629523b573d4e2826\
             394f3e2020200a656e640a",
        );
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 2, "expected 2 blocks");

        let b0 = &blocks[0];
        assert_eq!(b0.mode, 0o644);
        assert_eq!(b0.filename, "hello.txt");
        assert_eq!(b0.data, hex_bytes("48656c6c6f")); // "Hello"
        assert!(!b0.is_encoding_problem);
        assert_eq!(b0.begin_offset, 0);
        assert_eq!(b0.begin_length, 34);

        let b1 = &blocks[1];
        assert_eq!(b1.mode, 0o600);
        assert_eq!(b1.filename, "fox.bin");
        assert_eq!(
            b1.data,
            hex_bytes("54686520717569636b2062726f776e20666f78") // "The quick brown fox"
        );
        assert!(!b1.is_encoding_problem);
        // block2 starts at offset 55 (34 + len("Some text in between\n") = 34+21=55)
        assert_eq!(b1.begin_offset, 55);
        assert_eq!(b1.begin_length, 52);

        // Verify slices
        let s0 = &raw[b0.begin_offset as usize..(b0.begin_offset + b0.begin_length) as usize];
        let s1 = &raw[b1.begin_offset as usize..(b1.begin_offset + b1.begin_length) as usize];
        // s0 should start with "begin 644 hello.txt\n"
        assert!(s0.starts_with(b"begin 644 hello.txt\n"));
        assert!(s0.ends_with(b"end\n"));
        // s1 should start with "begin 600 fox.bin\n"
        assert!(s1.starts_with(b"begin 600 fox.bin\n"));
        assert!(s1.ends_with(b"end\n"));
    }

    // -----------------------------------------------------------------------
    // TV2b: two blocks, absolute offsets with non-zero body_range
    // -----------------------------------------------------------------------
    #[test]
    fn test_two_blocks_with_prefix_offset() {
        let body = hex_bytes(
            "626567696e203634342068656c6c6f2e7478740a253226354c3b265c200a656e\
             640a536f6d65207465787420696e206265747765656e0a626567696e20363030\
             20666f782e62696e0a3335264145282725553a362d4b282629523b573d4e2826\
             394f3e2020200a656e640a",
        );
        let prefix = b"Content-Type: text/plain\r\n\r\n"; // 28 bytes
        let (raw, part) = make_part(prefix, &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 2);

        // Absolute offsets = prefix_len + relative_offset
        assert_eq!(blocks[0].begin_offset, 28);
        assert_eq!(blocks[1].begin_offset, 28 + 55);

        // Verify by slicing raw with absolute offsets
        for b in &blocks {
            let sliced = &raw[b.begin_offset as usize..(b.begin_offset + b.begin_length) as usize];
            assert!(sliced.starts_with(b"begin "));
            assert!(sliced.ends_with(b"end\n"));
        }
    }

    // -----------------------------------------------------------------------
    // TV3: missing 'end' line → is_encoding_problem = true
    // -----------------------------------------------------------------------
    #[test]
    fn test_missing_end_line() {
        // body_hex: "begin 644 test.txt\n" + UU line for Hello, no "end\n"
        let body = hex_bytes("626567696e2036343420746573742e7478740a253226354c3b265c200a");
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 1, "block still found even without end");
        assert!(
            blocks[0].is_encoding_problem,
            "missing end must set is_encoding_problem"
        );
    }

    // -----------------------------------------------------------------------
    // TV4: 45 bytes decoded from one full UU line (all bytes 0x00..0x2c)
    // Oracle: python3 -c "import binascii; print(binascii.b2a_uu(bytes(range(45))))"
    // -----------------------------------------------------------------------
    #[test]
    fn test_full_line_45_bytes() {
        // body_hex from oracle output
        let body = hex_bytes(
            "626567696e2036343420616c6c62797465732e62696e0a4d20202422205030\
             2521403c282230482b2320542e2351203124412c34253138372621443a2651\
             503d27415c402832284329223446295240492a424c4c0a656e640a",
        );
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].mode, 0o644);
        assert_eq!(blocks[0].filename, "allbytes.bin");
        assert_eq!(
            blocks[0].data,
            hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c")
        );
        assert!(!blocks[0].is_encoding_problem);
    }

    // -----------------------------------------------------------------------
    // TV5: backtick-terminated empty block (empty data)
    // -----------------------------------------------------------------------
    #[test]
    fn test_backtick_empty_block() {
        // body_hex: "begin 755 empty.bin\n`\nend\n"
        let body = hex_bytes("626567696e2037353520656d7074792e62696e0a600a656e640a");
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].mode, 0o755);
        assert_eq!(blocks[0].filename, "empty.bin");
        assert!(blocks[0].data.is_empty(), "expected empty data");
        assert!(!blocks[0].is_encoding_problem);
    }

    // -----------------------------------------------------------------------
    // TV6: multi-line block
    // Oracle: python3 -c "import binascii; d=b'Hello, World! ...' (74 bytes); ..."
    // -----------------------------------------------------------------------
    #[test]
    fn test_multiline_block() {
        let body = hex_bytes(
            "626567696e20363434206d756c74696c696e652e7478740a4d3226354c3b265c\
             4c28253d4f3c465144283221343a26455328264553282624403d263553\
             3d22214f3942214d3d3651543a32554c3a365945282535350a3d282635\
             4e38565d443a3659472b422121392631493b463c403b365d52393221\
             423e3731453c5258200a656e640a",
        );
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].mode, 0o644);
        assert_eq!(blocks[0].filename, "multiline.txt");
        assert_eq!(
            blocks[0].data,
            hex_bytes("48656c6c6f2c20576f726c6421205468697320697320612074657374206f66206d756c74692d6c696e6520555520656e636f64696e672e20416464696e67206d6f72652062797465732e")
        );
        assert!(!blocks[0].is_encoding_problem);
    }

    // -----------------------------------------------------------------------
    // No UU blocks → empty Vec
    // -----------------------------------------------------------------------
    #[test]
    fn test_no_uu_blocks() {
        let body = b"This is just plain text.\nNo UU blocks here.\n";
        let (raw, part) = make_part(b"", body);
        let blocks = scan_inline_uuencode(&raw, &part);
        assert!(blocks.is_empty());
    }

    // -----------------------------------------------------------------------
    // Out-of-bounds body_range → empty Vec
    // -----------------------------------------------------------------------
    #[test]
    fn test_out_of_bounds_body_range() {
        let raw = b"short";
        let part = ParsedPart {
            part_id: "1".to_owned(),
            content_type: "text/plain".to_owned(),
            charset: None,
            transfer_encoding: TransferEncoding::Identity,
            disposition: None,
            filename: None,
            cid: None,
            header_range: (0, 0),
            body_range: (3, 100), // end = 103, beyond raw.len() = 5
            children: vec![],
            is_encoding_problem: false,
        };
        let blocks = scan_inline_uuencode(raw, &part);
        assert!(
            blocks.is_empty(),
            "out-of-bounds body_range must return empty Vec"
        );
    }

    // -----------------------------------------------------------------------
    // Overflow-safe body_range (offset + length wraps u32)
    // -----------------------------------------------------------------------
    #[test]
    fn test_overflow_safe_body_range() {
        let raw = b"data";
        let part = ParsedPart {
            part_id: "1".to_owned(),
            content_type: "text/plain".to_owned(),
            charset: None,
            transfer_encoding: TransferEncoding::Identity,
            disposition: None,
            filename: None,
            cid: None,
            header_range: (0, 0),
            body_range: (u32::MAX, 1), // wraps on usize add
            children: vec![],
            is_encoding_problem: false,
        };
        let blocks = scan_inline_uuencode(raw, &part);
        assert!(
            blocks.is_empty(),
            "overflowing body_range must return empty Vec"
        );
    }

    // -----------------------------------------------------------------------
    // Helper: decode a hex string to bytes.
    // -----------------------------------------------------------------------
    fn hex_bytes(s: &str) -> Vec<u8> {
        // Strip any whitespace (allows multi-line hex literals in tests).
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
