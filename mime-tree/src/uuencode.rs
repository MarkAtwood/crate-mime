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
    /// length byte, wrong number of encoded characters, missing `end` line,
    /// or a `begin-base64` block was detected).
    /// A partial decode may still be present in `data`.
    pub is_encoding_problem: bool,
}

/// Scan a MIME part's body for inline UU-encoded blocks.
///
/// Slices `raw` using `part.body_range` to obtain the body bytes, then scans
/// for one or more `begin NNN filename` / `end` UU blocks embedded anywhere
/// in the body text.  Returns one [`InlineUUBlock`] per block found.
///
/// Delegates to [`uuencoding::scan()`] for all parsing and decoding, so all
/// real-world tolerance built into that crate (CRLF line endings, space/backtick
/// zero-value handling, `begin-base64` detection, data-after-terminator
/// discarding, etc.) applies automatically.
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
/// // Oracle (Python 3.12 `uu` module):
/// //   uu.encode(b"Hello", ...) → b'begin 644 hello.txt\n%2&5L;&\\ \n \nend\n'
/// let raw: &[u8] = b"Content-Type: text/plain\r\n\r\nbegin 644 hello.txt\n%2&5L;&\\ \n \nend\n";
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

    uuencoding::scan(body)
        .map(|result| match result {
            Ok(block) => {
                // Convert relative-to-body usize offsets to absolute u32 offsets.
                let abs_begin = offset_u32
                    .saturating_add(u32::try_from(block.begin_offset).unwrap_or(u32::MAX));
                let block_len = u32::try_from(block.end_offset.saturating_sub(block.begin_offset))
                    .unwrap_or(u32::MAX);
                InlineUUBlock {
                    begin_offset: abs_begin,
                    begin_length: block_len,
                    mode: block.metadata.mode,
                    filename: block.metadata.filename,
                    data: block.data,
                    is_encoding_problem: block.is_truncated,
                }
            }
            Err(_) => {
                // UuError::BeginBase64 or UuError::InvalidBeginLine.
                // We have no offset info from an error item, so we emit a
                // zero-offset sentinel with is_encoding_problem=true and no data.
                // In practice scan() does not emit Err items for blocks that
                // were successfully located — only for begin-base64 or
                // completely unrecognised begin lines.
                InlineUUBlock {
                    begin_offset: 0,
                    begin_length: 0,
                    mode: 0,
                    filename: String::new(),
                    data: Vec::new(),
                    is_encoding_problem: true,
                }
            }
        })
        .collect()
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
    // Oracle (Python 3.12 `uu` module):
    //   uu.encode(io.BytesIO(b'Hello'), buf, 'hello.txt', 0o644)
    //   → b'begin 644 hello.txt\n%2&5L;&\\ \n \nend\n'
    // -----------------------------------------------------------------------
    #[test]
    fn test_single_block_hello() {
        // body hex: begin 644 hello.txt\n%2&5L;&\\ \n \nend\n
        let body =
            hex_bytes("626567696e203634342068656c6c6f2e7478740a253226354c3b265c200a200a656e640a");
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 1, "expected 1 block");

        let b = &blocks[0];
        assert_eq!(b.mode, 0o644);
        assert_eq!(b.filename, "hello.txt");
        // expected decoded: 48656c6c6f = "Hello"
        assert_eq!(b.data, hex_bytes("48656c6c6f"));
        assert!(!b.is_encoding_problem);
        // begin_offset = 0 (no prefix), begin_length = body.len() = 36
        assert_eq!(b.begin_offset, 0);
        assert_eq!(b.begin_length, body.len() as u32);
        // Verify by slicing raw
        let sliced = &raw[b.begin_offset as usize..(b.begin_offset + b.begin_length) as usize];
        assert_eq!(sliced, body.as_slice());
    }

    // -----------------------------------------------------------------------
    // TV2: two blocks with interleaved text
    // Oracle (Python 3.12 `uu` module):
    //   hello = uu.encode(b'Hello', 'hello.txt', 0o644)
    //           → b'begin 644 hello.txt\n%2&5L;&\\ \n \nend\n'  (36 bytes)
    //   fox   = uu.encode(b'The quick brown fox', 'fox.bin', 0o600)
    //           → b"begin 600 fox.bin\n35&AE('%U:6-K(&)R;W=N(&9O>   \n \nend\n"  (54 bytes)
    //   interleaved = hello + b'Some text in between\n' + fox
    //   fox offset = 36 + 21 = 57
    // -----------------------------------------------------------------------
    #[test]
    fn test_two_blocks() {
        // full_body_hex from oracle output (hello 36 bytes + "Some text in between\n" 21 bytes + fox 54 bytes = 111 bytes)
        let body = hex_bytes(
            "626567696e203634342068656c6c6f2e7478740a253226354c3b265c200a200a656e64\
             0a536f6d65207465787420696e206265747765656e0a626567696e2036303020666f78\
             2e62696e0a3335264145282725553a362d4b282629523b573d4e2826394f3e2020200a\
             200a656e640a",
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
        assert_eq!(b0.begin_length, 36); // 36-byte block with terminator

        let b1 = &blocks[1];
        assert_eq!(b1.mode, 0o600);
        assert_eq!(b1.filename, "fox.bin");
        assert_eq!(
            b1.data,
            hex_bytes("54686520717569636b2062726f776e20666f78") // "The quick brown fox"
        );
        assert!(!b1.is_encoding_problem);
        // block2 starts at offset 57 (36 + len("Some text in between\n") = 36+21=57)
        assert_eq!(b1.begin_offset, 57);
        assert_eq!(b1.begin_length, 54); // 54-byte fox block with terminator

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
            "626567696e203634342068656c6c6f2e7478740a253226354c3b265c200a200a656e64\
             0a536f6d65207465787420696e206265747765656e0a626567696e2036303020666f78\
             2e62696e0a3335264145282725553a362d4b282629523b573d4e2826394f3e2020200a\
             200a656e640a",
        );
        let prefix = b"Content-Type: text/plain\r\n\r\n"; // 28 bytes
        let (raw, part) = make_part(prefix, &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 2);

        // Absolute offsets = prefix_len + relative_offset
        assert_eq!(blocks[0].begin_offset, 28);
        assert_eq!(blocks[1].begin_offset, 28 + 57); // fox starts at 57 in body

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
    // Oracle (Python 3.12 `uu` module):
    //   uu.encode(io.BytesIO(bytes(range(45))), buf, 'allbytes.bin', 0o644)
    //   → b'begin 644 allbytes.bin\nM  $" P0%!@...Ll\n \nend\n'
    // -----------------------------------------------------------------------
    #[test]
    fn test_full_line_45_bytes() {
        // body_hex from oracle output (includes ' \n' terminator before end)
        let body = hex_bytes(
            "626567696e2036343420616c6c62797465732e62696e0a4d202024222050302521\
             403c282230482b2320542e2351203124412c34253138372621443a2651503d27\
             415c402832284329223446295240492a424c4c0a200a656e640a",
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
    // Oracle (Python 3.12 `uu` module):
    //   data = b'Hello, World! This is a test of multi-line UU encoding. Adding more bytes.'
    //   uu.encode(io.BytesIO(data), buf, 'multiline.txt', 0o644)
    //   → b'begin 644 multiline.txt\nM2&5L;&\\...\n=...\n \nend\n'
    // -----------------------------------------------------------------------
    #[test]
    fn test_multiline_block() {
        // Oracle hex (Python 3.12, includes ' \n' terminator before end)
        let body = hex_bytes(
            "626567696e20363434206d756c74696c696e652e7478740a4d3226354c3b265c4c\
             28253d4f3c465144283221343a26455328264553282624403d2635533d22214f39\
             42214d3d3651543a32554c3a365945282535350a3d2826354e38565d443a365947\
             2b422121392631493b463c403b365d52393221423e3731453c5258200a200a656e\
             640a",
        );
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].mode, 0o644);
        assert_eq!(blocks[0].filename, "multiline.txt");
        // Oracle decoded bytes: "Hello, World! This is a test of multi-line UU encoding. Adding more bytes."
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
    // begin-base64 block is reported with is_encoding_problem=true
    // -----------------------------------------------------------------------
    #[test]
    fn test_begin_base64_is_encoding_problem() {
        // A begin-base64 block followed by a normal UU block.
        // The begin-base64 generates an Err item; the UU block is decoded normally.
        // Oracle: uu.encode(b'Hello', ...) → b'begin 644 hello.txt\n%2&5L;&\\ \n \nend\n'
        let b64_block = b"begin-base64 644 file.txt\naGVsbG8=\n====\n";
        let uu_block = b"begin 644 hello.txt\n%2&5L;&\\ \n \nend\n";
        let mut body = Vec::new();
        body.extend_from_slice(b64_block);
        body.extend_from_slice(uu_block);
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_uuencode(&raw, &part);
        // Two items: one Err (begin-base64) → is_encoding_problem, one Ok (UU block).
        assert_eq!(blocks.len(), 2, "expected 2 items");
        assert!(
            blocks[0].is_encoding_problem,
            "begin-base64 block must have is_encoding_problem=true"
        );
        assert!(
            !blocks[1].is_encoding_problem,
            "valid UU block must not have is_encoding_problem"
        );
        assert_eq!(blocks[1].data, b"Hello");
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
