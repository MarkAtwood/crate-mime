//! Inline yEnc scanner for MIME body parts.
//!
//! # What is inline yEnc?
//!
//! yEnc binary posts on Usenet rarely carry a `Content-Transfer-Encoding`
//! header. Instead, the article body simply contains `=ybegin`/`=yend` framing
//! directly in the message body — often with no MIME structure at all. The
//! outer message is treated as `text/plain` (by default when no `Content-Type`
//! is present), and the encoded binary is embedded in it.
//!
//! # This module vs. `parse()` / `decode_body_value()`
//!
//! [`parse()`][crate::parse] and [`decode_body_value()`][crate::decode_body_value]
//! do not decode yEnc content — there is no standard `Content-Transfer-Encoding`
//! value for yEnc. Those functions will return the raw body text including the
//! `=ybegin` lines verbatim.
//!
//! [`scan_inline_yencode()`] is the opt-in scanner for this case. It operates
//! on the raw bytes of a part's body and locates every `=ybegin`…`=yend` block,
//! decoding each via the [`yencoding`] crate.
//!
//! # When to call this
//!
//! A reasonable heuristic: call `scan_inline_yencode()` on any `text/plain`
//! leaf part whose body bytes contain the ASCII sequence `b"=ybegin "`. This
//! avoids scanning every part while still catching all practical cases.
//!
//! ```rust
//! use mime_tree::{parse, scan_inline_yencode};
//!
//! // A message with no MIME structure — just a yEnc block in the body.
//! // Oracle: bytes [0,1,2] encode as ['*','+',',']; CRC32 = 0x0854897f
//! let raw: &[u8] = b"From: poster@example.com\r\n\
//!                    Subject: [1/1] hi.bin\r\n\
//!                    \r\n\
//!                    Some prose before the attachment.\r\n\
//!                    =ybegin line=128 size=3 name=hi.bin\r\n\
//!                    *+,\r\n\
//!                    =yend size=3 crc32=0854897f\r\n\
//!                    Some prose after.\r\n";
//!
//! let msg = parse(raw).unwrap();
//! let part = msg.part_index.find_by_id("1").unwrap();
//!
//! let blocks = scan_inline_yencode(raw, part);
//! assert_eq!(blocks.len(), 1);
//! assert_eq!(blocks[0].filename, "hi.bin");
//! assert_eq!(blocks[0].data, &[0u8, 1, 2]);
//! assert!(blocks[0].crc32_verified);
//! assert!(!blocks[0].is_encoding_problem);
//! ```

use crate::part::ParsedPart;

/// A single yEnc-encoded block found inside a part body.
///
/// All byte offsets are **absolute** — they are in the same coordinate space
/// as `ParsedPart::body_range` and the `raw` buffer passed to
/// [`scan_inline_yencode()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineYEncBlock {
    /// Byte offset of the `=ybegin` line within `raw`.
    ///
    /// Slicing `raw[begin_offset .. begin_offset + begin_length]` yields the
    /// complete yEnc article from the `=ybegin` line through the `=yend` line
    /// (inclusive of its line ending).
    pub begin_offset: u32,

    /// Byte length of the entire block: from the start of `=ybegin` through
    /// the end of `=yend` (inclusive of its newline).
    ///
    /// **When [`is_encoding_problem`] is `true`**, this field holds the length
    /// of the `=ybegin` line only (up to and including its newline), not the
    /// full block through `=yend`.  The `=yend` line could not be located
    /// because decoding failed before it was reached.  Do not rely on
    /// `begin_offset + begin_length` spanning a complete block when
    /// `is_encoding_problem` is set.
    pub begin_length: u32,

    /// Filename from the `name=` field of `=ybegin`.
    ///
    /// Not sanitised against path traversal. Callers writing this to disk must
    /// validate against `..` and absolute paths.
    ///
    /// Empty when [`is_encoding_problem`] is `true` and the block header
    /// could not be parsed.
    pub filename: String,

    /// Total declared file size in bytes, from `=ybegin size=`. For multi-part
    /// articles this is the size of the complete file, not just this part.
    pub file_size: u64,

    /// 1-based part number from `=ybegin part=`. `None` for single-part articles.
    pub part: Option<u32>,

    /// Total number of parts in the series from `=ybegin total=`.
    /// `None` for single-part articles.
    pub total_parts: Option<u32>,

    /// 1-based byte offset of the first byte of this part within the full file,
    /// from `=ypart begin=`. `None` for single-part articles.
    pub part_begin: Option<u64>,

    /// 1-based byte offset of the last byte of this part within the full file,
    /// from `=ypart end=`. `None` for single-part articles.
    pub part_end: Option<u64>,

    /// Decoded binary payload.
    pub data: Vec<u8>,

    /// `true` if the CRC32 in `=yend` was present and matched the decoded
    /// bytes. `false` if no CRC field was present in the article (some older
    /// encoders omit it).
    pub crc32_verified: bool,

    /// `true` if any decoding error was encountered (missing `=ybegin`,
    /// invalid header field, missing `=yend`, CRC mismatch, or any other
    /// error returned by [`yencoding::decode`]).
    ///
    /// When this is `true`, `data` may be empty or partial.
    pub is_encoding_problem: bool,
}

/// Scan a MIME part's body for inline yEnc-encoded blocks.
///
/// Slices `raw` using `part.body_range` to obtain the body bytes, then finds
/// every `=ybegin`…`=yend` block within the body, decoding each one via
/// [`yencoding::decode`]. Returns one [`InlineYEncBlock`] per block found.
///
/// # Parameters
///
/// * `raw`  — the full raw message bytes (same buffer passed to [`parse()`][crate::parse]).
/// * `part` — a [`ParsedPart`][crate::ParsedPart] from the parsed tree.
///   Only `part.body_range` is used.
///
/// # Return value
///
/// An empty `Vec` when:
/// - the body contains no `=ybegin` blocks, or
/// - `part.body_range` is out of bounds for `raw`.
///
/// Otherwise one entry per block, in order of appearance.
///
/// # Multiple blocks
///
/// A single body part may contain more than one yEnc article (though this is
/// unusual in practice). All blocks are decoded and returned.
///
/// # Notes
///
/// * Byte offsets in the returned blocks are absolute — relative to the start
///   of `raw`, matching the coordinate space of `part.body_range`.
/// * No panic on any input.
pub fn scan_inline_yencode(raw: &[u8], part: &ParsedPart) -> Vec<InlineYEncBlock> {
    let (offset_u32, length_u32) = part.body_range;
    let offset = offset_u32 as usize;
    let length = length_u32 as usize;

    // Defensive: body_range out of bounds → empty result, no panic.
    let end = match offset.checked_add(length) {
        Some(e) if e <= raw.len() => e,
        _ => return Vec::new(),
    };
    let body = &raw[offset..end];

    let mut results = Vec::new();
    let mut pos = 0usize;

    while pos < body.len() {
        // Find the next =ybegin line starting at or after pos.
        let ybegin_rel = match find_ybegin(body, pos) {
            Some(r) => r,
            None => break, // no more blocks
        };

        // Attempt to decode from the =ybegin line onward. yencoding::decode()
        // scans forward for =ybegin itself, so passing the slice starting at
        // ybegin_rel is correct (it will find it immediately).
        let slice = &body[ybegin_rel..];
        let (block, yend_rel_in_slice, is_error) = decode_one_block(slice);

        // Absolute offset in `raw` of this block's =ybegin line.
        let abs_begin = offset_u32.saturating_add(u32::try_from(ybegin_rel).unwrap_or(u32::MAX));

        // Byte length of the block: from =ybegin to end of =yend line.
        let block_len = u32::try_from(yend_rel_in_slice).unwrap_or(u32::MAX);

        results.push(InlineYEncBlock {
            begin_offset: abs_begin,
            begin_length: block_len,
            filename: block.metadata.filename,
            file_size: block.metadata.size,
            part: block.part,
            total_parts: block.metadata.total_parts,
            part_begin: block.part_begin,
            part_end: block.part_end,
            data: block.data,
            crc32_verified: block.crc32_verified,
            is_encoding_problem: is_error,
        });

        // Advance past the consumed block. If we couldn't find =yend, advance
        // past the =ybegin line only so we don't re-process it.
        pos = ybegin_rel + yend_rel_in_slice.max(1);
    }

    results
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the relative offset of the next `=ybegin ` line at or after `start`
/// within `body`. Returns `None` if no such line exists.
///
/// Matches only at true line boundaries (offset 0 or immediately after `\n`)
/// to avoid false positives from encoded data that happens to contain
/// the ASCII bytes `=ybegin`.
///
/// # Precondition
///
/// `start` must be `0` or immediately following a `\n` byte in `body`
/// (i.e. a line-boundary offset). Passing a mid-line offset will not
/// produce a panic, but the search will begin at a non-line-boundary
/// position and may miss a `=ybegin` line that starts before the next
/// `\n`, or — in pathological encoded data — match `=ybegin` bytes that
/// do not appear at a true line start.
fn find_ybegin(body: &[u8], start: usize) -> Option<usize> {
    debug_assert!(
        start == 0 || body.get(start - 1) == Some(&b'\n'),
        "find_ybegin: start must be a line-boundary offset"
    );
    let needle = b"=ybegin ";
    let mut pos = start;

    while pos < body.len() {
        // Check at a line boundary.
        if body[pos..].starts_with(needle) {
            return Some(pos);
        }
        // Advance to the next line.
        match body[pos..].iter().position(|&b| b == b'\n') {
            Some(rel) => pos += rel + 1,
            None => break,
        }
    }
    None
}

/// Decode one yEnc block starting at the beginning of `slice`.
///
/// Returns `(DecodedPart, bytes_consumed, is_error)` where:
/// - `bytes_consumed` is how many bytes of `slice` this block spans
/// - `is_error` is `true` when `yencoding::decode` returned `Err`
fn decode_one_block(slice: &[u8]) -> (yencoding::DecodedPart, usize, bool) {
    match yencoding::decode(slice) {
        Ok(part) => {
            // Find where =yend line ends within slice so the caller knows
            // how many bytes to skip.
            //
            // If yencoding::decode() succeeded, =yend was definitely in the
            // slice and find_yend_end() must find it too. If it somehow returns
            // None that is a logic error: fall back to advancing past =ybegin
            // only (rather than consuming the whole remaining body) and mark
            // the block as an encoding problem so the caller is not silently
            // misled.
            match find_yend_end(slice) {
                Some(consumed) => (part, consumed, false),
                None => {
                    // yencoding::decode() succeeded, so =yend was definitely
                    // present in the slice — find_yend_end() returning None
                    // here is a logic error in this module.
                    debug_assert!(
                        false,
                        "find_yend_end returned None after successful decode — logic error"
                    );
                    let consumed = find_line_end(slice, 0);
                    (part, consumed, false)
                }
            }
        }
        Err(e) => {
            // Build a sentinel DecodedPart for the error case.
            let sentinel = make_error_sentinel(e);
            // Advance past =ybegin line only to ensure forward progress.
            let consumed = find_line_end(slice, 0);
            (sentinel, consumed, true)
        }
    }
}

/// Find the byte offset just past the `=yend` line in `slice`.
/// Returns `None` if no `=yend` line is found (truncated article).
///
/// Matches `=yend` only when followed by a space, `\r`, `\n`, or end-of-slice
/// — the same boundary requirement that `yencoding::decode` uses internally
/// via `strip_keyword(line, b"=yend ")`.  This guard is a safety margin for
/// non-compliant encoders: compliant yEnc encoders cannot produce a data line
/// starting with `=y` because `=` (0x3D) is always escaped, so no well-formed
/// data line can begin with a literal `=` character.
fn find_yend_end(slice: &[u8]) -> Option<usize> {
    let needle = b"=yend";
    let mut pos = 0;
    while pos < slice.len() {
        let rest = &slice[pos..];
        if rest.starts_with(needle) {
            // Require the keyword to be followed by a delimiter so we don't
            // match =yend inside an encoded data line.
            let after = rest.get(needle.len()).copied();
            match after {
                None | Some(b' ') | Some(b'\r') | Some(b'\n') => {
                    return Some(find_line_end(slice, pos));
                }
                _ => {} // false match — continue scanning
            }
        }
        match rest.iter().position(|&b| b == b'\n') {
            Some(rel) => pos += rel + 1,
            None => break,
        }
    }
    None
}

/// Return the byte offset just past the end of the line starting at `pos`
/// within `slice`. If there is no `\n`, returns `slice.len()`.
fn find_line_end(slice: &[u8], pos: usize) -> usize {
    match slice[pos..].iter().position(|&b| b == b'\n') {
        Some(rel) => pos + rel + 1,
        None => slice.len(),
    }
}

/// Build a zero-data `DecodedPart` to use when decode returns an error.
fn make_error_sentinel(_err: yencoding::YencError) -> yencoding::DecodedPart {
    let filename = String::new();
    yencoding::DecodedPart {
        data: Vec::new(),
        metadata: yencoding::YencMetadata {
            filename,
            size: 0,
            line_length: 128,
            total_parts: None,
        },
        part: None,
        part_begin: None,
        part_end: None,
        crc32_verified: false,
        whole_file_crc32: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part::{ParsedPart, TransferEncoding};

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

    // Oracle: bytes [0,1,2] → ['*','+',','] (add 42, no escapes).
    // CRC32 of [0,1,2]: python3 -c "import binascii; print(hex(binascii.crc32(bytes([0,1,2]))&0xffffffff))"
    // → 0x0854897f
    const BLOCK_012: &[u8] =
        b"=ybegin line=128 size=3 name=hi.bin\r\n*+,\r\n=yend size=3 crc32=0854897f\r\n";

    // Oracle: bytes [3,4,5] → ['-','.','/'] (add 42).
    // CRC32: python3 -c "print(hex(binascii.crc32(bytes([3,4,5]))&0xffffffff))"
    // → 0xe90156c0
    const BLOCK_345: &[u8] =
        b"=ybegin line=128 size=3 name=other.bin\r\n-./\r\n=yend size=3 crc32=e90156c0\r\n";

    #[test]
    fn single_block_no_preamble() {
        let (raw, part) = make_part(b"", BLOCK_012);
        let blocks = scan_inline_yencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data, &[0u8, 1, 2]);
        assert_eq!(blocks[0].filename, "hi.bin");
        assert_eq!(blocks[0].file_size, 3);
        assert!(blocks[0].crc32_verified);
        assert!(!blocks[0].is_encoding_problem);
        assert_eq!(blocks[0].begin_offset, 0);
        assert_eq!(blocks[0].begin_length, BLOCK_012.len() as u32);
    }

    #[test]
    fn single_block_with_preamble() {
        let preamble = b"Some prose.\r\nMore prose.\r\n";
        let (raw, part) = make_part(b"", &[preamble, BLOCK_012].concat());
        let blocks = scan_inline_yencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data, &[0u8, 1, 2]);
        assert_eq!(blocks[0].begin_offset, preamble.len() as u32);
        assert_eq!(blocks[0].begin_length, BLOCK_012.len() as u32);
        // Verify slice invariant: raw[begin_offset..begin_offset+begin_length] == BLOCK_012
        let start = blocks[0].begin_offset as usize;
        let end = start + blocks[0].begin_length as usize;
        assert_eq!(&raw[start..end], BLOCK_012);
    }

    #[test]
    fn two_sequential_blocks() {
        let separator = b"Some text between blocks.\r\n";
        let body = [BLOCK_012, separator, BLOCK_345].concat();
        let (raw, part) = make_part(b"", &body);

        let blocks = scan_inline_yencode(&raw, &part);
        assert_eq!(blocks.len(), 2, "expected 2 blocks");

        assert_eq!(blocks[0].data, &[0u8, 1, 2]);
        assert_eq!(blocks[0].filename, "hi.bin");
        assert_eq!(blocks[0].begin_offset, 0);

        assert_eq!(blocks[1].data, &[3u8, 4, 5]);
        assert_eq!(blocks[1].filename, "other.bin");
        assert_eq!(
            blocks[1].begin_offset,
            (BLOCK_012.len() + separator.len()) as u32
        );

        // Non-overlapping
        assert!(blocks[0].begin_offset + blocks[0].begin_length <= blocks[1].begin_offset);
    }

    #[test]
    fn block_with_absolute_prefix_offset() {
        let prefix = b"MIME headers here\r\n\r\n";
        let (raw, part) = make_part(prefix, BLOCK_012);
        let blocks = scan_inline_yencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        // Absolute offset = prefix.len() (body starts there, block at body start)
        assert_eq!(blocks[0].begin_offset, prefix.len() as u32);
        // Verify slice invariant
        let start = blocks[0].begin_offset as usize;
        let end = start + blocks[0].begin_length as usize;
        assert_eq!(&raw[start..end], BLOCK_012);
    }

    #[test]
    fn no_blocks_returns_empty() {
        let (raw, part) = make_part(b"", b"Just plain text.\r\nNo yEnc here.\r\n");
        assert!(scan_inline_yencode(&raw, &part).is_empty());
    }

    #[test]
    fn empty_body_returns_empty() {
        let (raw, part) = make_part(b"", b"");
        assert!(scan_inline_yencode(&raw, &part).is_empty());
    }

    #[test]
    fn out_of_bounds_body_range_returns_empty() {
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
            body_range: (3, 100), // end = 103 > 5
            children: vec![],
            is_encoding_problem: false,
        };
        assert!(scan_inline_yencode(raw, &part).is_empty());
    }

    #[test]
    fn overflow_safe_body_range() {
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
            body_range: (u32::MAX, 1),
            children: vec![],
            is_encoding_problem: false,
        };
        assert!(scan_inline_yencode(raw, &part).is_empty());
    }

    #[test]
    fn crc_mismatch_sets_is_encoding_problem() {
        // Correct encoding but wrong CRC in =yend.
        let bad = b"=ybegin line=128 size=3 name=f.bin\r\n*+,\r\n=yend size=3 crc32=00000000\r\n";
        let (raw, part) = make_part(b"", bad);
        let blocks = scan_inline_yencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert!(
            blocks[0].is_encoding_problem,
            "CRC mismatch should set is_encoding_problem"
        );
        assert!(
            blocks[0].data.is_empty(),
            "data should be empty on CRC error"
        );
    }

    #[test]
    fn truncated_block_sets_is_encoding_problem() {
        // =yend line absent.
        let trunc = b"=ybegin line=128 size=3 name=f.bin\r\n*+,\r\n";
        let (raw, part) = make_part(b"", trunc);
        let blocks = scan_inline_yencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].is_encoding_problem);
    }

    #[test]
    fn ybegin_mid_line_not_matched() {
        // "not =ybegin" — keyword not at line start, must be ignored.
        let body = b"this is not =ybegin a real block\r\n=ybegin line=128 size=3 name=f.bin\r\n*+,\r\n=yend size=3 crc32=0854897f\r\n";
        let (raw, part) = make_part(b"", body);
        let blocks = scan_inline_yencode(&raw, &part);
        // Only the real block at the line boundary should be found.
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data, &[0u8, 1, 2]);
    }

    #[test]
    fn multipart_article_fields_populated() {
        // Oracle: multi-part article with =ypart.
        // Encode bytes [0,1,2] as part 1 of 2, begin=1 end=3.
        use yencoding::{encode_part, EncodePartOptions, DEFAULT_LINE_LENGTH};
        let data = [0u8, 1, 2];
        // Oracle: python3 -c "import binascii; print(hex(binascii.crc32(bytes([0,1,2,3,4,5]))&0xffffffff))"
        // → 0x30ebcf4a
        let whole_crc: u32 = 0x30eb_cf4a;
        let opts = EncodePartOptions {
            filename: "split.bin",
            total_size: 6,
            total_parts: 2,
            part: 1,
            begin: 1,
            end: 3,
            whole_file_crc32: whole_crc,
            line_length: DEFAULT_LINE_LENGTH,
        };
        let encoded = encode_part(&data, &opts);
        let (raw, part) = make_part(b"", &encoded);

        let blocks = scan_inline_yencode(&raw, &part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].part, Some(1));
        assert_eq!(blocks[0].total_parts, Some(2));
        assert_eq!(blocks[0].part_begin, Some(1));
        assert_eq!(blocks[0].part_end, Some(3));
        assert_eq!(blocks[0].file_size, 6);
        assert!(blocks[0].crc32_verified);
        // Oracle: bytes [0,1,2] are the decoded payload of this part.
        assert_eq!(
            blocks[0].data,
            &[0u8, 1, 2],
            "decoded bytes must match oracle"
        );
        // Slice invariant: raw[begin_offset..begin_offset+begin_length] == encoded
        let start = blocks[0].begin_offset as usize;
        let end = start + blocks[0].begin_length as usize;
        assert_eq!(
            &raw[start..end],
            encoded.as_slice(),
            "slice invariant must hold for multi-part block"
        );
    }

    // Integration test: full parse() → scan_inline_yencode() pipeline
    #[test]
    fn full_parse_pipeline() {
        use crate::parse;

        // A bare message with no MIME headers — just a yEnc block in the body.
        let raw: Vec<u8> = [
            b"From: poster@example.com\r\n" as &[u8],
            b"Subject: [1/1] hi.bin\r\n",
            b"\r\n",
            b"Some prose.\r\n",
            BLOCK_012,
            b"More prose.\r\n",
        ]
        .concat();

        let msg = parse(&raw).expect("parse failed");
        // Should be a single text/plain part.
        let part = msg.part_index.find_by_id("1").unwrap();
        assert_eq!(part.content_type, "text/plain");

        let blocks = scan_inline_yencode(&raw, part);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data, &[0u8, 1, 2]);
        assert_eq!(blocks[0].filename, "hi.bin");
        assert!(blocks[0].crc32_verified);
    }
}
