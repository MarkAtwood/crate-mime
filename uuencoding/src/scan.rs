//! Implementation of [`scan`] — locate and decode UU blocks in arbitrary text.

use crate::decode::decode_line;
use crate::{BlockMetadata, ScannedBlock, UuError};

/// Collect all UU blocks found in `input`, returning them in order.
///
/// This is a non-lazy helper: it walks the entire input once and builds a Vec.
/// `scan()` in lib.rs wraps this in `.into_iter()`.
pub(crate) fn scan_impl(input: &[u8]) -> Vec<Result<ScannedBlock, UuError>> {
    let mut results = Vec::new();
    let mut pos = 0usize; // current byte position in `input`

    while pos < input.len() {
        // Find the next newline from pos to get the next line.
        let line_start = pos;
        let line_end = memchr(b'\n', &input[pos..])
            .map(|rel| pos + rel + 1) // include the \n
            .unwrap_or(input.len());
        let line = &input[line_start..line_end];
        let line_trimmed = line.strip_suffix(b"\n").unwrap_or(line);
        let line_trimmed = line_trimmed.strip_suffix(b"\r").unwrap_or(line_trimmed);

        // Only match begin at a true line boundary: pos == 0 or preceded by '\n'.
        // (Since we always advance line-by-line starting at 0, every line_start
        // is already at a line boundary.)
        if is_begin_line(line_trimmed) {
            handle_block(input, line_start, line_trimmed, &mut results, &mut pos);
        } else {
            pos = line_end;
        }
    }

    results
}

/// Find first occurrence of `needle` in `haystack`, returning relative offset.
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Returns true if `line` (already stripped of \r\n) starts with `begin ` or
/// `begin-base64 ` (case-insensitive ASCII).
fn is_begin_line(line: &[u8]) -> bool {
    // Fast path: must start with 'b' or 'B'
    if line.len() < 6 {
        return false;
    }
    let lo: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
    lo.starts_with(b"begin ") || lo.starts_with(b"begin-base64 ")
}

/// Returns true if the line (stripped) looks like `begin-base64 ...`
fn is_begin_base64(line: &[u8]) -> bool {
    let lo: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
    lo.starts_with(b"begin-base64 ")
}

/// Parse `begin <mode> <filename>` from a stripped line. Returns None on failure.
///
/// Accepts case-insensitive `begin` keyword followed by a space.
fn parse_begin_line(line: &[u8]) -> Option<BlockMetadata> {
    // Expect: "begin <octal-mode> <filename>"
    // The keyword is case-insensitive; strip the leading "begin " case-insensitively.
    if line.len() < 7 {
        return None;
    }
    if !line[..6].eq_ignore_ascii_case(b"begin ") {
        return None;
    }
    let rest = &line[6..];

    // Find the space separating mode from filename
    let space_pos = memchr(b' ', rest)?;
    let mode_bytes = &rest[..space_pos];
    let filename_bytes = &rest[space_pos + 1..];

    // Parse mode as octal
    let mode_str = std::str::from_utf8(mode_bytes).ok()?;
    let mode = u32::from_str_radix(mode_str.trim(), 8).ok()?;

    let filename = std::str::from_utf8(filename_bytes).ok()?.trim().to_string();
    if filename.is_empty() {
        return None;
    }

    Some(BlockMetadata { filename, mode })
}

/// Returns true if a stripped line is `====` (base64 terminator).
fn is_base64_terminator(line: &[u8]) -> bool {
    line == b"===="
}

/// Returns true if a stripped line is `end`.
fn is_end_line(line: &[u8]) -> bool {
    line.eq_ignore_ascii_case(b"end")
}

/// Handle one block starting at `line_start`. Appends to `results` and
/// updates `pos` to the byte after the block (or input.len() on EOF).
fn handle_block(
    input: &[u8],
    line_start: usize,
    begin_line_trimmed: &[u8],
    results: &mut Vec<Result<ScannedBlock, UuError>>,
    pos: &mut usize,
) {
    if is_begin_base64(begin_line_trimmed) {
        // Emit the error, then skip past the ==== terminator.
        results.push(Err(UuError::BeginBase64));

        // Advance past the begin-base64 line
        let begin_line_end = memchr(b'\n', &input[line_start..])
            .map(|r| line_start + r + 1)
            .unwrap_or(input.len());
        let mut scan_pos = begin_line_end;

        // Skip lines until we hit ==== or EOF
        while scan_pos < input.len() {
            let ls = scan_pos;
            let le = memchr(b'\n', &input[ls..])
                .map(|r| ls + r + 1)
                .unwrap_or(input.len());
            let lraw = &input[ls..le];
            let lt = lraw.strip_suffix(b"\n").unwrap_or(lraw);
            let lt = lt.strip_suffix(b"\r").unwrap_or(lt);
            scan_pos = le;
            if is_base64_terminator(lt) {
                break;
            }
        }
        *pos = scan_pos;
        return;
    }

    // Standard UU block.
    let metadata = match parse_begin_line(begin_line_trimmed) {
        Some(m) => m,
        None => {
            // Malformed begin line: emit error, advance past this line and continue.
            let line_end = memchr(b'\n', &input[line_start..])
                .map(|r| line_start + r + 1)
                .unwrap_or(input.len());
            results.push(Err(UuError::InvalidBeginLine {
                line: String::from_utf8_lossy(begin_line_trimmed).into_owned(),
            }));
            *pos = line_end;
            return;
        }
    };

    let begin_offset = line_start;

    // Advance past the begin line
    let begin_line_end = memchr(b'\n', &input[line_start..])
        .map(|r| line_start + r + 1)
        .unwrap_or(input.len());
    let mut scan_pos = begin_line_end;

    let mut data: Vec<u8> = Vec::new();
    let mut found_end = false;
    let mut end_offset = input.len();
    let mut saw_terminator = false; // decode_line returned Ok(0)

    while scan_pos < input.len() {
        let ls = scan_pos;
        let le = memchr(b'\n', &input[ls..])
            .map(|r| ls + r + 1)
            .unwrap_or(input.len());
        let lraw = &input[ls..le];
        let lt = lraw.strip_suffix(b"\n").unwrap_or(lraw);
        let lt = lt.strip_suffix(b"\r").unwrap_or(lt);

        if saw_terminator && is_end_line(lt) {
            // Proper termination.
            end_offset = le;
            found_end = true;
            break;
        }

        // Try decoding as a data line.
        match decode_line(lt, &mut data) {
            Ok(0) => {
                saw_terminator = true;
                scan_pos = le;
            }
            Ok(_) => {
                saw_terminator = false;
                scan_pos = le;
            }
            Err(e) => {
                // Decoding error: emit error for this line, but keep scanning
                // the block. We record the error and continue to gather the rest
                // of the block's bytes.
                results.push(Err(e));
                scan_pos = le;
            }
        }
    }

    let is_truncated = !found_end;

    results.push(Ok(ScannedBlock {
        begin_offset,
        end_offset,
        metadata,
        data,
        is_truncated,
    }));

    *pos = end_offset;
}

#[cfg(test)]
mod tests {
    use super::scan_impl;
    use crate::UuError;

    // Oracle: Python 3.12 (uu module):
    //   import uu, io
    //   def make(data): buf=io.BytesIO(); uu.encode(io.BytesIO(data),buf,'file.bin',0o644); return buf.getvalue()
    //   make(b'Hello') => b'begin 644 file.bin\n%2&5L;&\\ \n \nend\n'
    //   make(b'World') => b'begin 644 file.bin\n%5V]R;&0 \n \nend\n'
    //
    // Single block with preamble:
    //   text = b'Some preamble text\n' + hello_block + b'Some postamble\n'
    //   begin_offset=19, end_offset=54
    //
    // Two blocks:
    //   two = b'prefix\n' + hello_block + b'between\n' + world_block + b'suffix\n'
    //   block1: begin_offset=7, end_offset=42
    //   block2: begin_offset=50, end_offset=85

    const HELLO_BLOCK: &[u8] = b"begin 644 file.bin\n%2&5L;&\\ \n \nend\n";
    const WORLD_BLOCK: &[u8] = b"begin 644 file.bin\n%5V]R;&0 \n \nend\n";

    #[test]
    fn no_blocks_yields_nothing() {
        let results = scan_impl(b"just some plain text\nno uu here\n");
        assert!(results.is_empty());
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(scan_impl(b"").is_empty());
    }

    #[test]
    fn single_block_with_preamble_and_postamble() {
        // Oracle: begin_offset=19, end_offset=54, data=b"Hello"
        let text = b"Some preamble text\n" as &[u8];
        let postamble = b"Some postamble\n" as &[u8];
        let mut input = Vec::new();
        input.extend_from_slice(text);
        input.extend_from_slice(HELLO_BLOCK);
        input.extend_from_slice(postamble);

        let results = scan_impl(&input);
        assert_eq!(results.len(), 1);
        let block = results[0].as_ref().unwrap();
        assert_eq!(block.begin_offset, 19);
        assert_eq!(block.end_offset, 54);
        assert_eq!(block.data, b"Hello");
        assert_eq!(block.metadata.filename, "file.bin");
        assert_eq!(block.metadata.mode, 0o644);
        assert!(!block.is_truncated);

        // Verify the slice from begin..end starts with "begin" and ends with "end\n"
        let slice = &input[block.begin_offset..block.end_offset];
        assert!(slice.starts_with(b"begin"));
        assert!(slice.ends_with(b"end\n"));
    }

    #[test]
    fn two_sequential_blocks() {
        // Oracle: block1: begin_offset=7, end_offset=42
        //         block2: begin_offset=50, end_offset=85
        let mut input = Vec::new();
        input.extend_from_slice(b"prefix\n");
        input.extend_from_slice(HELLO_BLOCK);
        input.extend_from_slice(b"between\n");
        input.extend_from_slice(WORLD_BLOCK);
        input.extend_from_slice(b"suffix\n");

        let results = scan_impl(&input);
        assert_eq!(results.len(), 2);

        let b1 = results[0].as_ref().unwrap();
        assert_eq!(b1.begin_offset, 7);
        assert_eq!(b1.end_offset, 42);
        assert_eq!(b1.data, b"Hello");
        assert!(!b1.is_truncated);

        let b2 = results[1].as_ref().unwrap();
        assert_eq!(b2.begin_offset, 50);
        assert_eq!(b2.end_offset, 85);
        assert_eq!(b2.data, b"World");
        assert!(!b2.is_truncated);

        // Offsets must not overlap
        assert!(b1.end_offset <= b2.begin_offset);

        // Slice sanity checks
        let s1 = &input[b1.begin_offset..b1.end_offset];
        assert!(s1.starts_with(b"begin") && s1.ends_with(b"end\n"));
        let s2 = &input[b2.begin_offset..b2.end_offset];
        assert!(s2.starts_with(b"begin") && s2.ends_with(b"end\n"));
    }

    #[test]
    fn truncated_block_no_end_line() {
        // Oracle: prefix\nbegin 644 file.bin\n#0V%T\n  → begin_offset=7, end_offset=32 (=len)
        // "#0V%T" decodes "Cat"
        let input = b"prefix\nbegin 644 file.bin\n#0V%T\n";
        let results = scan_impl(input);
        assert_eq!(results.len(), 1);
        let block = results[0].as_ref().unwrap();
        assert_eq!(block.begin_offset, 7);
        assert_eq!(block.end_offset, input.len()); // input.len() == 32
        assert_eq!(block.data, b"Cat");
        assert!(block.is_truncated);
    }

    #[test]
    fn begin_base64_yields_error_then_continues() {
        // A begin-base64 block followed by a normal UU block.
        // The error should come first, then the valid block.
        let b64_block = b"begin-base64 644 file.txt\naGVsbG8=\n====\n";
        let mut input = Vec::new();
        input.extend_from_slice(b64_block);
        input.extend_from_slice(HELLO_BLOCK);

        let results = scan_impl(&input);
        assert_eq!(results.len(), 2);

        // First: error for begin-base64
        assert!(matches!(results[0], Err(UuError::BeginBase64)));

        // Second: the valid UU block
        let block = results[1].as_ref().unwrap();
        assert_eq!(block.data, b"Hello");
        assert!(!block.is_truncated);
        // begin_offset must be after the b64 block
        assert!(block.begin_offset >= b64_block.len());
    }

    #[test]
    fn begin_mid_line_not_matched() {
        // "not begin 644 file.bin" has "begin" but not at a line boundary — should be ignored.
        // The real block on the next line should be found.
        let input = b"not begin 644 ignore.bin\nbegin 644 real.bin\n#0V%T\n`\nend\n";
        let results = scan_impl(input);
        assert_eq!(results.len(), 1);
        let block = results[0].as_ref().unwrap();
        assert_eq!(block.metadata.filename, "real.bin");
        assert_eq!(block.data, b"Cat");
        assert!(!block.is_truncated);
        // begin_offset must point to the second "begin", not the first
        assert_eq!(&input[block.begin_offset..block.begin_offset + 5], b"begin");
        // the character before begin_offset must be '\n' (line boundary)
        assert_eq!(input[block.begin_offset - 1], b'\n');
    }

    #[test]
    fn block_at_start_of_input_offset_zero() {
        let results = scan_impl(HELLO_BLOCK);
        assert_eq!(results.len(), 1);
        let block = results[0].as_ref().unwrap();
        assert_eq!(block.begin_offset, 0);
        assert_eq!(block.end_offset, HELLO_BLOCK.len());
        assert_eq!(block.data, b"Hello");
    }

    #[test]
    fn offset_slice_invariant() {
        // For every successfully scanned block, input[begin_offset..end_offset]
        // must start with "begin" and end with "end\n" (or end at EOF for truncated).
        let mut input = Vec::new();
        input.extend_from_slice(b"noise\n");
        input.extend_from_slice(HELLO_BLOCK);
        input.extend_from_slice(b"more noise\n");
        input.extend_from_slice(WORLD_BLOCK);

        for result in scan_impl(&input) {
            let block = result.unwrap();
            let slice = &input[block.begin_offset..block.end_offset];
            assert!(
                slice.starts_with(b"begin"),
                "slice should start with 'begin'"
            );
            if !block.is_truncated {
                assert!(slice.ends_with(b"end\n"), "slice should end with 'end\\n'");
            }
        }
    }
}
