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

/// Returns true if `line` (already stripped of \r\n) starts with `begin`
/// (case-insensitive ASCII) followed by whitespace, `-`, or end-of-line.
///
/// Requiring a delimiter after the 5-byte keyword prevents prose lines such as
/// "beginners guide…" or "beginning of part 2" from triggering block handling
/// and emitting spurious `InvalidBeginLine` errors.
fn is_begin_line(line: &[u8]) -> bool {
    if line.len() < 5 {
        return false;
    }
    if !line[..5].eq_ignore_ascii_case(b"begin") {
        return false;
    }
    // Bare "begin" with nothing following is a valid (if unusual) begin line.
    if line.len() == 5 {
        return true;
    }
    let next = line[5];
    next.is_ascii_whitespace() || next == b'-'
}

/// Returns true if the line (stripped) looks like `begin-base64 ...`
fn is_begin_base64(line: &[u8]) -> bool {
    line.len() >= 13 && line[..13].eq_ignore_ascii_case(b"begin-base64 ")
}

/// Parse `begin <mode> <filename>` from a stripped line. Returns None on failure.
///
/// Accepts case-insensitive `begin` keyword. A bare `begin` line with no mode
/// or filename tokens produces `mode=0` and `filename=""`, matching the
/// behavior of `uuencoding::decode`. An empty filename is accepted (returns
/// `BlockMetadata { filename: "", mode }`) to align with `decode()`.
fn parse_begin_line(line: &[u8]) -> Option<BlockMetadata> {
    // Must start with "begin" (case-insensitive).
    if line.len() < 5 || !line[..5].eq_ignore_ascii_case(b"begin") {
        return None;
    }

    // Everything after "begin"
    let after_begin = &line[5..];

    // If nothing follows (bare "begin"), return mode=0, filename="".
    if after_begin.is_empty() || after_begin == b"\r" {
        return Some(BlockMetadata {
            filename: String::new(),
            mode: 0,
        });
    }

    // Must have a space/tab after "begin".
    if !after_begin[0].is_ascii_whitespace() {
        // e.g. "begin-base64" — not a standard UU begin line
        return None;
    }

    // Skip whitespace after "begin"
    let rest = {
        let skip = after_begin
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(after_begin.len());
        &after_begin[skip..]
    };

    // If no more tokens (just "begin   "), mode=0, filename="".
    if rest.is_empty() {
        return Some(BlockMetadata {
            filename: String::new(),
            mode: 0,
        });
    }

    // Parse mode token (up to next whitespace).
    let mode_end = rest
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let mode_bytes = &rest[..mode_end];
    let mode_str = std::str::from_utf8(mode_bytes).ok()?;
    let mode = u32::from_str_radix(mode_str.trim(), 8).unwrap_or(0);

    // Filename: everything after the mode token and its trailing whitespace.
    let after_mode = &rest[mode_end..];
    let filename_skip = after_mode
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(after_mode.len());
    let filename_bytes = &after_mode[filename_skip..];
    let filename = std::str::from_utf8(filename_bytes)
        .ok()?
        .trim_end()
        .to_string();

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
            Err(_) => {
                // Decoding error: stop here, emit a truncated Ok(ScannedBlock)
                // with the bytes decoded so far. This matches decode() behavior,
                // which also stops at the first bad data line and returns a
                // partial result with is_truncated=true. A single block never
                // produces both Err and Ok items.
                //
                // Update end_offset to le (past the bad line) so that *pos
                // advances past this block, allowing the outer loop to continue
                // scanning for subsequent blocks.  Without this, end_offset
                // stays at input.len() and all following blocks are dropped.
                end_offset = le;
                break;
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

    // MIME-gcz.4: bare "begin" line (no mode, no filename) is now accepted by
    // scan, matching decode() behavior which accepts it with mode=0, filename="".
    // Oracle: "begin\n \nend\n" accepted by decode() with mode=0, filename="".
    #[test]
    fn bare_begin_no_mode_no_filename_scanned() {
        let input = b"begin\n \nend\n";
        let results = scan_impl(input);
        assert_eq!(results.len(), 1);
        let block = results[0].as_ref().unwrap();
        assert_eq!(block.metadata.filename, "");
        assert_eq!(block.metadata.mode, 0);
        assert!(block.data.is_empty());
        assert!(!block.is_truncated);
    }

    // MIME-gcz.2: empty filename is accepted by scan, matching decode() behavior.
    // Oracle: "begin 644 \n#0V%T\n`\nend\n" — "begin 644 " with no filename.
    // Python: uu module does not produce empty filenames, but decode() accepts them.
    #[test]
    fn empty_filename_block_scanned() {
        let input = b"begin 644 \n#0V%T\n`\nend\n";
        let results = scan_impl(input);
        assert_eq!(results.len(), 1);
        let block = results[0].as_ref().unwrap();
        assert_eq!(block.metadata.filename, "");
        assert_eq!(block.metadata.mode, 0o644);
        assert_eq!(block.data, b"Cat");
        assert!(!block.is_truncated);
    }

    // MIME-gcz.3: a block with one bad data line produces exactly one Ok result
    // with is_truncated=true and the bytes decoded before the error. No separate
    // Err items are emitted for the same block.
    // Oracle: "#0V%T" decodes "Cat"; "!a   " has invalid char 0x61 ('a').
    #[test]
    fn bad_data_line_yields_single_truncated_ok() {
        let input = b"begin 644 file.bin\n#0V%T\n!a   \n \nend\n";
        let results = scan_impl(input);
        // Must be exactly one Ok item, no Err items from the bad data line.
        assert_eq!(results.len(), 1, "expected exactly one result");
        let block = results[0].as_ref().unwrap();
        assert_eq!(
            block.data, b"Cat",
            "bytes before bad line should be present"
        );
        assert!(block.is_truncated, "block should be truncated");
    }

    // MIME-gcz.19: after a decode error in one block, subsequent blocks must
    // still be scanned.  Before the fix, *pos was set to input.len() on error,
    // silently dropping everything after the first bad block.
    #[test]
    fn decode_error_in_block_does_not_drop_subsequent_blocks() {
        // "!a   " has invalid char 0x61 ('a') — triggers Err from decode_line.
        let bad_block = b"begin 644 bad.bin\n#0V%T\n!a   \n \nend\n";
        let mut input = Vec::new();
        input.extend_from_slice(bad_block);
        input.extend_from_slice(b"between\n");
        input.extend_from_slice(HELLO_BLOCK);

        let results = scan_impl(&input);
        // Must have two results: one truncated block (the bad one) and one good block.
        assert_eq!(
            results.len(),
            2,
            "subsequent block after decode error was dropped"
        );

        let bad = results[0].as_ref().unwrap();
        assert!(bad.is_truncated, "first block should be truncated");
        assert_eq!(bad.data, b"Cat", "bytes before bad line should be present");

        let good = results[1].as_ref().unwrap();
        assert!(!good.is_truncated, "second block should not be truncated");
        assert_eq!(good.data, b"Hello", "second block data should be Hello");
    }

    // MIME-gcz.20: prose lines starting with "begin" but not followed by
    // whitespace or '-' must not trigger InvalidBeginLine errors.
    #[test]
    fn prose_beginners_not_matched_as_begin_line() {
        let input =
            b"beginners guide to Linux\nbeginning of part 2\nbegin 644 real.bin\n#0V%T\n`\nend\n";
        let results = scan_impl(input);
        // No spurious InvalidBeginLine errors — only the real block.
        assert_eq!(results.len(), 1, "spurious begin matches found");
        let block = results[0].as_ref().unwrap();
        assert_eq!(block.metadata.filename, "real.bin");
        assert_eq!(block.data, b"Cat");
        assert!(!block.is_truncated);
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
