use crate::{BlockMetadata, DecodedBlock, UuError};

/// Decode a complete UU block (begin … end framing) from `input`.
///
/// Lines are split on `\n`; trailing `\r` is stripped from each.
/// The function searches forward for the first `begin` line (case-insensitive),
/// then decodes subsequent data lines until a terminator (length 0) and `end`
/// line are found, or input is exhausted.
///
/// # Return values
/// - `Err(UuError::InvalidBeginLine)` — no `begin` line found
/// - `Err(UuError::BeginBase64)` — `begin-base64` detected
/// - `Ok(DecodedBlock { is_truncated: false, .. })` — complete block
/// - `Ok(DecodedBlock { is_truncated: true,  .. })` — partial block (no `end`)
///
/// Decode errors on individual data lines do **not** propagate; the function
/// returns the bytes decoded so far with `is_truncated = true`.
///
/// Delegates to [`decode_limited`] with no byte limit.
pub fn decode(input: &[u8]) -> Result<DecodedBlock, UuError> {
    decode_limited(input, None)
}

/// Decode a UU block from `input`, stopping as soon as `max_bytes` decoded
/// bytes have been produced.
///
/// Identical to [`decode`] except that decoding halts early once the
/// accumulated payload reaches `max_bytes`. When the limit is hit,
/// `is_truncated` is set to `true` and `data` contains at most `max_bytes`
/// bytes.
///
/// **Complexity note:** the input is split into lines up-front (O(input) time
/// and O(line-count) space) before any limit check takes effect. Only the
/// *decoding* of data lines is bounded by `max_bytes`. For large inputs with a
/// small limit, callers that need true O(max_bytes) behaviour should switch to
/// a streaming line iterator approach.
///
/// Passing `None` for `max_bytes` is equivalent to calling [`decode`].
///
/// # Errors
///
/// Same as [`decode`]: [`UuError::InvalidBeginLine`] when no `begin` line
/// is found, [`UuError::BeginBase64`] when a `begin-base64` line is detected.
pub fn decode_limited(input: &[u8], max_bytes: Option<usize>) -> Result<DecodedBlock, UuError> {
    let max = max_bytes.unwrap_or(usize::MAX);

    // Split on LF, strip trailing CR from each line.
    let lines: Vec<&[u8]> = input
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();

    // --- Find the begin line ---
    let mut begin_idx = None;
    for (i, line) in lines.iter().enumerate() {
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"begin") {
            begin_idx = Some(i);
            break;
        }
    }
    let begin_idx = match begin_idx {
        Some(i) => i,
        None => {
            return Err(UuError::InvalidBeginLine {
                line: String::new(),
            })
        }
    };

    let begin_line = lines[begin_idx];

    // Detect begin-base64 before further parsing.
    // Require that "begin-base64" is followed by whitespace or is the entire
    // line (no trailing character at position 12), so that a hypothetical
    // "begin-base64X …" is not silently misclassified.  Real encoders always
    // emit "begin-base64 <mode> <filename>".
    let is_begin_base64 = begin_line.len() >= 12
        && begin_line[..12].eq_ignore_ascii_case(b"begin-base64")
        && (begin_line.len() == 12 || begin_line[12].is_ascii_whitespace());
    if is_begin_base64 {
        return Err(UuError::BeginBase64);
    }

    // --- Parse begin line ---
    let tokens: Vec<&[u8]> = begin_line
        .split(|b: &u8| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty())
        .collect();

    if tokens.is_empty() || !tokens[0].eq_ignore_ascii_case(b"begin") {
        return Err(UuError::InvalidBeginLine {
            line: String::from_utf8_lossy(begin_line).into_owned(),
        });
    }

    let mode: u32 = if tokens.len() >= 2 {
        let mode_str = std::str::from_utf8(tokens[1]).unwrap_or("");
        u32::from_str_radix(mode_str, 8).unwrap_or(0)
    } else {
        0
    };

    let filename: String = {
        fn skip_token(s: &[u8]) -> &[u8] {
            let after = s
                .iter()
                .position(|b| b.is_ascii_whitespace())
                .unwrap_or(s.len());
            let s = &s[after..];
            let ws = s
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .unwrap_or(s.len());
            &s[ws..]
        }
        let rest = skip_token(begin_line);
        let rest = skip_token(rest);
        // Trim trailing whitespace to match scan.rs behaviour: a begin line
        // like "begin 644 foo.txt   " (trailing spaces from mailer wrapping)
        // should produce filename "foo.txt", not "foo.txt   ".
        let rest = rest
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|pos| &rest[..=pos])
            .unwrap_or(b"");
        String::from_utf8_lossy(rest).into_owned()
    };

    // --- Decode data lines, stopping at max_bytes ---
    let mut data: Vec<u8> = Vec::new();
    let mut is_truncated = true;
    let mut was_limit_hit = false;
    let data_lines = &lines[begin_idx + 1..];

    'outer: for (rel_idx, &line) in data_lines.iter().enumerate() {
        // Stop early only when we have strictly more bytes than the limit.
        // At exactly max bytes we must still process the current line: if it is
        // the terminator (decode_line returns Ok(0)) the look-ahead below will
        // find "end" and correctly set is_truncated=false.  If it is a data
        // line, decode_line will push more bytes and the post-loop truncation
        // below will clamp data to max and set is_truncated=true.
        if data.len() > max {
            is_truncated = true;
            was_limit_hit = true;
            break;
        }
        match decode_line(line, &mut data) {
            Ok(0) => {
                // Terminator line found. Look ahead for "end".
                for &subsequent in &data_lines[rel_idx + 1..] {
                    if subsequent.eq_ignore_ascii_case(b"end") {
                        is_truncated = false;
                        break 'outer;
                    }
                    if !subsequent.is_empty() {
                        break;
                    }
                }
                break 'outer;
            }
            Ok(_) => {}
            Err(_) => {
                is_truncated = true;
                break 'outer;
            }
        }
    }

    // Truncate to max_bytes if a data line pushed us over.
    if data.len() > max {
        data.truncate(max);
        is_truncated = true;
        was_limit_hit = true;
    }

    Ok(DecodedBlock {
        data,
        metadata: BlockMetadata { filename, mode },
        is_truncated,
        was_limit_hit,
    })
}

/// Decodes one UU data line into `out`.
///
/// `line` must already have leading/trailing whitespace and `\r` stripped.
/// Returns the number of decoded bytes appended to `out`, or an error if
/// any encoded byte is outside the valid UU character range.
pub(crate) fn decode_line(line: &[u8], out: &mut Vec<u8>) -> Result<usize, crate::error::UuError> {
    // Step 1: strip trailing \r defensively
    let line = line.strip_suffix(b"\r").unwrap_or(line);

    // Step 2: terminator detection
    if line.is_empty() {
        return Ok(0);
    }
    let first = line[0];
    if first == b'`' || first == b' ' {
        return Ok(0);
    }

    // Step 3: read length byte
    let n = (first.wrapping_sub(32)) & 0x3F;

    // Step 4: zero-length
    if n == 0 {
        return Ok(0);
    }

    // Step 5: number of encoded bytes needed
    let encoded_needed = (n as usize).div_ceil(3) * 4;

    // Helper: decode one UU-encoded byte to its 6-bit value.
    // col is the 0-based index into the encoded payload (after the length byte).
    let decode_byte = |c: u8, col: usize| -> Result<u8, crate::error::UuError> {
        if c == b'`' {
            Ok(0)
        } else if (0x20..=0x5F).contains(&c) {
            Ok(c - 0x20)
        } else {
            Err(crate::error::UuError::InvalidChar { col, byte: c })
        }
    };

    // The encoded payload starts at index 1 (after the length byte).
    let payload = &line[1..];

    // Step 6 & 7: decode groups of 4 encoded bytes into up to 3 decoded bytes
    let mut decoded = 0usize;
    let mut group = 0usize;
    while decoded < n as usize {
        let base = group * 4;

        // Fetch 4 encoded bytes, padding with 0x20 if line is short.
        // Two independent guards:
        //   idx < payload.len()     — prevents out-of-bounds on a truncated line
        //   base + i < encoded_needed — prevents reading garbage chars that a
        //                              mailer may have appended after the last
        //                              encoded group (both must hold to use the
        //                              real byte; either failing pads with 0x20).
        let get = |i: usize| -> u8 {
            let idx = base + i;
            if idx < payload.len() && base + i < encoded_needed {
                payload[idx]
            } else {
                0x20
            }
        };

        let a = decode_byte(get(0), base)?;
        let b = decode_byte(get(1), base + 1)?;
        let c = decode_byte(get(2), base + 2)?;
        let d = decode_byte(get(3), base + 3)?;

        let b0 = (a << 2) | (b >> 4);
        let b1 = (b << 4) | (c >> 2);
        let b2 = (c << 6) | d;

        // Step 7: emit exactly N bytes total, stop mid-group if needed
        if decoded < n as usize {
            out.push(b0);
            decoded += 1;
        }
        if decoded < n as usize {
            out.push(b1);
            decoded += 1;
        }
        if decoded < n as usize {
            out.push(b2);
            decoded += 1;
        }

        group += 1;
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{decode as decode_block, decode_limited, decode_line};
    use crate::error::UuError;

    fn decode(line: &[u8]) -> Result<Vec<u8>, UuError> {
        let mut out = Vec::new();
        decode_line(line, &mut out)?;
        Ok(out)
    }

    // Oracle: python3 -c "import binascii; print(binascii.b2a_uu(b'Cat').rstrip(b'\n'))"
    // => b'#0V%T'
    #[test]
    fn three_bytes_cat() {
        // input: 436174  encoded: 2330562554
        let line = b"#0V%T";
        assert_eq!(decode(line).unwrap(), b"Cat");
    }

    // Oracle: binascii.b2a_uu(bytes(range(45))).rstrip(b'\n')
    // => b'M  $" P0%!@<("0H+# T.#Q 1$A,4%187&!D:&QP=\'A\\@(2(C)"4F)R@I*BLL'
    #[test]
    fn full_45_byte_line() {
        let line = b"M  $\" P0%!@<(\"0H+# T.#Q 1$A,4%187&!D:&QP='A\\@(2(C)\"4F)R@I*BLL";
        let expected: Vec<u8> = (0u8..45).collect();
        assert_eq!(decode(line).unwrap(), expected);
    }

    // Oracle: binascii.b2a_uu(b'A').rstrip(b'\n') => b'!00  '
    // input: 41  encoded: 2130302020
    #[test]
    fn one_byte() {
        let line = b"!00  ";
        assert_eq!(decode(line).unwrap(), b"A");
    }

    // Oracle: binascii.b2a_uu(b'AB').rstrip(b'\n') => b'"04( '
    // input: 4142  encoded: 2230342820
    #[test]
    fn two_bytes() {
        let line = b"\"04( ";
        assert_eq!(decode(line).unwrap(), b"AB");
    }

    // Oracle: binascii.b2a_uu(b'\x00\x00\x00').rstrip(b'\n') => b'#    '
    // input: 000000  encoded: 2320202020
    #[test]
    fn null_bytes() {
        let line = b"#    ";
        assert_eq!(decode(line).unwrap(), b"\x00\x00\x00");
    }

    // Terminator: backtick (0x60) as first byte → Ok(0), no output
    #[test]
    fn backtick_terminator() {
        let mut out = Vec::new();
        let n = decode_line(b"`", &mut out).unwrap();
        assert_eq!(n, 0);
        assert!(out.is_empty());
    }

    // Terminator: space (0x20) as first byte → Ok(0), no output
    #[test]
    fn space_terminator() {
        let mut out = Vec::new();
        let n = decode_line(b" ", &mut out).unwrap();
        assert_eq!(n, 0);
        assert!(out.is_empty());
    }

    // Empty line → Ok(0), no output
    #[test]
    fn empty_line() {
        let mut out = Vec::new();
        let n = decode_line(b"", &mut out).unwrap();
        assert_eq!(n, 0);
        assert!(out.is_empty());
    }

    // Backtick (0x60) treated as zero value in data positions.
    // Manually construct: length byte '#' (3 bytes), then 4 encoded bytes all 0x60.
    // 0x60 as encoded value = 0, so decoded = 0x00 0x00 0x00
    #[test]
    fn backtick_as_zero_in_data() {
        // '#' = 0x23 = 3 bytes, followed by four 0x60 bytes
        let line = b"#````";
        assert_eq!(decode(line).unwrap(), b"\x00\x00\x00");
    }

    // 0x20 (space) treated as zero value in data positions.
    // Same as null_bytes test: '#' then four spaces
    #[test]
    fn space_as_zero_in_data() {
        let line = b"#    ";
        assert_eq!(decode(line).unwrap(), b"\x00\x00\x00");
    }

    // Invalid character: 0x61 ('a') is above 0x5F and not 0x60 → error
    #[test]
    fn invalid_char_error() {
        // '!' = 1 byte, then 0x61 ('a') as first encoded byte
        let line = b"!a   ";
        let err = decode(line).unwrap_err();
        assert!(matches!(err, UuError::InvalidChar { byte: 0x61, .. }));
    }

    // Line shorter than length implies → pad with spaces (treat as 0x20 = 0)
    // '#' says 3 bytes, but we only provide 2 encoded bytes after the length.
    // Missing bytes treated as 0x20 = 0.
    // '!' (1 encoded byte) followed by nothing. '!' => a=1, rest=0 => b0 = (1<<2)|(0>>4) = 4
    // But the length byte says 1, so only b0 is emitted.
    #[test]
    fn short_line_padded_with_spaces() {
        // length byte '!' = 1 byte, then single encoded byte '0' (0x30 - 0x20 = 0x10 = 16)
        // a=16, b=0, c=0, d=0 (padded)
        // b0 = (16<<2)|(0>>4) = 64 = 0x40
        let line = b"!0";
        let result = decode(line).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0x40);
    }

    // Trailing \r is stripped defensively
    #[test]
    fn trailing_cr_stripped() {
        let line = b"#0V%T\r";
        assert_eq!(decode(line).unwrap(), b"Cat");
    }

    // Chars beyond encoded_needed are ignored
    #[test]
    fn extra_chars_ignored() {
        // '#0V%T' normally decodes 'Cat'; add garbage after
        let line = b"#0V%T!!!!!!";
        assert_eq!(decode(line).unwrap(), b"Cat");
    }

    // ---- decode() (full block) tests ----
    //
    // Oracle: python3 with the `uu` stdlib module (Python 3.11).
    // All encoded strings are taken verbatim from oracle output; the decoded
    // byte values are independently known.

    /// Oracle (Python 3.11 `uu` module, 2026-05-04):
    ///   data = b'Hello, World!'  fname='hello.txt'  mode=0o644
    ///   encoded = b"begin 644 hello.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n"
    #[test]
    fn well_formed_hello() {
        let input = b"begin 644 hello.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.data, b"Hello, World!");
        assert_eq!(block.metadata.filename, "hello.txt");
        assert_eq!(block.metadata.mode, 0o644);
        assert!(!block.is_truncated);
    }

    /// Oracle: same as well_formed_hello but with CRLF line endings throughout.
    /// binascii.b2a_uu(b'Hello, World!') => b'-2&5L;&\\L(%=O<FQD(0  \n'
    #[test]
    fn crlf_line_endings() {
        let input = b"begin 644 hello.txt\r\n-2&5L;&\\L(%=O<FQD(0  \r\n \r\nend\r\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.data, b"Hello, World!");
        assert_eq!(block.metadata.filename, "hello.txt");
        assert_eq!(block.metadata.mode, 0o644);
        assert!(!block.is_truncated);
    }

    /// Oracle:
    ///   data='' fname='empty.txt' mode=644
    ///   encoded=b'begin 644 empty.txt\n \nend\n'
    #[test]
    fn empty_data() {
        let input = b"begin 644 empty.txt\n \nend\n";
        let block = decode_block(input).unwrap();
        assert!(block.data.is_empty());
        assert_eq!(block.metadata.filename, "empty.txt");
        assert_eq!(block.metadata.mode, 0o644);
        assert!(!block.is_truncated);
    }

    /// Oracle (Python 3.11 `uu` module, 2026-05-04):
    ///   data = bytes(range(45))  fname='full_line.bin'  mode=0o644
    ///   encoded = b"begin 644 full_line.bin\n
    ///     M  $\" P0%!@<(\"0H+# T.#Q 1$A,4%187&!D:&QP='A\\@(2(C)\"4F)R@I*BLL\n
    ///     \\ \nend\n"
    #[test]
    fn full_45_byte_block() {
        let input = b"begin 644 full_line.bin\nM  $\" P0%!@<(\"0H+# T.#Q 1$A,4%187&!D:&QP='A\\@(2(C)\"4F)R@I*BLL\n \nend\n";
        let block = decode_block(input).unwrap();
        let expected: Vec<u8> = (0u8..45).collect();
        assert_eq!(block.data, expected);
        assert_eq!(block.metadata.filename, "full_line.bin");
        assert_eq!(block.metadata.mode, 0o644);
        assert!(!block.is_truncated);
    }

    /// Oracle (Python 3.11 `uu` module, 2026-05-04):
    ///   data = bytes(range(46))  fname='two_lines.bin'  mode=0o755
    ///   encoded = b"begin 755 two_lines.bin\n
    ///     M  $\" P0%!@<(\"0H+# T.#Q 1$A,4%187&!D:&QP='A\\@(2(C)\"4F)R@I*BLL\n
    ///     !+0  \n \nend\n"
    #[test]
    fn two_line_block_mode_755() {
        let input = b"begin 755 two_lines.bin\nM  $\" P0%!@<(\"0H+# T.#Q 1$A,4%187&!D:&QP='A\\@(2(C)\"4F)R@I*BLL\n!+0  \n \nend\n";
        let block = decode_block(input).unwrap();
        let expected: Vec<u8> = (0u8..46).collect();
        assert_eq!(block.data, expected);
        assert_eq!(block.metadata.mode, 0o755);
        assert_eq!(block.metadata.filename, "two_lines.bin");
        assert!(!block.is_truncated);
    }

    /// begin-base64 → Err(UuError::BeginBase64)
    #[test]
    fn begin_base64_error() {
        let input = b"begin-base64 644 foo.txt\nSGVsbG8=\n====\nend\n";
        let err = decode_block(input).unwrap_err();
        assert_eq!(err, UuError::BeginBase64);
    }

    /// begin-base64 is case-insensitive
    #[test]
    fn begin_base64_case_insensitive() {
        let input = b"BEGIN-BASE64 644 foo.txt\nSGVsbG8=\n====\nend\n";
        let err = decode_block(input).unwrap_err();
        assert_eq!(err, UuError::BeginBase64);
    }

    /// Malformed begin line (just "begin", no mode or filename)
    #[test]
    fn malformed_begin_no_mode_no_filename() {
        // "begin" alone: tokens[0]="begin", no tokens[1]. Per spec this should
        // NOT be an error — mode defaults to 0, filename is "".
        // Actually the task says: ≥2 tokens minimum? Re-reading the spec:
        // tokens[0]="begin", tokens[1]=mode (default 0 on parse failure), tokens[2..]=filename.
        // A bare "begin" with no tokens after is treated as mode=0, filename="".
        // The spec says Err only when NO "begin" line is found. Bare "begin " with
        // empty remainder is valid. But "begin\n \nend\n" with no space at all
        // has no mode/filename tokens — defaults apply.
        let input = b"begin\n \nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.metadata.mode, 0);
        assert_eq!(block.metadata.filename, "");
    }

    /// No begin line at all → Err(UuError::InvalidBeginLine { line: "" })
    #[test]
    fn no_begin_line() {
        let input = b"some random text\nM  $\"\n \nend\n";
        let err = decode_block(input).unwrap_err();
        assert_eq!(
            err,
            UuError::InvalidBeginLine {
                line: String::new()
            }
        );
    }

    /// Missing end line → Ok with is_truncated=true
    #[test]
    fn missing_end_line() {
        // Data line present but no terminator and no end line.
        // Uses oracle hello data line (b"Hello, World!" encoded).
        let input = b"begin 644 foo.txt\n-2&5L;&\\L(%=O<FQD(0  \n";
        let block = decode_block(input).unwrap();
        assert!(block.is_truncated);
        assert!(!block.data.is_empty());
    }

    /// No terminator line → is_truncated=true
    #[test]
    fn no_terminator_or_end() {
        let input = b"begin 644 foo.txt\n-2&5L;&\\L(%=O<FQD(0  \n";
        let block = decode_block(input).unwrap();
        assert!(block.is_truncated);
    }

    /// Trailing whitespace on begin line is stripped from filename, matching scan().
    /// A mailer that wraps or adds a trailing space should not affect the filename.
    #[test]
    fn trailing_whitespace_on_begin_line_stripped_from_filename() {
        // Three trailing spaces after the filename.
        let input = b"begin 644 foo.txt   \n \nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(
            block.metadata.filename, "foo.txt",
            "trailing whitespace must be stripped to match scan() behaviour"
        );
        assert_eq!(block.metadata.mode, 0o644);
    }

    /// Filename with spaces: "begin 644 My File.doc" → filename="My File.doc"
    #[test]
    fn filename_with_spaces() {
        let input = b"begin 644 My File.doc\n \nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.metadata.filename, "My File.doc");
        assert_eq!(block.metadata.mode, 0o644);
    }

    /// Empty filename: "begin 644 " → filename=""
    #[test]
    fn empty_filename() {
        let input = b"begin 644 \n \nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.metadata.filename, "");
        assert_eq!(block.metadata.mode, 0o644);
    }

    /// Tabs in begin line treated as whitespace: "begin\t644\tfoo.txt"
    #[test]
    fn tabs_in_begin_line() {
        let input = b"begin\t644\tfoo.txt\n \nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.metadata.filename, "foo.txt");
        assert_eq!(block.metadata.mode, 0o644);
    }

    /// mode 0644 octal == 420 decimal
    #[test]
    fn mode_octal_to_decimal() {
        let input = b"begin 644 foo.txt\n \nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.metadata.mode, 420u32); // 0o644 == 420
    }

    /// Backtick as terminator line accepted.
    /// Oracle: same hello encoding as well_formed_hello but with backtick terminator.
    #[test]
    fn backtick_terminator_block() {
        let input = b"begin 644 foo.txt\n-2&5L;&\\L(%=O<FQD(0  \n`\nend\n";
        let block = decode_block(input).unwrap();
        assert_eq!(block.data, b"Hello, World!");
        assert!(!block.is_truncated);
    }

    /// Leading garbage lines before begin are skipped
    #[test]
    fn leading_garbage_skipped() {
        let input = b"This is some prose text.\nMore text here.\nbegin 644 foo.txt\n \nend\n";
        let block = decode_block(input).unwrap();
        assert!(block.data.is_empty());
        assert_eq!(block.metadata.filename, "foo.txt");
        assert!(!block.is_truncated);
    }

    /// No panic on empty input
    #[test]
    fn empty_input_no_panic() {
        let err = decode_block(b"").unwrap_err();
        assert!(matches!(err, UuError::InvalidBeginLine { .. }));
    }

    /// No panic on single newline
    #[test]
    fn single_newline_no_panic() {
        let err = decode_block(b"\n").unwrap_err();
        assert!(matches!(err, UuError::InvalidBeginLine { .. }));
    }

    /// Decode error on data line → partial Ok with is_truncated=true
    #[test]
    fn decode_error_yields_partial() {
        // Valid begin, one good data line ('Cat'), then an invalid data line.
        // '!' = 1 byte, 'a' is invalid (0x61 > 0x5f and not 0x60).
        let input = b"begin 644 foo.txt\n#0V%T\n!a   \n \nend\n";
        let block = decode_block(input).unwrap();
        // First line decoded to "Cat" before the error
        assert_eq!(block.data, b"Cat");
        assert!(block.is_truncated);
    }

    // ---- decode_limited() edge-case tests ----
    //
    // Block used throughout: "begin 644 f\n#0V%T\n \nend\n"
    //   - data line "#0V%T" encodes "Cat" (3 bytes)
    // Oracle: python3 -c "import binascii; print(binascii.b2a_uu(b'Cat').rstrip(b'\n'))"
    //   => b'#0V%T'

    /// Exact limit: max_bytes == decoded size of a complete block.
    /// Regression for P0 bug: limit check at loop start must not fire on the
    /// terminator line when data.len() == max, which would leave is_truncated=true.
    #[test]
    fn decode_limited_exact_limit_is_not_truncated() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        let block = decode_limited(input, Some(3)).unwrap();
        assert_eq!(block.data, b"Cat");
        assert!(
            !block.is_truncated,
            "exact-limit complete block must not be truncated"
        );
    }

    /// Over limit: max_bytes < decoded size → data clamped, is_truncated=true.
    #[test]
    fn decode_limited_over_limit_is_truncated() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        let block = decode_limited(input, Some(2)).unwrap();
        assert_eq!(block.data.len(), 2);
        assert!(block.is_truncated);
    }

    /// Zero limit: no bytes decoded, is_truncated=true.
    #[test]
    fn decode_limited_zero_limit() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        let block = decode_limited(input, Some(0)).unwrap();
        assert!(block.data.is_empty());
        assert!(block.is_truncated);
    }

    /// Zero limit on an empty (zero-byte) block: no data to truncate → is_truncated=false.
    #[test]
    fn decode_limited_zero_limit_empty_block_not_truncated() {
        // Empty UU block: begin line, backtick terminator, end line.
        // Oracle: Python uu.encode(b"") → "begin 644 f\n`\nend\n"
        let input = b"begin 644 f\n`\nend\n";
        let block = decode_limited(input, Some(0)).unwrap();
        assert!(block.data.is_empty());
        // Zero bytes decoded, limit never exceeded → block is structurally complete.
        assert!(
            !block.is_truncated,
            "empty block with max=0 should not be truncated"
        );
    }

    /// None limit: equivalent to decode() — complete block, is_truncated=false.
    #[test]
    fn decode_limited_none_limit_equals_decode() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        let block = decode_limited(input, None).unwrap();
        assert_eq!(block.data, b"Cat");
        assert!(!block.is_truncated);
    }

    /// Limit larger than decoded size: complete block, is_truncated=false.
    #[test]
    fn decode_limited_large_limit_not_truncated() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        let block = decode_limited(input, Some(100)).unwrap();
        assert_eq!(block.data, b"Cat");
        assert!(!block.is_truncated);
    }

    // ---- was_limit_hit field tests ----

    /// was_limit_hit = true when max_bytes fires during decoding.
    #[test]
    fn decode_limited_was_limit_hit_true_when_truncated_by_limit() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        // max_bytes=2 < 3 decoded bytes → limit fires
        let block = decode_limited(input, Some(2)).unwrap();
        assert!(block.is_truncated);
        assert!(block.was_limit_hit, "limit hit must set was_limit_hit");
    }

    /// was_limit_hit = false when block truncated by missing end line (not limit).
    #[test]
    fn decode_limited_was_limit_hit_false_when_truncated_by_missing_end() {
        // Missing end line — is_truncated=true but was_limit_hit=false.
        let input = b"begin 644 f\n#0V%T\n";
        let block = decode_limited(input, Some(100)).unwrap();
        assert!(block.is_truncated);
        assert!(
            !block.was_limit_hit,
            "missing-end truncation must not set was_limit_hit"
        );
    }

    /// was_limit_hit = false on a complete block (no limit).
    #[test]
    fn decode_limited_was_limit_hit_false_when_complete() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        let block = decode_limited(input, None).unwrap();
        assert!(!block.is_truncated);
        assert!(!block.was_limit_hit);
    }

    /// was_limit_hit = false on exact-limit complete block (limit == decoded size).
    #[test]
    fn decode_limited_was_limit_hit_false_on_exact_limit() {
        let input = b"begin 644 f\n#0V%T\n \nend\n";
        // max_bytes == 3 (exact decoded size) → complete, limit never exceeded
        let block = decode_limited(input, Some(3)).unwrap();
        assert!(!block.is_truncated);
        assert!(
            !block.was_limit_hit,
            "exact-limit complete block must not set was_limit_hit"
        );
    }
}
