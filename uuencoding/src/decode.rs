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
pub fn decode(input: &[u8]) -> Result<DecodedBlock, UuError> {
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
    if begin_line.len() >= 12 && begin_line[..12].eq_ignore_ascii_case(b"begin-base64") {
        return Err(UuError::BeginBase64);
    }

    // --- Parse begin line ---
    // Split on ASCII whitespace; tokens[0]="begin", tokens[1]=mode, tokens[2..]=filename
    let tokens: Vec<&[u8]> = begin_line
        .split(|b: &u8| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty())
        .collect();

    // Need at least "begin" token; everything else has a sensible default.
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

    // Filename: everything after "begin <mode>" on the original line,
    // preserving internal spaces. We skip two whitespace-separated tokens
    // ("begin" and the mode) then take the rest of the raw line as-is.
    let filename: String = {
        // skip_token advances past a run of non-whitespace, then past trailing
        // whitespace, returning the remainder.
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
        let rest = skip_token(begin_line); // skip "begin"
        let rest = skip_token(rest); // skip mode
        String::from_utf8_lossy(rest).into_owned()
    };

    // --- Decode data lines ---
    let mut data: Vec<u8> = Vec::new();
    let mut is_truncated = true;
    let data_lines = &lines[begin_idx + 1..];

    'outer: for (rel_idx, &line) in data_lines.iter().enumerate() {
        match decode_line(line, &mut data) {
            Ok(0) => {
                // Terminator line found.  Look ahead for "end".
                for &subsequent in &data_lines[rel_idx + 1..] {
                    if subsequent.eq_ignore_ascii_case(b"end") {
                        is_truncated = false;
                        break 'outer;
                    }
                    // Skip blank lines; stop if we hit something non-blank, non-end.
                    if !subsequent.is_empty() {
                        break;
                    }
                }
                // No "end" found — truncated.
                break 'outer;
            }
            Ok(_) => {} // normal data line
            Err(_) => {
                // Decode error → partial result.
                is_truncated = true;
                break 'outer;
            }
        }
    }

    Ok(DecodedBlock {
        data,
        metadata: BlockMetadata { filename, mode },
        is_truncated,
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
            Err(crate::error::UuError::InvalidChar {
                line: 0,
                col,
                byte: c,
            })
        }
    };

    // The encoded payload starts at index 1 (after the length byte).
    let payload = &line[1..];

    // Step 6 & 7: decode groups of 4 encoded bytes into up to 3 decoded bytes
    let mut decoded = 0usize;
    let mut group = 0usize;
    while decoded < n as usize {
        let base = group * 4;

        // Fetch 4 encoded bytes, padding with 0x20 if line is short
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
    use super::{decode as decode_block, decode_line};
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
}
