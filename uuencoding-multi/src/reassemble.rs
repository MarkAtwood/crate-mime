use crate::{MultiUuError, PartCollection};

/// A successfully reassembled multi-part UU-encoded file.
///
/// Returned by [`reassemble`]. The `data` field holds the decoded binary
/// payload; callers should inspect `is_truncated` before trusting the result.
///
/// # Security note
///
/// `data` may contain a compressed archive. **This crate never decompresses
/// the output.** Apply independent size and resource limits before
/// decompressing to protect against decompression-bomb attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledFile {
    /// Filename from the first UU `begin` line in the concatenated parts
    /// (normally part 1's). The subject line is never used.
    ///
    /// **Security — path traversal**: the filename comes directly from the
    /// email or Usenet message and is not sanitised. Real-world UU archives
    /// have been observed with filenames containing `../` sequences. Sanitise
    /// this value before using it as a filesystem path to prevent directory
    /// traversal attacks (e.g. reject names containing `/`, `\`, or `..`
    /// components, and resolve the final path against an allowed base
    /// directory).
    pub filename: String,
    /// Unix permission mode (e.g. `0o644`) from the same `begin` line as
    /// [`filename`][Self::filename]. If later parts repeat the `begin` line
    /// with a different mode, only the first value is used.
    pub mode: u32,
    /// Decoded binary payload.
    ///
    /// When [`is_truncated`][Self::is_truncated] is `false`, this is the
    /// complete decoded file content, formed by concatenating the UU text of
    /// every part in ascending `part_number` order and decoding it once.
    ///
    /// # When `is_truncated` is `true`
    ///
    /// `data` contains **only the decoded bytes of the parts that were
    /// present** (up to the first undecodable line), in ascending part-number
    /// order. This is **not**
    /// a contiguous region of the reconstructed file: the bytes belonging to
    /// the absent parts are simply missing from the middle (or start, or end).
    /// The resulting byte sequence does **not** correspond to any valid file
    /// offset range.
    ///
    /// **Do not write truncated data to disk as if it were a complete file.**
    /// The bytes are provided for diagnostic inspection only (e.g. logging,
    /// partial-content display). To obtain a usable file, wait until
    /// [`is_complete()`][crate::PartCollection::is_complete] returns `true`
    /// before calling [`reassemble`].
    pub data: Vec<u8>,
    /// `true` when the data is likely incomplete or corrupt: one or more
    /// parts were absent from the collection, or the concatenated UU text was
    /// itself defective (no final `end` line, an undecodable data line, a
    /// per-part-framed part that ran into the next part without its `end`,
    /// or a repeated `begin` line naming a different file).
    ///
    /// To distinguish the two kinds of cause:
    /// - `is_truncated && !missing_parts.is_empty()` — gap in the collection.
    /// - `is_truncated && missing_parts.is_empty()` — all parts were present
    ///   but the UU text itself was defective.
    pub is_truncated: bool,
    /// Part numbers in `1..=total` that were absent from the collection, in
    /// ascending order. Empty when the collection was complete. Same value
    /// as [`PartCollection::missing_parts`][crate::PartCollection::missing_parts],
    /// including its length cap.
    pub missing_parts: Vec<u32>,
}

/// Reassemble a multi-part UU-encoded file from its parts.
///
/// Takes all [`PartEntry`][crate::PartEntry] values with `part_number >= 1`
/// in ascending order (the [`PartCollection`]'s `BTreeMap` guarantees this),
/// concatenates their `body_bytes` into one UU text, and decodes it once with
/// `uuencoding::decode`. `filename` and `mode` come from the first `begin`
/// line.
///
/// The TOC part (`part_number = 0`), if present, is silently ignored.
///
/// # Supported layouts
///
/// - **Split stream** (the classic Usenet layout): only the first part has
///   the `begin` line and only the last part has the terminator and `end`
///   line; the parts in between are bare data lines. Bodies are joined as
///   they are (a missing final newline is supplied).
/// - **Per-part framing**: every part is a complete `begin` … `end` block for
///   the same file. When a part after the first has its own `begin` line, the
///   text before and including that `begin` line is dropped, as is anything
///   after the part's `end` line, and the previous part's closing terminator
///   and `end` lines are removed, so the data lines join into one stream.
///
/// A closing `end` that is followed by another part is never treated as the
/// end of the file, so later parts are not silently ignored.
///
/// # Errors
///
/// - [`MultiUuError::EmptyCollection`] — the collection contains no parts
///   with `part_number >= 1` (including the case of a TOC-only collection).
/// - [`MultiUuError::DecodeError`] — `uuencoding::decode` returned an error
///   for the concatenated text: no `begin` line in any present part
///   ([`InvalidBeginLine`][uuencoding::UuError::InvalidBeginLine], e.g.
///   because the part carrying it is missing), or the first `begin` line is
///   `begin-base64` ([`BeginBase64`][uuencoding::UuError::BeginBase64]).
///
/// # Partial results
///
/// When parts are missing the function still returns `Ok` rather than an
/// error (provided some present part carries the `begin` line). The result
/// has `is_truncated = true` and `missing_parts` listing the absent part
/// numbers. `data` contains the decoded bytes of only the **present** parts
/// concatenated in order. Defects in the UU text itself (no final `end`, an
/// undecodable line) also produce `Ok` with `is_truncated = true`; see
/// [`ReassembledFile::is_truncated`].
///
/// **This is not a contiguous file region.** The bytes from the missing parts
/// are absent, so the data does not correspond to a valid byte range within
/// the original file. Do not write this to disk as a complete file. It is
/// suitable for diagnostics only. Call
/// [`PartCollection::is_complete()`][crate::PartCollection::is_complete]
/// before reassembling if you require a usable result.
///
/// # Never panics
///
/// This function never panics. The `unreachable!` on the internal `get()`
/// call cannot be reached by construction: `present_parts()` only yields
/// numbers that are keys in the underlying map.
///
/// # Security
///
/// The decoded `data` may be a compressed archive. Any subsequent
/// decompression is the caller's responsibility and must be independently
/// guarded against decompression-bomb attacks. This crate does not
/// decompress.
///
/// The `filename` field of the returned [`ReassembledFile`] comes from the
/// UU `begin` line and is **not sanitised**. Sanitise it
/// before using it as a filesystem path to prevent directory traversal
/// attacks.
///
/// # Example
///
/// ```no_run
/// use uuencoding_multi::{PartCollection, PartEntry, reassemble};
///
/// // In practice `body_bytes` comes from message parts fetched from NNTP
/// // or a mailbox; `no_run` is used here because constructing valid UU
/// // bodies inline is verbose.
/// let mut coll = PartCollection::with_total(2);
/// coll.add(PartEntry { part_number: 1, body_bytes: todo!(), subject: None }).unwrap();
/// coll.add(PartEntry { part_number: 2, body_bytes: todo!(), subject: None }).unwrap();
///
/// let file = reassemble(&coll).unwrap();
/// assert!(!file.is_truncated);
/// // Apply size limits before decompressing file.data.
/// println!("{}: {} bytes", file.filename, file.data.len());
/// ```
pub fn reassemble(collection: &PartCollection) -> Result<ReassembledFile, MultiUuError> {
    // Collect present part numbers >= 1, in ascending order (BTreeMap guarantees this).
    let present: Vec<u32> = collection.present_parts().filter(|&n| n >= 1).collect();

    if present.is_empty() {
        return Err(MultiUuError::EmptyCollection);
    }

    let missing_parts = collection.missing_parts();

    let mut stream = Stream::default();
    for part_num in &present {
        let entry = collection
            .get(*part_num)
            .unwrap_or_else(|| unreachable!("present_parts listed a part that get() cannot find"));
        stream.push_part(&entry.body_bytes);
    }

    let block = uuencoding::decode(&stream.bytes)?;

    let is_truncated = block.is_truncated || stream.suspect || !missing_parts.is_empty();

    Ok(ReassembledFile {
        filename: block.metadata.filename,
        mode: block.metadata.mode,
        data: block.data,
        is_truncated,
        missing_parts,
    })
}

/// The concatenated UU text of all parts, built part by part.
///
/// Two layouts are supported (see [`reassemble`]):
///
/// - **Split stream** (classic Usenet): only the first part has `begin`,
///   only the last has the terminator and `end`; part bodies are appended
///   verbatim.
/// - **Per-part framing**: every part carries its own `begin`/`end`. A part
///   with its own `begin` line after the stream has started is a
///   continuation: the previous closing terminator/`end` is removed from the
///   stream, the part's text before and including its `begin` line is
///   dropped, and its text after its `end` line is dropped.
#[derive(Default)]
struct Stream {
    /// Concatenated UU text, every line terminated by `\n` (or `\r\n`).
    bytes: Vec<u8>,
    /// Filename from the first `begin` line, once one has been appended.
    filename: Option<String>,
    /// Set when the layout shows that data is probably lost or mixed: a
    /// per-part-framed part ran into the next part without its `end`, or a
    /// continuation `begin` names a different file.
    suspect: bool,
}

impl Stream {
    fn push_part(&mut self, body: &[u8]) {
        let lines: Vec<&[u8]> = body.split_inclusive(|&b| b == b'\n').collect();
        let begin = lines
            .iter()
            .enumerate()
            .find_map(|(i, l)| begin_filename(strip_eol(l)).map(|name| (i, name)));

        let started = self.filename.is_some();
        // Lines of this part to append, after per-part framing is removed.
        let body_lines: &[&[u8]] = match (started, begin) {
            // Before the first `begin`: append verbatim; `uuencoding::decode`
            // skips any text before the `begin` line.
            (false, None) => &lines,
            (false, Some((i, name))) => {
                self.filename = Some(name);
                cut_after_end(&lines[i..])
            }
            // Split-stream continuation: a part that closed the stream with
            // `end` but is followed by another part was not really the end;
            // reopen it so the following data is decoded (or, if it is not
            // UU data, makes the result truncated rather than ignored).
            (true, None) => {
                self.pop_closing_trailer();
                &lines
            }
            // Per-part framing: drop this part's repeated `begin` line.
            (true, Some((i, name))) => {
                if !self.pop_closing_trailer() {
                    // The previous segment never reached its `end`: that
                    // post was cut off, so data is probably missing.
                    self.suspect = true;
                }
                if self.filename.as_deref() != Some(name.as_str()) {
                    self.suspect = true;
                }
                cut_after_end(&lines[i + 1..])
            }
        };

        for line in body_lines {
            self.bytes.extend_from_slice(line);
        }
        if self.bytes.last().is_some_and(|&b| b != b'\n') {
            self.bytes.push(b'\n');
        }
    }

    /// Remove a closing `<terminator>` + `end` trailer (with any blank lines
    /// around `end`) from the end of the stream. Returns `true` if an `end`
    /// line was removed. Data lines are never removed.
    fn pop_closing_trailer(&mut self) -> bool {
        let mut len = self.bytes.len();
        let mut found_end = false;
        loop {
            let (start, line) = last_line(&self.bytes[..len]);
            let Some(line) = line else { break };
            if line.is_empty() {
                len = start;
            } else if !found_end && line.eq_ignore_ascii_case(b"end") {
                found_end = true;
                len = start;
            } else if found_end && is_terminator(line) {
                len = start;
                break;
            } else {
                break;
            }
        }
        if found_end {
            self.bytes.truncate(len);
        }
        found_end
    }
}

/// The last line of `buf` (which ends with `\n` or is empty), returned as
/// `(start offset, line without EOL)`; `None` when `buf` is empty.
fn last_line(buf: &[u8]) -> (usize, Option<&[u8]>) {
    if buf.is_empty() {
        return (0, None);
    }
    let body = buf.strip_suffix(b"\n").unwrap_or(buf);
    let start = body.iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
    (start, Some(strip_eol(&buf[start..])))
}

/// Strip a trailing `\n` and then a trailing `\r`.
fn strip_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// A UU terminator line: zero-length data line (backtick or space length).
fn is_terminator(line: &[u8]) -> bool {
    matches!(line.first(), Some(b'`' | b' '))
}

/// The lines up to and including the first `end` line, or all of them.
fn cut_after_end<'a, 'b>(lines: &'a [&'b [u8]]) -> &'a [&'b [u8]] {
    match lines
        .iter()
        .position(|l| strip_eol(l).eq_ignore_ascii_case(b"end"))
    {
        Some(i) => &lines[..=i],
        None => lines,
    }
}

/// If `line` is a UU `begin` line, return its filename.
///
/// Delegates to `uuencoding::decode` on the single line so that the rule for
/// what is a `begin` line is exactly the one the final decode applies.
fn begin_filename(line: &[u8]) -> Option<String> {
    if !line.first().is_some_and(|b| b.eq_ignore_ascii_case(&b'b')) {
        return None;
    }
    uuencoding::decode(line).ok().map(|b| b.metadata.filename)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PartCollection, PartEntry};

    // ------------------------------------------------------------------
    // Oracle: Python 3.11 `uu` module, 2026-05-04
    //
    //   full = b'Hello, World! This is a multi-part test.'  (40 bytes)
    //   p1_data = full[:14]  = b'Hello, World! '
    //   p2_data = full[14:27] = b'This is a mul'
    //   p3_data = full[27:]  = b'ti-part test.'
    //
    //   uu.encode(p1_data, buf, 'file.bin', 0o644)
    //     => b'begin 644 file.bin\n.2&5L;&\\L(%=O<FQD(2  \n \nend\n'
    //   uu.encode(p2_data, buf, 'file.bin', 0o644)
    //     => b'begin 644 file.bin\n-5&AI<R!I<R!A(&UU;   \n \nend\n'
    //   uu.encode(p3_data, buf, 'file.bin', 0o644)
    //     => b'begin 644 file.bin\n-=&DM<&%R="!T97-T+@  \n \nend\n'
    // ------------------------------------------------------------------

    const PART1_BODY: &[u8] = b"begin 644 file.bin\n.2&5L;&\\L(%=O<FQD(2  \n \nend\n";
    const PART2_BODY: &[u8] = b"begin 644 file.bin\n-5&AI<R!I<R!A(&UU;   \n \nend\n";
    const PART3_BODY: &[u8] = b"begin 644 file.bin\n-=&DM<&%R=\"!T97-T+@  \n \nend\n";

    fn make_entry(part_number: u32, body: &[u8]) -> PartEntry {
        PartEntry {
            part_number,
            body_bytes: body.to_vec(),
            subject: None,
        }
    }

    // ------------------------------------------------------------------
    // Single-part reassembly
    // ------------------------------------------------------------------

    /// Oracle: uu.encode(b'Hello, World! ', 'file.bin', 0o644)
    ///   => b'begin 644 file.bin\n.2&5L;&\\L(%=O<FQD(2  \n \nend\n'
    ///   decoded: b'Hello, World! '
    #[test]
    fn single_part_correct_data_and_metadata() {
        let mut c = PartCollection::with_total(1);
        c.add(make_entry(1, PART1_BODY)).unwrap();

        let result = reassemble(&c).unwrap();
        assert_eq!(result.data, b"Hello, World! ");
        assert_eq!(result.filename, "file.bin");
        assert_eq!(result.mode, 0o644);
        assert!(!result.is_truncated);
        assert!(result.missing_parts.is_empty());
    }

    // ------------------------------------------------------------------
    // Three-part reassembly
    // ------------------------------------------------------------------

    /// Oracle: concatenated decoded bytes of all 3 parts = full 40-byte file.
    #[test]
    fn three_parts_full_reassembly() {
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(1, PART1_BODY)).unwrap();
        c.add(make_entry(2, PART2_BODY)).unwrap();
        c.add(make_entry(3, PART3_BODY)).unwrap();

        let result = reassemble(&c).unwrap();
        assert_eq!(result.data, b"Hello, World! This is a multi-part test.");
        assert_eq!(result.filename, "file.bin");
        assert_eq!(result.mode, 0o644);
        assert!(!result.is_truncated);
        assert!(result.missing_parts.is_empty());
    }

    /// Parts arrive out of order — reassembly must sort ascending.
    #[test]
    fn three_parts_out_of_order_still_correct() {
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(3, PART3_BODY)).unwrap();
        c.add(make_entry(1, PART1_BODY)).unwrap();
        c.add(make_entry(2, PART2_BODY)).unwrap();

        let result = reassemble(&c).unwrap();
        assert_eq!(result.data, b"Hello, World! This is a multi-part test.");
        assert!(!result.is_truncated);
    }

    // ------------------------------------------------------------------
    // Missing part — is_truncated + missing_parts populated
    // ------------------------------------------------------------------

    /// Missing part 2 of 3: is_truncated=true, missing_parts=[2],
    /// data = part1 decoded ++ part3 decoded (parts present: 1 and 3).
    #[test]
    fn missing_middle_part_yields_truncated() {
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(1, PART1_BODY)).unwrap();
        // part 2 deliberately omitted
        c.add(make_entry(3, PART3_BODY)).unwrap();

        let result = reassemble(&c).unwrap();
        assert!(result.is_truncated);
        assert_eq!(result.missing_parts, vec![2]);
        // Data contains part1 + part3 decoded bytes
        // Oracle: part1 decoded = b'Hello, World! ', part3 decoded = b'ti-part test.'
        assert_eq!(result.data, b"Hello, World! ti-part test.");
    }

    // ------------------------------------------------------------------
    // Empty collection
    // ------------------------------------------------------------------

    #[test]
    fn empty_collection_returns_error() {
        let c = PartCollection::new();
        let err = reassemble(&c).unwrap_err();
        assert!(matches!(err, MultiUuError::EmptyCollection));
    }

    /// Collection with only a TOC part (part_number=0) has no data parts.
    #[test]
    fn toc_only_is_empty_collection() {
        let mut c = PartCollection::new();
        c.add(PartEntry {
            part_number: 0,
            body_bytes: b"toc data".to_vec(),
            subject: None,
        })
        .unwrap();
        let err = reassemble(&c).unwrap_err();
        assert!(matches!(err, MultiUuError::EmptyCollection));
    }

    // ------------------------------------------------------------------
    // Truncated UU body — all parts present but missing `end` terminator
    // ------------------------------------------------------------------

    /// All parts are present (no gap) and every part has its own `begin`
    /// line, but part 2's body has its ` \nend\n` trailer stripped: the
    /// per-part-framed post was cut off before part 3's `begin`, so data is
    /// probably missing. The result must have is_truncated=true and
    /// missing_parts empty.
    #[test]
    fn truncated_uu_body_with_all_parts_present() {
        // PART2_BODY ends with: <data line> + " \n" + "end\n"
        // Strip the last 6 bytes (" \nend\n") to remove the terminator.
        let truncated_part2: Vec<u8> = PART2_BODY[..PART2_BODY.len() - 6].to_vec();

        let mut c = PartCollection::with_total(3);
        c.add(make_entry(1, PART1_BODY)).unwrap();
        c.add(PartEntry {
            part_number: 2,
            body_bytes: truncated_part2,
            subject: None,
        })
        .unwrap();
        c.add(make_entry(3, PART3_BODY)).unwrap();

        let result = reassemble(&c).unwrap();
        assert!(result.is_truncated, "body missing `end` must be truncated");
        assert!(
            result.missing_parts.is_empty(),
            "all parts were present; missing_parts must be empty"
        );
    }

    // ------------------------------------------------------------------
    // Decode error on first part
    // ------------------------------------------------------------------

    /// A corrupt body (no begin line) → DecodeError
    #[test]
    fn decode_error_on_first_part_propagates() {
        let mut c = PartCollection::with_total(1);
        // No part has a "begin" line → uuencoding::decode returns InvalidBeginLine
        c.add(make_entry(1, b"this is not valid uu data\n"))
            .unwrap();

        let err = reassemble(&c).unwrap_err();
        assert!(matches!(err, MultiUuError::DecodeError(_)));
    }

    /// A second part that is not UU data, after a self-contained first part.
    ///
    /// Parts are concatenated and decoded as one stream, so part 2 is not
    /// decoded on its own (a part without `begin` is normal in a split
    /// stream). Part 1's closing `end` is followed by another part, so it is
    /// not taken as the end of the file; decoding then stops at part 2's
    /// invalid line ('n' = 0x6E is outside the UU alphabet) and the result is
    /// truncated rather than silently ignoring part 2.
    #[test]
    fn undecodable_second_part_yields_truncated() {
        let mut c = PartCollection::with_total(2);
        c.add(make_entry(1, PART1_BODY)).unwrap();
        c.add(make_entry(2, b"not valid uu\n")).unwrap();

        let result = reassemble(&c).unwrap();
        assert!(result.is_truncated);
        assert!(result.missing_parts.is_empty());
        assert_eq!(result.data, b"Hello, World! ");
    }

    // ------------------------------------------------------------------
    // Split-stream layout: only part 1 has `begin`, only the last part has
    // the terminator and `end` (the classic Usenet layout).
    //
    // Hand-built from the same oracle data lines as PART1..3_BODY: UU data
    // lines are self-describing (length character first), so one stream
    // holding these three lines decodes to the full 40-byte file.
    // ------------------------------------------------------------------

    const LINE1: &[u8] = b".2&5L;&\\L(%=O<FQD(2  \n";
    const LINE2: &[u8] = b"-5&AI<R!I<R!A(&UU;   \n";
    const LINE3: &[u8] = b"-=&DM<&%R=\"!T97-T+@  \n";
    const FULL: &[u8] = b"Hello, World! This is a multi-part test.";

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn split_stream_parts() -> [Vec<u8>; 3] {
        [
            cat(&[b"begin 644 file.bin\n", LINE1]),
            LINE2.to_vec(),
            cat(&[LINE3, b" \nend\n"]),
        ]
    }

    #[test]
    fn split_stream_layout_reassembles() {
        let [p1, p2, p3] = split_stream_parts();
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(2, &p2)).unwrap();
        c.add(make_entry(1, &p1)).unwrap();
        c.add(make_entry(3, &p3)).unwrap();

        let result = reassemble(&c).unwrap();
        assert_eq!(result.data, FULL);
        assert_eq!(result.filename, "file.bin");
        assert_eq!(result.mode, 0o644);
        assert!(!result.is_truncated);
        assert!(result.missing_parts.is_empty());
    }

    /// Prose before `begin` in part 1 (including an Apple Mail style
    /// "Begin forwarded message:" line), CRLF line endings, a body without a
    /// final newline, and a signature after `end` in the last part.
    #[test]
    fn split_stream_with_noise_and_crlf() {
        let p1 = cat(&[
            b"Begin forwarded message:\r\n\r\nHere it is.\r\n",
            b"begin 644 file.bin\r\n",
            &LINE1[..LINE1.len() - 1],
            b"\r\n",
        ]);
        let p2 = LINE2[..LINE2.len() - 1].to_vec(); // no trailing newline
        let p3 = cat(&[LINE3, b"`\nend\n-- \nsig\n"]);
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(1, &p1)).unwrap();
        c.add(make_entry(2, &p2)).unwrap();
        c.add(make_entry(3, &p3)).unwrap();

        let result = reassemble(&c).unwrap();
        assert_eq!(result.data, FULL);
        assert_eq!(result.filename, "file.bin");
        assert!(!result.is_truncated);
    }

    #[test]
    fn split_stream_missing_middle_part() {
        let [p1, _, p3] = split_stream_parts();
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(1, &p1)).unwrap();
        c.add(make_entry(3, &p3)).unwrap();

        let result = reassemble(&c).unwrap();
        assert!(result.is_truncated);
        assert_eq!(result.missing_parts, vec![2]);
        assert_eq!(result.data, b"Hello, World! ti-part test.");
    }

    #[test]
    fn split_stream_missing_last_part() {
        let [p1, p2, _] = split_stream_parts();
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(1, &p1)).unwrap();
        c.add(make_entry(2, &p2)).unwrap();

        let result = reassemble(&c).unwrap();
        assert!(result.is_truncated);
        assert_eq!(result.missing_parts, vec![3]);
        assert_eq!(result.data, b"Hello, World! This is a mul");
    }

    /// Without part 1 there is no `begin` line, so nothing can be decoded.
    #[test]
    fn split_stream_missing_first_part_is_decode_error() {
        let [_, p2, p3] = split_stream_parts();
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(2, &p2)).unwrap();
        c.add(make_entry(3, &p3)).unwrap();

        let err = reassemble(&c).unwrap_err();
        assert!(matches!(
            err,
            MultiUuError::DecodeError(uuencoding::UuError::InvalidBeginLine { .. })
        ));
    }

    // ------------------------------------------------------------------
    // Per-part framing variations
    // ------------------------------------------------------------------

    /// Per-part framed bodies with prose before each `begin` and after each
    /// `end` (as some posting tools add "section N of M" banners).
    #[test]
    fn per_part_framing_with_banners() {
        let wrap = |n: u8, body: &[u8]| {
            cat(&[
                format!("section {n} of 3 of file file.bin\n\n").as_bytes(),
                body,
                b"\nposted with some tool\n",
            ])
        };
        let mut c = PartCollection::with_total(3);
        c.add(make_entry(1, &wrap(1, PART1_BODY))).unwrap();
        c.add(make_entry(2, &wrap(2, PART2_BODY))).unwrap();
        c.add(make_entry(3, &wrap(3, PART3_BODY))).unwrap();

        let result = reassemble(&c).unwrap();
        assert_eq!(result.data, FULL);
        assert!(!result.is_truncated);
    }

    /// A per-part `begin` naming a different file means the parts do not
    /// belong together: flagged as truncated.
    #[test]
    fn per_part_framing_filename_mismatch_is_truncated() {
        let other = b"begin 644 other.bin\n-5&AI<R!I<R!A(&UU;   \n \nend\n";
        let mut c = PartCollection::with_total(2);
        c.add(make_entry(1, PART1_BODY)).unwrap();
        c.add(make_entry(2, other)).unwrap();

        let result = reassemble(&c).unwrap();
        assert!(result.is_truncated);
        assert_eq!(result.filename, "file.bin");
    }
}
