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
#[derive(Debug, PartialEq)]
pub struct ReassembledFile {
    /// Filename extracted from the `begin` line of the first UU part.
    ///
    /// **Security — path traversal**: the filename comes directly from the
    /// email or Usenet message and is not sanitised. Real-world UU archives
    /// have been observed with filenames containing `../` sequences. Sanitise
    /// this value before using it as a filesystem path to prevent directory
    /// traversal attacks (e.g. reject names containing `/`, `\`, or `..`
    /// components, and resolve the final path against an allowed base
    /// directory).
    pub filename: String,
    /// Unix permission mode (e.g. `0o644`) from the `begin` line of the first
    /// part. Subsequent parts may specify different modes; only the first
    /// part's value is used.
    pub mode: u32,
    /// Decoded binary payload.
    ///
    /// When [`is_truncated`][Self::is_truncated] is `false`, this is the
    /// complete decoded file content, formed by concatenating the decoded
    /// output of every part in ascending `part_number` order.
    ///
    /// # When `is_truncated` is `true`
    ///
    /// `data` contains **only the decoded bytes of the parts that were
    /// present**, concatenated in ascending part-number order. This is **not**
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
    /// `true` when one or more parts were absent from the collection, or when
    /// any individual part's UU body was missing its `end` line. The data is
    /// likely corrupt in this case.
    ///
    /// To distinguish the two truncation causes:
    /// - `is_truncated && !missing_parts.is_empty()` — gap in the collection.
    /// - `is_truncated && missing_parts.is_empty()` — all parts were present
    ///   but at least one part's UU body was itself truncated (missing `end`).
    pub is_truncated: bool,
    /// Part numbers in `1..=total` that were absent from the collection, in
    /// ascending order. Empty when the collection was complete.
    pub missing_parts: Vec<u32>,
}

/// Reassemble a multi-part UU-encoded file from its parts.
///
/// Iterates over all [`PartEntry`][crate::PartEntry] values with
/// `part_number >= 1` in ascending order (the [`PartCollection`]'s
/// `BTreeMap` guarantees this). Each part's `body_bytes` is independently
/// decoded via `uuencoding::decode` and the decoded payloads are concatenated.
/// `filename` and `mode` are taken from the first part only.
///
/// The TOC part (`part_number = 0`), if present, is silently ignored.
///
/// # Errors
///
/// - [`MultiUuError::EmptyCollection`] — the collection contains no parts
///   with `part_number >= 1` (including the case of a TOC-only collection).
/// - [`MultiUuError::DecodeError`] — `uuencoding::decode` returned an error
///   for one of the parts. Reassembly stops at the first failing part.
///
/// # Partial results
///
/// When parts are missing the function still returns `Ok` rather than an
/// error. The result has `is_truncated = true` and `missing_parts` listing
/// the absent part numbers. `data` contains the decoded bytes of only the
/// **present** parts concatenated in order.
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
/// This function never panics. The `expect` on the internal `get()` call
/// is unreachable by construction: `present_parts()` only yields numbers
/// that are keys in the underlying map.
///
/// # Security
///
/// The decoded `data` may be a compressed archive. Any subsequent
/// decompression is the caller's responsibility and must be independently
/// guarded against decompression-bomb attacks. This crate does not
/// decompress.
///
/// The `filename` field of the returned [`ReassembledFile`] comes from the
/// email subject or UU `begin` line and is **not sanitised**. Sanitise it
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

    // Decode each present part individually and concatenate.
    let mut all_data: Vec<u8> = Vec::new();
    let mut any_truncated = false;
    let mut filename = String::new();
    let mut mode = 0u32;
    let mut first = true;

    for part_num in &present {
        let entry = collection
            .get(*part_num)
            .unwrap_or_else(|| unreachable!("present_parts listed a part that get() cannot find"));
        let block = uuencoding::decode(&entry.body_bytes)?;

        if first {
            filename = block.metadata.filename;
            mode = block.metadata.mode;
            first = false;
        }

        if block.is_truncated {
            any_truncated = true;
        }

        all_data.extend_from_slice(&block.data);
    }

    let is_truncated = any_truncated || !missing_parts.is_empty();

    Ok(ReassembledFile {
        filename,
        mode,
        data: all_data,
        is_truncated,
        missing_parts,
    })
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

    /// All parts are present (no gap) but part 2's body has its ` \nend\n`
    /// terminator stripped, so uuencoding::decode returns is_truncated=true.
    /// The result must have is_truncated=true and missing_parts empty.
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
        // Body has no "begin" line → uuencoding::decode returns InvalidBeginLine
        c.add(make_entry(1, b"this is not valid uu data\n"))
            .unwrap();

        let err = reassemble(&c).unwrap_err();
        assert!(matches!(err, MultiUuError::DecodeError(_)));
    }

    /// A corrupt second part → DecodeError (stops at first error).
    #[test]
    fn decode_error_on_second_part_propagates() {
        let mut c = PartCollection::with_total(2);
        c.add(make_entry(1, PART1_BODY)).unwrap();
        c.add(make_entry(2, b"not valid uu\n")).unwrap();

        let err = reassemble(&c).unwrap_err();
        assert!(matches!(err, MultiUuError::DecodeError(_)));
    }
}
