//! Byte-range-based assembler for multi-part yEnc Usenet articles.
//!
//! yEnc multi-part articles include explicit byte-range headers (`=ypart
//! begin=N end=M`) that say exactly which slice of the final file each article
//! covers. This makes reassembly straightforward: pre-allocate a buffer of the
//! declared file size, write each decoded part into its claimed byte range, and
//! verify the whole-file CRC32 at the end.
//!
//! The assembler uses a sorted list of covered intervals for gap detection and
//! overlap rejection. Intervals are stored in `(begin, end)` pairs in ascending
//! order (guaranteed because [`BTreeMap`] key-sorts by `begin`). Overlap
//! detection on insertion is O(log n) per part.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::error::AssemblyError;

/// Reassembles multi-part yEnc articles into a complete file.
///
/// The caller:
/// 1. Creates an `Assembler` with the total file size (from `=ybegin size=`).
/// 2. Calls [`add_part`][Self::add_part] for each decoded part as it arrives
///    (in any order).
/// 3. Optionally sets the expected whole-file CRC32 with
///    [`set_expected_crc32`][Self::set_expected_crc32].
/// 4. Polls [`is_complete`][Self::is_complete] and calls
///    [`finish`][Self::finish] when all parts have arrived.
///
/// # Byte offset convention
///
/// yEnc uses **1-based** byte offsets in `=ypart begin=/end=`. The `begin`
/// and `end` values on `DecodedPart` reflect the raw 1-based values from the
/// article. `Assembler` converts them to **0-based** offsets internally.
/// The `missing_ranges()` return value uses **0-based** ranges.
pub struct Assembler {
    /// Pre-allocated buffer of `total_size` bytes. Parts are written directly
    /// into their claimed byte ranges as they arrive.
    buffer: Vec<u8>,

    /// Total expected file size in bytes.
    total_size: u64,

    /// Sorted map of covered intervals: key = 0-based start, value = 0-based end
    /// (exclusive). Using `BTreeMap<u64, u64>` lets us quickly find the
    /// predecessor/successor of any new interval for overlap/gap detection.
    covered: BTreeMap<u64, u64>,

    /// Whole-file CRC32, if known. Set by `set_expected_crc32()` or extracted
    /// from the first part's `=yend crc32=` field by `add_part()`.
    expected_crc32: Option<u32>,
}

/// Maximum `total_size` accepted by [`Assembler::new`].
///
/// Requests for a buffer larger than 512 MiB are rejected with
/// [`AssemblyError::TotalSizeTooLarge`] to prevent a remote sender from
/// forcing an arbitrarily large allocation via the `=ybegin size=` field.
pub const MAX_TOTAL_SIZE: u64 = 512 * 1024 * 1024; // 512 MiB

impl Assembler {
    /// Create a new assembler for a file of exactly `total_size` bytes.
    ///
    /// `total_size` must match the `size=` field on the `=ybegin` line of all
    /// articles in the series.
    ///
    /// # Errors
    ///
    /// Returns [`AssemblyError::TotalSizeTooLarge`] if `total_size` exceeds
    /// [`MAX_TOTAL_SIZE`] (512 MiB) or cannot be represented as a `usize` on
    /// the current platform (e.g. > 4 GiB on 32-bit targets).
    pub fn new(total_size: u64) -> Result<Self, AssemblyError> {
        if total_size > MAX_TOTAL_SIZE {
            return Err(AssemblyError::TotalSizeTooLarge { total_size });
        }
        let size = usize::try_from(total_size)
            .map_err(|_| AssemblyError::TotalSizeTooLarge { total_size })?;
        Ok(Self {
            buffer: vec![0u8; size],
            total_size,
            covered: BTreeMap::new(),
            expected_crc32: None,
        })
    }

    /// Set the expected whole-file CRC32.
    ///
    /// This is optional. If set, [`finish`][Self::finish] verifies the
    /// reassembled bytes against this value and returns
    /// [`AssemblyError::CrcMismatch`] on mismatch.
    ///
    /// You can extract the whole-file CRC32 directly from a decoded part:
    /// `DecodedPart::whole_file_crc32` carries the `crc32=` field from `=yend`
    /// (distinct from `pcrc32=`, which is per-part). Not every encoder includes
    /// it; check `DecodedPart::whole_file_crc32.is_some()` to determine whether
    /// it is available.
    pub fn set_expected_crc32(&mut self, crc32: u32) {
        self.expected_crc32 = Some(crc32);
    }

    /// Add a decoded yEnc part to the assembler.
    ///
    /// `part.part_begin` and `part.part_end` (1-based byte offsets from
    /// `=ypart begin=/end=`) determine where the decoded bytes are written
    /// into the file buffer.
    ///
    /// # Errors
    ///
    /// - [`AssemblyError::OutOfRange`] — the part's byte range extends beyond
    ///   `total_size` or the begin/end offsets are missing.
    /// - [`AssemblyError::OverlappingPart`] — the part's range overlaps with
    ///   a previously added part.
    /// - [`AssemblyError::DataLengthMismatch`] — the part's decoded data length
    ///   does not match its declared `begin`/`end` range.
    ///
    /// # Per-part CRC and `crc32_verified`
    ///
    /// `yencoding::decode()` performs per-part CRC verification itself: if a
    /// `pcrc32=` field is present in `=yend` and the decoded bytes do not match,
    /// `decode()` returns `Err(YencError::CrcMismatch)` and the corrupt part
    /// never reaches this function. A `DecodedPart` that arrives here with
    /// `crc32_verified = false` means only that **no per-part CRC was present**
    /// in the article (e.g. an older encoder that omitted `pcrc32=`), not that a
    /// CRC check failed silently.
    ///
    /// When no `pcrc32=` is present the only file-integrity safety net is the
    /// whole-file CRC32 checked by [`finish`][Self::finish]. If you need
    /// integrity guarantees for encoders that omit per-part CRCs, always call
    /// [`set_expected_crc32`][Self::set_expected_crc32] before calling `finish()`.
    /// The value to pass is `part.whole_file_crc32` when it is `Some` — the
    /// last part in a multi-part series typically carries this field.
    ///
    /// # Notes
    ///
    /// Parts may be added in any order. A part with no `part_begin`/`part_end`
    /// (i.e. a single-part article passed to the assembler) is written starting
    /// at offset 0.
    pub fn add_part(&mut self, part: &yencoding::DecodedPart) -> Result<(), AssemblyError> {
        // Convert 1-based yEnc offsets to 0-based internal offsets.
        // A single-part article has no =ypart, so begin/end are both None.
        // Having only one of the two set is a malformed part.
        let (begin_0, end_0, is_multi_part) = match (part.part_begin, part.part_end) {
            (None, None) => (0u64, part.data.len() as u64, false),
            (Some(b), Some(e)) => {
                // yEnc begin= is 1-based and must be ≥ 1.  begin=0 is not a
                // valid yEnc offset; reject it rather than silently treating it
                // as begin=1 via saturating_sub.
                if b == 0 {
                    return Err(AssemblyError::MalformedPartRange);
                }
                // Convert to 0-based:
                //   begin_0 = b - 1  (1-based → 0-based start)
                //   end_0   = e      (numerically unchanged: 1-based-inclusive
                //                    equals 0-based-exclusive for this convention)
                // e.g. begin=1, end=64 → begin_0=0, end_0=64, 64 bytes [0..64)
                (b - 1, e, true)
            }
            _ => return Err(AssemblyError::MalformedPartRange),
        };

        // Validate range against declared total size.
        //
        // For multi-part articles: use begin_0 >= end_0 to also reject zero-
        // length ranges (begin_0 == end_0), which cannot carry any data bytes
        // and are not valid per the yEnc spec.
        //
        // For single-part articles (is_multi_part == false): begin_0 is always
        // 0 and end_0 = data.len(), so zero-length means an empty file — which
        // is legitimate (total_size == 0 assemblers are valid).  Use the strict
        // begin_0 > end_0 check in that case.
        let range_invalid = if is_multi_part {
            begin_0 >= end_0
        } else {
            begin_0 > end_0
        };
        if end_0 > self.total_size || range_invalid {
            return Err(AssemblyError::OutOfRange {
                begin: begin_0,
                end: end_0,
                total_size: self.total_size,
            });
        }

        // Validate that decoded data fits the declared range.
        let range_len = (end_0 - begin_0) as usize;
        if part.data.len() != range_len {
            return Err(AssemblyError::DataLengthMismatch {
                declared_range_len: range_len,
                actual_data_len: part.data.len(),
            });
        }

        // Check for overlap with any existing covered interval.
        // A new interval [begin_0, end_0) overlaps an existing [a, b) if
        // begin_0 < b AND end_0 > a.
        // We use the BTreeMap to find the closest predecessor (highest start ≤
        // begin_0) and successor (lowest start > begin_0).
        if let Some((&a, &b)) = self.covered.range(..=begin_0).next_back() {
            // Predecessor interval [a, b). Overlaps if b > begin_0.
            if b > begin_0 {
                return Err(AssemblyError::OverlappingPart {
                    existing: a..b,
                    new: begin_0..end_0,
                });
            }
        }
        if let Some((&a, &b)) = self.covered.range(begin_0..).next() {
            // Successor interval [a, b). Overlaps if a < end_0.
            if a < end_0 {
                return Err(AssemblyError::OverlappingPart {
                    existing: a..b,
                    new: begin_0..end_0,
                });
            }
        }

        // Write the decoded bytes into the buffer.
        // Safety: data.len() == range_len is guaranteed by the check above.
        let start = begin_0 as usize;
        self.buffer[start..start + range_len].copy_from_slice(&part.data);

        // Record the covered interval.
        self.covered.insert(begin_0, end_0);

        Ok(())
    }

    /// Returns `true` iff all bytes in `[0, total_size)` are covered.
    ///
    /// When `total_size` is 0 this always returns `true` (a zero-byte file
    /// needs no parts).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing_ranges().is_empty()
    }

    /// Returns the 0-based byte ranges within `[0, total_size)` not yet covered
    /// by any added part, in ascending order.
    ///
    /// An empty `Vec` means the file is complete.
    #[must_use]
    pub fn missing_ranges(&self) -> Vec<Range<u64>> {
        let mut gaps = Vec::new();
        let mut cursor: u64 = 0;

        for (&start, &end) in &self.covered {
            if start > cursor {
                gaps.push(cursor..start);
            }
            cursor = end;
        }

        if cursor < self.total_size {
            gaps.push(cursor..self.total_size);
        }

        gaps
    }

    /// Finish assembly and return the reassembled file bytes.
    ///
    /// Verifies that all byte ranges are covered. If an expected CRC32 was
    /// set via [`set_expected_crc32`][Self::set_expected_crc32], also verifies
    /// the whole-file CRC32.
    ///
    /// # Errors
    ///
    /// - [`AssemblyError::Incomplete`] — some byte ranges are not yet covered.
    /// - [`AssemblyError::CrcMismatch`] — CRC32 mismatch (only when an expected
    ///   CRC was set).
    ///
    /// # Integrity note
    ///
    /// If no expected CRC32 was set (via [`set_expected_crc32`][Self::set_expected_crc32]),
    /// this function cannot detect corruption in parts whose articles lacked a
    /// `pcrc32=` field — `yencoding::decode()` only verifies integrity when a
    /// per-part CRC is present. For maximum reliability, always provide the
    /// whole-file CRC32 from the `crc32=` field in the final part's `=yend` line.
    ///
    /// On success the assembler is consumed and the buffer is returned without
    /// copying.
    pub fn finish(self) -> Result<Vec<u8>, AssemblyError> {
        let missing = self.missing_ranges();
        if !missing.is_empty() {
            return Err(AssemblyError::Incomplete { missing });
        }

        if let Some(expected) = self.expected_crc32 {
            let actual = crc32fast::hash(&self.buffer);
            if actual != expected {
                return Err(AssemblyError::CrcMismatch { expected, actual });
            }
        }

        Ok(self.buffer)
    }

    /// Total declared file size in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use yencoding::{DecodedPart, EncodePartOptions, YencMetadata};

    // Convenience: build a DecodedPart with given data and 1-based byte range.
    fn make_part(data: &[u8], begin_1: u64, end_1: u64) -> DecodedPart {
        DecodedPart {
            data: data.to_vec(),
            metadata: YencMetadata {
                filename: "test.bin".to_string(),
                size: 128,
                line_length: 128,
                total_parts: Some(2),
            },
            part: None,
            part_begin: Some(begin_1),
            part_end: Some(end_1),
            crc32_verified: true,
            whole_file_crc32: None,
        }
    }

    // Convenience: build a DecodedPart with no byte-range info (single-part).
    fn make_single_part(data: &[u8]) -> DecodedPart {
        DecodedPart {
            data: data.to_vec(),
            metadata: YencMetadata {
                filename: "test.bin".to_string(),
                size: data.len() as u64,
                line_length: 128,
                total_parts: None,
            },
            part: None,
            part_begin: None,
            part_end: None,
            crc32_verified: true,
            whole_file_crc32: None,
        }
    }

    // -----------------------------------------------------------------------
    // missing_ranges tests
    // -----------------------------------------------------------------------

    #[test]
    fn missing_ranges_empty_assembler() {
        let a = Assembler::new(100).unwrap();
        assert_eq!(a.missing_ranges(), vec![0..100]);
    }

    #[test]
    fn missing_ranges_zero_size() {
        let a = Assembler::new(0).unwrap();
        assert!(a.missing_ranges().is_empty());
        assert!(a.is_complete());
    }

    #[test]
    fn missing_ranges_one_part_of_two() {
        let mut a = Assembler::new(10).unwrap();
        a.add_part(&make_part(&[0u8; 5], 1, 5)).unwrap();
        // Part 1 covers bytes 0..5 (0-based), missing is 5..10.
        assert_eq!(a.missing_ranges(), vec![5..10]);
    }

    #[test]
    fn missing_ranges_gap_in_middle() {
        let mut a = Assembler::new(9).unwrap();
        a.add_part(&make_part(&[0u8; 3], 1, 3)).unwrap(); // bytes 0..3
        a.add_part(&make_part(&[0u8; 3], 7, 9)).unwrap(); // bytes 6..9
                                                          // Gap: bytes 3..6
        assert_eq!(a.missing_ranges(), vec![3..6]);
    }

    #[test]
    fn missing_ranges_complete() {
        let mut a = Assembler::new(6).unwrap();
        a.add_part(&make_part(&[0u8; 3], 1, 3)).unwrap();
        a.add_part(&make_part(&[0u8; 3], 4, 6)).unwrap();
        assert!(a.missing_ranges().is_empty());
        assert!(a.is_complete());
    }

    // -----------------------------------------------------------------------
    // Overlap / out-of-range rejection
    // -----------------------------------------------------------------------

    #[test]
    fn overlap_rejected() {
        let mut a = Assembler::new(10).unwrap();
        a.add_part(&make_part(&[0u8; 5], 1, 5)).unwrap();
        // Overlap: 0..5 vs 3..8 (0-based)
        let err = a.add_part(&make_part(&[0u8; 5], 4, 8)).unwrap_err();
        assert!(matches!(err, AssemblyError::OverlappingPart { .. }));
    }

    #[test]
    fn exact_duplicate_rejected() {
        let mut a = Assembler::new(10).unwrap();
        a.add_part(&make_part(&[0u8; 5], 1, 5)).unwrap();
        let err = a.add_part(&make_part(&[0u8; 5], 1, 5)).unwrap_err();
        assert!(matches!(err, AssemblyError::OverlappingPart { .. }));
    }

    #[test]
    fn out_of_range_rejected() {
        let mut a = Assembler::new(5).unwrap();
        // Part claims bytes 0..6 but total_size is 5.
        let err = a.add_part(&make_part(&[0u8; 6], 1, 6)).unwrap_err();
        assert!(matches!(
            err,
            AssemblyError::OutOfRange { total_size: 5, .. }
        ));
    }

    // -----------------------------------------------------------------------
    // finish() tests
    // -----------------------------------------------------------------------

    #[test]
    fn finish_incomplete_returns_error() {
        let mut a = Assembler::new(10).unwrap();
        a.add_part(&make_part(&[0u8; 5], 1, 5)).unwrap();
        let err = a.finish().unwrap_err();
        assert!(matches!(err, AssemblyError::Incomplete { .. }));
    }

    #[test]
    fn finish_crc_mismatch_returns_error() {
        let data = vec![1u8; 4];
        let mut a = Assembler::new(4).unwrap();
        a.add_part(&make_single_part(&data)).unwrap();
        a.set_expected_crc32(0xdeadbeef); // wrong CRC
        let err = a.finish().unwrap_err();
        assert!(matches!(err, AssemblyError::CrcMismatch { .. }));
    }

    #[test]
    fn finish_correct_crc_succeeds() {
        let data: Vec<u8> = (0u8..64).collect();
        let crc = crc32fast::hash(&data);
        let mut a = Assembler::new(64).unwrap();
        a.add_part(&make_single_part(&data)).unwrap();
        a.set_expected_crc32(crc);
        let result = a.finish().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn finish_no_crc_check_if_not_set() {
        let data = vec![42u8; 4];
        let mut a = Assembler::new(4).unwrap();
        a.add_part(&make_single_part(&data)).unwrap();
        // No CRC set — finish() should succeed without verification.
        let result = a.finish().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn finish_zero_size_succeeds_with_empty_vec() {
        // A zero-size assembler is immediately complete (no parts needed).
        // finish() must return Ok(vec![]) without any add_part() calls.
        let a = Assembler::new(0).unwrap();
        assert!(
            a.is_complete(),
            "zero-size assembler must be immediately complete"
        );
        let result = a.finish().unwrap();
        assert!(
            result.is_empty(),
            "finish() on zero-size assembler must return empty vec"
        );
    }

    // -----------------------------------------------------------------------
    // Byte content tests
    // -----------------------------------------------------------------------

    #[test]
    fn two_parts_correct_content() {
        // Oracle: part1 = bytes 0..4, part2 = bytes 4..8
        let part1_data: Vec<u8> = (0u8..4).collect();
        let part2_data: Vec<u8> = (4u8..8).collect();
        let expected: Vec<u8> = (0u8..8).collect();

        let mut a = Assembler::new(8).unwrap();
        a.add_part(&make_part(&part2_data, 5, 8)).unwrap(); // out of order
        a.add_part(&make_part(&part1_data, 1, 4)).unwrap();
        let result = a.finish().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn out_of_order_insertion_same_result() {
        let data: Vec<u8> = (0u8..9).collect();
        let p1 = &data[0..3];
        let p2 = &data[3..6];
        let p3 = &data[6..9];

        // Insert in reverse order
        let mut a = Assembler::new(9).unwrap();
        a.add_part(&make_part(p3, 7, 9)).unwrap();
        a.add_part(&make_part(p1, 1, 3)).unwrap();
        a.add_part(&make_part(p2, 4, 6)).unwrap();

        assert_eq!(a.finish().unwrap(), data);
    }

    // -----------------------------------------------------------------------
    // DataLengthMismatch and TotalSizeTooLarge error paths
    // -----------------------------------------------------------------------

    #[test]
    fn data_length_mismatch_rejected() {
        let mut a = Assembler::new(10).unwrap();
        // Claims begin=1 end=4 (4-byte range: bytes 0..4) but supplies 3 bytes.
        let part = make_part(&[0u8; 3], 1, 4);
        let err = a.add_part(&part).unwrap_err();
        assert!(matches!(
            err,
            AssemblyError::DataLengthMismatch {
                declared_range_len: 4,
                actual_data_len: 3
            }
        ));
    }

    #[test]
    fn data_length_mismatch_too_long_rejected() {
        let mut a = Assembler::new(10).unwrap();
        // Claims begin=1 end=3 (2-byte range) but supplies 5 bytes.
        let part = make_part(&[0u8; 5], 1, 2);
        let err = a.add_part(&part).unwrap_err();
        assert!(matches!(
            err,
            AssemblyError::DataLengthMismatch {
                declared_range_len: 2,
                actual_data_len: 5
            }
        ));
    }

    #[test]
    fn malformed_part_range_begin_without_end() {
        let mut a = Assembler::new(10).unwrap();
        let mut part = make_part(&[0u8; 5], 1, 5);
        part.part_end = None; // only begin is set
        let err = a.add_part(&part).unwrap_err();
        assert!(matches!(err, AssemblyError::MalformedPartRange));
    }

    #[test]
    fn malformed_part_range_end_without_begin() {
        let mut a = Assembler::new(10).unwrap();
        let mut part = make_part(&[0u8; 5], 1, 5);
        part.part_begin = None; // only end is set
        let err = a.add_part(&part).unwrap_err();
        assert!(matches!(err, AssemblyError::MalformedPartRange));
    }

    #[test]
    fn begin_zero_is_malformed() {
        // yEnc begin= is 1-based; begin=0 is not a valid offset per the spec.
        // It must be rejected with MalformedPartRange rather than silently
        // treated as begin=1.
        let mut a = Assembler::new(10).unwrap();
        let mut part = make_part(&[0u8; 5], 1, 5);
        part.part_begin = Some(0); // invalid: 0 is not a legal 1-based offset
        let err = a.add_part(&part).unwrap_err();
        assert!(
            matches!(err, AssemblyError::MalformedPartRange),
            "begin=0 must return MalformedPartRange, got: {err:?}"
        );
    }

    #[test]
    fn zero_length_range_is_out_of_range() {
        // A multi-part article with begin=1, end=0 would compute
        // begin_0=0, end_0=0.  A zero-length range cannot carry any data
        // bytes and is rejected as OutOfRange.
        let mut a = Assembler::new(10).unwrap();
        let mut part = make_part(&[], 1, 5); // start with a valid part
        part.part_begin = Some(3);
        part.part_end = Some(2); // end < begin → zero-length after conversion: begin_0=2, end_0=2
        let err = a.add_part(&part).unwrap_err();
        // begin_0 (2) >= end_0 (2): rejected as OutOfRange
        assert!(
            matches!(err, AssemblyError::OutOfRange { .. }),
            "zero-length range must return OutOfRange, got: {err:?}"
        );
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn total_size_too_large_rejected() {
        let err = Assembler::new(u64::MAX).unwrap_err();
        assert!(matches!(err, AssemblyError::TotalSizeTooLarge { .. }));
    }

    #[test]
    fn total_size_above_cap_rejected() {
        // Any size > MAX_TOTAL_SIZE must be rejected, regardless of platform
        // word size. Using cap+1 as the minimal over-limit value.
        let cap = crate::MAX_TOTAL_SIZE;
        let result = Assembler::new(cap + 1);
        assert!(
            matches!(result, Err(AssemblyError::TotalSizeTooLarge { .. })),
            "expected TotalSizeTooLarge for size > 512 MiB"
        );
    }

    #[test]
    fn total_size_within_cap_accepted() {
        // A small, well-within-cap size must still be accepted after adding
        // the 512 MiB cap check.
        let result = Assembler::new(1024);
        assert!(result.is_ok(), "1 KiB assembler must be accepted");
    }

    // -----------------------------------------------------------------------
    // Round-trip through yencoding::encode_part
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_via_yencoding_encode_part() {
        use yencoding::{decode, encode_part, DEFAULT_LINE_LENGTH};

        // Oracle: bytes 0..=127 split into two 64-byte parts.
        let full: Vec<u8> = (0u8..128).collect();
        let whole_crc = crc32fast::hash(&full);

        let opts1 = EncodePartOptions {
            filename: "full.bin",
            total_size: 128,
            total_parts: 2,
            part: 1,
            begin: 1,
            end: 64,
            whole_file_crc32: whole_crc,
            line_length: DEFAULT_LINE_LENGTH,
        };
        let opts2 = EncodePartOptions {
            filename: "full.bin",
            total_size: 128,
            total_parts: 2,
            part: 2,
            begin: 65,
            end: 128,
            whole_file_crc32: whole_crc,
            line_length: DEFAULT_LINE_LENGTH,
        };

        let enc1 = encode_part(&full[..64], &opts1);
        let enc2 = encode_part(&full[64..], &opts2);

        let p1 = decode(&enc1).unwrap();
        let p2 = decode(&enc2).unwrap();

        let mut assembler = Assembler::new(128).unwrap();
        assembler.set_expected_crc32(whole_crc);
        assembler.add_part(&p1).unwrap();
        assembler.add_part(&p2).unwrap();

        assert!(assembler.is_complete());
        let result = assembler.finish().unwrap();
        assert_eq!(result, full);
    }
}
