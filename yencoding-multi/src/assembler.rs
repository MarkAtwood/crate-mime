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

impl Assembler {
    /// Create a new assembler for a file of exactly `total_size` bytes.
    ///
    /// `total_size` must match the `size=` field on the `=ybegin` line of all
    /// articles in the series.
    ///
    /// # Errors
    ///
    /// Returns [`AssemblyError::TotalSizeTooLarge`] if `total_size` cannot be
    /// represented as a `usize` on the current platform (e.g. > 4 GiB on
    /// 32-bit targets).
    pub fn new(total_size: u64) -> Result<Self, AssemblyError> {
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
    /// You can extract the whole-file CRC32 from `DecodedPart` manually:
    /// it is the `crc32=` field in `=yend` (distinct from `pcrc32=`, which is
    /// per-part). Not every encoder includes it; check `DecodedPart::crc32_verified`.
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
    /// # Notes
    ///
    /// Parts may be added in any order. A part with no `part_begin`/`part_end`
    /// (i.e. a single-part article passed to the assembler) is written starting
    /// at offset 0.
    pub fn add_part(&mut self, part: &yencoding::DecodedPart) -> Result<(), AssemblyError> {
        // Convert 1-based yEnc offsets to 0-based internal offsets.
        // A single-part article has no =ypart, so begin/end are both None.
        // Having only one of the two set is a malformed part.
        let (begin_0, end_0) = match (part.part_begin, part.part_end) {
            (None, None) => (0u64, part.data.len() as u64),
            (Some(b), Some(e)) => (b.saturating_sub(1), e),
            _ => return Err(AssemblyError::MalformedPartRange),
        };

        // Validate range against declared total size.
        if end_0 > self.total_size || begin_0 > end_0 {
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
    pub fn is_complete(&self) -> bool {
        self.missing_ranges().is_empty()
    }

    /// Returns the 0-based byte ranges within `[0, total_size)` not yet covered
    /// by any added part, in ascending order.
    ///
    /// An empty `Vec` means the file is complete.
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
        // Claims begin=1 end=5 (4-byte range) but supplies 3 bytes.
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
    #[cfg(target_pointer_width = "32")]
    fn total_size_too_large_rejected() {
        let err = Assembler::new(u64::MAX).unwrap_err();
        assert!(matches!(err, AssemblyError::TotalSizeTooLarge { .. }));
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
