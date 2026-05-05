use std::ops::Range;

/// Errors produced by [`crate::Assembler`] operations.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblyError {
    /// A part's byte range overlaps with an already-accepted part.
    ///
    /// yEnc parts must cover non-overlapping, contiguous byte ranges of the
    /// final file. When two parts claim the same byte(s), the second is
    /// rejected. `existing` is the range already stored; `new` is the range
    /// that was rejected.
    ///
    /// **Caller action**: de-duplicate incoming articles (the same article
    /// may arrive multiple times from different Usenet servers).
    OverlappingPart {
        existing: Range<u64>,
        new: Range<u64>,
    },

    /// A part's byte range falls outside `[0, total_size)`.
    ///
    /// Either the `=ypart begin=/end=` values were invalid, or the wrong
    /// `total_size` was passed to [`Assembler::new`][crate::Assembler::new].
    OutOfRange {
        begin: u64,
        end: u64,
        total_size: u64,
    },

    /// Whole-file CRC32 mismatch on [`Assembler::finish`][crate::Assembler::finish].
    ///
    /// The reassembled bytes hash to a different CRC32 than the expected value
    /// set via [`Assembler::set_expected_crc32`][crate::Assembler::set_expected_crc32].
    CrcMismatch { expected: u32, actual: u32 },

    /// [`Assembler::finish`][crate::Assembler::finish] was called before all
    /// byte ranges were covered.
    ///
    /// `missing` lists the 0-based byte ranges that have not been received.
    /// Call [`Assembler::is_complete`][crate::Assembler::is_complete] before
    /// `finish()` to avoid this error.
    Incomplete { missing: Vec<Range<u64>> },

    /// A decoded part's data length does not match its declared `=ypart begin=/end=` range.
    ///
    /// This indicates a corrupt or malformed article: the decoded payload is
    /// a different size than the byte range it claims to cover.
    DataLengthMismatch {
        /// The byte count implied by the `begin`/`end` range header.
        declared_range_len: usize,
        /// The actual number of decoded bytes.
        actual_data_len: usize,
    },

    /// `total_size` exceeds the built-in safety cap or the addressable memory
    /// on this platform.
    ///
    /// [`Assembler::new`][crate::Assembler::new] rejects any `total_size`
    /// greater than [`MAX_TOTAL_SIZE`][crate::MAX_TOTAL_SIZE] (512 MiB) to
    /// prevent an adversarial `=ybegin size=` field from forcing a multi-GiB
    /// allocation.  On 32-bit targets the platform `usize` limit applies first.
    TotalSizeTooLarge {
        /// The value that was rejected.
        total_size: u64,
    },

    /// A decoded part has `part_begin` set but `part_end` absent, or vice versa.
    ///
    /// yEnc `=ypart begin=/end=` always provides both values or neither.
    /// A `DecodedPart` with only one of the two fields set indicates a corrupt
    /// or incorrectly constructed part.
    MalformedPartRange,

    /// Two parts carry conflicting whole-file CRC32 values.
    ///
    /// [`Assembler::add_part`][crate::Assembler::add_part] auto-extracts the
    /// `crc32=` whole-file CRC from each part that carries it.  If a later part
    /// reports a different value than one already recorded, the series is
    /// internally inconsistent and the assembly must be aborted.
    ///
    /// `first` is the CRC recorded from an earlier part; `new` is the
    /// conflicting value from the current part.
    InconsistentCrc { first: u32, new: u32 },
}

impl std::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssemblyError::OverlappingPart { existing, new } => write!(
                f,
                "part byte range {}..{} overlaps with already-stored range {}..{} — \
                 check for duplicate articles",
                new.start, new.end, existing.start, existing.end
            ),
            AssemblyError::OutOfRange {
                begin,
                end,
                total_size,
            } => write!(
                f,
                "part byte range {}..{} is outside total file size {} — \
                 verify =ypart begin=/end= and total_size",
                begin, end, total_size
            ),
            AssemblyError::CrcMismatch { expected, actual } => write!(
                f,
                "whole-file CRC32 mismatch: expected {:#010x}, got {:#010x} — \
                 re-fetch all parts and retry",
                expected, actual
            ),
            AssemblyError::Incomplete { missing } => {
                write!(
                    f,
                    "assembly incomplete: missing {} byte range(s): ",
                    missing.len()
                )?;
                for (i, r) in missing.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}..{}", r.start, r.end)?;
                }
                Ok(())
            }
            AssemblyError::DataLengthMismatch {
                declared_range_len,
                actual_data_len,
            } => write!(
                f,
                "part data length {actual_data_len} does not match declared range length \
                 {declared_range_len} — corrupt or malformed article"
            ),
            AssemblyError::TotalSizeTooLarge { total_size } => write!(
                f,
                "total_size {total_size} exceeds the 512 MiB safety cap or the \
                 addressable memory on this platform (usize::MAX = {})",
                usize::MAX
            ),
            AssemblyError::MalformedPartRange => write!(
                f,
                "part_begin and part_end must both be Some or both be None"
            ),
            AssemblyError::InconsistentCrc { first, new } => write!(
                f,
                "inconsistent whole-file CRC32 across parts: \
                 first seen {first:#010x}, new part reports {new:#010x} — \
                 corrupt or mismatched article series"
            ),
        }
    }
}

impl std::error::Error for AssemblyError {}
