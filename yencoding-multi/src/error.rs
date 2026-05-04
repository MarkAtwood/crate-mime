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
        }
    }
}

impl std::error::Error for AssemblyError {}
