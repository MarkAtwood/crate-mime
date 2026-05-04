/// Errors produced by multi-part UUencoding reassembly.
///
/// This enum is `#[non_exhaustive]`; new variants may be added in future
/// releases without a breaking change.
///
/// # Example
///
/// ```
/// use uuencoding_multi::MultiUuError;
///
/// let err = MultiUuError::EmptyCollection;
/// assert!(err.to_string().contains("empty"));
/// ```
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MultiUuError {
    /// Reserved for future use. **This variant is not returned by the current
    /// implementation.**
    ///
    /// [`reassemble()`][crate::reassemble()] represents absent parts by
    /// returning `Ok(`[`ReassembledFile`][crate::ReassembledFile]`
    /// { is_truncated: true, missing_parts: vec![..], .. })` rather than
    /// `Err(MissingParts { .. })`. This variant is retained in the public API
    /// as a placeholder for a potential strict-mode in a future version.
    ///
    /// Matching on this variant in a `match` arm today will produce dead code.
    MissingParts { expected: u32, present: Vec<u32> },

    /// [`reassemble()`][crate::reassemble()] was called on a [`PartCollection`][crate::PartCollection]
    /// that contains no parts with `part_number >= 1`. A collection that holds
    /// only a TOC part (`part_number = 0`) triggers this error.
    EmptyCollection,

    /// A UUdecode error was returned by the `uuencoding` crate while decoding
    /// one of the part bodies. Reassembly stops at the first failing part.
    DecodeError(uuencoding::UuError),

    /// Two calls to [`PartCollection::add`][crate::PartCollection::add] provided
    /// entries with the same `part_number`. The duplicate entry is rejected and
    /// the collection is left unchanged.
    DuplicatePart { part_number: u32 },
}

impl std::fmt::Display for MultiUuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultiUuError::MissingParts { expected, present } => write!(
                f,
                "missing parts: expected {} total, but only have parts {:?}",
                expected, present
            ),
            MultiUuError::EmptyCollection => {
                write!(f, "reassemble() called on empty PartCollection")
            }
            MultiUuError::DecodeError(e) => write!(f, "UUdecode error: {}", e),
            MultiUuError::DuplicatePart { part_number } => {
                write!(f, "duplicate part number: {}", part_number)
            }
        }
    }
}

impl std::error::Error for MultiUuError {}

impl From<uuencoding::UuError> for MultiUuError {
    fn from(e: uuencoding::UuError) -> Self {
        Self::DecodeError(e)
    }
}
