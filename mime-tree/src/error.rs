use std::fmt;

/// Error returned when `parse()` cannot produce any result from the input bytes.
///
/// Best-effort parsing: malformed-but-parseable input yields a `ParsedMessage`
/// with `warnings` populated. Only truly unrecoverable input returns `Err`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ParseError {
    /// The input byte slice is empty.
    EmptyInput,
    /// The input contains no recognizable RFC 5322 headers.
    NoHeaders,
    /// The byte range specified in a `ParsedPart` extends beyond the raw message bytes.
    ///
    /// `offset` and `length` are `u32` to match `ParsedPart::body_range`.
    /// `available` is `u64` because it comes from `raw.len() as u64` —
    /// using `u64` avoids a lossy truncation on platforms where `usize > u32`
    /// and makes the error message unambiguous even if the slice length
    /// exceeds 4 GiB (which `ParsedPart` cannot address, but the caller's
    /// buffer might be that large).
    InvalidRange {
        offset: u32,
        length: u32,
        available: u64,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyInput => write!(f, "input is empty"),
            ParseError::NoHeaders => write!(f, "input contains no RFC 5322 headers"),
            ParseError::InvalidRange {
                offset,
                length,
                available,
            } => write!(
                f,
                "body range [{}..{}] extends beyond message length {}",
                offset,
                u64::from(*offset) + u64::from(*length),
                available,
            ),
        }
    }
}

impl std::error::Error for ParseError {}
