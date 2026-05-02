use std::fmt;

/// Error returned when `parse()` cannot produce any result from the input bytes.
///
/// Best-effort parsing: malformed-but-parseable input yields a `ParsedMessage`
/// with `warnings` populated. Only truly unrecoverable input returns `Err`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The input byte slice is empty.
    EmptyInput,
    /// The input contains no recognizable RFC 5322 headers.
    NoHeaders,
    /// The byte range specified in a `ParsedPart` extends beyond the raw message bytes.
    InvalidRange {
        offset: u32,
        length: u32,
        available: usize,
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
