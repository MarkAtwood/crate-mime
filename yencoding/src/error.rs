/// Errors produced by yEnc decode operations.
///
/// All variants implement [`std::error::Error`] and [`std::fmt::Display`].
/// The enum is `#[non_exhaustive]` — new variants may be added in future
/// releases without a breaking change.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum YencError {
    /// No `=ybegin` line was found in the input.
    ///
    /// Either the input is not a yEnc article at all, or the `=ybegin` line
    /// was stripped before being passed to the decoder. Check that the full
    /// raw article body is being provided.
    NoHeader,

    /// A required field was missing or had an unparsable value in a
    /// `=ybegin`, `=ypart`, or `=yend` header line.
    ///
    /// `field` names the specific key that caused the error (e.g. `"size"`,
    /// `"name"`, `"begin"`). Unknown fields are silently skipped; this error
    /// fires only for fields the decoder must have to proceed.
    InvalidHeader { field: String },

    /// The CRC32 of the decoded bytes does not match the value in `=yend`.
    ///
    /// For single-part articles the `crc32=` field is checked; for multi-part
    /// parts `pcrc32=` (per-part CRC) is checked when present.
    ///
    /// **Caller action**: the decoded data is corrupt. Discard it and re-fetch
    /// the article. `expected` is what the header claimed; `actual` is what
    /// the decoder computed.
    CrcMismatch { expected: u32, actual: u32 },

    /// The `=yend` line was never found.
    ///
    /// The article was truncated. `data` in the returned [`crate::DecodedPart`]
    /// (when available via a partial-result path) may be incomplete.
    ///
    /// **Caller action**: the article was likely cut off mid-transfer. Re-fetch
    /// or skip.
    UnexpectedEof,
}

impl std::fmt::Display for YencError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YencError::NoHeader => write!(
                f,
                "no '=ybegin' line found — input is not a yEnc article or the header was stripped"
            ),
            YencError::InvalidHeader { field } => write!(
                f,
                "yEnc header missing or invalid required field '{}' — \
                 check that the full article header is present and well-formed",
                field
            ),
            YencError::CrcMismatch { expected, actual } => write!(
                f,
                "CRC32 mismatch: header claimed {:#010x}, decoded bytes hashed to {:#010x} — \
                 the article data is corrupt; re-fetch and retry",
                expected, actual
            ),
            YencError::UnexpectedEof => write!(
                f,
                "no '=yend' line found — article was truncated; re-fetch the article"
            ),
        }
    }
}

impl std::error::Error for YencError {}
