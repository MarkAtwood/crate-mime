/// Errors produced by yEnc decode operations.
///
/// All variants implement [`std::error::Error`] and [`std::fmt::Display`].
/// The enum is `#[non_exhaustive]` — new variants may be added in future
/// releases without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// The encoded stream ended before the `=yend` line was found.
    /// The article is truncated; no decoded data is returned.
    ///
    /// **Caller action**: the article was likely cut off mid-transfer. Re-fetch
    /// or skip.
    UnexpectedEof,

    /// The decoded payload length does not match a declared `size=` field.
    ///
    /// Checked against `=yend size=` (per-part size) and, for single-part
    /// articles, also cross-validated against `=ybegin size=` (total file
    /// size, which must equal the decoded payload for single-part).
    ///
    /// This signals a truncated or corrupt article. In the presence of a valid
    /// CRC, this error would never fire (CRC already detects corruption).
    /// In the absence of a CRC, this is the only integrity check.
    SizeMismatch {
        /// The byte count declared in `=yend size=` or `=ybegin size=`.
        expected: u64,
        /// The actual number of decoded bytes.
        actual: u64,
    },
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
            YencError::SizeMismatch { expected, actual } => write!(
                f,
                "size mismatch: =yend size={expected} but decoded {actual} bytes — \
                 the article data is corrupt or truncated; re-fetch and retry"
            ),
        }
    }
}

impl std::error::Error for YencError {}
