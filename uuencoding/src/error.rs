/// Errors produced by UUencode operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum UuError {
    /// The `begin` line was missing or malformed.
    ///
    /// Produced by [`decode`][crate::decode] when no line starting with the
    /// keyword `begin` (case-insensitive) is found, or when the `begin` line
    /// cannot be parsed. The `line` field contains the offending text, or an
    /// empty string when no `begin` line was found at all.
    ///
    /// **Caller action**: treat the input as not a UU block. Inspect `line`
    /// for diagnostics.
    InvalidBeginLine { line: String },

    /// A `begin-base64` line was detected.
    ///
    /// `begin-base64` is the header used by the `uuencode -m` (MIME) variant,
    /// which encodes data as standard Base64 rather than traditional
    /// UUencoding. This crate does not decode Base64; the block must be passed
    /// to a standard Base64 decoder (e.g. the `base64` crate or
    /// `data-encoding`). The terminator for such a block is `====` rather than
    /// `end`.
    ///
    /// **Caller action**: pass the block body (between the `begin-base64` line
    /// and the `====` terminator) to a Base64 decoder.
    BeginBase64,

    /// The `end` line was never found.
    ///
    /// Produced when [`decode`][crate::decode] reaches the end of input
    /// without encountering a zero-length terminator line followed by `end`.
    /// The [`DecodedBlock`][crate::DecodedBlock] returned in the `Ok` path
    /// (when `decode` is used) will have `is_truncated = true` and `data`
    /// containing bytes decoded so far.
    ///
    /// **Caller action**: use the partial data if acceptable, or discard the
    /// block and log a warning. Truncated blocks are common with aggressively
    /// trimmed email archives.
    UnexpectedEof,

    /// A byte outside the valid UU character range was encountered in a data
    /// line.
    ///
    /// Valid UU data characters are `0x20`–`0x5F` (space through underscore)
    /// and `` 0x60 `` (backtick, used as an alias for zero). Any other byte
    /// causes this error. `line` and `col` are 0-based indices into the
    /// encoded stream (after the length byte); `byte` is the offending value.
    ///
    /// **Caller action**: the block is corrupted. `decode` returns a partial
    /// result with `is_truncated = true` up to the bad line; callers may log
    /// `byte`, `line`, and `col` for diagnostics.
    InvalidChar { line: usize, col: usize, byte: u8 },
}

impl std::fmt::Display for UuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UuError::InvalidBeginLine { line } => {
                write!(f, "invalid or missing 'begin' line: {:?}", line)
            }
            UuError::BeginBase64 => write!(
                f,
                "'begin-base64' detected; this is Base64, not UUencoding — use a Base64 decoder"
            ),
            UuError::UnexpectedEof => write!(f, "unexpected end of input: 'end' line not found"),
            UuError::InvalidChar { line, col, byte } => write!(
                f,
                "invalid UU character 0x{:02x} at line {}, col {}",
                byte, line, col
            ),
        }
    }
}

impl std::error::Error for UuError {}
