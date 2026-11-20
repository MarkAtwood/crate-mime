/// Errors produced by UUencode operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UuError {
    /// No `begin` line was found.
    ///
    /// Returned by [`decode`][crate::decode] and
    /// [`decode_limited`][crate::decode_limited] when `input` contains no
    /// valid `begin <mode> <filename>` header line (see
    /// [`decode`][crate::decode] for the exact rule). Lines that merely start
    /// with `begin` but are not a valid header are skipped rather than
    /// reported, so in the current implementation `line` is always empty
    /// and `begin_offset` is always `0`.
    ///
    /// [`scan`][crate::scan] does not currently emit this variant; the fields
    /// are kept for compatibility.
    ///
    /// **Caller action**: treat the input as not a UU block.
    InvalidBeginLine {
        /// The offending line, or an empty string when no `begin` line was
        /// found at all (always empty in the current implementation).
        line: String,
        /// Byte offset of the offending line within the input. Always `0`
        /// in the current implementation.
        begin_offset: usize,
    },

    /// A `begin-base64` line was detected.
    ///
    /// `begin-base64` is the header used by the `uuencode -m` (MIME) variant,
    /// which encodes data as standard Base64 rather than traditional
    /// UUencoding. This crate does not decode Base64; the block must be passed
    /// to a standard Base64 decoder (e.g. the `base64` crate or
    /// `data-encoding`). The terminator for such a block is `====` rather than
    /// `end`.
    ///
    /// When produced by [`scan`][crate::scan], `begin_offset` is the byte
    /// offset of the `begin-base64` line within the input slice.
    ///
    /// **Caller action**: pass the block body (between the `begin-base64` line
    /// and the `====` terminator) to a Base64 decoder.
    BeginBase64 {
        /// Byte offset of the `begin-base64` line within the input.
        /// Always `0` when produced by [`decode`][crate::decode].
        begin_offset: usize,
    },

    /// A byte outside the valid UU character range was encountered in a data
    /// line.
    ///
    /// Valid UU data characters are `0x20`–`0x5F` (space through underscore)
    /// and `` 0x60 `` (backtick, used as an alias for zero). Any other byte
    /// causes this error.
    ///
    /// - `byte` — the offending byte value.
    /// - `col` — 0-based byte offset within the encoded payload of the bad
    ///   line (i.e. after the length byte).
    ///
    /// No public function currently returns this variant: when
    /// [`decode`][crate::decode], [`decode_limited`][crate::decode_limited],
    /// or [`scan`][crate::scan] meet a bad data byte they stop at that line
    /// and return the bytes decoded so far with `is_truncated = true`
    /// instead. The variant is kept for compatibility and possible future
    /// use.
    InvalidChar { col: usize, byte: u8 },
}

impl std::fmt::Display for UuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UuError::InvalidBeginLine { line, .. } => {
                write!(f, "invalid or missing 'begin' line: {:?}", line)
            }
            UuError::BeginBase64 { .. } => write!(
                f,
                "'begin-base64' detected; this is Base64, not UUencoding — use a Base64 decoder"
            ),
            UuError::InvalidChar { col, byte } => {
                write!(f, "invalid UU character 0x{:02x} at col {}", byte, col)
            }
        }
    }
}

impl std::error::Error for UuError {}
