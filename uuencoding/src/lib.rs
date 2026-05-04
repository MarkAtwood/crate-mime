//! UUencoding and UUdecoding.
//!
//! # Background
//!
//! UUencoding (Unix-to-Unix encoding) originated in the early 1980s as a way
//! to transfer binary files over Unix-to-Unix Copy Program (UUCP) links, which
//! carried only 7-bit ASCII text. A `begin` line records the file's Unix
//! permission mode and filename; data lines each start with a length character
//! followed by groups of four printable ASCII characters encoding three bytes;
//! an `end` line terminates the block. The scheme predates MIME by roughly a
//! decade and was the dominant binary-transfer mechanism on Usenet and early
//! email networks through the early 1990s.
//!
//! # Two use cases in MIME contexts
//!
//! 1. **CTE-declared blocks** — a message part carries the header
//!    `Content-Transfer-Encoding: x-uuencode` (or `x-uue`). The part body is
//!    a single UU block; [`decode`] processes it directly.
//!
//! 2. **Inline blocks in `text/plain`** — a human-composed message contains
//!    one or more UU blocks embedded in prose. [`scan`] locates each `begin`/`end`
//!    pair by offset so callers can extract and decode them individually.
//!
//! # Relationship to `mime-tree`
//!
//! `mime-tree` depends on this crate. This crate does **not** depend on
//! `mime-tree`. Callers are responsible for MIME/S/MIME recursion; neither
//! crate recurses into the other.
//!
//! # Real-world tolerance
//!
//! This crate tolerates common mailer mutations without requiring the caller
//! to pre-sanitize input:
//!
//! - **CRLF line endings** — trailing `\r` is stripped from every line.
//! - **Trailing-space stripping** — many mailers strip trailing spaces from
//!   data lines; the decoder pads short lines with `0x20` (space), which
//!   decodes to zero, matching the intended zero bits.
//! - **Space/backtick ambiguity for zero** — both `0x20` (space) and `` 0x60 ``
//!   (backtick) are accepted as the zero-value UU character in both length and
//!   data positions.
//! - **Missing `end` line** — a block whose `end` line was stripped is
//!   returned as [`DecodedBlock`] or [`ScannedBlock`] with `is_truncated = true`
//!   rather than an error, so callers receive the partial payload.
//!
//! # Security note
//!
//! Decoded output can be substantially larger than the encoded input (ratio
//! approaches 3:4 in the limit). Always apply a size budget **before** passing
//! decoded bytes to a decompressor or any other secondary processor. If decoded
//! bytes are a compressed archive, decompression is the caller's responsibility
//! and must be guarded against decompression bombs. This crate does not
//! decompress and does not impose size limits.
//!
//! # Quick start
//!
//! ```rust
//! // Encode bytes into a UU block.
//! let encoded = uuencoding::encode(b"Cat", "cat.txt", 0o644);
//! assert_eq!(encoded, b"begin 644 cat.txt\n#0V%T\n`\nend\n");
//! ```
//!
//! ```rust
//! // Decode a single UU block.
//! let block = uuencoding::decode(b"begin 644 hello.txt\n%2&5L;&\\ \n \nend\n").unwrap();
//! assert_eq!(block.data, b"Hello");
//! assert_eq!(block.metadata.filename, "hello.txt");
//! assert_eq!(block.metadata.mode, 420); // 0o644
//! ```
//!
//! ```rust
//! // Scan prose text for embedded UU blocks.
//! let text = b"Hi Alice,\nbegin 644 note.txt\n%2&5L;&\\ \n \nend\nSee you soon.\n";
//! for result in uuencoding::scan(text) {
//!     let block = result.unwrap();
//!     println!("found {} bytes for {}", block.data.len(), block.metadata.filename);
//! }
//! ```

pub(crate) mod decode;
mod encode;
mod error;
mod scan;

pub use error::UuError;

/// Metadata extracted from a UU `begin` line.
///
/// Every UU block starts with a line of the form `begin <mode> <filename>`.
/// This struct holds the two fields parsed from that line.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockMetadata {
    /// The filename recorded on the `begin` line.
    ///
    /// Preserved verbatim from the encoded stream, including any embedded
    /// spaces. An empty string is returned when the `begin` line has no
    /// filename token.
    pub filename: String,
    /// The Unix permission mode recorded on the `begin` line, stored as a
    /// `u32` (e.g. `0o644` = 420).
    ///
    /// The value is parsed from the octal string on the `begin` line. If the
    /// mode field is absent or unparseable, `0` is used.
    pub mode: u32,
}

/// A successfully decoded UU block.
///
/// Returned by [`decode`] and [`decode_limited`]. On success `is_truncated`
/// is `false` and `data` contains the complete binary payload. When the `end`
/// line is missing `is_truncated` is `true` and `data` contains whatever bytes
/// were decoded before input was exhausted or an error was encountered.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedBlock {
    /// The decoded binary payload.
    pub data: Vec<u8>,
    /// Metadata from the `begin` line (filename and mode).
    pub metadata: BlockMetadata,
    /// `true` if the `end` line was never found; `data` contains bytes decoded
    /// up to the point where input was exhausted or a decode error occurred.
    ///
    /// Note: when [`decode_limited`] is used and `is_truncated` is `true`,
    /// inspect [`was_limit_hit`][Self::was_limit_hit] to determine whether
    /// truncation was caused by the `max_bytes` limit or by a genuine encoding
    /// problem (missing `end` line, bad data byte).
    pub is_truncated: bool,
    /// `true` when [`decode_limited`] stopped early because the decoded byte
    /// count reached `max_bytes`.
    ///
    /// When this is `true`, `is_truncated` is also `true` and `data.len()` is
    /// at most `max_bytes`. Callers should treat this as a preview truncation
    /// rather than an encoding error. Always `false` when `max_bytes` is `None`
    /// (i.e. when called via [`decode`]).
    pub was_limit_hit: bool,
}

/// A UU block located and fully decoded from a larger byte slice.
///
/// Returned by [`scan`]. Contains both the byte offsets of the block within
/// the original input and the fully decoded binary payload. The offsets
/// satisfy `input[begin_offset..end_offset]` == the raw UU block (starting
/// with `begin` and ending with `end\n`, or ending at `input.len()` when
/// truncated).
#[derive(Debug, Clone, PartialEq)]
pub struct ScannedBlock {
    /// Byte offset of the `b` in the `begin` line within the input.
    pub begin_offset: usize,
    /// Byte offset one past the last byte of the `end\n` line, or
    /// `input.len()` if the block was truncated (no `end` line found).
    pub end_offset: usize,
    /// Metadata extracted from the `begin` line (filename and mode).
    pub metadata: BlockMetadata,
    /// Fully decoded binary payload.
    pub data: Vec<u8>,
    /// `true` if the `end` line was never found; `data` contains bytes decoded
    /// up to the point where input was exhausted.
    pub is_truncated: bool,
}

/// Decode a single UU block from `input`.
///
/// `input` should begin at (or before) the `begin` line; any leading lines
/// that do not start with `begin` are skipped. Returns a [`DecodedBlock`] on
/// success.
///
/// # Errors
///
/// - [`UuError::InvalidBeginLine`] — no `begin` line was found in `input`.
/// - [`UuError::BeginBase64`] — a `begin-base64` line was detected. This is
///   MIME base64, not UUencoding; pass the block to a standard base64 decoder.
///
/// # Partial results
///
/// When the `end` line is absent the function still returns `Ok`, with
/// `DecodedBlock::is_truncated = true` and `data` containing whatever bytes
/// were successfully decoded. A decode error on any data line is treated the
/// same way: decoding stops at that line and `is_truncated` is set.
///
/// # Examples
///
/// ```rust
/// let block = uuencoding::decode(
///     b"begin 644 hello.txt\n%2&5L;&\\ \n \nend\n"
/// ).unwrap();
/// assert_eq!(block.data, b"Hello");
/// assert_eq!(block.metadata.filename, "hello.txt");
/// assert_eq!(block.metadata.mode, 420); // 0o644
/// assert!(!block.is_truncated);
/// ```
pub fn decode(input: &[u8]) -> Result<DecodedBlock, UuError> {
    decode::decode(input)
}

/// Decode a single UU block from `input`, stopping early once `max_bytes`
/// decoded bytes have been produced.
///
/// This is a preview-efficient variant of [`decode`]: when only the first
/// `N` bytes of a potentially large attachment are needed, it avoids
/// allocating a decode buffer proportional to the full encoded input.
/// Decoding halts as soon as the payload reaches `max_bytes`; the returned
/// [`DecodedBlock`] will have `is_truncated = true` and at most `max_bytes`
/// bytes in `data`.
///
/// Passing `None` is equivalent to calling [`decode`].
///
/// # Errors
///
/// Same as [`decode`].
///
/// # Examples
///
/// ```rust
/// // Decode only the first 5 bytes of a 13-byte payload.
/// let block = uuencoding::decode_limited(
///     b"begin 644 hello.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n",
///     Some(5),
/// ).unwrap();
/// assert_eq!(block.data, b"Hello");
/// assert!(block.is_truncated);
/// ```
pub fn decode_limited(input: &[u8], max_bytes: Option<usize>) -> Result<DecodedBlock, UuError> {
    decode::decode_limited(input, max_bytes)
}

/// Encode `data` as a UU block with the given `filename` and Unix `mode`.
///
/// Returns the complete encoded block as a byte vector, including the
/// `begin <mode> <filename>` line, one data line per 45-byte chunk, a
/// backtick terminator line, and a final `end\n` line.
///
/// # Parameters
///
/// - `data` — the raw bytes to encode. May be empty.
/// - `filename` — recorded verbatim on the `begin` line. No validation is
///   performed; embedded spaces and special characters are passed through.
/// - `mode` — Unix permission bits written as a zero-padded three-digit octal
///   number on the `begin` line (e.g. `0o644` → `644`).
///
/// # Examples
///
/// ```rust
/// let encoded = uuencoding::encode(b"Cat", "cat.txt", 0o644);
/// assert_eq!(encoded, b"begin 644 cat.txt\n#0V%T\n`\nend\n");
/// ```
pub fn encode(data: &[u8], filename: &str, mode: u32) -> Vec<u8> {
    encode::encode(data, filename, mode)
}

/// Scan `input` for UU blocks, returning one entry per block found.
///
/// Walks the input once, locating every `begin`/`end` pair at true line
/// boundaries. Each item is a fully-decoded [`ScannedBlock`] on success, or a
/// [`UuError`] for `begin-base64` blocks (which this crate does not decode)
/// or malformed `begin` lines.
///
/// # Error continuation
///
/// After an error the scanner continues past the offending construct so that
/// subsequent valid blocks are still returned. Specifically:
///
/// - **`begin-base64`**: one [`UuError::BeginBase64`] is emitted; the scanner
///   then skips to the `====` terminator before resuming.
/// - **Malformed `begin` line**: one [`UuError::InvalidBeginLine`] is emitted;
///   the scanner advances one line before resuming.
/// - **Decode error on a data line**: decoding stops at that line; a single
///   [`ScannedBlock`] with `is_truncated = true` is emitted containing the
///   bytes decoded before the error. No separate [`UuError`] is emitted for
///   the bad line — only the `Ok(ScannedBlock)` with `is_truncated`.
///
/// # Note on `begin` detection
///
/// A `begin` keyword is only matched at a true line boundary (offset 0 or
/// immediately after a `\n`). A `begin` that appears mid-line (e.g.
/// `"not begin 644 …"`) is ignored.
///
/// # Examples
///
/// ```rust
/// let text = b"Prose.\nbegin 644 hello.txt\n%2&5L;&\\ \n \nend\nMore prose.\n";
/// let blocks = uuencoding::scan(text);
/// assert_eq!(blocks.len(), 1);
/// let block = blocks[0].as_ref().unwrap();
/// assert_eq!(block.data, b"Hello");
/// assert_eq!(block.metadata.filename, "hello.txt");
/// assert_eq!(block.begin_offset, 7);
/// ```
pub fn scan(input: &[u8]) -> Vec<Result<ScannedBlock, UuError>> {
    scan::scan_impl(input)
}
