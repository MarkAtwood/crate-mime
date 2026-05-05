//! yEnc encoding and decoding.
//!
//! # Background
//!
//! yEnc (short for "Why Encode?") was developed by Jürgen Helbing and released
//! in 2001 as a replacement for UUencode and Base64 on Usenet. The key insight
//! is that most byte values (252 out of 256) pass through the encoding with
//! only a single-byte overhead (add 42, mod 256), instead of the 33% overhead
//! of Base64 or the similar overhead of UUencode. In practice yEnc articles are
//! only 1–2% larger than the raw binary they carry.
//!
//! yEnc became the dominant Usenet binary encoding in the early 2000s and
//! remains in use today, especially in NZB-based binary download ecosystems.
//!
//! # Two use cases
//!
//! 1. **Single-part articles** — the entire file is encoded in one article.
//!    The body contains `=ybegin`, the encoded data, and `=yend` with a CRC32.
//!    Use [`decode`] and [`encode`].
//!
//! 2. **Multi-part articles** — large files are split across numbered articles.
//!    Each article carries `=ybegin part= total=`, a `=ypart begin= end=` line
//!    giving its byte range, the encoded data, and `=yend` with a per-part CRC32
//!    (`pcrc32=`) and optionally the whole-file CRC32 (`crc32=`).
//!    Use [`decode`] on each article individually, then reassemble using the
//!    [`yencoding_multi`](https://crates.io/crates/yencoding-multi) crate.
//!
//! # Relationship to other crates in this workspace
//!
//! - [`uuencoding`](https://crates.io/crates/uuencoding) — handles the older
//!   UUencode format. yEnc replaced UUencode on Usenet but both still appear
//!   in email archives.
//! - `yencoding-multi` — multi-part reassembly for yEnc, analogous to
//!   `uuencoding-multi` for UUencode. This crate is a dependency of that one.
//!
//! This crate has **no dependency** on `mime-tree`, `uuencoding`, or any other
//! workspace crate.
//!
//! # Not in scope
//!
//! - **NZB files** — NZB is an XML format that describes which Usenet articles
//!   carry the parts of a file. Parsing NZB is a separate concern; this crate
//!   operates on raw article bodies, not NZB metadata.
//! - **NNTP protocol** — fetching articles from an NNTP server is the caller's
//!   responsibility. This crate operates on byte slices.
//! - **SIMD optimisation** — the byte transform is a single subtraction per
//!   byte and already vectorises automatically at `-O2`; explicit SIMD adds
//!   complexity without measurable benefit.
//!
//! # Security note
//!
//! Unlike Base64, yEnc-encoded data is approximately the same size as the
//! original binary (1–2% overhead). There is no significant size amplification
//! from decoding. However, decoded bytes may represent a compressed archive
//! (`.tar.gz`, `.zip`, `.rar`, etc.). **This crate never decompresses the
//! output.** Any subsequent decompression is the caller's responsibility and
//! must be independently guarded against decompression-bomb attacks before
//! beginning decompression.
//!
//! # Quick start
//!
//! ```rust
//! // Decode a single-part yEnc article.
//! // Oracle: bytes [0,1,2] encode as ['*','+',','] (add 42, no escapes needed).
//! // CRC32 of [0,1,2]: python3 -c "import binascii; print(hex(binascii.crc32(bytes([0,1,2]))&0xffffffff))"
//! // → 0x0854897f
//! let raw_article: &[u8] = b"\
//!     =ybegin line=128 size=3 name=hi.bin\r\n\
//!     *+,\r\n\
//!     =yend size=3 crc32=0854897f\r\n";
//! let part = yencoding::decode(raw_article).unwrap();
//! assert_eq!(part.data, &[0u8, 1, 2]);
//! assert_eq!(part.metadata.filename, "hi.bin");
//! assert!(part.crc32_verified);
//! ```
//!
//! ```rust
//! // Encode bytes as a single-part yEnc article.
//! let encoded = yencoding::encode(b"\x00\x01\x02", "hi.bin", yencoding::DEFAULT_LINE_LENGTH);
//! assert!(encoded.starts_with(b"=ybegin"));
//! assert!(encoded.ends_with(b"\r\n"));
//! ```

mod decode;
mod encode;
mod error;
mod header;

pub use encode::DEFAULT_LINE_LENGTH;
pub use error::YencError;

/// Metadata extracted from a yEnc `=ybegin` header line.
///
/// Common to both single-part and multi-part articles.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct YencMetadata {
    /// Filename from the `name=` field of `=ybegin`.
    ///
    /// Preserved verbatim from the encoded stream, including any embedded
    /// spaces. Not sanitised against path traversal — callers that write this
    /// to disk must validate against `..` components and absolute paths.
    pub filename: String,

    /// Total size of the file in bytes, from the `size=` field of `=ybegin`.
    ///
    /// For multi-part articles this is the size of the **entire** file, not
    /// just this part.
    pub size: u64,

    /// Encoded line length from the `line=` field. Informational only; the
    /// decoder does not require lines to be exactly this length.
    ///
    /// Stored as `u8`. Declared values larger than 255 (produced by some
    /// non-standard encoders) are clamped to 255.
    pub line_length: u8,

    /// Total number of parts in a multi-part series (`total=` on `=ybegin`).
    ///
    /// `None` for single-part articles (where `total=` is absent). When
    /// present, this lets the caller set up a `yencoding_multi::PartCollection`
    /// without separately parsing the subject line.
    pub total_parts: Option<u32>,
}

/// A successfully decoded yEnc part.
///
/// Returned by [`decode`]. Contains the decoded binary payload, metadata from
/// the article headers, and verification status.
///
/// For single-part articles, `part`, `part_begin`, and `part_end` are all
/// `None`. For multi-part articles they carry the values from `=ybegin part=`
/// and `=ypart begin=/end=`.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DecodedPart {
    /// Decoded binary payload.
    pub data: Vec<u8>,

    /// Metadata from the `=ybegin` line.
    pub metadata: YencMetadata,

    /// 1-based part number from `=ybegin part=`. `None` for single-part
    /// articles.
    pub part: Option<u32>,

    /// 1-based byte offset of the first byte of this part within the full
    /// file, from `=ypart begin=`. `None` for single-part articles.
    ///
    /// Note: yEnc uses 1-based offsets. Subtract 1 to get a 0-based offset
    /// for indexing into a pre-allocated file buffer.
    pub part_begin: Option<u64>,

    /// 1-based byte offset of the last byte of this part within the full file,
    /// from `=ypart end=`. `None` for single-part articles.
    pub part_end: Option<u64>,

    /// `true` if the CRC32 in `=yend` was present and matched the decoded
    /// bytes. `false` if no CRC field was present in the article (some older
    /// encoders omit it). A CRC mismatch causes [`YencError::CrcMismatch`] to
    /// be returned as an `Err` rather than setting this to `false`.
    pub crc32_verified: bool,

    /// Whole-file CRC32 from the `crc32=` field in `=yend`, if present.
    ///
    /// For single-part articles this is the CRC of the entire file (same as
    /// what was verified against `data`). For multi-part articles the per-part
    /// CRC is in `pcrc32=` (verified above); `crc32=` is the CRC of the
    /// **complete assembled file** and cannot be verified against a single
    /// part's payload — but it is surfaced here so that the caller or the
    /// `yencoding-multi` assembler can use it for whole-file verification once
    /// all parts are reassembled.
    ///
    /// `None` if the encoder omitted the `crc32=` field (older encoders and
    /// some multi-part encoders that only include `pcrc32=` do this).
    pub whole_file_crc32: Option<u32>,
}

/// Decode a yEnc article from raw bytes.
///
/// `input` may begin with arbitrary prose (NNTP article headers, preamble
/// text, etc.) — the decoder scans forward for the first `=ybegin` line.
///
/// # Errors
///
/// - [`YencError::NoHeader`] — no `=ybegin` line found.
/// - [`YencError::InvalidHeader`] — a required field is missing or unparsable.
/// - [`YencError::UnexpectedEof`] — no `=yend` line found.
/// - [`YencError::CrcMismatch`] — CRC mismatch between decoded bytes and
///   the `crc32=` / `pcrc32=` field in `=yend`.
///
/// # Examples
///
/// ```rust
/// // Oracle: [0,1,2] encodes as ['*','+',','] (add 42); CRC32 = 0x0854897f
/// let article: &[u8] = b"\
///     =ybegin line=128 size=3 name=hi.bin\r\n\
///     *+,\r\n\
///     =yend size=3 crc32=0854897f\r\n";
/// let part = yencoding::decode(article).unwrap();
/// assert_eq!(part.data, &[0u8, 1, 2]);
/// assert!(part.crc32_verified);
/// ```
pub fn decode(input: &[u8]) -> Result<DecodedPart, YencError> {
    decode::decode(input)
}

/// Encode `data` as a single-part yEnc article.
///
/// Returns the complete article body including `=ybegin`, encoded data lines,
/// and `=yend` with CRC32. Does **not** include NNTP message headers.
///
/// # Parameters
///
/// - `data` — raw bytes to encode. May be empty.
/// - `filename` — written verbatim to `name=` on `=ybegin`.
/// - `line_length` — encoded bytes per line. Use [`DEFAULT_LINE_LENGTH`] (128)
///   unless you have a specific reason to deviate.
///
/// # Examples
///
/// ```rust
/// // Oracle: [0,1,2] encodes as ['*','+',',']; CRC32 = 0x0854897f
/// let encoded = yencoding::encode(b"\x00\x01\x02", "hi.bin", yencoding::DEFAULT_LINE_LENGTH);
/// assert!(encoded.starts_with(b"=ybegin"));
/// let part = yencoding::decode(&encoded).unwrap();
/// assert_eq!(part.data, b"\x00\x01\x02");
/// assert!(part.crc32_verified);
/// ```
#[must_use]
pub fn encode(data: &[u8], filename: &str, line_length: u8) -> Vec<u8> {
    encode::encode(data, filename, line_length)
}

/// Parameters for encoding one part of a multi-part yEnc series.
///
/// Used with [`encode_part`]. All fields are required; there are no defaults
/// because all values must be derived from the caller's knowledge of the full
/// file split.
///
/// # Example
///
/// ```rust
/// let full_data = b"\x00\x01\x02\x03\x04\x05";
/// let whole_crc = crc32fast::hash(full_data);
///
/// let opts = yencoding::EncodePartOptions {
///     filename: "f.bin",
///     total_size: 6,
///     total_parts: 2,
///     part: 1,
///     begin: 1,
///     end: 3,
///     whole_file_crc32: whole_crc,
///     line_length: yencoding::DEFAULT_LINE_LENGTH,
/// };
/// let encoded = yencoding::encode_part(&full_data[..3], &opts);
/// let p = yencoding::decode(&encoded).unwrap();
/// assert_eq!(p.part, Some(1));
/// assert_eq!(p.metadata.total_parts, Some(2));
/// ```
#[derive(Debug, Clone)]
pub struct EncodePartOptions<'a> {
    /// Verbatim filename for `=ybegin name=`.
    pub filename: &'a str,
    /// Size of the **entire** file, written to `=ybegin size=`.
    pub total_size: u64,
    /// Total number of parts in the series, written to `=ybegin total=`.
    pub total_parts: u32,
    /// 1-based part number.
    pub part: u32,
    /// 1-based byte offset in the full file where this part starts (`=ypart begin=`).
    pub begin: u64,
    /// 1-based byte offset in the full file where this part ends, inclusive (`=ypart end=`).
    pub end: u64,
    /// CRC32 of the **complete** file, written as `crc32=` in `=yend`.
    /// Compute this from the full unsplit data before calling.
    pub whole_file_crc32: u32,
    /// Encoded bytes per line. Use [`DEFAULT_LINE_LENGTH`] (128) for the
    /// standard value.
    pub line_length: u8,
}

/// Encode one part of a multi-part yEnc series.
///
/// `data` is the raw bytes of **this part only** (not the whole file).
/// All other parameters are in `opts`; see [`EncodePartOptions`].
///
/// Returns the complete part article body including `=ybegin`, `=ypart`,
/// encoded data, and `=yend` with `pcrc32=` and `crc32=`.
#[must_use]
pub fn encode_part(data: &[u8], opts: &EncodePartOptions<'_>) -> Vec<u8> {
    encode::encode_part(
        data,
        opts.filename,
        opts.total_size,
        opts.total_parts,
        opts.part,
        opts.begin,
        opts.end,
        opts.whole_file_crc32,
        opts.line_length,
    )
}
