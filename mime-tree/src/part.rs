use std::fmt;

use serde::{Deserialize, Serialize};

/// Transfer encoding of a MIME body part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TransferEncoding {
    Identity,
    QuotedPrintable,
    Base64,
    SevenBit,
    EightBit,
    Binary,
    /// UUencode, as used in `Content-Transfer-Encoding: x-uuencode`,
    /// `x-uue`, or `uuencode`.  RFC 2045 permits x-token CTE values.
    UUEncode,
}

impl fmt::Display for TransferEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferEncoding::Identity => f.write_str("identity"),
            TransferEncoding::QuotedPrintable => f.write_str("quoted-printable"),
            TransferEncoding::Base64 => f.write_str("base64"),
            TransferEncoding::SevenBit => f.write_str("7bit"),
            TransferEncoding::EightBit => f.write_str("8bit"),
            TransferEncoding::Binary => f.write_str("binary"),
            TransferEncoding::UUEncode => f.write_str("x-uuencode"),
        }
    }
}

/// A decoded RFC 5322 / MIME header field.
///
/// For headers whose value mail-parser parses as plain text (`Subject`,
/// `Comments`, `Content-Description`, and any unstructured header), `value`
/// contains the fully decoded Unicode string (RFC 2047 encoded-words are
/// already resolved).
///
/// For all other header types (`Address`, `DateTime`, `ContentType`,
/// `Received`), `value` is the raw bytes sliced from the original message
/// and converted with `String::from_utf8_lossy`.  These structured values
/// require their own dedicated parsers — see
/// [`parse_header_typed`][crate::parse_header_typed].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedHeader {
    pub name: String,
    pub value: String,
}

/// A single MIME part in the parsed tree.
///
/// Byte ranges (`header_range`, `body_range`) are `(offset, length)` indices
/// into the caller's original `&[u8]`. The crate never stores raw bytes.
///
/// Both fields use `u32` to guarantee identical serialized representation on
/// 32-bit and 64-bit hosts (MIME messages are bounded well within 4 GiB).
///
/// For `multipart/*` parts, `children` is non-empty and `body_range` covers
/// the entire multipart body including boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedPart {
    /// IMAP dotted-path part ID: `"1"`, `"1.1"`, `"1.2"`, etc.
    pub part_id: String,
    /// Content-Type media type/subtype (e.g. `"text/plain"`).
    pub content_type: String,
    /// Charset parameter from Content-Type, if present.
    ///
    /// `None` means no explicit `charset=` parameter was present on the
    /// Content-Type header. Per RFC 2045 §5.2 the default is US-ASCII, but
    /// `decode_body_value()` defaults to UTF-8 instead (a strict superset)
    /// for better handling of the modern email corpus.
    pub charset: Option<String>,
    /// Content-Transfer-Encoding.
    pub transfer_encoding: TransferEncoding,
    /// Content-Disposition value (e.g. `"attachment"`, `"inline"`).
    pub disposition: Option<String>,
    /// Filename from Content-Disposition or Content-Type.
    pub filename: Option<String>,
    /// Content-ID header value, if present.
    pub cid: Option<String>,
    /// `(offset, length)` of this part's headers in the original bytes.
    ///
    /// To access individual typed headers for a part, slice
    /// `raw[offset..offset+length]` and pass the result to
    /// [`parse_header_typed`][crate::parse_header_typed].
    pub header_range: (u32, u32),
    /// `(offset, length)` of this part's body (pre-decode) in the original bytes.
    pub body_range: (u32, u32),
    /// Child parts. Non-empty only for `multipart/*` content types.
    pub children: Vec<ParsedPart>,
    /// True if mail-parser flagged this part as having a structural encoding
    /// problem (e.g., invalid base64 padding in the raw transfer encoding).
    ///
    /// This is a parse-time flag, distinct from
    /// [`DecodedBodyValue::is_encoding_problem`] which is set during
    /// charset conversion in `decode_body_value()`.
    pub is_encoding_problem: bool,
}

impl ParsedPart {
    /// Find a descendant part by its dotted IMAP part ID.
    ///
    /// Searches this part and all descendants depth-first.  Returns `None` if
    /// no part with the given ID exists in the tree.
    ///
    /// # Part ID conventions
    ///
    /// - **Non-multipart root**: the root part has `part_id = "1"`.
    /// - **Multipart root**: the root part has `part_id = ""` (empty string);
    ///   its children are `"1"`, `"2"`, etc.
    /// - **Nested multipart**: children use dotted paths like `"1.1"`, `"1.2"`.
    ///
    /// ```
    /// # use mime_tree::parse;
    /// // Non-multipart: root is "1"
    /// let raw = b"Content-Type: text/plain\r\n\r\nHello\r\n";
    /// let msg = parse(raw).unwrap();
    /// let part = msg.part_index.find_by_id("1").unwrap();
    /// assert_eq!(part.content_type, "text/plain");
    /// ```
    pub fn find_by_id(&self, id: &str) -> Option<&ParsedPart> {
        if self.part_id == id {
            return Some(self);
        }
        self.children.iter().find_map(|child| child.find_by_id(id))
    }
}
