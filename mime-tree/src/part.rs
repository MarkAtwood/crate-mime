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
}

/// A decoded RFC 5322 / MIME header field.
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
    pub header_range: (u32, u32),
    /// `(offset, length)` of this part's body (pre-decode) in the original bytes.
    pub body_range: (u32, u32),
    /// Child parts. Non-empty only for `multipart/*` content types.
    pub children: Vec<ParsedPart>,
}

impl ParsedPart {
    /// Find a descendant part by its dotted IMAP part ID.
    ///
    /// Searches this part and all descendants depth-first.  Returns `None` if
    /// no part with the given ID exists in the tree.
    ///
    /// ```
    /// # use mime_tree::parse;
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
