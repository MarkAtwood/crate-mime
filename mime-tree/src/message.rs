use serde::{Deserialize, Serialize};

use crate::part::{ParsedHeader, ParsedPart};

/// The result of `parse()`.
///
/// All fields are owned. No lifetime parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedMessage {
    /// The MIME part tree rooted at the message.
    pub part_index: ParsedPart,
    /// Part IDs of text/plain body parts, per RFC 8621 §4.1.4.
    pub text_body: Vec<String>,
    /// Part IDs of text/html body parts, per RFC 8621 §4.1.4.
    pub html_body: Vec<String>,
    /// Part IDs of attachment parts, per RFC 8621 §4.1.4.
    pub attachments: Vec<String>,
    /// Top-level message headers.
    pub headers: Vec<ParsedHeader>,
    /// Short preview of the message body (first ~256 chars of text content).
    ///
    /// `None` when there is no text body part, when the first text part is
    /// empty, or when decoding the first text part fails (e.g. unsupported
    /// charset or transfer-encoding error).
    pub preview: Option<String>,
    /// Non-fatal parse warnings.
    pub warnings: Vec<String>,
}

/// Result of `decode_body_value()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedBodyValue {
    /// Decoded, charset-converted text.
    pub value: String,
    /// True if `max_bytes` was reached before the full body was decoded.
    pub is_truncated: bool,
    /// True if the charset conversion encountered unmappable or replacement
    /// characters. Note: also set when `max_bytes` truncates a multi-byte
    /// character sequence mid-codepoint; in that case the flag reflects the
    /// truncation artifact, not underlying data corruption.
    pub is_encoding_problem: bool,
}
