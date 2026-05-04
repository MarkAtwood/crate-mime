//! RFC 5322 / MIME parser producing a byte-range-indexed part tree.
//!
//! # Quick start
//!
//! ```rust
//! use mime_tree::{parse, decode_body_value};
//!
//! let raw = b"From: alice@example.com\r\n\
//!             Content-Type: text/plain; charset=utf-8\r\n\
//!             \r\n\
//!             Hello, world!\r\n";
//!
//! let msg = parse(raw).expect("parse failed");
//!
//! // text_body / html_body / attachments follow RFC 8621 §4.1.4.
//! assert_eq!(msg.text_body, vec!["1"]);
//!
//! // Decode a body part on demand (transfer-decode + charset-convert).
//! let part = msg.part_index.find_by_id("1").unwrap();
//! let decoded = decode_body_value(raw, part, None).unwrap();
//! assert_eq!(decoded.value, "Hello, world!\r\n");
//! ```
//!
//! # Design
//!
//! - `parse()` returns a [`ParsedMessage`] with the MIME part tree and RFC 8621
//!   `text_body` / `html_body` / `attachments` part-ID lists.
//! - Each [`ParsedPart`] carries `(offset, length)` byte ranges into the
//!   original `&[u8]` — no raw bytes are stored internally.
//! - `decode_body_value()` decodes a part's body on demand: transfer-encoding
//!   decode (Base64, QP, identity) followed by charset conversion via `encoding_rs`.
//! - Parsing is best-effort: malformed input yields a partial result plus
//!   `ParsedMessage::warnings`. Only empty input or no-headers returns `Err`.
//! - No JMAP dependency. No async. No `unsafe`.

mod decode;
mod error;
mod message;
mod parse;
mod part;
mod uuencode;
mod walk;
mod yenc;

pub use error::ParseError;
pub use message::{DecodedBodyValue, ParsedMessage};
pub use parse::{decode_body_value, parse};
pub use part::{ParsedHeader, ParsedPart, TransferEncoding};
pub use uuencode::{scan_inline_uuencode, InlineUUBlock};
pub use yenc::{scan_inline_yencode, InlineYEncBlock};
