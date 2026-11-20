//! RFC 5322 / MIME parser producing a byte-range-indexed part tree, and the
//! matching message writer.
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
//! assert_eq!(msg.html_body, vec!["1"]); // mirrors text_body for non-multipart
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
//!   `ParsedMessage::warnings`. Only empty, oversized (over `u32::MAX`
//!   bytes) or header-less input returns `Err`.
//! - [`write_message()`] goes the other way: it writes an RFC 5322 / MIME
//!   message from [`Header`] fields and a [`Part`] tree, folding header lines
//!   (RFC 5322 §2.1.1), encoding non-ASCII text as RFC 2047 encoded words
//!   and non-ASCII parameters per RFC 2231, and choosing a boundary absent
//!   from every child (RFC 2046 §5.1.1).
//! - No JMAP dependency. No async. No `unsafe`.
//!
//! # Writing a message
//!
//! ```rust
//! use mime_tree::{write_message, Body, Header, HeaderValue, Mailbox, Part};
//!
//! let headers = [
//!     Header::new(
//!         "From",
//!         HeaderValue::Mailboxes(vec![Mailbox {
//!             name: Some("Alice".into()),
//!             address: "alice@example.com".into(),
//!         }]),
//!     ),
//!     Header::new("Subject", HeaderValue::Text("Café".into())),
//! ];
//! let body = Part {
//!     content_type: "text/plain".into(),
//!     params: vec![("charset".into(), "utf-8".into())],
//!     disposition: None,
//!     headers: Vec::new(),
//!     body: Body::Text("Hello, world!\n".into()),
//! };
//!
//! let raw = write_message(&headers, &body).expect("valid header fields");
//! assert_eq!(
//!     raw,
//!     b"From: Alice <alice@example.com>\r\n\
//!       Subject: =?UTF-8?B?Q2Fmw6k=?=\r\n\
//!       MIME-Version: 1.0\r\n\
//!       Content-Type: text/plain; charset=utf-8\r\n\
//!       Content-Transfer-Encoding: quoted-printable\r\n\
//!       \r\n\
//!       Hello, world!\r\n"
//! );
//!
//! // The writer's output parses back.
//! let msg = mime_tree::parse(&raw).expect("parse failed");
//! assert_eq!(msg.text_body, vec!["1"]);
//! ```

mod decode;
mod error;
mod header_typed;
mod message;
mod parse;
mod part;
mod uuencode;
mod walk;
mod writer;
mod yenc;

pub use error::ParseError;
pub use header_typed::{
    parse_addresses, parse_date, parse_grouped_addresses, parse_header_typed,
    parse_header_typed_from, parse_message_ids, parse_raw, parse_text, parse_urls, AddressGroup,
    EmailAddress, HeaderDateTime, HeaderForm, HeaderValueTyped, TzSign, UnknownHeaderForm,
};
pub use message::{DecodedBodyValue, ParsedMessage};
pub use parse::{decode_body_value, parse, MAX_NESTING_DEPTH};
pub use part::{ParsedHeader, ParsedPart, TransferEncoding};
pub use uuencode::{scan_inline_uuencode, InlineUUBlock};
pub use writer::{write_message, Body, Group, Header, HeaderValue, Mailbox, Part, WriteError};
pub use yenc::{scan_inline_yencode, InlineYEncBlock};
