//! RFC 5322 / MIME parser producing a byte-range-indexed part tree.

mod decode;
mod error;
mod message;
mod parse;
mod part;
mod walk;

pub use error::ParseError;
pub use message::{DecodedBodyValue, ParsedMessage};
pub use parse::{decode_body_value, parse};
pub use part::{ParsedHeader, ParsedPart, TransferEncoding};
