# mime-tree

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE)
[![MSRV: 1.75](https://img.shields.io/badge/MSRV-1.75-orange.svg)](Cargo.toml)

RFC 5322 / MIME parser that produces a walkable, byte-range-indexed part tree.
Given raw message bytes, it returns a `ParsedMessage` with the full MIME structure,
RFC 8621-compatible body views, and on-demand body decoding.

## Why this crate exists

Most MIME parsers either give back owned strings (losing the original byte positions
needed for S/MIME signature verification) or expose the underlying parsing library's
types in their API (locking callers to that dependency). `mime-tree` gives you
`(offset, length)` byte ranges into your original `&[u8]` buffer — so you can feed
the exact bytes of a signed part directly to a cryptographic verifier without copying
or re-encoding. The parsed result is fully owned, lifetime-free, and
`Serialize + Deserialize`, so it round-trips through any store or message bus.

For S/MIME sign/verify/encrypt/decrypt, see the companion crate
[`smime-tree`](../smime-tree/).

## Quick example

```rust
use mime_tree::{parse, decode_body_value};

let raw: &[u8] = b"From: alice@example.com\r\n\
                   Content-Type: text/plain; charset=utf-8\r\n\
                   \r\n\
                   Hello, world!\r\n";

let msg = parse(raw).expect("parse failed");

// Walk the text_body part IDs to find plain-text parts.
for id in &msg.text_body {
    let part = msg.part_index.find_by_id(id).unwrap();
    let decoded = decode_body_value(raw, part, None).unwrap();
    println!("{}", decoded.value);
}
```

## Key types

### `ParsedMessage`

The result of `parse()`. All fields are owned; no lifetime parameters.

| Field | Type | Description |
|---|---|---|
| `part_index` | `ParsedPart` | Root of the MIME part tree |
| `text_body` | `Vec<String>` | Part IDs of text/plain body parts (RFC 8621 §4.1.4) |
| `html_body` | `Vec<String>` | Part IDs of text/html body parts |
| `attachments` | `Vec<String>` | Part IDs of attachment parts |
| `headers` | `Vec<ParsedHeader>` | Top-level message headers |
| `preview` | `Option<String>` | First ~256 chars of text content |
| `warnings` | `Vec<String>` | Non-fatal parse warnings |

`ParsedMessage` implements `Serialize + Deserialize` — store it however you like.

### `ParsedPart`

A single node in the MIME tree.

| Field | Type | Description |
|---|---|---|
| `part_id` | `String` | IMAP dotted-path ID: `"1"`, `"1.1"`, `"1.2"`, … |
| `content_type` | `String` | Media type/subtype, e.g. `"text/plain"` |
| `charset` | `Option<String>` | Charset from Content-Type, if present |
| `transfer_encoding` | `TransferEncoding` | `Identity \| QuotedPrintable \| Base64 \| SevenBit \| EightBit \| Binary` |
| `disposition` | `Option<String>` | Content-Disposition value |
| `filename` | `Option<String>` | Filename from Content-Disposition or Content-Type |
| `cid` | `Option<String>` | Content-ID header value |
| `header_range` | `(u32, u32)` | `(offset, length)` of part headers in original bytes |
| `body_range` | `(u32, u32)` | `(offset, length)` of part body (pre-decode) in original bytes |
| `children` | `Vec<ParsedPart>` | Child parts — non-empty only for `multipart/*` |

Byte ranges use `u32` so the serialized representation is identical on 32-bit and
64-bit hosts. MIME messages are bounded well within 4 GiB.

### `DecodedBodyValue`

Returned by `decode_body_value()`.

| Field | Type | Description |
|---|---|---|
| `value` | `String` | Decoded, charset-converted text |
| `is_truncated` | `bool` | True if `max_bytes` limit was reached |
| `is_encoding_problem` | `bool` | True if charset conversion found unmappable characters |

## Decoding body content

`decode_body_value` slices the raw bytes using a part's `body_range`, applies
transfer-encoding decode (Base64, Quoted-Printable, etc.), and charset-converts
the result to UTF-8 via `encoding_rs`. Decoding is on-demand — parse time is fast.

```rust
// Decode with a 64 KiB cap (pass None for unlimited).
let decoded = decode_body_value(raw, &part, Some(65_536))?;
if decoded.is_truncated {
    // body was larger than max_bytes
}
```

## Design invariants

- **No JMAP dependency.** General-purpose MIME parser; no `jmap-mail-types`.
- **No S/MIME crypto.** `application/pkcs7-mime` and `application/pkcs7-signature`
  parts are treated as opaque binary leaves. Use `smime-tree` for S/MIME processing.
- **Best-effort parsing.** Malformed input yields a partial result plus
  `warnings`; only truly unparseable input (empty bytes, no headers) returns `Err`.
- **No async.** Synchronous only.
- **Byte ranges, not stored bytes.** The crate never retains the raw message bytes.

## Specification references

| RFC | Title |
|---|---|
| [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) | Internet Message Format |
| [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045) | MIME Part One: Format of Internet Message Bodies |
| [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046) | MIME Part Two: Media Types (multipart boundaries) |
| [RFC 2047](https://www.rfc-editor.org/rfc/rfc2047) | MIME Part Three: Encoded-Word in headers |
| [RFC 2183](https://www.rfc-editor.org/rfc/rfc2183) | Content-Disposition header |
| [RFC 2231](https://www.rfc-editor.org/rfc/rfc2231) | MIME Parameter Value and Encoded Word Extensions |
| [RFC 8621 §4.1.4](https://www.rfc-editor.org/rfc/rfc8621#section-4.1.4) | JMAP for Mail — body structure algorithm (textBody / htmlBody / attachments) |

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.
