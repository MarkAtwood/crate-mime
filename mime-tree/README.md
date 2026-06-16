# mime-tree

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-orange.svg)](Cargo.toml)

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

`ParsedMessage` implements `Serialize + Deserialize`.

### `ParsedPart`

A single node in the MIME tree.

| Field | Type | Description |
|---|---|---|
| `part_id` | `String` | IMAP dotted-path ID: `"1"`, `"1.1"`, `"1.2"`, … |
| `content_type` | `String` | Media type/subtype, e.g. `"text/plain"` |
| `charset` | `Option<String>` | Charset from Content-Type, if present |
| `transfer_encoding` | `TransferEncoding` | See table below |
| `disposition` | `Option<String>` | Content-Disposition value |
| `filename` | `Option<String>` | Filename from Content-Disposition or Content-Type |
| `cid` | `Option<String>` | Content-ID header value |
| `header_range` | `(u32, u32)` | `(offset, length)` of part headers in original bytes |
| `body_range` | `(u32, u32)` | `(offset, length)` of part body (pre-decode) in original bytes |
| `children` | `Vec<ParsedPart>` | Child parts — non-empty for `multipart/*` only |
| `is_encoding_problem` | `bool` | True if mail-parser flagged a structural encoding problem at parse time |

Byte ranges use `u32` so the serialized representation is stable across 32-bit and
64-bit hosts. MIME messages are bounded well within 4 GiB.

#### `TransferEncoding` variants

| Variant | CTE header value(s) |
|---|---|
| `QuotedPrintable` | `quoted-printable` |
| `Base64` | `base64` |
| `SevenBit` | `7bit` |
| `EightBit` | `8bit` |
| `Binary` | `binary` |
| `Identity` | Fallback for missing or unknown CTE values |
| `UUEncode` | `x-uuencode`, `x-uue`, `uuencode` |

Unknown CTE values fall back to `Identity` and add a warning to `ParsedMessage::warnings`.

### `DecodedBodyValue`

Returned by `decode_body_value()`.

| Field | Type | Description |
|---|---|---|
| `value` | `String` | Decoded, charset-converted text |
| `is_truncated` | `bool` | True if `max_bytes` limit was reached |
| `is_encoding_problem` | `bool` | True if transfer-decode or charset conversion encountered an error |

## Decoding body content

`decode_body_value` slices the raw bytes using a part's `body_range`, applies
transfer-encoding decode (Base64, Quoted-Printable, UUencode, etc.), and
charset-converts the result to UTF-8 via `encoding_rs`. Decoding is on-demand —
parse time is O(message size) and does not decode any bodies.

```rust
// Decode with a 64 KiB preview cap (pass None for unlimited).
let decoded = decode_body_value(raw, &part, Some(65_536))?;
if decoded.is_truncated {
    // body was larger than max_bytes
}
if decoded.is_encoding_problem {
    // transfer-decode or charset conversion hit an error; `value` may be partial
}
```

## Inline UUencoded blocks

Some legacy messages — especially Usenet archives and mailing-list digests from the
1990s — embed UU-encoded files inside `text/plain` bodies with no
`Content-Transfer-Encoding` header. Use `scan_inline_uuencode` to locate and decode
those blocks:

```rust
use mime_tree::{parse, scan_inline_uuencode};

let raw: &[u8] = /* raw message bytes */;
let msg = parse(raw).unwrap();

for id in &msg.text_body {
    let part = msg.part_index.find_by_id(id).unwrap();
    for block in scan_inline_uuencode(raw, part) {
        if !block.is_encoding_problem {
            println!("found {} ({} bytes, mode {:o})",
                block.filename, block.data.len(), block.mode);
        }
    }
}
```

`InlineUUBlock` fields:

| Field | Type | Description |
|---|---|---|
| `begin_offset` | `u32` | Absolute byte offset of the `begin` line in `raw` |
| `begin_length` | `Option<u32>` | Byte length of the entire block (through `end\n`); `None` for error items |
| `mode` | `u32` | Unix permission mode from the `begin` line |
| `filename` | `String` | Filename from the `begin` line |
| `data` | `Vec<u8>` | Decoded binary payload |
| `is_encoding_problem` | `bool` | True if the block was truncated or malformed |

## Inline yEnc blocks

Usenet binary posts from the 2000s onward typically use yEnc encoding with no
`Content-Transfer-Encoding` header — the article body is simply `text/plain`
with `=ybegin`/`=yend` framing embedded in it. Use `scan_inline_yencode` to
locate and decode those blocks:

```rust
use mime_tree::{parse, scan_inline_yencode};

let raw: &[u8] = /* raw message bytes */;
let msg = parse(raw).unwrap();

for id in &msg.text_body {
    let part = msg.part_index.find_by_id(id).unwrap();
    for block in scan_inline_yencode(raw, part) {
        if !block.is_encoding_problem {
            println!("found {} ({} bytes)", block.filename, block.data.len());
        }
    }
}
```

A reasonable heuristic before calling: check whether the part's decoded text
contains the byte sequence `b"=ybegin "`.

`InlineYEncBlock` fields:

| Field | Type | Description |
|---|---|---|
| `begin_offset` | `u32` | Absolute byte offset of the `=ybegin` line in `raw` |
| `begin_length` | `u32` | Byte length of the entire block (through `=yend\n`) |
| `filename` | `String` | Filename from `=ybegin name=` |
| `file_size` | `u64` | Total file size from `=ybegin size=` |
| `part` | `Option<u32>` | Part number (multi-part only) |
| `total_parts` | `Option<u32>` | Total parts (multi-part only) |
| `part_begin` | `Option<u64>` | 1-based start offset in full file (multi-part only) |
| `part_end` | `Option<u64>` | 1-based end offset in full file (multi-part only) |
| `data` | `Vec<u8>` | Decoded binary payload |
| `crc32_verified` | `bool` | True if CRC32 was present and matched |
| `is_encoding_problem` | `bool` | True if the block was truncated, had a bad header, or CRC mismatch |

For multi-part reassembly, pass each `InlineYEncBlock`'s fields to
[`yencoding_multi::Assembler`](https://crates.io/crates/yencoding-multi).

## Typed header values (RFC 8621 `As*` forms)

`ParsedHeader` exposes each header as a decoded raw string. For callers that need
the RFC 8621 §4.1.2 parsed forms (the JMAP `header:<name>:as<form>` selectors),
`parse_header_typed` takes the raw bytes of a header's field value and returns
the requested parsed form:

```rust
use mime_tree::{parse_header_typed, HeaderForm, HeaderValueTyped};

let raw_value = b" \"Alice\" <alice@example.com>, bob@example.com";
match parse_header_typed(HeaderForm::Addresses, raw_value) {
    HeaderValueTyped::Addresses(addrs) => {
        for a in &addrs {
            println!("{:?} <{:?}>", a.name, a.address);
        }
    }
    _ => unreachable!(),
}
```

| `HeaderForm` | RFC 8621 § | Output variant |
|---|---|---|
| `Raw` | 4.1.2.1 | `Raw(String)` — trimmed UTF-8 only, no other decoding |
| `Text` | 4.1.2.2 | `Text(String)` — unfolded, RFC 2047 decoded, NFC-normalised |
| `Addresses` | 4.1.2.3 | `Addresses(Vec<EmailAddress>)` — flat list, group structure discarded |
| `GroupedAddresses` | 4.1.2.4 | `GroupedAddresses(Vec<AddressGroup>)` — groups preserved |
| `MessageIds` | 4.1.2.5 | `MessageIds(Vec<String>)` — bare ids, no `<>` or CFWS |
| `Date` | 4.1.2.6 | `DateTime(Option<HeaderDateTime>)` — `None` if unparseable |
| `URLs` | 4.1.2.7 | `URLs(Vec<String>)` — bare URLs, no `<>` or comments |

`EmailAddress`, `AddressGroup`, `HeaderDateTime`, `HeaderForm`, and
`HeaderValueTyped` are all owned, lifetime-free, and `Serialize + Deserialize`.
Parsing is best-effort: malformed input yields the empty result for the
requested form (empty `Vec`, empty string, or `DateTime(None)`) — never an
error and never a panic.

## Design invariants

- **No JMAP dependency.** General-purpose MIME parser; no `jmap-mail-types`.
- **No S/MIME crypto.** `application/pkcs7-mime` and `application/pkcs7-signature`
  parts are treated as opaque binary leaves. Use `smime-tree` for S/MIME processing.
- **Best-effort parsing.** Malformed input yields a partial result plus
  `warnings`; only truly unparsable input (empty bytes, no headers) returns `Err`.
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
| [RFC 8621 §4.1.4](https://www.rfc-editor.org/rfc/rfc8621#section-4.1.4) | JMAP for Mail — body structure algorithm |

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.
