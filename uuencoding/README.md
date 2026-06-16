# uuencoding

UUencoding and UUdecoding for Rust — encode, decode, and scan for UU blocks.

UUencoding (Unix-to-Unix encoding) is a binary-to-text encoding from the UUCP/Usenet era
(1980s). It appears in email as `Content-Transfer-Encoding: x-uuencode` and as inline
`begin`/`end` blocks embedded in `text/plain` message bodies.

## Features

- `encode(data, filename, mode)` — produce a well-formed `begin`/`end` UU block
- `decode(input)` — decode a full UU block including `begin`/`end` framing
- `decode_limited(input, max_bytes)` — preview-efficient decode with a byte cap
- `scan(input)` — find and decode all UU blocks by byte offset in arbitrary text
- Handles real-world noise: CRLF line endings, trailing-space stripping by mail relays,
  space/backtick ambiguity for zero, missing `end` lines, `begin-base64` detection
- `DecodedBlock::was_limit_hit` distinguishes preview truncation from encoding errors
- No panics on any input
- No unsafe code
- MSRV: 1.75

## Usage

```rust
use uuencoding::{encode, decode, decode_limited, scan};

// Encode
let encoded = encode(b"Hello, World!", "hello.txt", 0o644);

// Decode the full block
let block = decode(&encoded).unwrap();
assert_eq!(block.data, b"Hello, World!");
assert_eq!(block.metadata.filename, "hello.txt");
assert_eq!(block.metadata.mode, 0o644);

// Decode only the first 5 bytes (preview)
let preview = decode_limited(&encoded, Some(5)).unwrap();
assert_eq!(preview.data, b"Hello");
assert!(preview.is_truncated);
assert!(preview.was_limit_hit);   // stopped by limit, not an encoding error

// Scan arbitrary text for embedded blocks
let text = b"Some prose.\nbegin 644 hello.txt\n%2&5L;&\\ \n \nend\nMore prose.\n";
for result in scan(text) {
    let block = result.unwrap();
    println!("found {} bytes for {} at offset {}",
        block.data.len(), block.metadata.filename, block.begin_offset);
}
```

## Error types

```rust
pub enum UuError {
    /// No `begin` line was found, or the begin line was malformed.
    InvalidBeginLine { line: String, begin_offset: usize },
    /// A `begin-base64` header was found — this is Base64, not UUencoding.
    BeginBase64 { begin_offset: usize },
    /// An out-of-range byte was found in a data line.
    /// `col` is the 0-based offset within the encoded payload; `byte` is the bad value.
    InvalidChar { col: usize, byte: u8 },
}
```

## Partial results and truncation

Both `decode` and `decode_limited` return `Ok` even when the block is malformed:

| Condition | `is_truncated` | `was_limit_hit` |
|---|---|---|
| Complete, well-formed block | `false` | `false` |
| Stopped by `max_bytes` limit | `true` | `true` |
| Missing `end` line or bad data byte | `true` | `false` |

## Security

Decoded output can be substantially larger than encoded input (ratio up to 3:4).
If the decoded bytes are a compressed archive, any decompression is the caller's
responsibility and must be independently guarded against decompression bombs.
This crate does not decompress.

## License

MIT OR Apache-2.0
