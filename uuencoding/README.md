# uuencoding

UUencoding and UUdecoding for Rust — encode, decode, and scan for UU blocks.

UUencoding is a binary-to-text encoding from the UUCP/Usenet era (1980s). It appears
in email as `Content-Transfer-Encoding: x-uuencode` and as inline `begin`/`end` blocks
embedded in `text/plain` message bodies.

## Features

- `encode(data, filename, mode)` — produce a well-formed `begin`/`end` UU block
- `decode(input)` — decode a full UU block including `begin`/`end` framing
- `scan(input)` — find all UU blocks by byte offset in arbitrary text (inline use case)
- Handles real-world noise: CRLF line endings, trailing-space stripping by mail relays,
  space/backtick ambiguity for zero, missing `end` lines, `begin-base64` detection
- No panics on any input
- No unsafe code
- MSRV: 1.75

## Usage

```rust
use uuencoding::{encode, decode, scan};

// Encode
let encoded = encode(b"Hello, World!", "hello.txt", 0o644);

// Decode
let block = decode(&encoded).unwrap();
assert_eq!(block.data, b"Hello, World!");
assert_eq!(block.metadata.filename, "hello.txt");

// Scan for inline blocks
for result in scan(&encoded) {
    let block = result.unwrap();
    println!("found block at {}..{}", block.begin_offset, block.end_offset);
}
```

## Security

Decoded output can be significantly larger than encoded input. If the decoded bytes
are a compressed archive, any decompression is the caller's responsibility and must
be independently guarded against decompression bombs.

## License

MIT OR Apache-2.0
