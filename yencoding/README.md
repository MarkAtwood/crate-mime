# yencoding

yEnc encoding and decoding for Usenet binary posts.

yEnc (2001) replaced UUencode and Base64 on Usenet by passing most bytes through
with only a +42 offset, giving ~1–2% overhead instead of 33%. This crate provides
a pure-Rust, no-filesystem, no-unsafe implementation.

## Features

- `decode(input)` — decode a yEnc article from raw bytes, with CRC32 verification
- `encode(data, filename, line_length)` — encode bytes as a single-part article
- `encode_part(...)` — encode one part of a multi-part series
- Handles preamble text before `=ybegin` (NNTP article headers, etc.)
- Accepts both LF and CRLF line endings
- Handles NNTP dot-stuffing
- `total_parts` exposed on `YencMetadata` for multi-part reassembly
- No filesystem I/O — all operations on `&[u8]` / `Vec<u8>`
- No unsafe code
- MSRV: 1.75

## Usage

```rust
use yencoding::{decode, encode, DEFAULT_LINE_LENGTH};

// Decode a yEnc article (preamble/NNTP headers are skipped automatically)
let article: &[u8] = b"=ybegin line=128 size=3 name=hi.bin\r\n*+,\r\n=yend size=3 crc32=0854897f\r\n";
let part = decode(article).unwrap();
assert_eq!(part.data, &[0u8, 1, 2]);
assert_eq!(part.metadata.filename, "hi.bin");
assert!(part.crc32_verified);

// Encode bytes as a single-part article
let encoded = encode(b"Hello", "hello.bin", DEFAULT_LINE_LENGTH);
assert!(encoded.starts_with(b"=ybegin"));
```

## Multi-part articles

For multi-part Usenet posts, decode each article individually with `decode()`,
then reassemble using the companion
[`yencoding-multi`](https://crates.io/crates/yencoding-multi) crate.
`DecodedPart::metadata.total_parts` and `part_begin`/`part_end` carry the
information needed for reassembly without separately parsing subject lines.

## Error types

```rust
pub enum YencError {
    NoHeader,                            // no =ybegin line found
    InvalidHeader { field: String },     // required field missing or unparsable
    CrcMismatch { expected: u32, actual: u32 },
    UnexpectedEof,                       // =yend line never found
    SizeMismatch { expected: u64, actual: u64 }, // decoded size != =yend size=
}
```

## Security

Decoded bytes may represent a compressed archive. Any decompression is the
caller's responsibility and must be independently guarded against
decompression-bomb attacks. This crate does not decompress.

## License

MIT OR Apache-2.0
