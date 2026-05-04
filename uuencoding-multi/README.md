# uuencoding-multi

Multi-part UUencoded Usenet/email post reassembly.

Multi-part UUencoding was the standard way to post binary files to Usenet before MIME.
A large file was split into numbered parts, each posted as a separate message with a
subject line like `filename.tar.gz (03/17)`. This crate reassembles those parts.

## Features

- Parse 5 real-world subject line formats to extract part number and total
- Accumulate parts via `PartCollection` with gap detection and `is_complete()` check
- Best-effort TOC (table-of-contents) parsing for part-0 summary posts
- `reassemble()` — decode each part and concatenate into the original file bytes
- Partial reassembly when parts are missing (`is_truncated` flag, `missing_parts` list)
- No panics on any input
- No unsafe code
- MSRV: 1.75

## Usage

```rust
use uuencoding_multi::{PartCollection, PartEntry, parse_subject, reassemble};

// Parse subject lines to get part numbers
let s = parse_subject("filename.tar.gz (02/03)").unwrap();
assert_eq!(s.part_index, Some(2));
assert_eq!(s.part_total, Some(3));

// Collect parts (body_bytes is the raw UU-encoded body of each message)
let mut collection = PartCollection::with_total(3);
collection.add(PartEntry { part_number: 1, body_bytes: part1_bytes, subject: None }).unwrap();
collection.add(PartEntry { part_number: 2, body_bytes: part2_bytes, subject: None }).unwrap();
collection.add(PartEntry { part_number: 3, body_bytes: part3_bytes, subject: None }).unwrap();

// Reassemble
if collection.is_complete() {
    let file = reassemble(&collection).unwrap();
    println!("filename: {}, {} bytes", file.filename, file.data.len());
}
```

## Subject line formats supported

| Format | Example |
|--------|---------|
| Parenthesized fraction | `filename.tar.gz (03/17)` |
| Bracketed fraction | `filename.tar.gz [03/17]` |
| English Part N/M | `filename.zip Part 3/17` |
| English Part N of M | `filename.zip Part 03 of 17` |
| Dash-separated | `filename.zip - 03/17` |

`Re:` and `Fwd:` prefixes are stripped. yEnc subjects return `None` (different encoding, out of scope).

## Security

Reassembled `data` is raw bytes which may be a compressed archive. Any decompression
is the caller's responsibility and must be independently guarded against decompression
bombs. This crate does not decompress.

## License

MIT OR Apache-2.0
