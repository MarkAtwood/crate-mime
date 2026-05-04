# uuencoding-multi

Multi-part UUencoded Usenet/email post reassembly.

Multi-part UUencoding was the standard way to post binary files to Usenet before MIME.
A large file was split into numbered parts, each posted as a separate message with a
subject line like `filename.tar.gz (03/17)`. This crate reassembles those parts.

Depends on the [`uuencoding`](https://crates.io/crates/uuencoding) crate for decoding
individual parts.

## Features

- Parse 5 real-world subject line formats to extract part number and total
- Accumulate parts via `PartCollection` with gap detection and `is_complete()` check
- Best-effort TOC (table-of-contents) parsing for part-0 summary posts
- `reassemble()` — decode each part and concatenate into the original file bytes
- Partial reassembly when parts are missing (`is_truncated` flag, `missing_parts` list)
- No panics on any input
- No unsafe code
- MSRV: 1.75

## Quick start

```rust
use uuencoding_multi::{PartCollection, PartEntry, parse_subject, reassemble};

// Step 1: parse subject lines to identify part number and grouping key
let sp = parse_subject("bigfile.tar.gz (02/05)").unwrap();
assert_eq!(sp.part_index, Some(2));
assert_eq!(sp.part_total, Some(5));
assert_eq!(sp.base_subject, "bigfile.tar.gz");

// Step 2: collect parts (body_bytes is the raw UU-encoded message body)
let mut coll = PartCollection::with_total(3);
coll.add(PartEntry { part_number: 1, body_bytes: part1_bytes, subject: None }).unwrap();
coll.add(PartEntry { part_number: 2, body_bytes: part2_bytes, subject: None }).unwrap();
coll.add(PartEntry { part_number: 3, body_bytes: part3_bytes, subject: None }).unwrap();

// Step 3: reassemble when complete
if coll.is_complete() {
    let file = reassemble(&coll).unwrap();
    // IMPORTANT: apply size/resource limits before decompressing file.data
    println!("{}: {} bytes (mode {:o})", file.filename, file.data.len(), file.mode);
}
```

## Subject line formats supported

| Format | Example |
|---|---|
| Parenthesized fraction | `filename.tar.gz (03/17)` |
| Bracketed fraction | `filename.tar.gz [03/17]` |
| English Part N/M | `filename.zip Part 3/17` |
| English Part N of M | `filename.zip Part 03 of 17` |
| Dash-separated | `filename.zip - 03/17` |

`Re:` and `Fwd:` prefixes are stripped before matching. yEnc subjects return `None`
(distinct encoding, out of scope for this crate).

## Partial reassembly

When parts are missing, `reassemble()` still returns `Ok` rather than an error:

```rust
let file = reassemble(&coll).unwrap();
if file.is_truncated {
    if !file.missing_parts.is_empty() {
        // Gap in the collection — these parts were absent
        eprintln!("missing parts: {:?}", file.missing_parts);
    } else {
        // All parts present but at least one had a truncated UU body
        eprintln!("per-part encoding problem");
    }
}
```

## Error types

```rust
pub enum MultiUuError {
    /// reassemble() called with no parts (part_number >= 1).
    EmptyCollection,
    /// uuencoding::decode failed on one of the part bodies.
    DecodeError(uuencoding::UuError),
    /// Two parts with the same part_number were added.
    DuplicatePart { part_number: u32 },
}
```

## Security

Reassembled `data` is raw bytes which may be a compressed archive. Any decompression
is the caller's responsibility and must be independently guarded against decompression
bombs. This crate does not decompress.

## License

MIT OR Apache-2.0
