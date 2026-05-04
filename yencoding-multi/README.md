# yencoding-multi

Multi-part yEnc Usenet article reassembly.

Large binary files on Usenet are split across numbered articles, each carrying
yEnc-encoded data and `=ypart begin=N end=M` headers specifying its byte range.
This crate collects decoded parts and reassembles them into the complete file.

Depends on the [`yencoding`](https://crates.io/crates/yencoding) crate for
decoding individual articles.

## Features

- Byte-range-based assembly (`=ypart begin=/end=` headers, not part numbers)
- Out-of-order part arrival — parts may be added in any order
- Overlap detection — duplicate or conflicting parts are rejected
- Gap reporting — `missing_ranges()` returns 0-based byte ranges not yet received
- Optional whole-file CRC32 verification on `finish()`
- No filesystem I/O
- No unsafe code
- MSRV: 1.75

## Usage

```rust
use yencoding_multi::Assembler;
use yencoding::decode;

// 1. Decode each article with the yencoding crate.
let part1 = decode(raw_article_1).unwrap();
let part2 = decode(raw_article_2).unwrap();

// 2. Set up the assembler with the total file size.
let total_size = part1.metadata.size; // from =ybegin size=
let mut assembler = Assembler::new(total_size);

// 3. Add parts in any order.
assembler.add_part(&part1).unwrap();
assembler.add_part(&part2).unwrap();

// 4. Finish when complete.
if assembler.is_complete() {
    let file_bytes = assembler.finish().unwrap();
    // Apply size/resource limits before decompressing file_bytes.
}
```

## Error types

```rust
pub enum AssemblyError {
    OverlappingPart { existing: Range<u64>, new: Range<u64> },
    OutOfRange { begin: u64, end: u64, total_size: u64 },
    CrcMismatch { expected: u32, actual: u32 },
    Incomplete { missing: Vec<Range<u64>> },
}
```

## Differences from `uuencoding-multi`

`uuencoding-multi` tracks parts by **part number** (from the subject line)
because UUencode has no byte-range headers. `yencoding-multi` tracks parts by
**byte range** (from `=ypart begin=/end=`) because yEnc carries explicit offsets.

## Security

Reassembled data may be a compressed archive. Any decompression is the caller's
responsibility and must be guarded against decompression-bomb attacks. This
crate does not decompress.

## License

MIT OR Apache-2.0
