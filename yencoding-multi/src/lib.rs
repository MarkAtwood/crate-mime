//! Multi-part yEnc Usenet article reassembly.
//!
//! # Background
//!
//! Large binary files on Usenet are split across multiple articles. Each
//! article is independently yEnc-encoded and carries `=ypart begin=N end=M`
//! headers that declare exactly which byte range of the final file this article
//! contains. After collecting all articles and decoding each with the
//! [`yencoding`] crate, the decoded parts can be assembled back into the
//! original file.
//!
//! # How this crate differs from `uuencoding-multi`
//!
//! [`uuencoding-multi`](https://crates.io/crates/uuencoding-multi) tracks
//! parts by **part number** (1-based integer from the subject line) because UUencode
//! articles carry no byte-range headers. yEnc articles carry explicit
//! **byte-range headers** (`=ypart begin=/end=`), so this crate tracks parts
//! by byte range instead. This enables:
//! - Immediate overlap/gap detection without knowing the total part count.
//! - Out-of-order assembly without sorting.
//! - Byte-accurate missing-range reporting.
//!
//! # What this crate does NOT do
//!
//! - **NZB parsing** — NZB is an XML format describing which articles carry
//!   each file. Use a dedicated NZB parser to extract the article list before
//!   passing decoded parts here.
//! - **NNTP transport** — fetching articles is the caller's responsibility.
//! - **Subject-line parsing** — use
//!   [`uuencoding-multi::parse_subject`](https://docs.rs/uuencoding-multi/latest/uuencoding_multi/fn.parse_subject.html)
//!   or similar for subject parsing if needed; this crate operates on decoded
//!   bytes only.
//! - **yEnc decoding** — use the [`yencoding`] crate to decode individual
//!   articles before passing them to [`Assembler`].
//!
//! # Security
//!
//! Reassembled `data` may represent a compressed archive (`.tar.gz`, `.zip`,
//! `.rar`, etc.). **This crate never decompresses the output.** Any subsequent
//! decompression is the caller's responsibility and must be independently
//! guarded against decompression-bomb attacks before beginning decompression.
//!
//! # Quick start
//!
//! ```no_run
//! use yencoding_multi::Assembler;
//! use yencoding::decode;
//!
//! // Imagine these raw article bytes come from an NNTP server.
//! let raw_articles: Vec<Vec<u8>> = todo!("fetch from NNTP");
//! let total_file_size: u64 = todo!("from =ybegin size= or NZB");
//! let whole_file_crc32: Option<u32> = todo!("from last-part =yend crc32= or NZB");
//!
//! let mut assembler = Assembler::new(total_file_size).expect("total_size too large");
//! if let Some(crc) = whole_file_crc32 {
//!     assembler.set_expected_crc32(crc);
//! }
//!
//! for raw in &raw_articles {
//!     let part = decode(raw).expect("decode failed");
//!     assembler.add_part(&part).expect("assembly error");
//! }
//!
//! if assembler.is_complete() {
//!     let file_bytes = assembler.finish().expect("CRC mismatch");
//!     // IMPORTANT: apply size/resource limits before decompressing file_bytes.
//! } else {
//!     eprintln!("still missing: {:?}", assembler.missing_ranges());
//! }
//! ```

mod assembler;
mod error;

pub use assembler::{Assembler, MAX_TOTAL_SIZE};
pub use error::AssemblyError;
