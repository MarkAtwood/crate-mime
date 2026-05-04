//! Multi-part UUencoded Usenet/email post reassembly.
//!
//! # Background
//!
//! Before MIME attachments became universal, large binary files were shared on
//! Usenet and via email by UUencoding them and splitting the result across
//! multiple posts or messages. Each post contained a sequential segment of the
//! encoded data, identified by a subject-line marker such as `[2/7]` or
//! `(2 of 7)`. Readers would collect all parts and concatenate the UU bodies
//! before decoding.
//!
//! Each multi-part series often began with a part 0 (the TOC post) that listed
//! the files being distributed along with their sizes and which parts each file
//! spanned. This crate handles both the TOC and the data parts.
//!
//! # What this crate provides
//!
//! - [`parse_subject`] — extract part index, part total, and base subject from
//!   a Usenet/email subject line. Recognises five common marker formats:
//!   `(N/M)`, `[N/M]`, `Part N/M`, `Part N of M`, and `- N/M`.
//! - [`PartCollection`] — accumulate [`PartEntry`] values keyed by part number
//!   until all parts are present, with gap detection and duplicate rejection.
//! - [`reassemble()`] — validate completeness, concatenate raw UU bodies in
//!   ascending part order, and decode via the `uuencoding` crate.
//! - [`parse_toc`] — best-effort parse of a TOC body (part 0), returning a
//!   [`ParsedToc`] with [`TocEntry`] records for each file listed.
//!
//! # What this crate does NOT do
//!
//! - **MIME parsing**: this crate operates on raw message body bytes that the
//!   caller has already extracted from the MIME structure. Use the `mime-tree`
//!   crate (or equivalent) to parse the enclosing MIME message and locate the
//!   plain-text body part before passing bytes here.
//! - **Message fetching or storage**: retrieving articles from an NNTP server,
//!   reading mailbox files, or persisting collected parts is entirely the
//!   caller's responsibility.
//! - **yEnc decoding**: subject lines that contain a `yEnc` marker are
//!   explicitly rejected by [`parse_subject`] (returns `None`). yEnc is a
//!   distinct binary encoding with its own tools.
//!
//! # Integration with `mime-tree`
//!
//! The expected integration pattern is:
//! 1. Parse the raw RFC 5322 message bytes with `mime-tree` to obtain the
//!    `Subject` header value and the plain-text body.
//! 2. Pass the `Subject` string to [`parse_subject`] to identify the part
//!    number and group key.
//! 3. Wrap the body bytes in a [`PartEntry`] and insert it into a
//!    [`PartCollection`] keyed by the base subject.
//! 4. Once the collection is complete, call [`reassemble()`].
//!
//! # Security
//!
//! The `data` field of [`ReassembledFile`] is raw decoded bytes that may
//! represent a compressed archive (`.tar.gz`, `.zip`, `.rar`, etc.). **This
//! crate never decompresses the output.** Callers that subsequently decompress
//! the data must apply independent size and resource limits to defend against
//! decompression-bomb attacks before beginning decompression.
//!
//! # End-to-end usage example
//!
//! ```no_run
//! use uuencoding_multi::{
//!     parse_subject, PartCollection, PartEntry, reassemble,
//! };
//!
//! // Imagine these come from an NNTP server or mailbox.
//! let raw_messages: Vec<(String, Vec<u8>)> = todo!("fetch messages");
//!
//! let mut collections: std::collections::HashMap<String, PartCollection> =
//!     std::collections::HashMap::new();
//!
//! for (subject, body_bytes) in raw_messages {
//!     // Step 1: parse the subject to identify part number and grouping key.
//!     let Some(sp) = parse_subject(&subject) else {
//!         continue; // empty or yEnc subject — skip
//!     };
//!     let Some(part_index) = sp.part_index else {
//!         continue; // no part marker — treat as a plain message
//!     };
//!
//!     // Step 2: accumulate parts by base subject.
//!     let coll = collections.entry(sp.base_subject).or_default();
//!     if let Some(total) = sp.part_total {
//!         if coll.total().is_none() {
//!             *coll = PartCollection::with_total(total);
//!         }
//!     }
//!     let entry = PartEntry { part_number: part_index, body_bytes, subject: Some(subject) };
//!     let _ = coll.add(entry); // ignore duplicates
//! }
//!
//! // Step 3: reassemble complete collections.
//! for (key, coll) in &collections {
//!     if !coll.is_complete() {
//!         eprintln!("{key}: still waiting for {:?}", coll.missing_parts());
//!         continue;
//!     }
//!     let file = reassemble(coll).expect("complete collection should decode");
//!     // IMPORTANT: apply size/resource limits before decompressing `file.data`.
//!     println!("decoded {} ({} bytes, mode {:o})", file.filename, file.data.len(), file.mode);
//! }
//! ```

pub mod collection;
pub mod error;
pub mod reassemble;
pub mod subject;
pub mod toc;

pub use collection::{PartCollection, PartEntry};
pub use error::MultiUuError;
pub use reassemble::{reassemble, ReassembledFile};
pub use subject::parse_subject;
pub use toc::{parse_toc, ParsedToc, TocEntry};

/// Fields extracted from a parsed Usenet/email subject line.
///
/// Returned by [`parse_subject`]. The `base_subject` field can be used as a
/// stable grouping key across parts of the same series.
///
/// # Field invariants
///
/// - `base_subject` is never empty when `SubjectParts` is returned (the only
///   way to get an empty or no-marker subject back is if `parse_subject`
///   returns `Some` with `part_index = None`).
/// - `part_total` is always `Some` when `part_index` is `Some`, because every
///   supported marker format includes the total count.
pub struct SubjectParts {
    /// Subject line with the part-number marker removed and surrounding
    /// whitespace trimmed. Safe to use as a collection grouping key because
    /// all parts of the same series share the same base subject.
    pub base_subject: String,
    /// 1-based part number extracted from the marker. `Some(0)` indicates a
    /// TOC post (e.g. `(00/17)`). `None` when no recognised marker was found.
    pub part_index: Option<u32>,
    /// Total number of parts as declared in the subject marker.
    /// Always `Some` when `part_index` is `Some`; `None` otherwise.
    pub part_total: Option<u32>,
}
