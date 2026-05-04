//! Integration tests for `uuencoding-multi`.
//!
//! # Oracle provenance
//!
//! UU bodies generated with Python 3.11 `uu` module (2026-05-04):
//!
//! ```python
//! import uu, io
//! def uu_encode(data, filename, mode):
//!     buf = io.BytesIO()
//!     uu.encode(io.BytesIO(data), buf, filename, mode)
//!     return buf.getvalue()
//!
//! full = b'The quick brown fox jumps over the lazy dog.'
//! p1 = uu_encode(full[0:15],  'fox.bin', 0o644)
//! p2 = uu_encode(full[15:30], 'fox.bin', 0o644)
//! p3 = uu_encode(full[30:],   'fox.bin', 0o644)
//! single = uu_encode(b'Hello, World!', 'hello.txt', 0o600)
//! ```
//!
//! CRC32 of full payload: 0x519025e9  (binascii.crc32)

use uuencoding_multi::{
    parse_subject, parse_toc, reassemble, MultiUuError, PartCollection, PartEntry,
};

// ---------------------------------------------------------------------------
// Fixtures — externally-generated (Python `uu` module)
// ---------------------------------------------------------------------------

/// UU-encoded bytes for b'The quick brown fox j' (first 15 bytes of FULL).
const PART1: &[u8] = b"begin 644 fox.bin\n/5&AE('%U:6-K(&)R;W=N\n \nend\n";

/// UU-encoded bytes for b'umps over the lazy d' (bytes 15-29 of FULL).
/// Note: contains `"` in the encoded body (valid UU character); escaped as `\"`.
const PART2: &[u8] = b"begin 644 fox.bin\n/(&9O>\"!J=6UP<R!O=F5R\n \nend\n";

/// UU-encoded bytes for b' the lazy dog.' (bytes 30-end of FULL).
const PART3: &[u8] = b"begin 644 fox.bin\n.('1H92!L87IY(&1O9RX \n \nend\n";

/// Original 44-byte payload: b'The quick brown fox jumps over the lazy dog.'
const FULL: &[u8] = b"The quick brown fox jumps over the lazy dog.";

/// UU-encoded bytes for b'Hello, World!' with filename=hello.txt, mode=0o600.
/// Contains a backslash in the body (valid UU character); escaped as `\\`.
const SINGLE_PART: &[u8] = b"begin 600 hello.txt\n-2&5L;&\\L(%=O<FQD(0  \n \nend\n";
const SINGLE_DECODED: &[u8] = b"Hello, World!";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_entry(part_number: u32, body: &[u8]) -> PartEntry {
    PartEntry {
        part_number,
        body_bytes: body.to_vec(),
        subject: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Happy path 3-part (in order)
// ---------------------------------------------------------------------------

#[test]
fn happy_path_three_parts_in_order() {
    let mut c = PartCollection::with_total(3);
    c.add(make_entry(1, PART1)).unwrap();
    c.add(make_entry(2, PART2)).unwrap();
    c.add(make_entry(3, PART3)).unwrap();

    let result = reassemble(&c).unwrap();
    assert_eq!(result.data, FULL, "decoded payload must match oracle");
    assert_eq!(result.filename, "fox.bin");
    assert_eq!(result.mode, 0o644);
    assert!(!result.is_truncated);
    assert!(result.missing_parts.is_empty());
}

// ---------------------------------------------------------------------------
// 2. Out-of-order insertion
// ---------------------------------------------------------------------------

#[test]
fn three_parts_out_of_order() {
    let mut c = PartCollection::with_total(3);
    c.add(make_entry(3, PART3)).unwrap();
    c.add(make_entry(1, PART1)).unwrap();
    c.add(make_entry(2, PART2)).unwrap();

    let result = reassemble(&c).unwrap();
    assert_eq!(
        result.data, FULL,
        "out-of-order parts must reassemble to same bytes"
    );
    assert!(!result.is_truncated);
    assert!(result.missing_parts.is_empty());
}

// ---------------------------------------------------------------------------
// 3. Missing middle part
// ---------------------------------------------------------------------------

#[test]
fn missing_middle_part_is_truncated() {
    let mut c = PartCollection::with_total(3);
    c.add(make_entry(1, PART1)).unwrap();
    // Part 2 deliberately omitted.
    c.add(make_entry(3, PART3)).unwrap();

    let result = reassemble(&c).unwrap();
    assert!(result.is_truncated, "missing a part must set is_truncated");
    assert_eq!(result.missing_parts, vec![2]);
    // Data is part1-decoded ++ part3-decoded; no panics, no mixing of bytes.
    // We don't assert exact content beyond it being non-empty.
    assert!(!result.data.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Single-part reassembly
// ---------------------------------------------------------------------------

#[test]
fn single_part_hello_world() {
    let mut c = PartCollection::with_total(1);
    c.add(make_entry(1, SINGLE_PART)).unwrap();

    let result = reassemble(&c).unwrap();
    assert_eq!(result.data, SINGLE_DECODED);
    assert_eq!(result.filename, "hello.txt");
    assert_eq!(result.mode, 0o600);
    assert!(!result.is_truncated);
    assert!(result.missing_parts.is_empty());
}

// ---------------------------------------------------------------------------
// 5. Duplicate part rejected
// ---------------------------------------------------------------------------

#[test]
fn duplicate_part_returns_error() {
    let mut c = PartCollection::new();
    c.add(make_entry(1, PART1)).unwrap();
    let err = c.add(make_entry(1, PART1)).unwrap_err();
    assert!(
        matches!(err, MultiUuError::DuplicatePart { part_number: 1 }),
        "expected DuplicatePart{{1}}, got: {:?}",
        err
    );
}

// ---------------------------------------------------------------------------
// 6. Empty collection
// ---------------------------------------------------------------------------

#[test]
fn empty_collection_returns_error() {
    let c = PartCollection::new();
    let err = reassemble(&c).unwrap_err();
    assert!(
        matches!(err, MultiUuError::EmptyCollection),
        "expected EmptyCollection, got: {:?}",
        err
    );
}

/// A collection that contains only a TOC part (number 0) has no data parts.
#[test]
fn toc_only_collection_returns_empty_error() {
    let mut c = PartCollection::new();
    c.add(PartEntry {
        part_number: 0,
        body_bytes: b"some toc text".to_vec(),
        subject: None,
    })
    .unwrap();
    let err = reassemble(&c).unwrap_err();
    assert!(matches!(err, MultiUuError::EmptyCollection));
}

// ---------------------------------------------------------------------------
// 7. Subject line parsing — edge-case sweep
// ---------------------------------------------------------------------------

/// Parenthesised fraction with leading zero.
#[test]
fn subject_paren_fraction_leading_zero() {
    let p = parse_subject("filename.tar.gz (03/17)").unwrap();
    assert_eq!(p.part_index, Some(3));
    assert_eq!(p.part_total, Some(17));
}

/// Bracketed fraction.
#[test]
fn subject_bracket_fraction() {
    let p = parse_subject("filename.tar.gz [2/4]").unwrap();
    assert_eq!(p.part_index, Some(2));
    assert_eq!(p.part_total, Some(4));
}

/// "Part N/M" English form.
#[test]
fn subject_part_slash() {
    let p = parse_subject("archive.zip Part 3/17").unwrap();
    assert_eq!(p.part_index, Some(3));
    assert_eq!(p.part_total, Some(17));
}

/// "Part N of M" English form with leading zeros.
#[test]
fn subject_part_of() {
    let p = parse_subject("file.zip Part 03 of 17").unwrap();
    assert_eq!(p.part_index, Some(3));
    assert_eq!(p.part_total, Some(17));
}

/// Re: prefix is stripped before matching.
#[test]
fn subject_re_prefix_stripped() {
    let p = parse_subject("Re: file.zip (03/17)").unwrap();
    assert_eq!(p.part_index, Some(3));
    assert_eq!(p.part_total, Some(17));
}

/// Part 0 = TOC marker.
#[test]
fn subject_part_zero_is_toc() {
    let p = parse_subject("(0/5) README").unwrap();
    assert_eq!(p.part_index, Some(0));
    assert_eq!(p.part_total, Some(5));
}

/// Plain subject with no marker: both part fields are None.
#[test]
fn subject_no_marker_returns_none_indices() {
    let p = parse_subject("plaintext subject").unwrap();
    assert_eq!(p.part_index, None);
    assert_eq!(p.part_total, None);
    assert_eq!(p.base_subject, "plaintext subject");
}

/// yEnc subjects are out of scope — returns None.
#[test]
fn subject_yenc_returns_none() {
    assert!(parse_subject("\"file.nfo\" yEnc (1/3)").is_none());
}

/// Empty string returns None.
#[test]
fn subject_empty_returns_none() {
    assert!(parse_subject("").is_none());
}

/// base_subject has leading/trailing whitespace trimmed.
#[test]
fn subject_base_trimmed() {
    let p = parse_subject("  myfile.bin (1/3)  ").unwrap();
    assert!(!p.base_subject.starts_with(' '));
    assert!(!p.base_subject.ends_with(' '));
}

/// Very large part numbers (6 digits) don't overflow or panic.
#[test]
fn subject_large_part_numbers_no_panic() {
    let p = parse_subject("huge.bin (999999/999999)").unwrap();
    assert_eq!(p.part_index, Some(999_999));
    assert_eq!(p.part_total, Some(999_999));
}

/// Nested Re: Re: prefixes both stripped.
#[test]
fn subject_nested_re_stripped() {
    let p = parse_subject("Re: Re: file.tar.gz (1/3)").unwrap();
    assert_eq!(p.part_index, Some(1));
}

// ---------------------------------------------------------------------------
// 8. TOC parsing — edge-case sweep
// ---------------------------------------------------------------------------

/// "filename size parts" format.
#[test]
fn toc_format1_size_and_parts() {
    let body = b"file.tar.gz   1234567 bytes   parts 1-8\n";
    let toc = parse_toc(body).unwrap();
    assert_eq!(toc.entries.len(), 1);
    assert_eq!(toc.entries[0].filename, "file.tar.gz");
    assert_eq!(toc.entries[0].size_bytes, Some(1_234_567));
    assert_eq!(toc.entries[0].parts, Some(1..=8));
}

/// Comment lines and blank lines are skipped; KB unit is converted.
#[test]
fn toc_comment_and_kb_unit() {
    let body = b"# comment\n\nfile.zip (512 KB)\n";
    let toc = parse_toc(body).unwrap();
    assert_eq!(toc.entries.len(), 1);
    assert_eq!(toc.entries[0].filename, "file.zip");
    assert_eq!(toc.entries[0].size_bytes, Some(512 * 1024));
}

/// Completely unparseable body returns None.
#[test]
fn toc_not_a_toc_returns_none() {
    let body = b"not a toc at all";
    assert!(parse_toc(body).is_none());
}

/// Multiple entries parsed.
#[test]
fn toc_multiple_entries() {
    let body = b"archive.tar.gz   2 MB   parts 1-4\nreadme.txt   100 bytes\n";
    let toc = parse_toc(body).unwrap();
    assert_eq!(toc.entries.len(), 2);
    assert_eq!(toc.entries[0].filename, "archive.tar.gz");
    assert_eq!(toc.entries[0].size_bytes, Some(2 * 1024 * 1024));
    assert_eq!(toc.entries[0].parts, Some(1..=4));
    assert_eq!(toc.entries[1].filename, "readme.txt");
    assert_eq!(toc.entries[1].size_bytes, Some(100));
}

/// Garbage lines mixed with valid lines: valid entries are still returned.
#[test]
fn toc_garbage_lines_skipped() {
    let body = b"garbage prose\nfile.zip   500 bytes\nmore garbage\n";
    let toc = parse_toc(body).unwrap();
    assert_eq!(toc.entries.len(), 1);
    assert_eq!(toc.entries[0].filename, "file.zip");
}

/// Non-UTF-8 bytes do not cause a panic.
#[test]
fn toc_non_utf8_no_panic() {
    let mut body = vec![0xFF, 0xFE, b'\n'];
    body.extend_from_slice(b"file.bin   100 bytes\n");
    // Must not panic; may or may not produce an entry.
    let _ = parse_toc(&body);
}

/// Empty input returns None.
#[test]
fn toc_empty_returns_none() {
    assert!(parse_toc(b"").is_none());
}

/// raw_text field preserves verbatim input.
#[test]
fn toc_raw_text_preserved() {
    let body = b"# TOC header\nfile.tar.gz   100 bytes\n";
    let toc = parse_toc(body).unwrap();
    assert!(toc.raw_text.contains("# TOC header"));
    assert!(toc.raw_text.contains("file.tar.gz"));
}

// ---------------------------------------------------------------------------
// 9. PartCollection invariants
// ---------------------------------------------------------------------------

/// Adding a part auto-bumps the total to at least the part number.
#[test]
fn collection_total_auto_bumped() {
    let mut c = PartCollection::new();
    c.add(make_entry(5, PART1)).unwrap();
    assert_eq!(c.total(), Some(5));
}

/// TOC part (0) does not affect the total.
#[test]
fn collection_toc_does_not_affect_total() {
    let mut c = PartCollection::new();
    c.add(PartEntry {
        part_number: 0,
        body_bytes: vec![],
        subject: None,
    })
    .unwrap();
    assert_eq!(c.total(), None);
}

/// missing_parts returns empty when total is unknown.
#[test]
fn collection_missing_parts_empty_without_total() {
    let c = PartCollection::new();
    assert_eq!(c.missing_parts(), Vec::<u32>::new());
}

/// is_complete requires all parts present.
#[test]
fn collection_is_complete_with_gap() {
    let mut c = PartCollection::with_total(3);
    c.add(make_entry(1, PART1)).unwrap();
    c.add(make_entry(3, PART3)).unwrap();
    assert!(!c.is_complete());
    assert_eq!(c.missing_parts(), vec![2]);
}

/// present_parts iterates in ascending order regardless of insertion order.
#[test]
fn collection_present_parts_ascending() {
    let mut c = PartCollection::new();
    c.add(make_entry(3, PART3)).unwrap();
    c.add(make_entry(1, PART1)).unwrap();
    c.add(make_entry(2, PART2)).unwrap();
    let parts: Vec<u32> = c.present_parts().collect();
    assert_eq!(parts, vec![1, 2, 3]);
}
