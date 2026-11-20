//! Regression tests for `begin` line recognition and block boundaries,
//! exercised through the public `decode` and `scan` entry points.
//!
//! Expected values are hand-built from the classic uuencode format
//! (`begin %o %s` header, length-prefixed data lines, terminator, `end`):
//! the data line `#0V%T` is length `#` (3 bytes) and decodes to `Cat`, and
//! `%2&5L;&\ ` is length `%` (5 bytes) and decodes to `Hello`.

use uuencoding::{decode, scan, UuError};

/// Data, terminator and `end` lines appended after each header under test.
const BODY: &[u8] = b"\n#0V%T\n`\nend\n";

fn with_body(header: &[u8]) -> Vec<u8> {
    let mut v = header.to_vec();
    v.extend_from_slice(BODY);
    v
}

/// Headers that are *not* UU begin lines: `decode` must report that no
/// `begin` line exists and `scan` must find nothing. `decode` and `scan`
/// must agree on every one of them.
#[test]
fn non_begin_headers_rejected_by_decode_and_scan() {
    let headers: &[&[u8]] = &[
        b"Begin forwarded message:",
        b"begin forwarded message",
        b"begin here",
        b"begin-foo 644 x",
        b"begin +644 x",
        b"begin -644 x",
        b"begin 0x1a4 x",
        b"begin 8 x",
        b"begin 649 x",
        b"begin 000000000000 x",
        b"begin 40000000000 x",
        b"begin 644x y",
        b"begin \xff44 x",
        b"beginners guide",
    ];
    for h in headers {
        let input = with_body(h);
        let shown = String::from_utf8_lossy(h);
        assert!(
            matches!(decode(&input), Err(UuError::InvalidBeginLine { .. })),
            "decode accepted {shown:?} as a begin line"
        );
        assert!(
            scan(&input).is_empty(),
            "scan accepted {shown:?} as a begin line"
        );
    }
}

/// Headers that *are* UU begin lines, with the mode and filename each must
/// yield. `decode` and `scan` must agree.
#[test]
fn valid_begin_headers_accepted_by_decode_and_scan() {
    let cases: &[(&[u8], u32, &str)] = &[
        (b"begin 644 cat.txt", 0o644, "cat.txt"),
        (b"BEGIN 644 cat.txt", 0o644, "cat.txt"),
        (b"begin\t644\tcat.txt", 0o644, "cat.txt"),
        (b"begin 7 cat.txt", 0o7, "cat.txt"),
        (b"begin 0644 cat.txt", 0o644, "cat.txt"),
        (b"begin 1755 cat.txt", 0o1755, "cat.txt"),
        (b"begin 100644 cat.txt", 0o100644, "cat.txt"),
        (b"begin 37777777777 cat.txt", u32::MAX, "cat.txt"),
        (b"begin 644 my cat.txt  ", 0o644, "my cat.txt"),
        (b"begin 644", 0o644, ""),
        (b"begin", 0, ""),
    ];
    for &(h, mode, name) in cases {
        let input = with_body(h);
        let shown = String::from_utf8_lossy(h);

        let d = decode(&input).unwrap_or_else(|e| panic!("decode rejected {shown:?}: {e}"));
        assert_eq!(d.data, b"Cat", "{shown:?}");
        assert_eq!(d.metadata.mode, mode, "{shown:?}");
        assert_eq!(d.metadata.filename, name, "{shown:?}");
        assert!(!d.is_truncated, "{shown:?}");

        let s = scan(&input);
        assert_eq!(s.len(), 1, "{shown:?}");
        let b = s[0].as_ref().unwrap();
        assert_eq!(b.data, b"Cat", "{shown:?}");
        assert_eq!(b.metadata, d.metadata, "{shown:?}");
        assert!(!b.is_truncated, "{shown:?}");
    }
}

/// Apple Mail forwards start with "Begin forwarded message:". That prose line
/// must not be taken as the UU header; the real block after it must be found.
#[test]
fn apple_mail_forward_header_is_not_a_begin_line() {
    let input: &[u8] =
        b"Begin forwarded message:\n\nFrom: a@b\n\nbegin 644 hello.txt\n%2&5L;&\\ \n \nend\n";
    // "Begin forwarded message:\n" (25) + "\n" (1) + "From: a@b\n" (10) + "\n" (1)
    let real_begin = 37;
    assert_eq!(&input[real_begin..real_begin + 9], b"begin 644");

    let d = decode(input).unwrap();
    assert_eq!(d.data, b"Hello");
    assert_eq!(d.metadata.filename, "hello.txt");
    assert!(!d.is_truncated);

    let s = scan(input);
    assert_eq!(s.len(), 1);
    let b = s[0].as_ref().unwrap();
    assert_eq!(b.begin_offset, real_begin);
    assert_eq!(b.end_offset, input.len());
    assert_eq!(b.data, b"Hello");
    assert!(!b.is_truncated);
}

/// A block that lost its `end` line (terminator present) must not swallow the
/// `begin` line of the following block.
#[test]
fn scan_block_without_end_keeps_next_block() {
    let input: &[u8] = b"begin 644 a\n#0V%T\n`\nbegin 644 b\n#0V%T\n`\nend\n";
    // "begin 644 a\n" (12) + "#0V%T\n" (6) + "`\n" (2)
    let second = 20;
    let s = scan(input);
    assert_eq!(s.len(), 2, "second block was dropped: {s:?}");

    let a = s[0].as_ref().unwrap();
    assert_eq!(a.metadata.filename, "a");
    assert_eq!(a.data, b"Cat");
    assert!(a.is_truncated);
    assert_eq!(a.begin_offset, 0);
    assert_eq!(a.end_offset, second);

    let b = s[1].as_ref().unwrap();
    assert_eq!(b.metadata.filename, "b");
    assert_eq!(b.data, b"Cat");
    assert!(!b.is_truncated);
    assert_eq!(b.begin_offset, second);
    assert_eq!(b.end_offset, input.len());
}

/// Same as above, but the first block lost both its terminator and `end`.
#[test]
fn scan_block_without_terminator_or_end_keeps_next_block() {
    let input: &[u8] = b"begin 644 a\n#0V%T\nbegin 644 b\n#0V%T\n`\nend\n";
    let second = 18; // "begin 644 a\n" (12) + "#0V%T\n" (6)
    let s = scan(input);
    assert_eq!(s.len(), 2, "second block was dropped: {s:?}");

    let a = s[0].as_ref().unwrap();
    assert_eq!(a.data, b"Cat");
    assert!(a.is_truncated);
    assert_eq!(a.end_offset, second);

    let b = s[1].as_ref().unwrap();
    assert_eq!(b.metadata.filename, "b");
    assert_eq!(b.begin_offset, second);
    assert_eq!(b.data, b"Cat");
    assert!(!b.is_truncated);
}

/// A UU block that lost its `end` must not swallow a following
/// `begin-base64` line either.
#[test]
fn scan_block_without_end_keeps_next_base64_block() {
    let input: &[u8] = b"begin 644 a\n#0V%T\n`\nbegin-base64 644 b\nQ2F0\n====\n";
    let s = scan(input);
    assert_eq!(s.len(), 2, "{s:?}");
    let a = s[0].as_ref().unwrap();
    assert!(a.is_truncated);
    assert_eq!(a.end_offset, 20);
    assert_eq!(s[1], Err(UuError::BeginBase64 { begin_offset: 20 }));
}

/// An unterminated `begin-base64` block (no `====`) must not hide a later
/// UU block.
#[test]
fn scan_unterminated_base64_does_not_hide_later_block() {
    let input: &[u8] = b"begin-base64 644 x\nAAAA\nbegin 644 b\n#0V%T\n`\nend\n";
    // "begin-base64 644 x\n" (19) + "AAAA\n" (5)
    let uu = 24;
    let s = scan(input);
    assert_eq!(s.len(), 2, "{s:?}");
    assert_eq!(s[0], Err(UuError::BeginBase64 { begin_offset: 0 }));
    let b = s[1].as_ref().unwrap();
    assert_eq!(b.begin_offset, uu);
    assert_eq!(b.metadata.filename, "b");
    assert_eq!(b.data, b"Cat");
    assert!(!b.is_truncated);
}

/// Two unterminated `begin-base64` blocks are reported separately.
#[test]
fn scan_unterminated_base64_followed_by_base64() {
    let input: &[u8] = b"begin-base64 644 x\nAAAA\nbegin-base64 644 y\nAAAA\n";
    let s = scan(input);
    assert_eq!(
        s,
        vec![
            Err(UuError::BeginBase64 { begin_offset: 0 }),
            Err(UuError::BeginBase64 { begin_offset: 24 }),
        ]
    );
}

/// Prose starting with "begin" inside an unterminated base64 body does not
/// stop the skip; only a real begin line does.
#[test]
fn scan_unterminated_base64_skips_prose_begin() {
    let input: &[u8] = b"begin-base64 644 x\nAAAA\nBegin forwarded message:\n";
    let s = scan(input);
    assert_eq!(s, vec![Err(UuError::BeginBase64 { begin_offset: 0 })]);
}

/// Every mode `encode` can write must be recognised by `decode` and `scan`.
#[test]
fn encode_extreme_modes_round_trip() {
    for mode in [0, 0o7, 0o777, 0o7777, 0o100644, u32::MAX] {
        let enc = uuencoding::encode(b"Cat", "cat.txt", mode);
        let d = decode(&enc).unwrap();
        assert_eq!(d.metadata.mode, mode);
        assert_eq!(d.data, b"Cat");
        let s = scan(&enc);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].as_ref().unwrap().metadata.mode, mode);
    }
}
