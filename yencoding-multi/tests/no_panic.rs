//! Adversarial-input tests for `yencoding-multi::Assembler`.
//!
//! These tests verify that extreme, malformed, and boundary-case inputs
//! produce errors (not panics). None of them should ever panic.

use yencoding::DecodedPart;
use yencoding_multi::{Assembler, AssemblyError, MAX_TOTAL_SIZE};

fn make_part(data: &[u8], begin: Option<u64>, end: Option<u64>) -> DecodedPart {
    use yencoding::{decode, encode_part, EncodePartOptions, DEFAULT_LINE_LENGTH};
    let opts = EncodePartOptions {
        filename: "test.bin",
        total_size: 512,
        total_parts: 2,
        part: 1,
        begin: 1,
        end: 1,
        whole_file_crc32: 0,
        line_length: DEFAULT_LINE_LENGTH,
    };
    let mut part = decode(&encode_part(&[0u8], &opts)).unwrap();
    part.data = data.to_vec();
    part.part_begin = begin;
    part.part_end = end;
    part.whole_file_crc32 = None;
    part.crc32_verified = false;
    part
}

#[test]
fn u64_max_begin_and_end_returns_out_of_range() {
    let mut a = Assembler::new(512).unwrap();
    let part = make_part(&[0u8; 4], Some(u64::MAX), Some(u64::MAX));
    let err = a.add_part(&part).unwrap_err();
    // begin=u64::MAX: begin_0 = u64::MAX - 1, end_0 = u64::MAX
    // Both exceed total_size=512 → OutOfRange
    assert!(
        matches!(err, AssemblyError::OutOfRange { .. }),
        "u64::MAX offsets must return OutOfRange, got: {err:?}"
    );
}

#[test]
fn u64_max_total_size_returns_too_large() {
    match Assembler::new(u64::MAX) {
        Err(AssemblyError::TotalSizeTooLarge { .. }) => {}
        Err(other) => panic!("expected TotalSizeTooLarge, got: {other:?}"),
        Ok(_) => panic!("u64::MAX total_size must be rejected"),
    }
}

#[test]
fn begin_u64_max_end_u64_max_total_512() {
    // Specific scenario from the issue: part_begin=u64::MAX, part_end=u64::MAX,
    // total_size=512. Must return error, not panic from overflow.
    let mut a = Assembler::new(512).unwrap();
    let part = make_part(&[], Some(u64::MAX), Some(u64::MAX));
    let err = a.add_part(&part).unwrap_err();
    assert!(
        matches!(
            err,
            AssemblyError::OutOfRange { .. } | AssemblyError::DataLengthMismatch { .. }
        ),
        "extreme offsets on small assembler must error, got: {err:?}"
    );
}

#[test]
fn begin_1_end_u64_max_returns_out_of_range() {
    let mut a = Assembler::new(512).unwrap();
    let part = make_part(&[0u8; 4], Some(1), Some(u64::MAX));
    let err = a.add_part(&part).unwrap_err();
    assert!(
        matches!(err, AssemblyError::OutOfRange { .. }),
        "end=u64::MAX must return OutOfRange, got: {err:?}"
    );
}

#[test]
fn zero_length_data_with_nonzero_range() {
    let mut a = Assembler::new(100).unwrap();
    // Empty data but range claims 10 bytes
    let part = make_part(&[], Some(1), Some(10));
    let err = a.add_part(&part).unwrap_err();
    assert!(
        matches!(err, AssemblyError::DataLengthMismatch { .. }),
        "zero-length data with nonzero range must error, got: {err:?}"
    );
}

#[test]
fn many_small_adjacent_parts_no_panic() {
    // 256 one-byte parts covering bytes 0..256
    let mut a = Assembler::new(256).unwrap();
    for i in 0u64..256 {
        let begin_1 = i + 1; // 1-based
        let end_1 = i + 1; // 1-based inclusive = 0-based exclusive
        let part = make_part(&[i as u8], Some(begin_1), Some(end_1));
        a.add_part(&part).unwrap();
    }
    assert!(a.is_complete());
    let result = a.finish().unwrap();
    assert_eq!(result, (0u8..=255).collect::<Vec<_>>());
}

#[test]
fn overlapping_parts_with_large_offsets_no_panic() {
    // Two parts at high (but valid) offsets that overlap
    let size = 1024u64;
    let mut a = Assembler::new(size).unwrap();
    let data = vec![0u8; 100];
    // Part 1: bytes 900..1000
    a.add_part(&make_part(&data, Some(901), Some(1000)))
        .unwrap();
    // Part 2: bytes 950..1024 — overlaps with part 1
    let overlap_data = vec![0u8; 74];
    let err = a
        .add_part(&make_part(&overlap_data, Some(951), Some(1024)))
        .unwrap_err();
    assert!(
        matches!(err, AssemblyError::OverlappingPart { .. }),
        "overlapping parts must error, got: {err:?}"
    );
}

#[test]
fn max_total_size_cap_boundary() {
    // Exactly at cap: should succeed
    let a = Assembler::new(MAX_TOTAL_SIZE);
    assert!(a.is_ok(), "MAX_TOTAL_SIZE must be accepted");

    // One over cap: should fail
    match Assembler::new(MAX_TOTAL_SIZE + 1) {
        Err(AssemblyError::TotalSizeTooLarge { .. }) => {}
        Err(other) => panic!("expected TotalSizeTooLarge, got: {other:?}"),
        Ok(_) => panic!("MAX_TOTAL_SIZE + 1 must be rejected"),
    }
}

#[test]
fn begin_equals_end_multipart_is_rejected() {
    // begin=5, end=4 in 1-based → begin_0=4, end_0=4 → zero-length range
    let mut a = Assembler::new(100).unwrap();
    let part = make_part(&[], Some(5), Some(4));
    let err = a.add_part(&part).unwrap_err();
    assert!(
        matches!(err, AssemblyError::OutOfRange { .. }),
        "zero-length multipart range must be rejected, got: {err:?}"
    );
}

#[test]
fn reversed_begin_end_no_panic() {
    // begin > end (reversed range) must not cause underflow panic
    let mut a = Assembler::new(100).unwrap();
    let part = make_part(&[], Some(50), Some(10));
    // begin_0 = 49, end_0 = 10: begin_0 >= end_0 → OutOfRange
    let err = a.add_part(&part).unwrap_err();
    assert!(
        matches!(err, AssemblyError::OutOfRange { .. }),
        "reversed range must return OutOfRange, got: {err:?}"
    );
}

#[test]
fn begin_1_end_0_no_underflow_panic() {
    // begin=1, end=0: begin_0=0, end_0=0 → zero-length range
    let mut a = Assembler::new(100).unwrap();
    let part = make_part(&[], Some(1), Some(0));
    let err = a.add_part(&part).unwrap_err();
    assert!(
        matches!(err, AssemblyError::OutOfRange { .. }),
        "begin=1 end=0 must error, got: {err:?}"
    );
}
