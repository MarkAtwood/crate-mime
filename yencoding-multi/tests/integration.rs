//! Integration tests for `yencoding-multi`.
//!
//! # Oracle provenance
//!
//! All test payloads use known byte sequences. CRC32 values are computed
//! from Python: `binascii.crc32(data) & 0xFFFFFFFF`. Round-trip tests
//! use the yencoding crate's encode_part() to build articles, then decode()
//! to recover parts — verifying the full pipeline.

use yencoding::{decode, encode_part, EncodePartOptions, DEFAULT_LINE_LENGTH};
use yencoding_multi::{Assembler, AssemblyError};

// ---------------------------------------------------------------------------
// Helper: encode bytes(range(N)) into M equal parts, decode them, and add to
// an Assembler. Returns the Assembler and the original data for comparison.
// ---------------------------------------------------------------------------
fn encode_and_assemble(total_bytes: u8, num_parts: usize) -> (Assembler, Vec<u8>, u32) {
    let full: Vec<u8> = (0..total_bytes).collect();
    let whole_crc = crc32fast::hash(&full);
    let total = full.len() as u64;
    let chunk = (total as usize).div_ceil(num_parts);

    let mut assembler = Assembler::new(total).unwrap();
    assembler.set_expected_crc32(whole_crc);

    for i in 0..num_parts {
        let start = i * chunk;
        let end = ((i + 1) * chunk).min(full.len());
        if start >= full.len() {
            break;
        }
        let part_data = &full[start..end];
        let begin_1 = (start + 1) as u64;
        let end_1 = end as u64;

        let opts = EncodePartOptions {
            filename: "f.bin",
            total_size: total,
            total_parts: num_parts as u32,
            part: (i + 1) as u32,
            begin: begin_1,
            end: end_1,
            whole_file_crc32: whole_crc,
            line_length: DEFAULT_LINE_LENGTH,
        };
        let encoded = encode_part(part_data, &opts);
        let decoded = decode(&encoded).expect("encode_part → decode failed");
        assembler.add_part(&decoded).expect("add_part failed");
    }

    (assembler, full, whole_crc)
}

// ---------------------------------------------------------------------------
// 1. Happy path: 3-part in order
// ---------------------------------------------------------------------------

#[test]
fn three_parts_in_order() {
    let (assembler, full, _crc) = encode_and_assemble(90, 3); // 30 bytes each
    assert!(assembler.is_complete(), "should be complete");
    let result = assembler.finish().expect("finish failed");
    assert_eq!(result, full);
}

// ---------------------------------------------------------------------------
// 2. Out-of-order insertion
// ---------------------------------------------------------------------------

#[test]
fn three_parts_out_of_order() {
    // Oracle: bytes 0..90, 3 parts of 30.
    let full: Vec<u8> = (0u8..90).collect();
    let whole_crc = crc32fast::hash(&full);

    let make_enc = |start: usize, end: usize, part: u32| {
        let opts = EncodePartOptions {
            filename: "f.bin",
            total_size: 90,
            total_parts: 3,
            part,
            begin: (start + 1) as u64,
            end: end as u64,
            whole_file_crc32: whole_crc,
            line_length: DEFAULT_LINE_LENGTH,
        };
        decode(&encode_part(&full[start..end], &opts)).unwrap()
    };

    let p1 = make_enc(0, 30, 1);
    let p2 = make_enc(30, 60, 2);
    let p3 = make_enc(60, 90, 3);

    // Insert in reverse order
    let mut assembler = Assembler::new(90).unwrap();
    assembler.set_expected_crc32(whole_crc);
    assembler.add_part(&p3).unwrap();
    assembler.add_part(&p1).unwrap();
    assembler.add_part(&p2).unwrap();

    assert_eq!(assembler.finish().unwrap(), full);
}

// ---------------------------------------------------------------------------
// 3. Missing part: is_complete() false, missing_ranges correct
// ---------------------------------------------------------------------------

#[test]
fn missing_middle_part() {
    // 3 parts of 30 bytes; omit part 2.
    let full: Vec<u8> = (0u8..90).collect();
    let whole_crc = crc32fast::hash(&full);

    let make_enc = |start: usize, end: usize, part: u32| {
        let opts = EncodePartOptions {
            filename: "f.bin",
            total_size: 90,
            total_parts: 3,
            part,
            begin: (start + 1) as u64,
            end: end as u64,
            whole_file_crc32: whole_crc,
            line_length: DEFAULT_LINE_LENGTH,
        };
        decode(&encode_part(&full[start..end], &opts)).unwrap()
    };

    let mut assembler = Assembler::new(90).unwrap();
    assembler.add_part(&make_enc(0, 30, 1)).unwrap();
    // Part 2 (bytes 30..60) intentionally omitted.
    assembler.add_part(&make_enc(60, 90, 3)).unwrap();

    assert!(!assembler.is_complete());
    assert_eq!(assembler.missing_ranges(), vec![30..60]);

    let err = assembler.finish().unwrap_err();
    assert!(
        matches!(err, AssemblyError::Incomplete { ref missing } if missing == &[30u64..60]),
        "unexpected error: {:?}",
        err
    );
}

// ---------------------------------------------------------------------------
// 4. Duplicate/overlapping part rejected
// ---------------------------------------------------------------------------

#[test]
fn duplicate_part_rejected() {
    let full: Vec<u8> = (0u8..60).collect();
    let whole_crc = crc32fast::hash(&full);

    let opts = EncodePartOptions {
        filename: "f.bin",
        total_size: 60,
        total_parts: 2,
        part: 1,
        begin: 1,
        end: 30,
        whole_file_crc32: whole_crc,
        line_length: DEFAULT_LINE_LENGTH,
    };
    let p1 = decode(&encode_part(&full[..30], &opts)).unwrap();

    let mut assembler = Assembler::new(60).unwrap();
    assembler.add_part(&p1).unwrap();
    // Adding the same part again must fail.
    let err = assembler.add_part(&p1).unwrap_err();
    assert!(
        matches!(err, AssemblyError::OverlappingPart { .. }),
        "expected OverlappingPart, got: {:?}",
        err
    );
}

// ---------------------------------------------------------------------------
// 5. CRC mismatch on finish
// ---------------------------------------------------------------------------

#[test]
fn crc_mismatch_on_finish() {
    let data = vec![42u8; 20];
    let mut assembler = Assembler::new(20).unwrap();
    let part = yencoding::DecodedPart {
        data: data.clone(),
        metadata: yencoding::YencMetadata {
            filename: "f.bin".to_string(),
            size: 20,
            line_length: 128,
            total_parts: None,
        },
        part: None,
        part_begin: None,
        part_end: None,
        crc32_verified: false,
    };
    assembler.add_part(&part).unwrap();
    assembler.set_expected_crc32(0xdeadbeef); // wrong CRC

    let err = assembler.finish().unwrap_err();
    assert!(matches!(err, AssemblyError::CrcMismatch { .. }));
}

// ---------------------------------------------------------------------------
// 6. Empty file (zero total_size)
// ---------------------------------------------------------------------------

#[test]
fn zero_byte_file() {
    let assembler = Assembler::new(0).unwrap();
    assert!(assembler.is_complete());
    assert!(assembler.missing_ranges().is_empty());
    let result = assembler.finish().unwrap();
    assert!(result.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Large file: sweep of sizes
// ---------------------------------------------------------------------------

#[test]
fn sweep_sizes_round_trip() {
    // For each total payload size in [0, 4, 8, ..., 128], split into 1, 2,
    // or 3 parts and verify full round-trip.
    for total in (0u8..=127).step_by(4) {
        for parts in 1..=3usize {
            if total as usize > 0 && parts > total as usize {
                continue; // can't split N bytes into more than N parts
            }
            let (assembler, full, _) = encode_and_assemble(total, parts.max(1));
            if assembler.is_complete() {
                let result = assembler.finish().unwrap_or_else(|e| {
                    panic!("finish failed for total={total} parts={parts}: {e}")
                });
                assert_eq!(result, full, "mismatch at total={total} parts={parts}");
            }
        }
    }
}
