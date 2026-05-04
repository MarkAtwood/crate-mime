//! No-panic corpus tests for `yencoding`.
//!
//! Every item in this corpus is passed to `decode()`. The test asserts only
//! that no call panics — returning `Ok` or `Err` is equally acceptable.
//! This exercises boundary conditions, adversarial inputs, and malformed
//! articles that real-world Usenet archives can produce.
//!
//! Round-trip property: `decode(encode(x)) == x` for all inputs. Oracle:
//! the Python fixture generator is the ground truth for CRC values; the
//! round-trip tests below verify the Rust encoder and decoder are consistent
//! with each other AND that CRC32 verification passes.

use yencoding::{decode, encode, DEFAULT_LINE_LENGTH};

fn must_not_panic(input: &[u8]) {
    let _ = decode(input);
}

// ---------------------------------------------------------------------------
// No-panic static corpus
// ---------------------------------------------------------------------------

#[test]
fn corpus_no_panic() {
    // Empty input
    must_not_panic(b"");

    // Just a newline
    must_not_panic(b"\n");

    // Partial =ybegin keyword
    must_not_panic(b"=ybeg");
    must_not_panic(b"=ybegin");
    must_not_panic(b"=ybegin\n");
    must_not_panic(b"=ybegin \n");

    // =ybegin with missing required fields
    must_not_panic(b"=ybegin size=10\n=yend size=10\n");
    must_not_panic(b"=ybegin name=f.bin\n=yend size=0\n");
    must_not_panic(b"=ybegin size=notanumber name=f.bin\n=yend size=0\n");

    // =ybegin but no =yend
    must_not_panic(b"=ybegin size=0 name=f.bin\n");
    must_not_panic(b"=ybegin size=100 name=f.bin\n*+,-./\n");

    // =yend with bad CRC
    must_not_panic(b"=ybegin size=3 name=f.bin\n*+,\n=yend size=3 crc32=00000000\n");

    // All-zero bytes
    must_not_panic(&[0u8; 256]);

    // All-0xFF bytes
    must_not_panic(&[0xFF; 256]);

    // Valid =ybegin followed by lone '=' at end of data line
    must_not_panic(b"=ybegin size=1 name=f.bin\n*=\n=yend size=1 crc32=00000000\n");

    // Escape at very end of file (no byte following '=')
    must_not_panic(b"=ybegin size=10 name=f.bin\n*=");

    // CRLF throughout
    must_not_panic(b"=ybegin size=0 name=f.bin\r\n=yend size=0 crc32=00000000\r\n");

    // Very long filename
    let long_name = "x".repeat(1000);
    let article = format!("=ybegin size=0 name={long_name}\n=yend size=0 crc32=00000000\n");
    must_not_panic(article.as_bytes());

    // Dot-stuffing at start of data line
    must_not_panic(b"=ybegin size=10 name=f.bin\n..+\n=yend size=10 crc32=00000000\n");

    // =ypart before data with no =ybegin
    must_not_panic(b"=ypart begin=1 end=10\n*+,\n=yend size=3\n");

    // Prose before =ybegin (long preamble)
    let mut article = Vec::new();
    for _ in 0..100 {
        article.extend_from_slice(b"This is a very long preamble line that should be skipped.\r\n");
    }
    article.extend_from_slice(b"=ybegin size=0 name=f.bin\r\n=yend size=0 crc32=00000000\r\n");
    must_not_panic(&article);

    // Interleaved garbage between header lines
    must_not_panic(
        b"=ybegin size=3 name=f.bin\njunk line here\n*+,\n=yend size=3 crc32=00000000\n",
    );

    // Missing =ypart end= field (only begin= present)
    must_not_panic(
        b"=ybegin part=1 size=10 name=f.bin\n=ypart begin=1\n*\n=yend size=1 pcrc32=00000000\n",
    );

    // Large payload (10 000 bytes, all zeros)
    let large_data = vec![0u8; 10_000];
    let large_article = encode(&large_data, "big.bin", DEFAULT_LINE_LENGTH);
    must_not_panic(&large_article);

    // Verify the large payload round-trips correctly.
    let result = decode(&large_article).expect("large round-trip should succeed");
    assert_eq!(result.data, large_data);
    assert!(result.crc32_verified);
}

// ---------------------------------------------------------------------------
// Round-trip property tests
// Oracle: Python gen_fixtures.py is the encoding ground truth.
// These tests verify that the Rust encoder produces output the Rust decoder
// can round-trip, AND that CRC32 verification passes.
// They do NOT use the Rust encoder as the oracle for the decoder — the fixture
// files serve that role.
// ---------------------------------------------------------------------------

/// Sweep: for each length L in 0..=255, a buffer of L bytes all equal to L.
/// Exercises every possible partial-group alignment (multiples of 1, 3, etc.).
#[test]
fn sweep_lengths_repeating_byte() {
    for len in 0usize..=255 {
        let byte = (len & 0xFF) as u8;
        let data: Vec<u8> = vec![byte; len];
        let encoded = encode(&data, "t.bin", DEFAULT_LINE_LENGTH);
        let decoded = decode(&encoded)
            .unwrap_or_else(|e| panic!("decode failed for len={len} byte={byte:#x}: {e}"));
        assert_eq!(decoded.data, data, "round-trip mismatch at len={len}");
        assert!(decoded.crc32_verified, "CRC not verified at len={len}");
        assert!(!decoded.metadata.filename.is_empty());
    }
}

/// All 256 possible single-byte values.
#[test]
fn all_single_bytes_round_trip() {
    for byte in 0u8..=255 {
        let data = [byte];
        let encoded = encode(&data, "b.bin", DEFAULT_LINE_LENGTH);
        let decoded =
            decode(&encoded).unwrap_or_else(|e| panic!("decode failed for byte {byte:#x}: {e}"));
        assert_eq!(
            decoded.data, &data,
            "round-trip mismatch for byte {byte:#x}"
        );
        assert!(decoded.crc32_verified);
    }
}

/// The full 256-byte ramp [0x00..=0xFF].
#[test]
fn ramp_256_bytes_round_trip() {
    let data: Vec<u8> = (0u8..=255).collect();
    let encoded = encode(&data, "ramp.bin", DEFAULT_LINE_LENGTH);
    let decoded = decode(&encoded).expect("ramp decode failed");
    assert_eq!(decoded.data, data);
    assert!(decoded.crc32_verified);
}

/// Multi-part round-trip: split a payload and encode/decode each part.
#[test]
fn multipart_encode_decode_round_trip() {
    let full_data: Vec<u8> = (0u8..=127).collect(); // 128 bytes
    let whole_crc = crc32fast::hash(&full_data);

    let half = full_data.len() / 2; // 64

    let opts1 = yencoding::EncodePartOptions {
        filename: "split.bin",
        total_size: full_data.len() as u64,
        total_parts: 2,
        part: 1,
        begin: 1,
        end: half as u64,
        whole_file_crc32: whole_crc,
        line_length: DEFAULT_LINE_LENGTH,
    };
    let opts2 = yencoding::EncodePartOptions {
        filename: "split.bin",
        total_size: full_data.len() as u64,
        total_parts: 2,
        part: 2,
        begin: (half + 1) as u64,
        end: full_data.len() as u64,
        whole_file_crc32: whole_crc,
        line_length: DEFAULT_LINE_LENGTH,
    };

    let enc1 = yencoding::encode_part(&full_data[..half], &opts1);
    let enc2 = yencoding::encode_part(&full_data[half..], &opts2);

    let p1 = decode(&enc1).expect("part 1 decode failed");
    let p2 = decode(&enc2).expect("part 2 decode failed");

    // Verify part structure
    assert_eq!(p1.part, Some(1));
    assert_eq!(p1.metadata.total_parts, Some(2));
    assert_eq!(p1.part_begin, Some(1));
    assert_eq!(p1.part_end, Some(64));
    assert_eq!(p2.part, Some(2));
    assert_eq!(p2.part_begin, Some(65));
    assert_eq!(p2.part_end, Some(128));

    // Verify decoded bytes
    let mut reassembled = p1.data.clone();
    reassembled.extend_from_slice(&p2.data);
    assert_eq!(reassembled, full_data, "reassembled data mismatch");

    // Both parts must have verified CRCs
    assert!(p1.crc32_verified, "part 1 CRC not verified");
    assert!(p2.crc32_verified, "part 2 CRC not verified");
}
