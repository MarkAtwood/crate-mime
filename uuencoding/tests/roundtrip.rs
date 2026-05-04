/// Round-trip property tests: decode(encode(x)) == x for all x.
///
/// No external dependencies — hand-rolled sweep over a representative input
/// space.  Coverage:
///
///   1. For every length L in 0..=255, a buffer of L bytes all set to L.
///   2. Every single-byte value [0x00..=0xFF] as a one-byte input.
///   3. The 256-byte ramp [0x00, 0x01, …, 0xFF].
use uuencoding::{decode, encode};

/// Round-trip one input through encode then decode and assert equality.
fn assert_roundtrip(input: &[u8]) {
    let encoded = encode(input, "t", 0o644);
    let decoded =
        decode(&encoded).unwrap_or_else(|e| panic!("decode failed for input {:?}: {}", input, e));
    assert_eq!(
        decoded.data,
        input,
        "round-trip mismatch for input len {} (first byte {:?})",
        input.len(),
        input.first()
    );
    assert!(
        !decoded.is_truncated,
        "decoded block is unexpectedly truncated"
    );
}

/// Sweep: for each length L in 0..=255, a buffer of L bytes all equal to L.
///
/// This exercises every possible chunk-boundary alignment (multiples of 3 and
/// 45 bytes) with a variety of byte values.
#[test]
fn sweep_lengths_repeating_byte() {
    for len in 0usize..=255 {
        let byte = (len & 0xFF) as u8;
        let input: Vec<u8> = vec![byte; len];
        assert_roundtrip(&input);
    }
}

/// All single-byte values 0x00..=0xFF as one-byte inputs.
///
/// This exercises the encoder's handling of every possible byte value in a
/// 1-byte (partial last group) context.
#[test]
fn all_single_bytes() {
    for byte in 0u8..=255 {
        assert_roundtrip(&[byte]);
    }
}

/// The 256-byte ramp [0x00, 0x01, …, 0xFF].
///
/// This exercises multi-line encoding (256 bytes = 5 full 45-byte lines + 31
/// bytes on the last line) with all byte values present.
#[test]
fn ramp_256_bytes() {
    let input: Vec<u8> = (0u8..=255).collect();
    assert_roundtrip(&input);
}
