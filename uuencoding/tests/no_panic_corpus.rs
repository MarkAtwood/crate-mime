/// No-panic corpus test.
///
/// Each item in the corpus is passed to both `decode` and `scan`.  The test
/// asserts only that neither call panics; returning `Ok` or `Err` is equally
/// acceptable.
use uuencoding::{decode, encode, scan};

/// Call `decode(input)` and `scan(input).count()`.  Either may return an error;
/// neither must panic.
fn must_not_panic(input: &[u8]) {
    let _ = decode(input);
    let _ = scan(input).count();
}

#[test]
fn corpus_no_panic() {
    // --- Static corpus items ---

    // Empty input
    must_not_panic(b"");

    // No begin line
    must_not_panic(b"no begin line here");

    // Truncated begin keyword (too short for scanner's fast path)
    must_not_panic(b"begin");

    // begin line with mode but no filename
    must_not_panic(b"begin 644");

    // base64 block (not UUencoding)
    must_not_panic(b"begin-base64 644 file.txt\n====\n");

    // Byte outside valid UU character range (0x00) in data position
    must_not_panic(b"begin 644 f\n\x00malformed\nend\n");

    // 0x7F in data line
    must_not_panic(b"begin 644 f\n\x7f\nend\n");

    // 0xFF in data line
    must_not_panic(b"begin 644 f\n\xff\nend\n");

    // '!' claims 1 decoded byte but only 1 encoded char follows (needs 4)
    must_not_panic(b"begin 644 f\n!x\nend\n");

    // Size stress: 10,000 zero bytes encoded then decoded
    let large_input = vec![0u8; 10_000];
    let encoded_large = encode(&large_input, "stress.bin", 0o644);
    must_not_panic(&encoded_large);

    // Valid UU block with CRLF line endings throughout
    //
    // Oracle: encode(b"Hello, World!", "f.txt", 0o644) produces the same data
    // lines as the LF version; we just replace every \n with \r\n.
    let lf_block = encode(b"Hello, World!", "f.txt", 0o644);
    let crlf_block: Vec<u8> = lf_block
        .iter()
        .flat_map(|&b| {
            if b == b'\n' {
                vec![b'\r', b'\n']
            } else {
                vec![b]
            }
        })
        .collect();
    must_not_panic(&crlf_block);
}
