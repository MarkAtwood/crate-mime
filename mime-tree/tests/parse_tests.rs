//! Integration tests for mime-tree's `parse()` and `decode_body_value()`.
//!
//! All expected values are derived from external oracles:
//!   - RFC 5322, RFC 2045, RFC 2046, RFC 2047, RFC 2183, RFC 8621 §4.1.4
//!   - IANA media type registrations
//!   - Python `base64` / `quopri` modules (values confirmed with:
//!       python3 -c "import base64; print(base64.b64decode('SGVsbG8sIFdvcmxkIQ=='))"
//!       → b'Hello, World!'
//!       python3 -c "import base64; print(base64.b64decode('SGVsbG8='))"
//!       → b'Hello'
//!   - RFC 2047 encoded-word examples (see tests 9, 10, 11 below)
//!
//! None of the expected values are derived from running this crate.

use mime_tree::{decode_body_value, parse, ParseError, TransferEncoding};

// ---------------------------------------------------------------------------
// Test 1 — simple text/plain message
// ---------------------------------------------------------------------------

/// Oracle: RFC 5322 §2.1 (header/body separator), RFC 2045 §5 (Content-Type),
/// RFC 8621 §4.1.4 algorithm (a lone text/plain leaf outside any
/// multipart/alternative is isInline=true and is pushed to BOTH textBody and
/// htmlBody — matches the RFC's parts A and K in the §4.1.4 example table).
#[test]
fn test_simple_plain_text() {
    let raw = b"From: alice@example.com\r\n\
                To: bob@example.com\r\n\
                Subject: Hello\r\n\
                MIME-Version: 1.0\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                \r\n\
                Hello, World!\r\n";

    let msg = parse(raw).expect("parse of valid RFC 5322 message must succeed");

    // Content-Type and charset: per RFC 2045 §5.1, the type/subtype is
    // case-insensitive but we normalise to lowercase; charset is the attribute value.
    assert_eq!(msg.part_index.content_type, "text/plain");
    assert_eq!(msg.part_index.charset, Some("utf-8".to_owned()));

    // RFC 8621 §4.1.4: lone text/plain is inline — appears in both lists.
    assert_eq!(msg.text_body, vec!["1".to_owned()]);
    assert_eq!(msg.html_body, vec!["1".to_owned()]);
    assert!(msg.attachments.is_empty(), "no attachments expected");

    // No parse warnings for a well-formed message.
    assert!(
        msg.warnings.is_empty(),
        "unexpected warnings: {:?}",
        msg.warnings
    );

    // RFC 5322 §3.6.2: "From" is a mandatory originator field; it must be
    // present in the parsed header list.
    let has_from = msg.headers.iter().any(|h| h.name == "From");
    assert!(has_from, "From header must be present in parsed headers");
}

// ---------------------------------------------------------------------------
// Test 2 — multipart/alternative
// ---------------------------------------------------------------------------

/// Oracle: RFC 2046 §5.1.4 (multipart/alternative semantics) and
/// RFC 8621 §4.1.4 algorithm.
///
/// Inside multipart/alternative the algorithm routes text/plain to textBody
/// and text/html to htmlBody (they are NOT cross-populated because both lists
/// were populated by the alternative's own children).
///
/// IMAP part-ID assignment (RFC 3501 §6.4.5): the multipart root itself gets
/// the empty part-ID `""` and its children get `"1"`, `"2"`, etc.
#[test]
fn test_multipart_alternative() {
    let raw = concat!(
        "From: alice@example.com\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/alternative; boundary=\"boundary\"\r\n",
        "\r\n",
        "--boundary\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Plain text body\r\n",
        "--boundary\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<html><body>HTML body</body></html>\r\n",
        "--boundary--\r\n"
    )
    .as_bytes();

    let msg = parse(raw).expect("parse must succeed");

    // RFC 8621 §4.1.4: text/plain → textBody, text/html → htmlBody.
    assert_eq!(
        msg.text_body,
        vec!["1".to_owned()],
        "text/plain child must be in text_body"
    );
    assert_eq!(
        msg.html_body,
        vec!["2".to_owned()],
        "text/html child must be in html_body"
    );
    assert!(msg.attachments.is_empty(), "no attachments expected");

    // The multipart root has exactly 2 children (the two alternatives).
    assert_eq!(
        msg.part_index.children.len(),
        2,
        "root must have 2 children"
    );

    // Children are assigned sequential IMAP IDs per RFC 3501.
    assert_eq!(msg.part_index.children[0].part_id, "1");
    assert_eq!(msg.part_index.children[0].content_type, "text/plain");
    assert_eq!(msg.part_index.children[1].part_id, "2");
    assert_eq!(msg.part_index.children[1].content_type, "text/html");
}

// ---------------------------------------------------------------------------
// Test 3 — multipart/mixed with a binary attachment
// ---------------------------------------------------------------------------

/// Oracle: RFC 2046 §5.1.3 (multipart/mixed), RFC 2183 §2 (Content-Disposition),
/// RFC 8621 §4.1.4 (application/pdf with disposition=attachment goes to
/// attachments only; text/plain without attachment disposition is inline and
/// goes to both textBody and htmlBody).
///
/// Base64 oracle: "SGVsbG8=" decodes to b"Hello" per the base64 spec
/// (RFC 4648 §4); confirmed independently with Python's base64 module.
#[test]
fn test_multipart_mixed_with_attachment() {
    let raw = concat!(
        "From: alice@example.com\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "Main body text\r\n",
        "--b\r\n",
        "Content-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename=\"doc.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "SGVsbG8=\r\n",
        "--b--\r\n"
    )
    .as_bytes();

    let msg = parse(raw).expect("parse must succeed");

    // RFC 8621 §4.1.4: text/plain without attachment disposition is inline.
    assert_eq!(msg.text_body, vec!["1".to_owned()]);
    // text/plain outside multipart/alternative is pushed to both lists.
    assert_eq!(msg.html_body, vec!["1".to_owned()]);
    // application/pdf with attachment disposition goes to attachments.
    assert_eq!(msg.attachments, vec!["2".to_owned()]);

    // RFC 2183 §2: Content-Disposition "attachment" with filename parameter.
    let pdf_part = &msg.part_index.children[1];
    assert_eq!(
        pdf_part.disposition,
        Some("attachment".to_owned()),
        "disposition must be 'attachment'"
    );
    assert_eq!(
        pdf_part.filename,
        Some("doc.pdf".to_owned()),
        "filename must be 'doc.pdf'"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — byte range validity
// ---------------------------------------------------------------------------

/// Oracle: The raw bytes are hand-crafted so the expected body content is known
/// without running any code. The body content "Body content" appears after
/// the RFC 5322 header/body separator (blank line after last header).
///
/// RFC 5322 §2.1: headers are separated from the body by a CRLF-only line.
#[test]
fn test_byte_range_validity() {
    let raw = b"From: test@example.com\r\n\r\nBody content\r\n";

    let msg = parse(raw).expect("parse must succeed");

    let (body_off, body_len) = msg.part_index.body_range;
    let (hdr_off, hdr_len) = msg.part_index.header_range;

    // Both ranges must be contained within the original raw buffer.
    assert!(
        (body_off as usize).saturating_add(body_len as usize) <= raw.len(),
        "body_range ({body_off}, {body_len}) exceeds raw.len()={}",
        raw.len()
    );
    assert!(
        (hdr_off as usize).saturating_add(hdr_len as usize) <= raw.len(),
        "header_range ({hdr_off}, {hdr_len}) exceeds raw.len()={}",
        raw.len()
    );

    // The bytes at body_range must contain the known body text.
    // Oracle: "Body content" is the literal string placed in the message above.
    let body_slice = &raw[body_off as usize..(body_off + body_len) as usize];
    assert!(
        std::str::from_utf8(body_slice)
            .expect("body must be valid UTF-8")
            .contains("Body content"),
        "body slice does not contain expected text; got: {:?}",
        std::str::from_utf8(body_slice)
    );
}

// ---------------------------------------------------------------------------
// Test 5 — parse errors
// ---------------------------------------------------------------------------

/// Oracle: RFC 5322 §2.1 and the crate's documented contract: empty input
/// must return `Err(ParseError::EmptyInput)`.
#[test]
fn test_empty_input_error() {
    let result = parse(b"");
    assert!(
        matches!(result, Err(ParseError::EmptyInput)),
        "empty input must return EmptyInput, got: {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// Test 6 — decode_body_value integration (base64 + charset)
// ---------------------------------------------------------------------------

/// Oracle: "SGVsbG8sIFdvcmxkIQ==" is the standard base64 encoding of the
/// ASCII/UTF-8 string "Hello, World!" per RFC 4648 §4.
///
/// Independently confirmed with Python's base64 module:
///   python3 -c "import base64; print(base64.b64decode('SGVsbG8sIFdvcmxkIQ=='))"
///   → b'Hello, World!'
///
/// This test confirms that decode_body_value correctly:
///   1. Extracts the body slice using the byte range from parse()
///   2. Strips CRLF line-wrapping before base64 decoding (RFC 2045 §6.8)
///   3. Applies charset conversion (utf-8 → UTF-8 string)
#[test]
fn test_decode_body_value_base64() {
    let raw = b"From: test@example.com\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                Content-Transfer-Encoding: base64\r\n\
                \r\n\
                SGVsbG8sIFdvcmxkIQ==\r\n";

    let msg = parse(raw).expect("parse must succeed");

    let decoded = decode_body_value(raw, &msg.part_index, None)
        .expect("decode_body_value must succeed for valid base64");

    // Oracle: RFC 4648 base64 decode of "SGVsbG8sIFdvcmxkIQ==" is "Hello, World!"
    assert_eq!(decoded.value, "Hello, World!");
    assert!(!decoded.is_truncated, "no truncation limit was applied");
    assert!(
        !decoded.is_encoding_problem,
        "valid base64 + utf-8 must not report encoding problems"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — S/MIME parts are opaque leaves
// ---------------------------------------------------------------------------

/// Oracle: IANA media type registry and RFC 5751 §3.9.1 (application/pkcs7-mime
/// is an opaque binary type; it is not text/plain, text/html, or an inline
/// media type — it must not appear in textBody or htmlBody).
///
/// The crate's documented invariant (mime-tree/CLAUDE.md): "application/pkcs7-mime
/// and application/pkcs7-signature parts are treated as opaque binary leaves."
///
/// RFC 8621 §4.1.4: a part that is not text/plain, text/html, or an inline
/// media type (image/*, audio/*, video/*) goes to attachments (unless it has
/// some other disposition treatment — but with no explicit inline disposition
/// it still is not isInline per the algorithm).
#[test]
fn test_smime_parts_are_opaque_leaves() {
    let raw = b"From: test@example.com\r\n\
                Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\
                Content-Transfer-Encoding: base64\r\n\
                \r\n\
                SGVsbG8=\r\n";

    let msg = parse(raw).expect("parse must succeed");

    // The content-type must be preserved exactly per IANA registration.
    assert_eq!(
        msg.part_index.content_type, "application/pkcs7-mime",
        "content-type must be preserved as registered IANA type"
    );

    // S/MIME parts must NOT appear in textBody or htmlBody.
    // Oracle: RFC 8621 §4.1.4 isInline check — application/pkcs7-mime is
    // neither text/plain, text/html, nor an inline media type, so isInline=false.
    assert!(
        !msg.text_body.contains(&"1".to_owned()),
        "S/MIME part must not appear in text_body"
    );
    assert!(
        !msg.html_body.contains(&"1".to_owned()),
        "S/MIME part must not appear in html_body"
    );
    assert_eq!(
        msg.attachments,
        vec!["1".to_owned()],
        "S/MIME part must go to attachments"
    );
}

// ---------------------------------------------------------------------------
// Test 8 — RFC 2045 §5.2 default Content-Type
// ---------------------------------------------------------------------------

/// Oracle: RFC 2045 §5.2 — a MIME body part with no Content-Type header is
/// treated as "text/plain; charset=us-ascii". Such a part must appear in
/// text_body (isInline=true per RFC 8621 §4.1.4 algorithm).
#[test]
fn test_no_content_type_defaults_to_text_plain() {
    let raw = b"From: alice@example.com\r\n\
                MIME-Version: 1.0\r\n\
                \r\n\
                Hello, this is a bare body with no Content-Type header.\r\n";

    let msg = parse(raw).expect("parse must succeed");

    // RFC 2045 §5.2: no Content-Type defaults to text/plain.
    assert_eq!(
        msg.part_index.content_type, "text/plain",
        "missing Content-Type must default to text/plain per RFC 2045 §5.2"
    );
    assert_eq!(
        msg.part_index.charset,
        Some("us-ascii".to_owned()),
        "missing Content-Type must default to charset=us-ascii per RFC 2045 §5.2"
    );

    // RFC 8621 §4.1.4: text/plain is inline — must appear in text_body and html_body.
    assert!(
        msg.text_body.contains(&msg.part_index.part_id),
        "bare-body part must appear in text_body; text_body={:?}",
        msg.text_body
    );
}

// ---------------------------------------------------------------------------
// Test 9 — RFC 2047 encoded-word: UTF-8 base64
// ---------------------------------------------------------------------------

/// Oracle: RFC 2047 §2 encoded-word syntax and RFC 4648 §4 base64 alphabet.
///
/// The encoded-word `=?utf-8?b?SGVsbG8=?=` decodes as follows:
///   - charset:  utf-8
///   - encoding: b (base64, per RFC 2047 §4.1)
///   - encoded:  SGVsbG8=
///   - decoded:  base64("SGVsbG8=") = bytes [0x48,0x65,0x6C,0x6C,0x6F] = "Hello"
///
/// Independently confirmed:
///   python3 -c "import base64; print(base64.b64decode('SGVsbG8='))"
///   → b'Hello'
///
/// This test confirms that `ParsedMessage.headers` contains the decoded Unicode
/// string, not the raw encoded-word bytes.
#[test]
fn test_rfc2047_utf8_base64_subject() {
    let raw = b"From: alice@example.com\r\n\
                Subject: =?utf-8?b?SGVsbG8=?=\r\n\
                MIME-Version: 1.0\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                \r\n\
                body\r\n";

    let msg = parse(raw).expect("parse must succeed");

    let subject = msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Subject"))
        .map(|h| h.value.as_str())
        .unwrap_or("");

    // Oracle: RFC 2047 §2 + RFC 4648 §4: decoded value is "Hello"
    assert_eq!(
        subject, "Hello",
        "RFC 2047 UTF-8/base64 encoded-word must be decoded to 'Hello', got: {subject:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 10 — RFC 2047 encoded-word: ISO-8859-1 quoted-printable
// ---------------------------------------------------------------------------

/// Oracle: RFC 2047 §4.2 (quoted-printable in encoded-words) and the
/// ISO-8859-1 code chart (U+00E9 LATIN SMALL LETTER E WITH ACUTE = 0xE9).
///
/// The encoded-word `=?iso-8859-1?q?caf=E9?=` decodes as follows:
///   - charset:  iso-8859-1
///   - encoding: q (quoted-printable, per RFC 2047 §4.2)
///   - encoded:  caf=E9
///   - QP-decoded bytes: [0x63, 0x61, 0x66, 0xE9]  ("caf" + 0xE9)
///   - ISO-8859-1 0xE9 maps to U+00E9 LATIN SMALL LETTER E WITH ACUTE → "é"
///   - full string: "café"
///
/// Independently confirmed:
///   python3 -c "
///     import quopri, codecs
///     b = quopri.decodestring(b'caf=E9')
///     print(b.decode('iso-8859-1'))
///   "
///   → café
///
/// This test confirms that charset conversion (ISO-8859-1 → UTF-8) is applied
/// correctly for encoded-words with non-ASCII charsets.
#[test]
fn test_rfc2047_iso8859_qp_subject() {
    let raw = b"From: alice@example.com\r\n\
                Subject: =?iso-8859-1?q?caf=E9?=\r\n\
                MIME-Version: 1.0\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                \r\n\
                body\r\n";

    let msg = parse(raw).expect("parse must succeed");

    let subject = msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Subject"))
        .map(|h| h.value.as_str())
        .unwrap_or("");

    // Oracle: ISO-8859-1 QP decode: "caf" + 0xE9 → U+00E9 → "café"
    assert_eq!(
        subject, "café",
        "RFC 2047 ISO-8859-1/QP encoded-word must be decoded to 'café', got: {subject:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 11 — plain Subject (no encoded-words) is unchanged
// ---------------------------------------------------------------------------

/// Oracle: RFC 5322 §2.2 — a header with no encoded-words must be preserved
/// exactly as written (modulo leading/trailing whitespace trim which the
/// current implementation applies).
///
/// This regression test guards against over-decoding: a plain ASCII Subject
/// must pass through unchanged.
#[test]
fn test_plain_subject_unchanged() {
    let raw = b"From: alice@example.com\r\n\
                Subject: Just a plain subject\r\n\
                MIME-Version: 1.0\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                \r\n\
                body\r\n";

    let msg = parse(raw).expect("parse must succeed");

    let subject = msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Subject"))
        .map(|h| h.value.as_str())
        .unwrap_or("");

    // Oracle: the literal string placed in the message above.
    assert_eq!(
        subject, "Just a plain subject",
        "plain Subject must be preserved unchanged, got: {subject:?}"
    );
}

// ---------------------------------------------------------------------------
// Tests 12–22 — Content-Transfer-Encoding warnings
// ---------------------------------------------------------------------------
//
// Oracle: RFC 2045 §6.1–6.3 define the standard CTE values (7bit, 8bit,
// binary, quoted-printable, base64).  RFC 2045 §6.4 permits x-token values;
// x-uuencode / x-uue / uuencode are conventional spellings handled explicitly.
// Any other non-empty CTE token is unrecognised and must produce a warning.
//
// All "no warning" assertions are also verified by existing tests that check
// msg.warnings.is_empty(); these focused tests confirm the token-level mapping.

/// Helper: build a minimal single-part message with the given CTE header value.
fn make_cte_message(cte_value: &str) -> Vec<u8> {
    format!(
        "From: alice@example.com\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: {cte_value}\r\n\
         \r\n\
         body\r\n"
    )
    .into_bytes()
}

/// Helper: build a minimal single-part message with NO CTE header.
fn make_no_cte_message() -> Vec<u8> {
    b"From: alice@example.com\r\n\
      Content-Type: text/plain; charset=utf-8\r\n\
      \r\n\
      body\r\n"
        .to_vec()
}

// Test 12 — x-gzip produces a warning containing the token
#[test]
fn test_cte_unknown_x_gzip_warns() {
    let raw = make_cte_message("x-gzip");
    let msg = parse(&raw).expect("parse must succeed");

    assert!(
        !msg.warnings.is_empty(),
        "x-gzip CTE must produce a warning"
    );
    let w = msg.warnings.join(" ");
    assert!(
        w.contains("x-gzip"),
        "warning must mention 'x-gzip'; warnings={:?}",
        msg.warnings
    );
    // Identity is still returned for unrecognised CTE.
    assert_eq!(
        msg.part_index.transfer_encoding,
        TransferEncoding::Identity,
        "unrecognised CTE must map to Identity"
    );
}

// Test 13 — x-bzip2 produces a warning
#[test]
fn test_cte_unknown_x_bzip2_warns() {
    let raw = make_cte_message("x-bzip2");
    let msg = parse(&raw).expect("parse must succeed");

    assert!(
        !msg.warnings.is_empty(),
        "x-bzip2 CTE must produce a warning"
    );
    let w = msg.warnings.join(" ");
    assert!(
        w.contains("x-bzip2"),
        "warning must mention 'x-bzip2'; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::Identity);
}

// Test 14 — absent CTE produces no warning
#[test]
fn test_no_cte_header_no_warning() {
    let raw = make_no_cte_message();
    let msg = parse(&raw).expect("parse must succeed");

    assert!(
        msg.warnings.is_empty(),
        "absent CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
}

// Test 15 — 7bit produces no warning
#[test]
fn test_cte_7bit_no_warning() {
    let raw = make_cte_message("7bit");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "7bit CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::SevenBit);
}

// Test 16 — 8bit produces no warning
#[test]
fn test_cte_8bit_no_warning() {
    let raw = make_cte_message("8bit");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "8bit CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::EightBit);
}

// Test 17 — binary produces no warning
#[test]
fn test_cte_binary_no_warning() {
    let raw = make_cte_message("binary");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "binary CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::Binary);
}

// Test 18 — quoted-printable produces no warning
//
// Oracle: RFC 2045 §6.7 — quoted-printable is a standard CTE value.
// mail-parser sets Encoding::QuotedPrintable for this token so map_encoding()
// hits the QuotedPrintable arm before reaching the Encoding::None branch.
#[test]
fn test_cte_quoted_printable_no_warning() {
    let raw = make_cte_message("quoted-printable");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "quoted-printable CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(
        msg.part_index.transfer_encoding,
        TransferEncoding::QuotedPrintable
    );
}

// Test 19 — base64 produces no warning
//
// Oracle: RFC 2045 §6.8 — base64 is a standard CTE value.
// mail-parser sets Encoding::Base64 so map_encoding() hits the Base64 arm.
#[test]
fn test_cte_base64_no_warning() {
    let raw = make_cte_message("base64");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "base64 CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::Base64);
}

// Test 20 — x-uuencode produces no warning
#[test]
fn test_cte_x_uuencode_no_warning() {
    let raw = make_cte_message("x-uuencode");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "x-uuencode CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::UUEncode);
}

// Test 21 — x-uue produces no warning
#[test]
fn test_cte_x_uue_no_warning() {
    let raw = make_cte_message("x-uue");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "x-uue CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::UUEncode);
}

// Test 22 — uuencode produces no warning
#[test]
fn test_cte_uuencode_no_warning() {
    let raw = make_cte_message("uuencode");
    let msg = parse(&raw).expect("parse must succeed");
    assert!(
        msg.warnings.is_empty(),
        "uuencode CTE must not produce a warning; warnings={:?}",
        msg.warnings
    );
    assert_eq!(msg.part_index.transfer_encoding, TransferEncoding::UUEncode);
}

// ---------------------------------------------------------------------------
// Test 23 — NoHeaders: input with no RFC 5322 header lines
// ---------------------------------------------------------------------------

/// Oracle: input that contains no header-like lines (no "Name: value" pairs)
/// is rejected with ParseError::NoHeaders. mail-parser returns None for such
/// input, and parse() maps that to NoHeaders.
#[test]
fn test_no_headers_returns_error() {
    // Raw bytes with no colon-separated header lines — just body text.
    let raw = b"This is just some text with no headers at all.\r\n";
    let err = parse(raw).unwrap_err();
    assert_eq!(err, ParseError::NoHeaders);
}

// ---------------------------------------------------------------------------
// Test 24 — decode_body_value InvalidRange: offset+length overflow
// ---------------------------------------------------------------------------

/// Oracle: body_range (u32::MAX, u32::MAX) overflows usize on addition.
/// decode_body_value must return InvalidRange, not panic.
#[test]
fn test_decode_body_value_overflow_returns_invalid_range() {
    let raw = b"From: a@b.c\r\nContent-Type: text/plain\r\n\r\nHello\r\n";
    let msg = parse(raw).expect("parse must succeed");
    let mut part = msg.part_index.clone();
    // Forge an overflowing body_range.
    part.body_range = (u32::MAX, u32::MAX);
    let err = decode_body_value(raw, &part, None).unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidRange { .. }),
        "overflowing body_range must return InvalidRange, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 25 — decode_body_value InvalidRange: offset+length > raw.len()
// ---------------------------------------------------------------------------

/// Oracle: body_range extends past end of raw bytes.
/// decode_body_value must return InvalidRange.
#[test]
fn test_decode_body_value_past_end_returns_invalid_range() {
    let raw = b"From: a@b.c\r\nContent-Type: text/plain\r\n\r\nHi\r\n";
    let msg = parse(raw).expect("parse must succeed");
    let mut part = msg.part_index.clone();
    // Forge a body_range that extends past the raw bytes.
    part.body_range = (0, raw.len() as u32 + 100);
    let err = decode_body_value(raw, &part, None).unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidRange { .. }),
        "out-of-bounds body_range must return InvalidRange, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 26 — multipart/related with image/jpeg first child
// ---------------------------------------------------------------------------

/// Oracle: RFC 8621 §4.1.4 isInline condition — for multipart/related,
/// the first child (i==0) is always eligible for isInline regardless of
/// multipartType. An image/jpeg at i==0 satisfies isInline (it is an inline
/// media type and i==0), so it is pushed to both textBody and htmlBody.
#[test]
fn test_related_image_jpeg_first_child_in_both_body_lists() {
    let raw = concat!(
        "From: a@b.c\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/related; boundary=\"rel\"\r\n",
        "\r\n",
        "--rel\r\n",
        "Content-Type: image/jpeg\r\n",
        "\r\n",
        "jpeg-data-placeholder\r\n",
        "--rel\r\n",
        "Content-Type: image/png\r\n",
        "\r\n",
        "png-data-placeholder\r\n",
        "--rel--\r\n",
    );
    let msg = parse(raw.as_bytes()).expect("parse must succeed");

    // First child (image/jpeg at i==0) is inline → both text_body and html_body.
    assert!(
        msg.text_body.contains(&"1".to_owned()),
        "image/jpeg at i=0 must be in text_body; got: {:?}",
        msg.text_body
    );
    assert!(
        msg.html_body.contains(&"1".to_owned()),
        "image/jpeg at i=0 must be in html_body; got: {:?}",
        msg.html_body
    );

    // Second child (image/png at i=1) in multipart/related with i>0 is NOT inline
    // (the third isInline clause: i==0 OR multipartType != "related" — fails for i=1).
    assert!(
        msg.attachments.contains(&"2".to_owned()),
        "image/png at i=1 in related must be in attachments; got: {:?}",
        msg.attachments
    );
}

// ---------------------------------------------------------------------------
// Test 27 — preview for text/plain message
// ---------------------------------------------------------------------------

/// Oracle: preview is the first 256 chars of the first text_body part's
/// decoded content.
#[test]
fn test_preview_text_plain() {
    let raw = b"From: a@b.c\r\n\
                Content-Type: text/plain\r\n\
                \r\n\
                Hello, World!\r\n";
    let msg = parse(raw).expect("parse must succeed");
    let preview = msg.preview.expect("text message must have a preview");
    assert!(
        preview.starts_with("Hello, World!"),
        "preview must start with the decoded text body; got: {:?}",
        preview
    );
}

// ---------------------------------------------------------------------------
// Test 28 — preview for binary-only message
// ---------------------------------------------------------------------------

/// Oracle: a message with only a binary part (application/octet-stream)
/// has no text_body parts, so preview is None.
#[test]
fn test_preview_binary_only_is_none() {
    let raw = b"From: a@b.c\r\n\
                Content-Type: application/octet-stream\r\n\
                Content-Transfer-Encoding: base64\r\n\
                \r\n\
                AAAA\r\n";
    let msg = parse(raw).expect("parse must succeed");
    assert!(
        msg.preview.is_none(),
        "binary-only message must have no preview; got: {:?}",
        msg.preview
    );
}

// ---------------------------------------------------------------------------
// Test 29 — preview truncates to 256 characters
// ---------------------------------------------------------------------------

/// Oracle: preview is at most 256 characters. A body longer than 256 chars
/// must be truncated.
#[test]
fn test_preview_truncates_to_256_chars() {
    // Build a text/plain message with 500 'A' characters.
    let body = "A".repeat(500);
    let raw = format!(
        "From: a@b.c\r\nContent-Type: text/plain\r\n\r\n{}\r\n",
        body
    );
    let msg = parse(raw.as_bytes()).expect("parse must succeed");
    let preview = msg.preview.expect("text message must have a preview");
    assert_eq!(
        preview.chars().count(),
        256,
        "preview must be exactly 256 chars; got {}",
        preview.chars().count()
    );
    assert!(
        preview.chars().all(|c| c == 'A'),
        "preview must contain only 'A' characters"
    );
}
