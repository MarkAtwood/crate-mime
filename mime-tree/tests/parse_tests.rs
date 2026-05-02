//! Integration tests for mime-tree's `parse()` and `decode_body_value()`.
//!
//! All expected values are derived from external oracles:
//!   - RFC 5322, RFC 2045, RFC 2046, RFC 2183, RFC 8621 §4.1.4
//!   - IANA media type registrations
//!   - Python `base64` / `quopri` modules (values confirmed with:
//!       python3 -c "import base64; print(base64.b64decode('SGVsbG8sIFdvcmxkIQ=='))"
//!       → b'Hello, World!'
//!       python3 -c "import base64; print(base64.b64decode('SGVsbG8='))"
//!       → b'Hello'
//!
//! None of the expected values are derived from running this crate.

use mime_tree::{decode_body_value, parse, ParseError};

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
