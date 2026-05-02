//! RFC 8621 §4.1.4 body structure decomposition.
//!
//! Translates the reference JavaScript algorithm from the RFC into Rust,
//! walking a `ParsedPart` tree and classifying leaf parts into three lists.

use crate::part::ParsedPart;

/// Result of the RFC 8621 §4.1.4 walk algorithm.
pub(crate) struct BodyStructure {
    pub(crate) text_body: Vec<String>,
    pub(crate) html_body: Vec<String>,
    pub(crate) attachments: Vec<String>,
}

/// Compute RFC 8621 §4.1.4 `textBody`, `htmlBody`, and `attachments` part ID lists.
///
/// The root part is treated as if it were the sole child of a synthetic
/// `multipart/mixed` container, matching the RFC's invocation:
/// `parseStructure([bodyStructure], 'mixed', false, htmlBody, textBody, attachments)`.
pub fn compute_body_structure(root: &ParsedPart) -> BodyStructure {
    let mut text_body: Vec<String> = Vec::new();
    let mut html_body: Vec<String> = Vec::new();
    let mut attachments: Vec<String> = Vec::new();

    parse_structure(
        std::slice::from_ref(root),
        "mixed",
        false,
        &mut Some(&mut text_body),
        &mut Some(&mut html_body),
        &mut attachments,
    );

    BodyStructure {
        text_body,
        html_body,
        attachments,
    }
}

/// Returns true for media types that may appear inline in a rendered message.
fn is_inline_media_type(media_type: &str) -> bool {
    media_type.starts_with("image/")
        || media_type.starts_with("audio/")
        || media_type.starts_with("video/")
}

/// Recursive implementation of the RFC 8621 §4.1.4 `parseStructure` function.
///
/// `text_body` and `html_body` are `Option<&mut Vec<String>>` to model the
/// JavaScript algorithm's nullable array references: when set to `None`,
/// further pushes to that list are suppressed and inline media goes to
/// attachments instead.
///
/// The `part_index` parameter (`i` in the RFC) is the 0-based position of
/// each part within its sibling list, used for the `multipart/related` rule.
fn parse_structure<'a>(
    parts: &[ParsedPart],
    multipart_type: &str,
    in_alternative: bool,
    text_body: &mut Option<&'a mut Vec<String>>,
    html_body: &mut Option<&'a mut Vec<String>>,
    attachments: &mut Vec<String>,
) {
    // Snapshot lengths at entry — used at the end of multipart/alternative
    // to cross-populate: if only html was found, mirror it into textBody,
    // and vice versa.  These are only consulted inside `if tb_active &&
    // hb_active`, so they are always Some(len) at the point of comparison.
    let text_length_at_entry: usize = text_body.as_ref().map_or(0, |v| v.len());
    let html_length_at_entry: usize = html_body.as_ref().map_or(0, |v| v.len());

    for (i, part) in parts.iter().enumerate() {
        let is_multipart = part.content_type.starts_with("multipart/");

        // RFC 8621 §4.1.4 isInline:
        //   disposition != "attachment"
        //   AND (text/plain | text/html | inline media type)
        //   AND (first child OR (not related AND (inline media OR no filename)))
        let is_inline = part
            .disposition
            .as_deref()
            .is_none_or(|d| !d.eq_ignore_ascii_case("attachment"))
            && (part.content_type == "text/plain"
                || part.content_type == "text/html"
                || is_inline_media_type(&part.content_type))
            && (i == 0
                || (multipart_type != "related"
                    && (is_inline_media_type(&part.content_type) || part.filename.is_none())));

        if is_multipart {
            let sub_multipart_type = part
                .content_type
                .split_once('/')
                .map(|(_, sub)| sub)
                .unwrap_or("mixed");
            let new_in_alternative = in_alternative || sub_multipart_type == "alternative";
            parse_structure(
                &part.children,
                sub_multipart_type,
                new_in_alternative,
                text_body,
                html_body,
                attachments,
            );
        } else if is_inline {
            if multipart_type == "alternative" {
                // Inside multipart/alternative: route by type, then `continue`
                // (do not fall through to the textBody/htmlBody push below).
                match part.content_type.as_str() {
                    "text/plain" => {
                        if let Some(ref mut tb) = text_body {
                            tb.push(part.part_id.clone());
                        }
                    }
                    "text/html" => {
                        if let Some(ref mut hb) = html_body {
                            hb.push(part.part_id.clone());
                        }
                    }
                    _ => {
                        attachments.push(part.part_id.clone());
                    }
                }
                continue;
            } else if in_alternative {
                // Inside a container that is itself nested within an alternative:
                // nullify the opposite list so later inline media go to attachments.
                // RFC 8621 §4.1.4: "if (textBody) { htmlBody = null; }" / "if (htmlBody) { textBody = null; }"
                if part.content_type == "text/plain" {
                    *html_body = None; // RFC 8621 §4.1.4: plain text found — nullify htmlBody
                }
                if part.content_type == "text/html" {
                    *text_body = None; // RFC 8621 §4.1.4: html found — nullify textBody
                }
            }

            // Push to whichever lists are still active.
            if let Some(ref mut tb) = text_body {
                tb.push(part.part_id.clone());
            }
            if let Some(ref mut hb) = html_body {
                hb.push(part.part_id.clone());
            }
            // If one list was nullified and this is inline media, it goes to
            // attachments so it isn't silently dropped.
            if (text_body.is_none() || html_body.is_none())
                && is_inline_media_type(&part.content_type)
            {
                attachments.push(part.part_id.clone());
            }
        } else {
            attachments.push(part.part_id.clone());
        }
    }

    // End-of-alternative cross-population:
    // If we are at the top of a multipart/alternative and both lists are still
    // active, mirror any newly added parts across.
    if multipart_type == "alternative" {
        let tb_active = text_body.is_some();
        let hb_active = html_body.is_some();

        if tb_active && hb_active {
            let text_now = text_body.as_ref().map_or(0, |v| v.len());
            let html_now = html_body.as_ref().map_or(0, |v| v.len());

            // Only html parts were added — copy them into textBody too.
            if text_length_at_entry == text_now && html_length_at_entry != html_now {
                let new_ids: Vec<String> = html_body
                    .as_ref()
                    .map(|v| v[html_length_at_entry..].to_vec())
                    .unwrap_or_default();
                if let Some(ref mut tb) = text_body {
                    tb.extend(new_ids);
                }
            }

            // Only text parts were added — copy them into htmlBody too.
            if html_length_at_entry == html_now && text_length_at_entry != text_now {
                let new_ids: Vec<String> = text_body
                    .as_ref()
                    .map(|v| v[text_length_at_entry..].to_vec())
                    .unwrap_or_default();
                if let Some(ref mut hb) = html_body {
                    hb.extend(new_ids);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::parse;

    /// Test 1 — simple text/plain message.
    ///
    /// A single-part text/plain message. Expected:
    ///   text_body = ["1"], html_body = ["1"], attachments = []
    ///
    /// Oracle: RFC 8621 §4.1.4 algorithm, JS pseudocode. A lone text/plain
    /// leaf outside any multipart/alternative is `isInline`, and the algorithm
    /// pushes it to both `textBody` and `htmlBody` (lines
    /// `if (textBody) textBody.push(part)` and `if (htmlBody) htmlBody.push(part)`).
    /// This matches the RFC example where parts A and K appear in both lists.
    #[test]
    fn simple_text_plain() {
        let raw =
            b"From: a@b.com\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nHello\r\n";
        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1".to_owned()]);
        assert_eq!(msg.html_body, vec!["1".to_owned()]);
        assert!(msg.attachments.is_empty(), "attachments should be empty");
    }

    /// Test 2 — multipart/alternative with text and html parts.
    ///
    /// Expected: text_body = ["1"], html_body = ["2"], attachments = []
    ///
    /// Oracle: RFC 8621 §4.1.4 — inside multipart/alternative, text/plain goes
    /// to textBody and text/html goes to htmlBody; both lists are populated.
    #[test]
    fn multipart_alternative_text_and_html() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Hello text\r\n",
            "--b\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>Hello html</p>\r\n",
            "--b--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1".to_owned()]);
        assert_eq!(msg.html_body, vec!["2".to_owned()]);
        assert!(msg.attachments.is_empty(), "attachments should be empty");
    }

    /// Test 3 — multipart/mixed with text body and PDF attachment.
    ///
    /// Expected: text_body = ["1"], html_body = ["1"], attachments = ["2"]
    ///
    /// Oracle: RFC 8621 §4.1.4 — text/plain (no attachment disposition) is
    /// inline and goes to both textBody and htmlBody (same behaviour as parts
    /// A and K in the RFC §4.1.4 example). application/pdf with
    /// Content-Disposition: attachment goes to attachments only.
    #[test]
    fn multipart_mixed_text_and_attachment() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Body text\r\n",
            "--b\r\n",
            "Content-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename=\"doc.pdf\"\r\n",
            "\r\n",
            "<pdf content>\r\n",
            "--b--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1".to_owned()]);
        assert_eq!(msg.html_body, vec!["1".to_owned()]);
        assert_eq!(msg.attachments, vec!["2".to_owned()]);
    }

    /// Test 4 — html-only multipart/alternative: cross-population into textBody.
    ///
    /// Expected: text_body = ["1"], html_body = ["1"], attachments = []
    ///
    /// Oracle: RFC 8621 §4.1.4 end-of-alternative cross-population rule —
    /// "If textBody didn't have any parts added to it, copy htmlBody into
    /// textBody" (and vice versa). A sole text/html alternative mirrors into
    /// textBody, matching RFC §4.1.4 example part C (html-only body).
    #[test]
    fn alternative_html_only_mirrors_to_text_body() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>HTML only</p>\r\n",
            "--b--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1".to_owned()]);
        assert_eq!(msg.html_body, vec!["1".to_owned()]);
        assert!(msg.attachments.is_empty());
    }

    /// Test 5 — text-only multipart/alternative: cross-population into htmlBody.
    ///
    /// Expected: text_body = ["1"], html_body = ["1"], attachments = []
    ///
    /// Oracle: RFC 8621 §4.1.4 — symmetric to Test 4: a sole text/plain
    /// alternative mirrors into htmlBody.
    #[test]
    fn alternative_text_only_mirrors_to_html_body() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Text only\r\n",
            "--b--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1".to_owned()]);
        assert_eq!(msg.html_body, vec!["1".to_owned()]);
        assert!(msg.attachments.is_empty());
    }

    /// Test 6 — multipart/related: non-first children go to attachments.
    ///
    /// Structure: multipart/related → text/html (i=0) + image/gif (i=1)
    /// Expected: text_body = ["1"], html_body = ["1"], attachments = ["2"]
    ///
    /// Oracle: RFC 8621 §4.1.4 isInline condition — the third clause requires
    /// `(i == 0 OR (multipartType != "related" AND ...))`.  For i > 0 inside
    /// multipart/related the clause is always false, so non-first children are
    /// non-inline and go to attachments regardless of media type.
    #[test]
    fn related_non_first_child_goes_to_attachments() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/related; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>HTML with inline image</p>\r\n",
            "--b\r\n",
            "Content-Type: image/gif\r\n",
            "Content-ID: <img@example.com>\r\n",
            "\r\n",
            "<gif data>\r\n",
            "--b--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1".to_owned()]);
        assert_eq!(msg.html_body, vec!["1".to_owned()]);
        assert_eq!(msg.attachments, vec!["2".to_owned()]);
    }

    /// Test 7 — in_alternative nullification: mixed-within-alternative sets
    /// html_body to None when a text/plain is found.
    ///
    /// Structure:
    ///   multipart/alternative:
    ///     - multipart/mixed:
    ///         - text/plain   ← sets html_body=None (in_alternative=true, not in alternative)
    ///     - text/html        ← html_body is None; nothing pushed
    ///
    /// Expected: text_body = ["1.1"], html_body = [], attachments = []
    ///
    /// Oracle: RFC 8621 §4.1.4 — when in_alternative is set and the current
    /// multipart is not "alternative", encountering text/plain sets htmlBody to
    /// null (preventing html parts at the same level from populating htmlBody).
    #[test]
    fn alternative_mixed_subtree_nullifies_html_body() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"outer\"\r\n",
            "\r\n",
            "--outer\r\n",
            "Content-Type: multipart/mixed; boundary=\"inner\"\r\n",
            "\r\n",
            "--inner\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Plain text in mixed\r\n",
            "--inner--\r\n",
            "--outer\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>This html is suppressed because html_body was nullified</p>\r\n",
            "--outer--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1.1".to_owned()]);
        assert!(
            msg.html_body.is_empty(),
            "html_body should be empty after nullification; got: {:?}",
            msg.html_body
        );
        assert!(msg.attachments.is_empty());
    }
}
