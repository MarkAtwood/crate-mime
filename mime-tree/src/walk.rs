//! RFC 8621 §4.1.4 body structure decomposition.
//!
//! Translates the reference JavaScript algorithm from the RFC into Rust,
//! walking a `ParsedPart` tree and classifying leaf parts into three lists.

use crate::part::ParsedPart;

/// Nullable append target — models JavaScript's null-rebind semantics from
/// RFC 8621 §4.1.4.
///
/// In the RFC's JavaScript pseudocode, `htmlBody = null` inside a recursive
/// `parseStructure` call is a local variable rebind: it stops further pushes
/// to that list within the callee, but does NOT propagate back to the caller.
/// Meanwhile, `htmlBody.push(part)` writes through to the shared underlying
/// array.
///
/// This wrapper encapsulates `Option<&mut Vec<String>>`:
/// - **Active** (`Some`): `.push()` appends to the underlying `Vec`.
/// - **Disabled** (`None`): `.push()` is a no-op; `.is_active()` returns false.
/// - **`.as_child()`** reborrows the inner `Vec` into a fresh `AppendTarget`,
///   so the child can `.disable()` without affecting the parent's state.
struct AppendTarget<'a>(Option<&'a mut Vec<String>>);

impl<'a> AppendTarget<'a> {
    /// Create an active target backed by `vec`.
    fn new(vec: &'a mut Vec<String>) -> Self {
        Self(Some(vec))
    }

    /// Append `id` if active; no-op if disabled.
    fn push(&mut self, id: String) {
        if let Some(ref mut v) = self.0 {
            v.push(id);
        }
    }

    /// Disable this target — further `.push()` calls become no-ops.
    fn disable(&mut self) {
        self.0 = None;
    }

    /// Whether this target is still active (non-null).
    fn is_active(&self) -> bool {
        self.0.is_some()
    }

    /// Current length of the underlying `Vec`, or 0 if disabled.
    fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |v| v.len())
    }

    /// Clone items from `start..` out of the underlying `Vec`.
    /// Returns an empty `Vec` if disabled.
    fn slice_from(&self, start: usize) -> Vec<String> {
        self.0
            .as_ref()
            .map(|v| v[start..].to_vec())
            .unwrap_or_default()
    }

    /// Extend the underlying `Vec` with `ids` if active.
    fn extend(&mut self, ids: Vec<String>) {
        if let Some(ref mut v) = self.0 {
            v.extend(ids);
        }
    }

    /// Create a child target for recursive calls.
    ///
    /// The child reborrows the same underlying `Vec`, so `.push()` calls
    /// propagate. But the child's `Option` is independent: `.disable()` on
    /// the child does not affect this parent — exactly matching JavaScript's
    /// local variable rebind semantics.
    fn as_child(&mut self) -> AppendTarget<'_> {
        AppendTarget(self.0.as_deref_mut())
    }
}

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
        &mut AppendTarget::new(&mut text_body),
        &mut AppendTarget::new(&mut html_body),
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
/// `text_body` and `html_body` use `AppendTarget` to model the JavaScript
/// algorithm's nullable array references: when disabled, further pushes are
/// suppressed and inline media goes to attachments instead.
///
/// The loop variable `i` (index into `parts`) is the 0-based position of
/// each part within its sibling list, used for the `multipart/related` rule.
fn parse_structure(
    parts: &[ParsedPart],
    multipart_type: &str,
    in_alternative: bool,
    text_body: &mut AppendTarget<'_>,
    html_body: &mut AppendTarget<'_>,
    attachments: &mut Vec<String>,
) {
    // Snapshot lengths at entry — used at the end of multipart/alternative
    // to cross-populate: if only html was found, mirror it into textBody,
    // and vice versa.  These are only consulted inside `if tb_active &&
    // hb_active`, so they are always valid at the point of comparison.
    let text_length_at_entry = text_body.len();
    let html_length_at_entry = html_body.len();

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
            // Per RFC 8621 §4.1.4 JavaScript semantics: `htmlBody = null` inside
            // a recursive call is a local variable rebind and does NOT propagate
            // back to the caller.  `.as_child()` reborrows the underlying Vec
            // into a fresh AppendTarget: pushes propagate (same allocation), but
            // `.disable()` in the callee leaves the caller's target unchanged.
            let mut sub_text = text_body.as_child();
            let mut sub_html = html_body.as_child();
            parse_structure(
                &part.children,
                sub_multipart_type,
                new_in_alternative,
                &mut sub_text,
                &mut sub_html,
                attachments,
            );
        } else if is_inline {
            if multipart_type == "alternative" {
                // Inside multipart/alternative: route by type, then `continue`
                // (do not fall through to the textBody/htmlBody push below).
                match part.content_type.as_str() {
                    "text/plain" => {
                        text_body.push(part.part_id.clone());
                    }
                    "text/html" => {
                        html_body.push(part.part_id.clone());
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
                    html_body.disable(); // RFC 8621 §4.1.4: plain text found — nullify htmlBody
                }
                if part.content_type == "text/html" {
                    text_body.disable(); // RFC 8621 §4.1.4: html found — nullify textBody
                }
            }

            // Push to whichever lists are still active.
            text_body.push(part.part_id.clone());
            html_body.push(part.part_id.clone());
            // If one list was nullified and this is inline media, it goes to
            // attachments so it isn't silently dropped.
            if (!text_body.is_active() || !html_body.is_active())
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
        let tb_active = text_body.is_active();
        let hb_active = html_body.is_active();

        if tb_active && hb_active {
            let text_now = text_body.len();
            let html_now = html_body.len();

            // Only html parts were added — copy them into textBody too.
            if text_length_at_entry == text_now && html_length_at_entry != html_now {
                let new_ids = html_body.slice_from(html_length_at_entry);
                text_body.extend(new_ids);
            }

            // Only text parts were added — copy them into htmlBody too.
            if html_length_at_entry == html_now && text_length_at_entry != text_now {
                let new_ids = text_body.slice_from(text_length_at_entry);
                html_body.extend(new_ids);
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

    /// Test 7 — multipart/alternative → multipart/mixed → image/gif.
    ///
    /// Structure:
    ///   multipart/alternative (root, id=""):
    ///     - multipart/mixed (id="1"):
    ///         - image/gif (id="1.1")
    ///
    /// Walk trace:
    ///   parse_structure([alt], "mixed", false, Some(tb), Some(hb), att)
    ///     → alt is_multipart → recurse([mixed], "alternative", true, ...)
    ///       → mixed is_multipart → recurse([gif], "mixed", true, ...)
    ///         → gif: is_inline=true (inline media, i==0, no attachment disp)
    ///           → multipart_type != "alternative" → skip alt-specific branch
    ///           → in_alternative=true: content_type is neither text/plain nor
    ///             text/html → neither nullification fires
    ///           → pushes to both text_body ("1.1") and html_body ("1.1")
    ///           → text_body.is_none() || html_body.is_none() = false → no
    ///             push to attachments
    ///       → end-of-alternative: both lists active; both gained one part →
    ///         neither cross-population fires (both sides grew)
    ///
    /// Actual behaviour: image/gif lands in BOTH text_body and html_body.
    /// Attachments is empty — no attachment disposition, so it is treated as
    /// inline content duplicated across both body lists.
    ///
    /// Oracle: RFC 8621 §4.1.4 — image/gif is isInlineMediaType, so it is
    /// isInline. Inside the nested mixed container (inAlternative=true), the
    /// in_alternative nullification branch only fires for text/plain or
    /// text/html; gif triggers neither. Both textBody and htmlBody are still
    /// non-null, so the RFC's `if(textBody) textBody.push(part)` and
    /// `if(htmlBody) htmlBody.push(part)` both execute, placing "1.1" in both
    /// lists. The end-of-alternative cross-population does not fire because
    /// both lists gained one entry.
    #[test]
    fn alternative_mixed_image_gif_goes_to_both_body_lists() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"outer\"\r\n",
            "\r\n",
            "--outer\r\n",
            "Content-Type: multipart/mixed; boundary=\"inner\"\r\n",
            "\r\n",
            "--inner\r\n",
            "Content-Type: image/gif\r\n",
            "\r\n",
            "<gif data>\r\n",
            "--inner--\r\n",
            "--outer--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        // The image/gif part id is "1.1":
        //   root alt="" → child mixed="1" → child gif="1.1"
        assert_eq!(
            msg.text_body,
            vec!["1.1".to_owned()],
            "image/gif inside alt→mixed should appear in text_body"
        );
        assert_eq!(
            msg.html_body,
            vec!["1.1".to_owned()],
            "image/gif inside alt→mixed should appear in html_body"
        );
        assert!(
            msg.attachments.is_empty(),
            "image/gif with no attachment disposition should not be in attachments; got: {:?}",
            msg.attachments
        );
    }

    /// Test 8 — application/octet-stream without Content-Disposition goes to attachments.
    ///
    /// Structure: multipart/mixed → application/octet-stream (no Content-Disposition)
    /// Expected: text_body = [], html_body = [], attachments = ["1"]
    ///
    /// Oracle: RFC 8621 §4.1.4 isInline requires the content type to be
    /// text/plain, text/html, or an inline media type (image/*, audio/*, video/*).
    /// application/octet-stream matches none of these, so isInline = false
    /// regardless of whether a Content-Disposition header is present.
    /// The part therefore goes directly to attachments.
    #[test]
    fn octet_stream_no_disposition_goes_to_attachments() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: application/octet-stream\r\n",
            "\r\n",
            "<binary data>\r\n",
            "--b--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert!(
            msg.text_body.is_empty(),
            "text_body must be empty; got: {:?}",
            msg.text_body
        );
        assert!(
            msg.html_body.is_empty(),
            "html_body must be empty; got: {:?}",
            msg.html_body
        );
        assert_eq!(
            msg.attachments,
            vec!["1".to_owned()],
            "application/octet-stream without Content-Disposition must go to attachments"
        );
    }

    /// Test 9 — in_alternative nullification is local to the recursive call.
    ///
    /// Structure:
    ///   multipart/alternative:
    ///     - multipart/mixed (id="1"):
    ///         - text/plain (id="1.1")  ← inside mixed, inAlternative=true;
    ///                                     sets htmlBody=null LOCALLY
    ///     - text/html (id="2")         ← back in alternative; htmlBody is still
    ///                                     live because the null was local to the
    ///                                     nested call; pushed to htmlBody
    ///
    /// Expected: text_body = ["1.1"], html_body = ["2"], attachments = []
    ///
    /// Oracle: RFC 8621 §4.1.4 — in the JavaScript pseudocode, `htmlBody = null`
    /// inside a recursive `parseStructure` call is a local variable rebind; it
    /// does NOT propagate to the caller's `htmlBody` variable.  Therefore the
    /// outer alternative call's htmlBody is still the live array when the
    /// text/html sibling (id="2") is processed, and that part is pushed to it.
    /// The end-of-alternative cross-population does not fire because both lists
    /// gained at least one part.
    #[test]
    fn alternative_mixed_subtree_nullification_is_local() {
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
            "<p>HTML at alternative level; htmlBody is still live</p>\r\n",
            "--outer--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        assert_eq!(msg.text_body, vec!["1.1".to_owned()]);
        assert_eq!(
            msg.html_body,
            vec!["2".to_owned()],
            "html_body should contain text/html part '2'; nullification in nested call is local"
        );
        assert!(msg.attachments.is_empty());
    }

    /// Test 10 — multipart/mixed(text/plain, text/html) inside multipart/alternative.
    ///
    /// Structure:
    ///   multipart/alternative (root, id=""):
    ///     - multipart/mixed (id="1"):
    ///         - text/plain (id="1.1")
    ///         - text/html  (id="1.2")
    ///
    /// Walk trace (in_alternative=true inside the mixed container):
    ///   text/plain (i=0): nullifies local html_body → pushes "1.1" to text_body
    ///   text/html  (i=1): nullifies local text_body → both local Options are
    ///     now None, so text/html is not pushed anywhere
    ///
    /// The nullification is local to the recursive call (lines 110-111 create
    /// fresh Option locals via as_deref_mut).  Pushes propagate to the caller's
    /// underlying Vec, but setting the local Option to None does not affect the
    /// caller.  So text/plain ("1.1") remains in text_body after the recursive
    /// call returns.
    ///
    /// End-of-alternative cross-population: text_body grew (["1.1"]) but
    /// html_body did not → html_body gets a copy of ["1.1"].
    ///
    /// Result: text_body = ["1.1"], html_body = ["1.1"]
    ///
    /// The text/html part ("1.2") is silently dropped — an unusual MIME
    /// structure.  A multipart/mixed containing both text alternatives is more
    /// correctly expressed as a direct multipart/alternative.  Documented as
    /// accepted edge-case behavior.
    #[test]
    fn alternative_mixed_both_text_types_dual_nullification() {
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
            "Plain text\r\n",
            "--inner\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>HTML text</p>\r\n",
            "--inner--\r\n",
            "--outer--\r\n"
        )
        .as_bytes();

        let msg = parse(raw).expect("parse failed");
        // text/plain survives; text/html is dropped (see doc comment).
        assert_eq!(
            msg.text_body,
            vec!["1.1".to_owned()],
            "text/plain survives local nullification"
        );
        // Cross-population mirrors text_body into html_body.
        assert_eq!(
            msg.html_body,
            vec!["1.1".to_owned()],
            "cross-population mirrors text/plain into html_body"
        );
    }
}
