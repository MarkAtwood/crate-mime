//! Typed header value parsing for RFC 8621 JMAP `As*` header forms.
//!
//! RFC 8621 §4.1.2 defines several parsed-form selectors that a JMAP server
//! may apply to a single header field's raw bytes:
//!
//! | RFC 8621 form        | Section    | mime-tree result variant                |
//! |----------------------|------------|------------------------------------------|
//! | `asAddresses`        | §4.1.2.3   | [`HeaderValueTyped::Addresses`]          |
//! | `asGroupedAddresses` | §4.1.2.4   | [`HeaderValueTyped::GroupedAddresses`]   |
//! | `asMessageIds`       | §4.1.2.5   | [`HeaderValueTyped::MessageIds`]         |
//! | `asDate`             | §4.1.2.6   | [`HeaderValueTyped::DateTime`]           |
//! | `asURLs`             | §4.1.2.7   | [`HeaderValueTyped::URLs`]               |
//! | `Raw`                | §4.1.2.1   | [`HeaderValueTyped::Raw`]                |
//!
//! The entry point is [`parse_header_typed`]. It takes the [`HeaderForm`]
//! selector and the raw bytes of the header field value (the portion to the
//! right of the `:` in the header line, including any folded continuation
//! lines but excluding the header name and the trailing CRLF).
//!
//! Parsing is best-effort. On failure the function returns the appropriate
//! empty value (an empty `Vec`, an empty `Raw` string, or `DateTime(None)`
//! for an unparseable date) — it never panics and never returns an error.
//!
//! These types are independent of the [`crate::ParsedHeader`] surface, which
//! continues to expose only the decoded raw string. Add a typed view on top
//! of an existing `ParsedHeader` by slicing the original bytes covered by
//! [`crate::ParsedPart::header_range`] and feeding the field value to
//! [`parse_header_typed`].

use mail_parser::{parsers::MessageStream, Address, HeaderValue};
use serde::{Deserialize, Serialize};

/// A single RFC 5322 `mailbox` parsed from an `address-list`.
///
/// Mirrors the JMAP `EmailAddress` object defined in RFC 8621 §4.1.2.3.
///
/// `name` is the optional display name. `address` is the `addr-spec`. Both
/// are populated best-effort; either may be `None` if the original header
/// is malformed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailAddress {
    /// Display name from the `mailbox`, RFC 2047 encoded-words already decoded.
    pub name: Option<String>,
    /// `addr-spec` of the `mailbox`.
    pub address: Option<String>,
}

/// A group of `EmailAddress` values, optionally named.
///
/// Mirrors the JMAP `EmailAddressGroup` object defined in RFC 8621 §4.1.2.4.
///
/// Per RFC 8621 §4.1.2.4, consecutive mailboxes that are not part of a
/// declared RFC 5322 `group` are still collected under an `AddressGroup`
/// whose `name` is `None`, "to provide a uniform type".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressGroup {
    /// Display name of the group, or `None` for ungrouped mailboxes.
    pub name: Option<String>,
    /// Mailboxes belonging to this group.
    pub addresses: Vec<EmailAddress>,
}

/// An RFC 5322 §3.3 `date-time` value parsed from a header.
///
/// Mirrors `mail_parser::DateTime` but is owned and lifetime-free so it can
/// be embedded in `ParsedMessage`-adjacent state and serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// `true` if the offset from GMT is negative (i.e. west of GMT).
    pub tz_before_gmt: bool,
    pub tz_hour: u8,
    pub tz_minute: u8,
}

impl HeaderDateTime {
    /// Render as an RFC 3339 / ISO 8601 timestamp string.
    ///
    /// Delegates to mail-parser's formatter. Returns the canonical
    /// `YYYY-MM-DDTHH:MM:SS±HH:MM` form.
    #[must_use]
    pub fn to_rfc3339(&self) -> String {
        self.to_mail_parser().to_rfc3339()
    }

    /// Render as a Unix timestamp (seconds since 1970-01-01 UTC).
    #[must_use]
    pub fn to_timestamp(&self) -> i64 {
        self.to_mail_parser().to_timestamp()
    }

    fn to_mail_parser(self) -> mail_parser::DateTime {
        mail_parser::DateTime {
            year: self.year,
            month: self.month,
            day: self.day,
            hour: self.hour,
            minute: self.minute,
            second: self.second,
            tz_before_gmt: self.tz_before_gmt,
            tz_hour: self.tz_hour,
            tz_minute: self.tz_minute,
        }
    }

    fn from_mail_parser(dt: &mail_parser::DateTime) -> Self {
        Self {
            year: dt.year,
            month: dt.month,
            day: dt.day,
            hour: dt.hour,
            minute: dt.minute,
            second: dt.second,
            tz_before_gmt: dt.tz_before_gmt,
            tz_hour: dt.tz_hour,
            tz_minute: dt.tz_minute,
        }
    }
}

/// Selector for the RFC 8621 parsed-form of a header value.
///
/// This is the form-token from a JMAP `header:<name>:as<form>` property
/// selector, normalised to an enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HeaderForm {
    /// Trim whitespace; return the raw bytes as a UTF-8 string. (§4.1.2.1)
    Raw,
    /// Parse as an RFC 5322 `address-list`. Group structure is discarded;
    /// only the flat list of mailboxes is returned. (§4.1.2.3)
    Addresses,
    /// Parse as an RFC 5322 `address-list`, preserving group structure.
    /// (§4.1.2.4)
    GroupedAddresses,
    /// Parse as a list of RFC 5322 `msg-id` values. Surrounding angle
    /// brackets and CFWS are stripped. (§4.1.2.5)
    MessageIds,
    /// Parse as an RFC 5322 §3.3 `date-time`. (§4.1.2.6)
    Date,
    /// Parse as an RFC 2369 list of URLs. Surrounding angle brackets and
    /// comments are stripped. (§4.1.2.7)
    URLs,
}

/// A header field value rendered in one of the RFC 8621 parsed forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HeaderValueTyped {
    /// Result of [`HeaderForm::Raw`]: the trimmed UTF-8 string.
    Raw(String),
    /// Result of [`HeaderForm::Addresses`].
    Addresses(Vec<EmailAddress>),
    /// Result of [`HeaderForm::GroupedAddresses`].
    GroupedAddresses(Vec<AddressGroup>),
    /// Result of [`HeaderForm::MessageIds`]: bare msg-id strings with no
    /// angle brackets.
    MessageIds(Vec<String>),
    /// Result of [`HeaderForm::Date`], or `None` if the header value did
    /// not parse as a `date-time`.
    DateTime(Option<HeaderDateTime>),
    /// Result of [`HeaderForm::URLs`]: bare URL strings with no angle
    /// brackets.
    URLs(Vec<String>),
}

/// Parse a header field value into the requested RFC 8621 parsed form.
///
/// `raw_value` is the bytes of the header field value — the portion to the
/// right of the `:` in the header line, including any folded continuation
/// lines but excluding the header name and the trailing CRLF.
///
/// Parsing is best-effort. Malformed input yields the empty result for the
/// requested form (empty `Vec`, empty string, or `DateTime(None)`).
///
/// # Examples
///
/// ```
/// use mime_tree::{parse_header_typed, EmailAddress, HeaderForm, HeaderValueTyped};
///
/// // RFC 8621 §4.1.2.3 example (the "James Smythe" address-list, simplified).
/// let raw = b" \"James Smythe\" <james@example.com>";
/// let parsed = parse_header_typed(HeaderForm::Addresses, raw);
/// assert_eq!(
///     parsed,
///     HeaderValueTyped::Addresses(vec![EmailAddress {
///         name: Some("James Smythe".to_owned()),
///         address: Some("james@example.com".to_owned()),
///     }]),
/// );
/// ```
#[must_use]
pub fn parse_header_typed(form: HeaderForm, raw_value: &[u8]) -> HeaderValueTyped {
    if matches!(form, HeaderForm::Raw) {
        // RFC 8621 §4.1.2.1: the value is the header field value with
        // surrounding white space removed.
        let s = std::str::from_utf8(raw_value).unwrap_or("").trim();
        return HeaderValueTyped::Raw(s.to_owned());
    }

    // mail-parser's MessageStream parsers are written to consume header
    // bytes as they appear in a real RFC 5322 stream — terminated by
    // CRLF (a line on its own ends the header, and the parser uses LF to
    // recognise that). Callers pass the field value with no trailing
    // CRLF; append one so the underlying parsers see a well-formed end-
    // of-header. This is consistent with mail-parser's own use of these
    // parsers via `MessageParser::parse`.
    let owned: Vec<u8>;
    let buf: &[u8] = if raw_value.ends_with(b"\r\n") {
        raw_value
    } else if raw_value.ends_with(b"\n") {
        // Convert LF to CRLF so the parser sees the expected sequence.
        owned = raw_value
            .split_last()
            .map(|(_, head)| {
                let mut v = Vec::with_capacity(head.len() + 2);
                v.extend_from_slice(head);
                v.extend_from_slice(b"\r\n");
                v
            })
            .unwrap_or_else(|| b"\r\n".to_vec());
        &owned
    } else {
        owned = {
            let mut v = Vec::with_capacity(raw_value.len() + 2);
            v.extend_from_slice(raw_value);
            v.extend_from_slice(b"\r\n");
            v
        };
        &owned
    };

    match form {
        HeaderForm::Raw => unreachable!("handled above"),
        HeaderForm::Addresses => {
            let hv = MessageStream::new(buf).parse_address();
            HeaderValueTyped::Addresses(flatten_addresses(&hv))
        }
        HeaderForm::GroupedAddresses => {
            let hv = MessageStream::new(buf).parse_address();
            HeaderValueTyped::GroupedAddresses(group_addresses(&hv))
        }
        HeaderForm::MessageIds => {
            // mail-parser's `parse_id` has a broken-client recovery
            // branch (mail-parser-0.11/src/parsers/fields/id.rs) that
            // returns `HeaderValue::Text` containing the unparsed bytes
            // when no `<...>` tokens were found in the input. From the
            // result type alone we cannot tell that case apart from the
            // single-valid-msg-id case (`<x>` → `Text("x")`).
            //
            // Discriminator: a Text result is the result of bracket
            // stripping iff the original input contained at least one
            // `<` byte. mail-parser does not insert angle brackets that
            // were not present in the input, so absence of `<` in the
            // raw bytes is a sufficient signal that mail-parser cannot
            // have produced Text via the stripping branch.
            let hv = MessageStream::new(buf).parse_id();
            let had_angle_brackets = raw_value.contains(&b'<');
            HeaderValueTyped::MessageIds(extract_msg_ids(&hv, had_angle_brackets))
        }
        HeaderForm::Date => {
            let hv = MessageStream::new(buf).parse_date();
            let dt = match hv {
                // mail-parser's `parse_date` returns `HeaderValue::Empty`
                // when it cannot recover 6 numeric components. Belt-and-
                // braces: also reject all-zero year/month/day, which RFC
                // 5322 §3.3 does not permit.
                HeaderValue::DateTime(dt) if dt.year != 0 && dt.month != 0 && dt.day != 0 => {
                    Some(HeaderDateTime::from_mail_parser(&dt))
                }
                _ => None,
            };
            HeaderValueTyped::DateTime(dt)
        }
        HeaderForm::URLs => {
            // RFC 8621 §4.1.2.7 / RFC 2369 §2: each URL is wrapped in
            // angle brackets. RFC 8621 §4.1.2.7 mandates that any
            // value outside of the angle-bracket arguments MUST be
            // ignored. mail-parser's address parser doesn't honour
            // that contract (e.g. bare `https://example.com/u/abc`
            // is treated as a malformed address with `https` as a
            // group name), so we extract bracket contents directly
            // rather than delegating.
            HeaderValueTyped::URLs(extract_bracketed_urls(raw_value))
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn convert_addr(addr: &mail_parser::Addr<'_>) -> EmailAddress {
    // RFC 8621 §4.1.2.3 mandates that for a quoted-string display name,
    // surrounding DQUOTE characters be removed, quoted-pairs decoded, and
    // white space unfolded with leading/trailing white space removed.
    // mail-parser already does the dequoting and quoted-pair decoding, but
    // leaves surrounding white space inside the quoted-string in place
    // (e.g. `"  James Smythe"` parses to `Some("  James Smythe")`). Strip
    // here. An empty trimmed result is mapped to `None` so a lone empty
    // quoted-string does not surface as a phantom display name.
    let name = addr.name.as_ref().and_then(|s| {
        let trimmed = s.as_ref().trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    });
    EmailAddress {
        name,
        address: addr.address.as_ref().map(|s| s.as_ref().to_owned()),
    }
}

/// Flatten an `Address` (which is either a flat list of mailboxes or a
/// list of groups) into a single `Vec<EmailAddress>`. Used for
/// [`HeaderForm::Addresses`], which per RFC 8621 §4.1.2.3 discards group
/// structure and produces one item per mailbox.
fn flatten_addresses(hv: &HeaderValue<'_>) -> Vec<EmailAddress> {
    match hv {
        HeaderValue::Address(Address::List(list)) => list.iter().map(convert_addr).collect(),
        HeaderValue::Address(Address::Group(groups)) => groups
            .iter()
            .flat_map(|g| g.addresses.iter().map(convert_addr))
            .collect(),
        _ => Vec::new(),
    }
}

/// Convert an `Address` into a list of groups, per RFC 8621 §4.1.2.4. A
/// flat list of mailboxes is wrapped in a single group with `name = None`.
fn group_addresses(hv: &HeaderValue<'_>) -> Vec<AddressGroup> {
    match hv {
        HeaderValue::Address(Address::List(list)) if !list.is_empty() => {
            vec![AddressGroup {
                name: None,
                addresses: list.iter().map(convert_addr).collect(),
            }]
        }
        HeaderValue::Address(Address::Group(groups)) => groups
            .iter()
            .map(|g| AddressGroup {
                // RFC 8621 §4.1.2.4: the group `name` is "processed the
                // same as the name in the EmailAddress type" — trim white
                // space; empty after trimming becomes None.
                name: g.name.as_ref().and_then(|s| {
                    let trimmed = s.as_ref().trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_owned())
                    }
                }),
                addresses: g.addresses.iter().map(convert_addr).collect(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Extract bare msg-id strings from a `HeaderValue` produced by
/// mail-parser's `parse_id`.
///
/// `had_angle_brackets` indicates whether the original raw input
/// contained at least one `<` byte. mail-parser's `parse_id` returns
/// `HeaderValue::Text` both for a single valid bracket-stripped msg-id
/// and for its broken-client recovery branch on input with no brackets at
/// all (returning the lossy UTF-8 of the unparsed bytes). Without this
/// discriminator, malformed input would leak the unparsed bytes into the
/// result vec, violating the RFC 8621 §4.1.2.5 empty-on-malformed
/// contract.
fn extract_msg_ids(hv: &HeaderValue<'_>, had_angle_brackets: bool) -> Vec<String> {
    match hv {
        HeaderValue::Text(s) if had_angle_brackets => vec![s.as_ref().to_owned()],
        HeaderValue::TextList(list) => list.iter().map(|s| s.as_ref().to_owned()).collect(),
        _ => Vec::new(),
    }
}

/// Extract URL strings from RFC 2369 / RFC 8621 §4.1.2.7 bracketed
/// list-URL syntax.
///
/// Scans `raw_value` for `<...>` substrings and yields the byte sequence
/// between each matching pair, in order. Bytes outside the brackets are
/// ignored — including comments (`(...)`), CFWS, commas, and any
/// malformed framing — per RFC 8621 §4.1.2.7: "Any value outside of the
/// angle bracket arguments MUST be ignored."
///
/// ASCII whitespace inside a bracketed value is stripped, because RFC
/// 3986 URIs cannot contain literal whitespace; any whitespace seen is a
/// CRLF folding artifact. Non-UTF-8 bracket contents are dropped.
///
/// An unclosed `<` (no matching `>`) is ignored. An empty `<>` is
/// ignored.
fn extract_bracketed_urls(raw_value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = raw_value.iter();
    while let Some(&b) = iter.next() {
        if b != b'<' {
            continue;
        }
        let mut url = Vec::new();
        let mut closed = false;
        for &b2 in iter.by_ref() {
            if b2 == b'>' {
                closed = true;
                break;
            }
            // Drop ASCII whitespace; URIs per RFC 3986 cannot contain it
            // literally, so any whitespace seen is CRLF folding.
            if !matches!(b2, b' ' | b'\t' | b'\r' | b'\n') {
                url.push(b2);
            }
        }
        if !closed || url.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&url) {
            out.push(s.to_owned());
        }
    }
    out
}
