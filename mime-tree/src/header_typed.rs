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

/// Sign of a `date-time` timezone offset from GMT (RFC 5322 §3.3).
///
/// East of GMT corresponds to positive `+HHMM` offsets (e.g. `+0100`).
/// West of GMT corresponds to negative `-HHMM` offsets (e.g. `-0600`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TzSign {
    /// Offset is east of GMT (`+HHMM`).
    East,
    /// Offset is west of GMT (`-HHMM`).
    West,
}

/// An RFC 5322 §3.3 `date-time` value parsed from a header.
///
/// Public fields permit serde transparency and direct field access from
/// JMAP-shaped code. The fields mirror `mail_parser::DateTime` 1-to-1
/// **except** for `tz_sign`, which is an explicit enum rather than a
/// bool. This is a deliberate API choice — see `TzSign` — and means
/// `HeaderDateTime` and `mail_parser::DateTime` are not bit-identical
/// even though they round-trip via [`HeaderDateTime::from_mail_parser`]
/// / [`HeaderDateTime::to_mail_parser`].
///
/// # Wire-format dependency on mail-parser
///
/// [`Self::to_rfc3339`] and [`Self::to_timestamp`] delegate to
/// `mail_parser::DateTime`'s formatters. The exact strings produced by
/// `to_rfc3339`, and the exact value produced by `to_timestamp` for
/// edge-case input, are therefore defined by the pinned mail-parser
/// version. mime-tree's Cargo.toml uses a caret range (`mail-parser =
/// "0.11"`) so 0.11.x patch updates can in principle change the output
/// without a mime-tree version bump. Downstream callers that persist
/// these strings (database keys, JMAP wire responses, indexed columns)
/// SHOULD pin mail-parser tightly if they require byte-stable output
/// across mime-tree patch bumps.
///
/// # Field invariants
///
/// `parse_header_typed` only constructs `HeaderDateTime` values that
/// passed mail-parser's validation: `year >= 1900`, `month ∈ 1..=12`,
/// `day ∈ 1..=31` (calendar-validated), `hour ∈ 0..=23`,
/// `minute ∈ 0..=59`, `second ∈ 0..=60` (RFC 5322 §4.3 leap second),
/// `tz_hour ∈ 0..=23`, `tz_minute ∈ 0..=59`.
///
/// Direct construction with public fields can produce out-of-range
/// values. The behaviour of `to_rfc3339` and `to_timestamp` on such
/// values is unspecified — output may be syntactically malformed
/// RFC 3339 or a meaningless `i64`. Callers that build `HeaderDateTime`
/// from external sources should validate ranges themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HeaderDateTime {
    /// Four-digit calendar year. Parser-produced values: `1900..=3000`.
    pub year: u16,
    /// Month of the year, `1..=12` for parser-produced values.
    pub month: u8,
    /// Day of the month, `1..=31` (calendar-validated against
    /// `year`/`month`) for parser-produced values.
    pub day: u8,
    /// Hour of the day, `0..=23` for parser-produced values.
    pub hour: u8,
    /// Minute, `0..=59` for parser-produced values.
    pub minute: u8,
    /// Second, `0..=60` for parser-produced values (RFC 5322 §4.3
    /// allows 60 to represent a leap second).
    pub second: u8,
    /// Sign of the timezone offset from GMT.
    pub tz_sign: TzSign,
    /// Hours component of the timezone offset, `0..=23` for
    /// parser-produced values.
    pub tz_hour: u8,
    /// Minutes component of the timezone offset, `0..=59` for
    /// parser-produced values.
    pub tz_minute: u8,
}

impl HeaderDateTime {
    /// Render as an RFC 3339 / ISO 8601 §5.6 date-time string.
    ///
    /// # Output format
    ///
    /// * Non-UTC offset (any of `tz_hour`, `tz_minute` non-zero):
    ///   `YYYY-MM-DDTHH:MM:SS±HH:MM`. Each component is zero-padded;
    ///   `±` is `-` for west-of-GMT, `+` otherwise.
    /// * UTC (`tz_hour == 0 && tz_minute == 0`):
    ///   `YYYY-MM-DDTHH:MM:SSZ`. Zulu form, not `+00:00`.
    ///
    /// No subsecond fraction is emitted (the seconds-fraction extension
    /// of RFC 3339 is not represented in `HeaderDateTime`).
    ///
    /// # Examples
    ///
    /// * `1997-11-21T09:55:06-06:00` for `21 Nov 1997 09:55:06 -0600`.
    /// * `2024-01-15T12:34:56Z` for `15 Jan 2024 12:34:56 +0000`.
    ///
    /// # Behaviour on out-of-range input
    ///
    /// The exact string for out-of-range field values
    /// (e.g. `month = 13`) is unspecified — it depends on the pinned
    /// mail-parser version and may not be syntactically valid RFC 3339.
    /// See the type-level docs.
    #[must_use]
    pub fn to_rfc3339(&self) -> String {
        self.to_mail_parser().to_rfc3339()
    }

    /// Render as a Unix timestamp (seconds since 1970-01-01T00:00:00Z).
    ///
    /// Pre-epoch dates return negative values. The result is computed
    /// linearly from the field values without validation; on
    /// out-of-range or otherwise invalid input (e.g. `month = 0`,
    /// `day = 99`, year overflowing the calendar arithmetic) the
    /// returned `i64` is unspecified and SHOULD NOT be relied upon.
    /// See the type-level docs.
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
            tz_before_gmt: matches!(self.tz_sign, TzSign::West),
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
            tz_sign: if dt.tz_before_gmt {
                TzSign::West
            } else {
                TzSign::East
            },
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
    /// Trim surrounding whitespace; return the bytes as a UTF-8 string.
    /// (§4.1.2.1)
    ///
    /// Non-UTF-8 bytes — legal in raw RFC 5322 but not in JMAP wire
    /// format — are replaced with U+FFFD REPLACEMENT CHARACTER
    /// (lossy conversion). This preserves the position and rough shape
    /// of malformed input so callers can flag a mojibake header
    /// without losing the rest of the field body.
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
        // surrounding white space removed. Non-UTF-8 bytes are replaced
        // with U+FFFD via `from_utf8_lossy` so malformed-but-non-empty
        // input does not collapse into an indistinguishable empty
        // string. This matches mail-parser's own handling of non-UTF-8
        // header bytes (`HeaderValue::Text` is `Cow<str>` populated via
        // `from_utf8_lossy`).
        let s = String::from_utf8_lossy(raw_value);
        return HeaderValueTyped::Raw(s.trim().to_owned());
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
