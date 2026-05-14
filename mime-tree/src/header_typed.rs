//! Typed header value parsing for RFC 8621 JMAP `As*` header forms.
//!
//! RFC 8621 §4.1.2 defines several parsed-form selectors that a JMAP server
//! may apply to a single header field's raw bytes:
//!
//! | RFC 8621 form        | Section    | mime-tree result variant                |
//! |----------------------|------------|------------------------------------------|
//! | `asRaw`              | §4.1.2.1   | [`HeaderValueTyped::Raw`]                |
//! | `asText`             | §4.1.2.2   | [`HeaderValueTyped::Text`]               |
//! | `asAddresses`        | §4.1.2.3   | [`HeaderValueTyped::Addresses`]          |
//! | `asGroupedAddresses` | §4.1.2.4   | [`HeaderValueTyped::GroupedAddresses`]   |
//! | `asMessageIds`       | §4.1.2.5   | [`HeaderValueTyped::MessageIds`]         |
//! | `asDate`             | §4.1.2.6   | [`HeaderValueTyped::DateTime`]           |
//! | `asURLs`             | §4.1.2.7   | [`HeaderValueTyped::URLs`]               |
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
//! These types are independent of the [`crate::ParsedHeader`] surface,
//! which continues to expose only the decoded raw string. To layer a
//! typed view on top of an existing `ParsedHeader`, feed its `value`
//! bytes to [`parse_header_typed`]:
//!
//! ```ignore
//! let msg = mime_tree::parse(raw)?;
//! if let Some(h) = msg.headers.iter().find(|h| h.name.eq_ignore_ascii_case("From")) {
//!     let addrs = mime_tree::parse_addresses(h.value.as_bytes());
//! }
//! ```
//!
//! For convenience, [`parse_header_typed_from`] is a thin wrapper that
//! takes the `ParsedHeader` directly:
//!
//! ```ignore
//! let typed = mime_tree::parse_header_typed_from(h, mime_tree::HeaderForm::Addresses);
//! ```
//!
//! Either path yields the same result.

use std::borrow::Cow;
use std::fmt;

use mail_parser::{parsers::MessageStream, Address, HeaderValue};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::ParsedHeader;

/// A single RFC 5322 `mailbox` parsed from an `address-list`.
///
/// Mirrors the JMAP `EmailAddress` object defined in RFC 8621 §4.1.2.3.
///
/// `name` is the optional display name. `address` is the `addr-spec`. Both
/// are populated best-effort; either may be `None` if the original header
/// is malformed.
///
/// # Equality semantics
///
/// The derived `PartialEq`/`Eq`/`Hash` is byte-exact on both fields. In
/// particular, `address` comparison is case-sensitive across the entire
/// addr-spec, even though RFC 5321 §2.4 defines the *domain* part of an
/// addr-spec as case-insensitive — so `alice@example.com` and
/// `alice@EXAMPLE.COM` compare as not equal and hash differently. Callers
/// that need RFC-5321-conformant equality (HashSet dedup of recipient
/// lists, etc.) MUST canonicalise the domain part themselves before
/// comparing or hashing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EmailAddress {
    /// Display name from the `mailbox`, RFC 2047 encoded-words already
    /// decoded.
    ///
    /// Parser-produced values are RFC 8621 §4.1.2.3 normalised:
    /// surrounding ASCII whitespace is trimmed from the decoded
    /// display name. A name that is empty after trimming is mapped to
    /// `None` (a lone empty quoted-string never surfaces as
    /// `Some(String::new())`).
    pub name: Option<String>,
    /// `addr-spec` of the `mailbox`.
    pub address: Option<String>,
}

impl EmailAddress {
    /// Construct an `EmailAddress` from optional display name and
    /// addr-spec.
    ///
    /// `EmailAddress` is `#[non_exhaustive]` so external callers cannot
    /// use struct expression syntax. Use this constructor — or
    /// `Default::default()` followed by field assignment — instead.
    #[must_use]
    pub fn new(name: Option<String>, address: Option<String>) -> Self {
        Self { name, address }
    }

    /// Whether this `EmailAddress` carries an `addr-spec`.
    ///
    /// `parse_header_typed` produces `EmailAddress` values with
    /// `address == None` for malformed mailboxes (most commonly,
    /// display-name-only mailboxes from non-spec-conformant clients —
    /// e.g. a draft saved with just a typed-but-incomplete `To:`).
    /// Such entries are unusable for sending mail, address comparison,
    /// or addr-spec-keyed lookup.
    ///
    /// Use this helper to filter parsed address lists down to the
    /// usable subset:
    ///
    /// ```
    /// use mime_tree::EmailAddress;
    ///
    /// let parsed = vec![
    ///     EmailAddress::new(
    ///         Some("Alice".to_owned()),
    ///         Some("alice@example.com".to_owned()),
    ///     ),
    ///     EmailAddress::new(Some("Display-Name Only".to_owned()), None),
    /// ];
    /// let usable: Vec<EmailAddress> = parsed
    ///     .into_iter()
    ///     .filter(EmailAddress::is_addressable)
    ///     .collect();
    /// assert_eq!(usable.len(), 1);
    /// assert_eq!(usable[0].address.as_deref(), Some("alice@example.com"));
    /// ```
    #[must_use]
    pub fn is_addressable(&self) -> bool {
        self.address.is_some()
    }
}

impl fmt::Display for EmailAddress {
    /// Render in RFC 5322 §3.4 mailbox-ish form.
    ///
    /// * Both `name` and `address` present: `Display Name <addr@host>`.
    /// * `address` only: `addr@host` (bare addr-spec, no angle brackets).
    /// * `name` only: `Display Name` (degenerate; not a valid RFC 5322
    ///   mailbox, but the best a Display impl can do).
    /// * Neither present: the empty string.
    ///
    /// Names are emitted verbatim. This Display impl prioritises human
    /// readability over RFC 5322 round-trippability — names containing
    /// `<`, `>`, `,`, or other RFC 5322 specials are not quoted. Callers
    /// that need byte-stable round-trip into a header field MUST roll
    /// their own serializer with proper quoting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.name.as_deref(), self.address.as_deref()) {
            (Some(n), Some(a)) => write!(f, "{n} <{a}>"),
            (None, Some(a)) => f.write_str(a),
            (Some(n), None) => f.write_str(n),
            (None, None) => Ok(()),
        }
    }
}

/// A group of `EmailAddress` values, optionally named.
///
/// Mirrors the JMAP `EmailAddressGroup` object defined in RFC 8621 §4.1.2.4.
///
/// Per RFC 8621 §4.1.2.4, consecutive mailboxes that are not part of a
/// declared RFC 5322 `group` are still collected under an `AddressGroup`
/// whose `name` is `None`, "to provide a uniform type".
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AddressGroup {
    /// Display name of the group, or `None` for ungrouped mailboxes.
    ///
    /// Parser-produced values follow the same normalisation as
    /// [`EmailAddress::name`]: surrounding ASCII whitespace trimmed; an
    /// empty result is mapped to `None`, not `Some(String::new())`.
    pub name: Option<String>,
    /// Mailboxes belonging to this group.
    pub addresses: Vec<EmailAddress>,
}

impl AddressGroup {
    /// Construct an `AddressGroup` from an optional group name and a
    /// vector of mailboxes.
    ///
    /// `AddressGroup` is `#[non_exhaustive]` so external callers cannot
    /// use struct expression syntax. Use this constructor — or
    /// `Default::default()` followed by field assignment — instead.
    #[must_use]
    pub fn new(name: Option<String>, addresses: Vec<EmailAddress>) -> Self {
        Self { name, addresses }
    }
}

impl fmt::Display for AddressGroup {
    /// Render in RFC 5322 §3.4 group form: `name: mb1, mb2;`.
    ///
    /// * Named group: `Friends: alice@example.com, bob@example.com;`.
    /// * Anonymous group (`name == None`): just the comma-joined
    ///   mailbox list, no `:` and no terminating `;`.
    /// * Empty group: just `name:;` (or empty string for an anonymous
    ///   empty group).
    ///
    /// Same caveat as `EmailAddress` Display: prioritises human
    /// readability; not guaranteed RFC 5322 round-trippable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = &self.name {
            write!(f, "{n}:")?;
            if !self.addresses.is_empty() {
                f.write_str(" ")?;
            }
        }
        for (i, addr) in self.addresses.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{addr}")?;
        }
        if self.name.is_some() {
            f.write_str(";")?;
        }
        Ok(())
    }
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
///
/// # Equality semantics
///
/// The derived `PartialEq`/`Eq`/`Hash` is **field-wise**, not
/// **instant-wise**. Two `HeaderDateTime` values representing the same
/// moment in time at different offsets compare as not-equal and hash
/// differently. For example:
///
/// ```text
///   2024-01-01T12:00:00+00:00   (12:00 UTC)
///   2024-01-01T13:00:00+01:00   (12:00 UTC, expressed +01:00)
/// ```
///
/// are the same instant but compare `!=`. Callers needing
/// instant-equality (deduping timestamps across clients in different
/// time zones, time-series bucketing) MUST compare
/// [`Self::to_timestamp`] values rather than relying on the derived
/// `PartialEq`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    fn to_mail_parser(&self) -> mail_parser::DateTime {
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

    fn from_mail_parser(dt: mail_parser::DateTime) -> Self {
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

impl fmt::Display for HeaderDateTime {
    /// Render as an RFC 3339 / ISO 8601 §5.6 date-time string by
    /// delegating to [`HeaderDateTime::to_rfc3339`]. See that method
    /// for the exact output format and behaviour on out-of-range input.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Selector for the RFC 8621 parsed-form of a header value.
///
/// This is the form-token from a JMAP `header:<name>:as<form>` property
/// selector, normalised to an enum.
///
/// [`Display`](fmt::Display) emits the canonical JMAP form-token string
/// (`asRaw`, `asAddresses`, …, `asURLs`).
/// [`FromStr`](std::str::FromStr) accepts exactly that set of strings;
/// any other input yields [`UnknownHeaderForm`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// RFC 8621 §4.1.2.2 Text form. Unfold whitespace, strip the
    /// trailing CRLF and leading SP, decode all syntactically-correct
    /// RFC 2047 encoded-words, then Unicode-normalise the result to
    /// NFC.
    ///
    /// This is the form most commonly used by JMAP clients fetching
    /// human-readable header fields like Subject, Comments, Keywords,
    /// and List-Id.
    Text,
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

impl HeaderForm {
    /// Return the canonical RFC 8621 §4.1.2 form-token string for this
    /// variant.
    ///
    /// The token starts with `as` (the convention used in JMAP property
    /// selectors such as `header:Subject:asText`). Inverse of
    /// [`HeaderForm`]'s [`FromStr`](std::str::FromStr) impl.
    #[must_use]
    pub fn as_jmap_token(&self) -> &'static str {
        match self {
            HeaderForm::Raw => "asRaw",
            HeaderForm::Text => "asText",
            HeaderForm::Addresses => "asAddresses",
            HeaderForm::GroupedAddresses => "asGroupedAddresses",
            HeaderForm::MessageIds => "asMessageIds",
            HeaderForm::Date => "asDate",
            HeaderForm::URLs => "asURLs",
        }
    }
}

impl fmt::Display for HeaderForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_jmap_token())
    }
}

/// Error returned by [`HeaderForm`]'s [`FromStr`](std::str::FromStr) impl
/// when the input is not a recognised JMAP form-token.
///
/// The wrapped string is the input as given (case-sensitive); JMAP
/// form-tokens are case-sensitive per RFC 8621 §4.1.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownHeaderForm(pub String);

impl fmt::Display for UnknownHeaderForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown JMAP header form token: {:?}", self.0)
    }
}

impl std::error::Error for UnknownHeaderForm {}

impl std::str::FromStr for HeaderForm {
    type Err = UnknownHeaderForm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "asRaw" => Ok(HeaderForm::Raw),
            "asText" => Ok(HeaderForm::Text),
            "asAddresses" => Ok(HeaderForm::Addresses),
            "asGroupedAddresses" => Ok(HeaderForm::GroupedAddresses),
            "asMessageIds" => Ok(HeaderForm::MessageIds),
            "asDate" => Ok(HeaderForm::Date),
            "asURLs" => Ok(HeaderForm::URLs),
            _ => Err(UnknownHeaderForm(s.to_owned())),
        }
    }
}

/// A header field value rendered in one of the RFC 8621 parsed forms.
///
/// # Serde wire format
///
/// `HeaderValueTyped` and [`HeaderForm`] use serde's *default*
/// representation: externally-tagged for the enum, capitalised Rust
/// variant names. Examples:
///
/// ```json
/// {"Addresses": [{"name": "Alice", "address": "alice@example.com"}]}
/// {"DateTime": null}
/// {"Raw": "Subject line"}
/// "Addresses"               // serialized HeaderForm
/// ```
///
/// This is a **deliberate** choice for in-crate serialization (between
/// services, into databases). It is **not** the RFC 8621 wire format
/// used over JMAP HTTP/JSON. RFC 8621 §4.1.2 uses property-selector
/// strings such as `header:Subject:asAddresses` rather than serializing
/// the form name as an enum tag. Callers exposing parsed headers to a
/// JMAP client SHOULD map between this representation and the JMAP
/// wire format at the API boundary; relying on the in-crate serde
/// shape as the wire format will produce a non-conformant JMAP
/// response.
///
/// Pre-1.0, this representation is subject to change. From 1.0 onward
/// the in-crate serde format will be a stability surface and will be
/// changed only with a major version bump.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HeaderValueTyped {
    /// Result of [`HeaderForm::Raw`]: the trimmed UTF-8 string.
    Raw(String),
    /// Result of [`HeaderForm::Text`]: whitespace-unfolded, RFC 2047
    /// decoded, NFC-normalised UTF-8 string.
    Text(String),
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
/// `raw_value` is the bytes of the header field value — the portion to
/// the right of the `:` in the header line, including any folded
/// continuation lines.
///
/// # Trailing line ending
///
/// A trailing CRLF (or bare LF) is **permitted but not required**:
///
/// * Input ending in `\r\n` is used as-is.
/// * Input ending in `\n` is converted to `\r\n` internally.
/// * Input with no trailing line ending has `\r\n` appended internally.
///
/// All three shapes produce the same result. Callers may pass the field
/// body with or without the line ending — pick whichever is easiest to
/// extract from the source.
///
/// # Best-effort parsing
///
/// Malformed input yields the empty result for the requested form
/// (empty `Vec`, empty string, or `DateTime(None)`). The function never
/// panics and never returns an error.
///
/// # Empty-result ambiguity
///
/// The empty result is the **same value** regardless of cause:
///
/// | Form                | Empty value             | Triggered by                                       |
/// |---------------------|-------------------------|----------------------------------------------------|
/// | `Raw`               | `Raw("")`               | empty, all-whitespace, or all-malformed-UTF-8 input |
/// | `Addresses`         | `Addresses(vec![])`     | empty, malformed, or zero-mailbox input            |
/// | `GroupedAddresses`  | `GroupedAddresses(vec![])` | same as above                                   |
/// | `MessageIds`        | `MessageIds(vec![])`    | empty, no `<...>` brackets, all garbage            |
/// | `Date`              | `DateTime(None)`        | empty, malformed, or all-zero day/month            |
/// | `URLs`              | `URLs(vec![])`          | empty, no `<...>` brackets, all garbage            |
///
/// Callers cannot distinguish "header was present but empty" from
/// "header was present but malformed" from "input was non-UTF-8 noise"
/// using this API. Out-of-band signalling (e.g. recording a warning
/// alongside the parse result) is the caller's responsibility. Future
/// minor releases may add a parallel `parse_header_typed_strict`
/// returning `Result` or a tuple `(HeaderValueTyped, Warnings)` —
/// neither is exposed today.
///
/// # Examples
///
/// ## Addresses (RFC 8621 §4.1.2.3)
///
/// ```
/// use mime_tree::{parse_header_typed, EmailAddress, HeaderForm, HeaderValueTyped};
///
/// // RFC 8621 §4.1.2.3 example (the "James Smythe" address-list, simplified).
/// let raw = b" \"James Smythe\" <james@example.com>";
/// let parsed = parse_header_typed(HeaderForm::Addresses, raw);
/// assert_eq!(
///     parsed,
///     HeaderValueTyped::Addresses(vec![EmailAddress::new(
///         Some("James Smythe".to_owned()),
///         Some("james@example.com".to_owned()),
///     )]),
/// );
/// ```
///
/// ## GroupedAddresses (RFC 8621 §4.1.2.4)
///
/// ```
/// use mime_tree::{parse_header_typed, AddressGroup, EmailAddress, HeaderForm, HeaderValueTyped};
///
/// let raw = b"Friends: alice@example.com, bob@example.com;";
/// let parsed = parse_header_typed(HeaderForm::GroupedAddresses, raw);
/// assert_eq!(
///     parsed,
///     HeaderValueTyped::GroupedAddresses(vec![AddressGroup::new(
///         Some("Friends".to_owned()),
///         vec![
///             EmailAddress::new(None, Some("alice@example.com".to_owned())),
///             EmailAddress::new(None, Some("bob@example.com".to_owned())),
///         ],
///     )]),
/// );
/// ```
///
/// ## MessageIds (RFC 8621 §4.1.2.5)
///
/// ```
/// use mime_tree::{parse_header_typed, HeaderForm, HeaderValueTyped};
///
/// let raw = b"<abc@example.com> <def@example.com>";
/// let parsed = parse_header_typed(HeaderForm::MessageIds, raw);
/// assert_eq!(
///     parsed,
///     HeaderValueTyped::MessageIds(vec![
///         "abc@example.com".to_owned(),
///         "def@example.com".to_owned(),
///     ]),
/// );
/// ```
///
/// ## Date (RFC 5322 §3.3 / RFC 3339)
///
/// ```
/// use mime_tree::{parse_header_typed, HeaderForm, HeaderValueTyped};
///
/// let raw = b" Fri, 21 Nov 1997 09:55:06 -0600";
/// let parsed = parse_header_typed(HeaderForm::Date, raw);
/// if let HeaderValueTyped::DateTime(Some(dt)) = parsed {
///     assert_eq!(dt.to_rfc3339(), "1997-11-21T09:55:06-06:00");
/// } else {
///     panic!("expected DateTime");
/// }
/// ```
///
/// ## URLs (RFC 8621 §4.1.2.7 / RFC 2369)
///
/// ```
/// use mime_tree::{parse_header_typed, HeaderForm, HeaderValueTyped};
///
/// // RFC 2369 List-Help with comment after the URL.
/// let raw = b" <mailto:list@host.com?subject=help> (List Instructions)";
/// let parsed = parse_header_typed(HeaderForm::URLs, raw);
/// assert_eq!(
///     parsed,
///     HeaderValueTyped::URLs(vec!["mailto:list@host.com?subject=help".to_owned()]),
/// );
/// ```
///
/// ## Raw (RFC 8621 §4.1.2.1)
///
/// ```
/// use mime_tree::{parse_header_typed, HeaderForm, HeaderValueTyped};
///
/// // Surrounding whitespace stripped; no other transformation.
/// // Encoded-words survive verbatim.
/// let raw = b"  Subject line with =?UTF-8?Q?encoded?= words  ";
/// let parsed = parse_header_typed(HeaderForm::Raw, raw);
/// assert_eq!(
///     parsed,
///     HeaderValueTyped::Raw("Subject line with =?UTF-8?Q?encoded?= words".to_owned()),
/// );
/// ```
#[must_use]
pub fn parse_header_typed(form: HeaderForm, raw_value: &[u8]) -> HeaderValueTyped {
    match form {
        HeaderForm::Raw => {
            // RFC 8621 §4.1.2.1: the value is the header field value
            // with surrounding white space removed. Non-UTF-8 bytes are
            // replaced with U+FFFD via `from_utf8_lossy` so
            // malformed-but-non-empty input does not collapse into an
            // indistinguishable empty string. This matches mail-parser's
            // own handling of non-UTF-8 header bytes (`HeaderValue::Text`
            // is `Cow<str>` populated via `from_utf8_lossy`).
            let s = String::from_utf8_lossy(raw_value);
            HeaderValueTyped::Raw(s.trim().to_owned())
        }
        HeaderForm::Text => {
            // RFC 8621 §4.1.2.2: unfold whitespace, strip trailing CRLF
            // and leading SP, decode RFC 2047 encoded-words with known
            // charsets, NFC-normalise the result.
            //
            // mail-parser's `parse_unstructured` handles unfolding,
            // CRLF stripping, leading-SP removal, and RFC 2047 decoding
            // in one pass — that's steps 1-4 of RFC 8621 §4.1.2.2.
            // Step 5 (NFC) is applied here via the unicode-normalization
            // crate.
            let buf = crlf_terminated(raw_value);
            let hv = MessageStream::new(&buf).parse_unstructured();
            let decoded = match hv {
                HeaderValue::Text(s) => s.into_owned(),
                _ => String::new(),
            };
            HeaderValueTyped::Text(decoded.nfc().collect())
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
        HeaderForm::Addresses => {
            let buf = crlf_terminated(raw_value);
            let hv = MessageStream::new(&buf).parse_address();
            HeaderValueTyped::Addresses(flatten_addresses(&hv))
        }
        HeaderForm::GroupedAddresses => {
            let buf = crlf_terminated(raw_value);
            let hv = MessageStream::new(&buf).parse_address();
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
            let buf = crlf_terminated(raw_value);
            let hv = MessageStream::new(&buf).parse_id();
            let had_angle_brackets = raw_value.contains(&b'<');
            HeaderValueTyped::MessageIds(extract_msg_ids(&hv, had_angle_brackets))
        }
        HeaderForm::Date => {
            let buf = crlf_terminated(raw_value);
            let hv = MessageStream::new(&buf).parse_date();
            // mail-parser's `parse_date` returns `HeaderValue::Empty`
            // when it cannot recover 6 numeric components. Belt-and-
            // braces: also reject zero month/day, which RFC 5322 §3.3
            // does not permit and which mail-parser can emit when its
            // position counter advances past slots that never got
            // numeric digits. (A zero `year` is unreachable in
            // mail-parser-0.11: years are remapped 0..=49 → +2000,
            // 50..=99 → +1900, so `parts[2]` is never copied through
            // as 0.)
            let dt = match hv {
                HeaderValue::DateTime(dt) if dt.month != 0 && dt.day != 0 => {
                    Some(HeaderDateTime::from_mail_parser(dt))
                }
                _ => None,
            };
            HeaderValueTyped::DateTime(dt)
        }
    }
}

// ---------------------------------------------------------------------------
// Per-form entry points
// ---------------------------------------------------------------------------
//
// Convenience wrappers over `parse_header_typed` for callers that know
// the form statically. Each wrapper unwraps the `HeaderValueTyped`
// variant that `parse_header_typed` is contractually required to return
// for the matching `HeaderForm`, eliminating the boilerplate match at
// every call site. If `parse_header_typed` ever broke that contract, the
// wrapper returns the empty result for the form (defensive, not panic).

/// Parse the header field value as an RFC 8621 §4.1.2.1 Raw form: trim
/// surrounding whitespace, decode bytes as UTF-8 (lossy with U+FFFD on
/// invalid sequences).
///
/// Convenience wrapper over [`parse_header_typed`] with
/// [`HeaderForm::Raw`].
#[must_use]
pub fn parse_raw(raw_value: &[u8]) -> String {
    match parse_header_typed(HeaderForm::Raw, raw_value) {
        HeaderValueTyped::Raw(s) => s,
        _ => String::new(),
    }
}

/// Parse the header field value as an RFC 8621 §4.1.2.2 Text form:
/// whitespace unfolded, RFC 2047 encoded-words decoded, Unicode
/// normalised to NFC.
///
/// Convenience wrapper over [`parse_header_typed`] with
/// [`HeaderForm::Text`].
#[must_use]
pub fn parse_text(raw_value: &[u8]) -> String {
    match parse_header_typed(HeaderForm::Text, raw_value) {
        HeaderValueTyped::Text(s) => s,
        _ => String::new(),
    }
}

/// Parse the header field value as an RFC 8621 §4.1.2.3 Addresses form:
/// a flat list of mailboxes with group structure discarded.
///
/// Convenience wrapper over [`parse_header_typed`] with
/// [`HeaderForm::Addresses`].
#[must_use]
pub fn parse_addresses(raw_value: &[u8]) -> Vec<EmailAddress> {
    match parse_header_typed(HeaderForm::Addresses, raw_value) {
        HeaderValueTyped::Addresses(v) => v,
        _ => Vec::new(),
    }
}

/// Parse the header field value as an RFC 8621 §4.1.2.4 GroupedAddresses
/// form: preserves group structure; a flat mailbox-list is wrapped in a
/// single anonymous group.
///
/// Convenience wrapper over [`parse_header_typed`] with
/// [`HeaderForm::GroupedAddresses`].
#[must_use]
pub fn parse_grouped_addresses(raw_value: &[u8]) -> Vec<AddressGroup> {
    match parse_header_typed(HeaderForm::GroupedAddresses, raw_value) {
        HeaderValueTyped::GroupedAddresses(v) => v,
        _ => Vec::new(),
    }
}

/// Parse the header field value as an RFC 8621 §4.1.2.5 MessageIds form:
/// `<...>`-stripped msg-id strings.
///
/// Convenience wrapper over [`parse_header_typed`] with
/// [`HeaderForm::MessageIds`].
#[must_use]
pub fn parse_message_ids(raw_value: &[u8]) -> Vec<String> {
    match parse_header_typed(HeaderForm::MessageIds, raw_value) {
        HeaderValueTyped::MessageIds(v) => v,
        _ => Vec::new(),
    }
}

/// Parse the header field value as an RFC 8621 §4.1.2.6 Date form: an
/// RFC 5322 §3.3 date-time, or `None` on parse failure.
///
/// Convenience wrapper over [`parse_header_typed`] with
/// [`HeaderForm::Date`].
#[must_use]
pub fn parse_date(raw_value: &[u8]) -> Option<HeaderDateTime> {
    match parse_header_typed(HeaderForm::Date, raw_value) {
        HeaderValueTyped::DateTime(dt) => dt,
        _ => None,
    }
}

/// Parse the header field value as an RFC 8621 §4.1.2.7 URLs form: bare
/// URL strings with surrounding angle brackets stripped (RFC 2369).
///
/// Convenience wrapper over [`parse_header_typed`] with
/// [`HeaderForm::URLs`].
#[must_use]
pub fn parse_urls(raw_value: &[u8]) -> Vec<String> {
    match parse_header_typed(HeaderForm::URLs, raw_value) {
        HeaderValueTyped::URLs(v) => v,
        _ => Vec::new(),
    }
}

/// Parse an existing [`ParsedHeader`]'s value into the requested
/// RFC 8621 parsed form.
///
/// Composition helper: feeds `header.value.as_bytes()` to
/// [`parse_header_typed`]. Equivalent to writing that call by hand —
/// provided so callers do not have to remember to convert through
/// `as_bytes()` and so the typed-header API composes cleanly with the
/// `ParsedHeader` surface produced by [`crate::parse`].
#[must_use]
pub fn parse_header_typed_from(header: &ParsedHeader, form: HeaderForm) -> HeaderValueTyped {
    parse_header_typed(form, header.value.as_bytes())
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Trim ASCII whitespace from `s` and return `Some(trimmed)` if the
/// result is non-empty, otherwise `None`.
///
/// Centralises the RFC 8621 §4.1.2.3 / §4.1.2.4 normalisation rule for
/// display names ("trim surrounding white space; an empty result is
/// `None`").
fn trim_or_none(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Ensure `raw_value` ends with a CRLF, returning the original bytes
/// when it already does (no allocation), and a freshly allocated copy
/// terminated with `\r\n` otherwise.
///
/// mail-parser's `MessageStream` parsers expect header field bodies in
/// a real RFC 5322 stream — i.e. terminated by CRLF. Callers pass the
/// field value with no trailing CRLF; this helper normalises any of
/// {already-CRLF, LF-only, no-line-ending} to CRLF-terminated.
fn crlf_terminated(raw_value: &[u8]) -> Cow<'_, [u8]> {
    if raw_value.ends_with(b"\r\n") {
        Cow::Borrowed(raw_value)
    } else if raw_value.ends_with(b"\n") {
        // Strip the bare LF and replace with CRLF.
        let head = &raw_value[..raw_value.len() - 1];
        let mut v = Vec::with_capacity(head.len() + 2);
        v.extend_from_slice(head);
        v.extend_from_slice(b"\r\n");
        Cow::Owned(v)
    } else {
        let mut v = Vec::with_capacity(raw_value.len() + 2);
        v.extend_from_slice(raw_value);
        v.extend_from_slice(b"\r\n");
        Cow::Owned(v)
    }
}

fn convert_addr(addr: &mail_parser::Addr<'_>) -> EmailAddress {
    // RFC 8621 §4.1.2.3 mandates that for a quoted-string display name,
    // surrounding DQUOTE characters be removed, quoted-pairs decoded, and
    // white space unfolded with leading/trailing white space removed.
    // mail-parser already does the dequoting and quoted-pair decoding, but
    // leaves surrounding white space inside the quoted-string in place
    // (e.g. `"  James Smythe"` parses to `Some("  James Smythe")`). Strip
    // here. An empty trimmed result is mapped to `None` so a lone empty
    // quoted-string does not surface as a phantom display name.
    let name = addr.name.as_ref().and_then(|s| trim_or_none(s.as_ref()));
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
                name: g.name.as_ref().and_then(|s| trim_or_none(s.as_ref())),
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
