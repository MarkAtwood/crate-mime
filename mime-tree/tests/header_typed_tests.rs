//! Integration tests for the typed header API (`parse_header_typed`).
//!
//! All expected values are derived from external oracles:
//!   - RFC 8621 §4.1.2.3 worked example (Addresses)
//!   - RFC 8621 §4.1.2.4 worked example (GroupedAddresses)
//!   - RFC 8621 §4.1.2.5 (MessageIds — strip CFWS and angle brackets)
//!   - RFC 5322 Appendix A.1.1 sample dated message (Date)
//!   - RFC 8621 §4.1.2.7 / RFC 2369 (URLs in List-* headers)
//!
//! No expected value is derived from running mime-tree itself.

use mime_tree::{
    parse_header_typed, AddressGroup, EmailAddress, HeaderForm, HeaderValueTyped, TzSign,
};

// ---------------------------------------------------------------------------
// Addresses — RFC 8621 §4.1.2.3 worked example
// ---------------------------------------------------------------------------

/// Oracle: RFC 8621 §4.1.2.3 (page 28). The worked example states that
/// the address-list:
///
/// ```text
///     "  James Smythe" <james@example.com>, Friends:
///       jane@example.com, =?UTF-8?Q?John_Sm=C3=AEth?= <john@example.com>;
/// ```
///
/// when parsed in the `Addresses` form, yields three entries — group
/// information is discarded. RFC 2047 encoded-words are decoded.
#[test]
fn addresses_rfc8621_section_4_1_2_3_example() {
    // Note: per RFC 8621 §4.1.2.3, the name "James Smythe" has its leading
    // whitespace trimmed before being placed in the `name` field.
    let raw = concat!(
        "  \"  James Smythe\" <james@example.com>, Friends:\r\n",
        "    jane@example.com, =?UTF-8?Q?John_Sm=C3=AEth?= <john@example.com>;",
    )
    .as_bytes();

    let parsed = parse_header_typed(HeaderForm::Addresses, raw);

    let expected = HeaderValueTyped::Addresses(vec![
        EmailAddress::new(
            Some("James Smythe".to_owned()),
            Some("james@example.com".to_owned()),
        ),
        EmailAddress::new(None, Some("jane@example.com".to_owned())),
        // RFC 2047 encoded-word "=?UTF-8?Q?John_Sm=C3=AEth?=" decodes
        // to "John Smîth" (U+00EE LATIN SMALL LETTER I WITH CIRCUMFLEX).
        EmailAddress::new(
            Some("John Smîth".to_owned()),
            Some("john@example.com".to_owned()),
        ),
    ]);

    assert_eq!(parsed, expected);
}

// ---------------------------------------------------------------------------
// GroupedAddresses — RFC 8621 §4.1.2.4 worked example
// ---------------------------------------------------------------------------

/// Oracle: RFC 8621 §4.1.2.4 (page 29). The same address-list, in
/// `GroupedAddresses` form, yields two groups: the first un-named
/// (`name: None`) containing James, and a second named "Friends"
/// containing Jane and John.
#[test]
fn grouped_addresses_rfc8621_section_4_1_2_4_example() {
    let raw = concat!(
        "  \"  James Smythe\" <james@example.com>, Friends:\r\n",
        "    jane@example.com, =?UTF-8?Q?John_Sm=C3=AEth?= <john@example.com>;",
    )
    .as_bytes();

    let parsed = parse_header_typed(HeaderForm::GroupedAddresses, raw);

    let expected = HeaderValueTyped::GroupedAddresses(vec![
        AddressGroup::new(
            None,
            vec![EmailAddress::new(
                Some("James Smythe".to_owned()),
                Some("james@example.com".to_owned()),
            )],
        ),
        AddressGroup::new(
            Some("Friends".to_owned()),
            vec![
                EmailAddress::new(None, Some("jane@example.com".to_owned())),
                EmailAddress::new(
                    Some("John Smîth".to_owned()),
                    Some("john@example.com".to_owned()),
                ),
            ],
        ),
    ]);

    assert_eq!(parsed, expected);
}

/// A flat mailbox list (no group syntax) is still surfaced as a single
/// `AddressGroup` with `name = None`, per RFC 8621 §4.1.2.4:
/// "Consecutive 'mailbox' values that are not part of a group are still
/// collected under an EmailAddressGroup object to provide a uniform type."
#[test]
fn grouped_addresses_flat_list_wraps_in_anonymous_group() {
    let raw = b"alice@example.com, bob@example.com";

    let parsed = parse_header_typed(HeaderForm::GroupedAddresses, raw);

    let expected = HeaderValueTyped::GroupedAddresses(vec![AddressGroup::new(
        None,
        vec![
            EmailAddress::new(None, Some("alice@example.com".to_owned())),
            EmailAddress::new(None, Some("bob@example.com".to_owned())),
        ],
    )]);

    assert_eq!(parsed, expected);
}

// ---------------------------------------------------------------------------
// MessageIds — RFC 8621 §4.1.2.5
// ---------------------------------------------------------------------------

/// Oracle: RFC 8621 §4.1.2.5. Surrounding angle brackets and CFWS are
/// removed. The example uses an In-Reply-To-style header with two
/// msg-id values.
#[test]
fn message_ids_strip_angle_brackets_and_cfws() {
    let raw = b" <abc@example.com> <def@example.com>";

    let parsed = parse_header_typed(HeaderForm::MessageIds, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::MessageIds(vec![
            "abc@example.com".to_owned(),
            "def@example.com".to_owned(),
        ]),
    );
}

/// A single message-id with no whitespace is parsed correctly.
#[test]
fn message_ids_single_id() {
    let raw = b"<single@example.com>";

    let parsed = parse_header_typed(HeaderForm::MessageIds, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::MessageIds(vec!["single@example.com".to_owned()]),
    );
}

/// Oracle: RFC 8621 §4.1.2.5 explicitly requires malformed input to
/// yield an empty result. mail-parser's `parse_id` has a broken-client
/// recovery branch that produces `HeaderValue::Text(<unparsed bytes>)`
/// when no `<...>` tokens were found in the input; without a
/// discriminator, that branch's output would leak as a one-element
/// vec containing the raw garbage. Inputs with no angle brackets must
/// yield an empty vec.
#[test]
fn message_ids_malformed_no_angle_brackets_returns_empty() {
    // Plain garbage with no angle brackets at all.
    assert_eq!(
        parse_header_typed(HeaderForm::MessageIds, b" not-an-id"),
        HeaderValueTyped::MessageIds(vec![]),
    );

    // An `@`-containing string is still invalid without angle brackets;
    // a valid msg-id per RFC 5322 §3.6.4 requires `< ... >` framing.
    assert_eq!(
        parse_header_typed(HeaderForm::MessageIds, b" looks@like-an-id-but-no-brackets"),
        HeaderValueTyped::MessageIds(vec![]),
    );
}

// ---------------------------------------------------------------------------
// Date — RFC 5322 §3.3 / Appendix A.1.1 sample message
// ---------------------------------------------------------------------------

/// Oracle: RFC 5322 Appendix A.1.1 sample message header
/// `Date: Fri, 21 Nov 1997 09:55:06 -0600`.
///
/// Decoded by hand from the wire format: day=21, month=11 (Nov),
/// year=1997, hour=09, minute=55, second=06, tz offset = -06:00.
#[test]
fn date_rfc5322_appendix_a_1_1_example() {
    let raw = b" Fri, 21 Nov 1997 09:55:06 -0600";

    let parsed = parse_header_typed(HeaderForm::Date, raw);

    let dt = match parsed {
        HeaderValueTyped::DateTime(Some(dt)) => dt,
        other => panic!("expected DateTime, got {other:?}"),
    };

    assert_eq!(dt.year, 1997);
    assert_eq!(dt.month, 11);
    assert_eq!(dt.day, 21);
    assert_eq!(dt.hour, 9);
    assert_eq!(dt.minute, 55);
    assert_eq!(dt.second, 6);
    assert_eq!(dt.tz_sign, TzSign::West, "1997-11-21 -0600 is west of GMT");
    assert_eq!(dt.tz_hour, 6);
    assert_eq!(dt.tz_minute, 0);

    // Independent oracle for RFC 3339 form: 1997-11-21T09:55:06-06:00
    // (Python: datetime(1997,11,21,9,55,6,tzinfo=timezone(timedelta(hours=-6))).isoformat()
    // → '1997-11-21T09:55:06-06:00')
    assert_eq!(dt.to_rfc3339(), "1997-11-21T09:55:06-06:00");
}

/// Oracle: mail-parser-0.11's `DateTime::to_rfc3339` uses Zulu form `Z`
/// for a zero offset (`tz_hour == 0 && tz_minute == 0`), not `+00:00`.
/// Pin that behaviour in mime-tree's documented contract.
#[test]
fn date_utc_offset_emits_zulu_form() {
    let raw = b" Mon, 15 Jan 2024 12:34:56 +0000";

    let parsed = parse_header_typed(HeaderForm::Date, raw);

    let dt = match parsed {
        HeaderValueTyped::DateTime(Some(dt)) => dt,
        other => panic!("expected DateTime, got {other:?}"),
    };

    // Independent oracle: ISO 8601 / RFC 3339 §5.6 — UTC is conventionally
    // written as `Z`. Python: `datetime(...,tzinfo=timezone.utc).isoformat()`
    // emits `+00:00`, but mail-parser canonicalises UTC to `Z`. We pin
    // mail-parser's choice as the documented mime-tree contract.
    assert_eq!(dt.to_rfc3339(), "2024-01-15T12:34:56Z");
    assert_eq!(dt.tz_hour, 0);
    assert_eq!(dt.tz_minute, 0);
}

/// Garbage in the Date field must produce `DateTime(None)`. Per crate
/// invariant #4 (best-effort parsing), this must not error.
#[test]
fn date_garbage_returns_none() {
    let raw = b" not a date at all";

    let parsed = parse_header_typed(HeaderForm::Date, raw);

    assert_eq!(parsed, HeaderValueTyped::DateTime(None));
}

// ---------------------------------------------------------------------------
// URLs — RFC 8621 §4.1.2.7
// ---------------------------------------------------------------------------

/// Oracle: RFC 2369 §3.4 List-Help example
/// `List-Help: <mailto:list@host.com?subject=help> (List Instructions)`
///
/// Per RFC 8621 §4.1.2.7, surrounding angle brackets and comments are
/// removed; the result is the bare URL string.
#[test]
fn urls_rfc2369_list_help_example() {
    let raw = b" <mailto:list@host.com?subject=help> (List Instructions)";

    let parsed = parse_header_typed(HeaderForm::URLs, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::URLs(vec!["mailto:list@host.com?subject=help".to_owned()]),
    );
}

/// Multiple URLs in one header (e.g. List-Unsubscribe with both mailto:
/// and https: URLs, per RFC 2369 §3.2).
#[test]
fn urls_list_unsubscribe_multiple() {
    let raw = b" <https://example.com/u/abc>, <mailto:unsubscribe@example.com>";

    let parsed = parse_header_typed(HeaderForm::URLs, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::URLs(vec![
            "https://example.com/u/abc".to_owned(),
            "mailto:unsubscribe@example.com".to_owned(),
        ]),
    );
}

/// Oracle: RFC 8621 §4.1.2.7: "Any value outside of the angle bracket
/// arguments MUST be ignored." A bare URL with no `<...>` framing is
/// outside any bracket and MUST produce an empty result, not be
/// surfaced as a URL.
#[test]
fn urls_bare_no_brackets_returns_empty() {
    assert_eq!(
        parse_header_typed(HeaderForm::URLs, b"https://example.com/u/abc"),
        HeaderValueTyped::URLs(vec![]),
    );

    // Multiple bare URLs separated by comma — still no brackets.
    assert_eq!(
        parse_header_typed(HeaderForm::URLs, b"https://example.com/, http://other.com/",),
        HeaderValueTyped::URLs(vec![]),
    );
}

/// A URL containing commas must survive intact when bracketed.
/// mail-parser's address parser would split on the commas; the
/// dedicated bracket tokenizer doesn't.
#[test]
fn urls_with_commas_inside_brackets_preserved() {
    let raw = b"<https://example.com/path,with,commas>";

    let parsed = parse_header_typed(HeaderForm::URLs, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::URLs(vec!["https://example.com/path,with,commas".to_owned()]),
    );
}

/// tel: URLs (RFC 3966) are valid per RFC 2369 §2's `unknown-URL`
/// production. Bracketed extraction must surface them without parsing.
#[test]
fn urls_tel_scheme_inside_brackets() {
    let raw = b"<tel:+1-555-1234>";

    let parsed = parse_header_typed(HeaderForm::URLs, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::URLs(vec!["tel:+1-555-1234".to_owned()]),
    );
}

/// CRLF folding inside a URL is stripped: per RFC 3986 URIs cannot
/// contain literal whitespace, so any whitespace seen is folding.
#[test]
fn urls_internal_crlf_folding_stripped() {
    let raw = b"<https://example.com/\r\n very/long/path>";

    let parsed = parse_header_typed(HeaderForm::URLs, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::URLs(vec!["https://example.com/very/long/path".to_owned()]),
    );
}

/// An unclosed `<` produces no URL.
#[test]
fn urls_unclosed_bracket_ignored() {
    let raw = b"<https://example.com/";

    let parsed = parse_header_typed(HeaderForm::URLs, raw);

    assert_eq!(parsed, HeaderValueTyped::URLs(vec![]));
}

// ---------------------------------------------------------------------------
// Raw — RFC 8621 §4.1.2.1
// ---------------------------------------------------------------------------

/// Oracle: RFC 8621 §4.1.2.1 — the Raw form is the header field value
/// with surrounding whitespace removed; no other transformation.
#[test]
fn raw_form_trims_whitespace_only() {
    let raw = b"  Subject line with =?UTF-8?Q?encoded?= words  ";

    let parsed = parse_header_typed(HeaderForm::Raw, raw);

    // No RFC 2047 decoding in Raw form — the encoded-word survives verbatim.
    assert_eq!(
        parsed,
        HeaderValueTyped::Raw("Subject line with =?UTF-8?Q?encoded?= words".to_owned()),
    );
}

/// Oracle: U+FFFD substitution per `String::from_utf8_lossy` (Rust std
/// docs). A header field body containing non-UTF-8 bytes (legal in raw
/// RFC 5322 but not in JMAP wire format) must surface with replacement
/// characters rather than collapsing into an empty string — that
/// collapse would be indistinguishable from a missing header.
///
/// Test input: `Subject: ` followed by the Latin-1 byte 0xE9 (é in
/// ISO-8859-1, invalid as standalone UTF-8) embedded between ASCII text.
#[test]
fn raw_form_non_utf8_bytes_become_replacement_chars() {
    let raw: &[u8] = b" caf\xE9 latte ";

    let parsed = parse_header_typed(HeaderForm::Raw, raw);

    // `String::from_utf8_lossy(b"caf\xE9 latte")` → "caf\u{FFFD} latte"
    assert_eq!(
        parsed,
        HeaderValueTyped::Raw("caf\u{FFFD} latte".to_owned()),
    );
}

// ---------------------------------------------------------------------------
// Empty / malformed input — best-effort, never panic
// ---------------------------------------------------------------------------

/// Per crate invariant #4 (best-effort parsing), empty input yields an
/// empty result of the requested form, not an error.
#[test]
fn empty_input_returns_empty_results() {
    assert_eq!(
        parse_header_typed(HeaderForm::Addresses, b""),
        HeaderValueTyped::Addresses(vec![]),
    );
    assert_eq!(
        parse_header_typed(HeaderForm::GroupedAddresses, b""),
        HeaderValueTyped::GroupedAddresses(vec![]),
    );
    assert_eq!(
        parse_header_typed(HeaderForm::MessageIds, b""),
        HeaderValueTyped::MessageIds(vec![]),
    );
    assert_eq!(
        parse_header_typed(HeaderForm::Date, b""),
        HeaderValueTyped::DateTime(None),
    );
    assert_eq!(
        parse_header_typed(HeaderForm::URLs, b""),
        HeaderValueTyped::URLs(vec![]),
    );
    assert_eq!(
        parse_header_typed(HeaderForm::Raw, b""),
        HeaderValueTyped::Raw(String::new()),
    );
}

// ---------------------------------------------------------------------------
// Public types implement Serialize + Deserialize
// ---------------------------------------------------------------------------

/// Crate invariant: all public types are Serialize + Deserialize.
/// This test compiles only if the trait bounds hold.
#[test]
fn public_types_round_trip_through_serde_json() {
    // Use serde_json via the existing dev path. mime-tree itself does not
    // depend on serde_json, so we hand-roll a no-op assert that exercises
    // the trait bounds at compile time.
    fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
    assert_serde::<EmailAddress>();
    assert_serde::<AddressGroup>();
    assert_serde::<HeaderForm>();
    assert_serde::<HeaderValueTyped>();
    assert_serde::<mime_tree::HeaderDateTime>();
}

/// Crate invariant: all public payload types are `Hash`. This test
/// compiles only if the trait bounds hold, and exercises actual
/// `HashSet` insertion to catch any silent issue.
#[test]
fn public_types_are_hash() {
    use std::collections::HashSet;

    fn assert_hash<T: std::hash::Hash + Eq>() {}
    assert_hash::<EmailAddress>();
    assert_hash::<AddressGroup>();
    assert_hash::<mime_tree::HeaderDateTime>();
    assert_hash::<HeaderForm>();
    assert_hash::<HeaderValueTyped>();

    // Round-trip insertion smoke check.
    let mut s: HashSet<EmailAddress> = HashSet::new();
    s.insert(EmailAddress::new(
        Some("Alice".to_owned()),
        Some("alice@example.com".to_owned()),
    ));
    s.insert(EmailAddress::new(
        Some("Alice".to_owned()),
        Some("alice@example.com".to_owned()),
    ));
    assert_eq!(s.len(), 1, "duplicate EmailAddress should dedupe via Hash");

    let mut h: HashSet<HeaderValueTyped> = HashSet::new();
    h.insert(HeaderValueTyped::Raw("foo".to_owned()));
    h.insert(HeaderValueTyped::Raw("foo".to_owned()));
    assert_eq!(h.len(), 1);
}

// ---------------------------------------------------------------------------
// Display impls (RFC 5322 §3.4 mailbox / group form, RFC 3339 date)
// ---------------------------------------------------------------------------

/// Display for EmailAddress: standard `Name <addr@host>` form for the
/// both-present case.
#[test]
fn display_email_address_name_and_address() {
    let e = EmailAddress::new(
        Some("Alice Cooper".to_owned()),
        Some("alice@example.com".to_owned()),
    );
    assert_eq!(format!("{e}"), "Alice Cooper <alice@example.com>");
}

#[test]
fn display_email_address_address_only() {
    let e = EmailAddress::new(None, Some("bob@example.com".to_owned()));
    assert_eq!(format!("{e}"), "bob@example.com");
}

#[test]
fn display_email_address_name_only() {
    let e = EmailAddress::new(Some("Display Only".to_owned()), None);
    assert_eq!(format!("{e}"), "Display Only");
}

#[test]
fn display_email_address_empty() {
    let e = EmailAddress::default();
    assert_eq!(format!("{e}"), "");
}

/// Display for AddressGroup: RFC 5322 §3.4 group form
/// `name: mb1, mb2;` when named.
#[test]
fn display_address_group_named() {
    let g = AddressGroup::new(
        Some("Friends".to_owned()),
        vec![
            EmailAddress::new(None, Some("alice@example.com".to_owned())),
            EmailAddress::new(Some("Bob".to_owned()), Some("bob@example.com".to_owned())),
        ],
    );
    assert_eq!(
        format!("{g}"),
        "Friends: alice@example.com, Bob <bob@example.com>;"
    );
}

/// Anonymous group renders as just the comma-joined mailbox list, no
/// `:` and no terminating `;`.
#[test]
fn display_address_group_anonymous() {
    let g = AddressGroup::new(
        None,
        vec![
            EmailAddress::new(None, Some("a@example.com".to_owned())),
            EmailAddress::new(None, Some("b@example.com".to_owned())),
        ],
    );
    assert_eq!(format!("{g}"), "a@example.com, b@example.com");
}

#[test]
fn display_address_group_empty_named() {
    let g = AddressGroup::new(Some("Empty".to_owned()), vec![]);
    assert_eq!(format!("{g}"), "Empty:;");
}

/// Display for HeaderDateTime delegates to to_rfc3339.
#[test]
fn display_header_date_time_delegates_to_rfc3339() {
    let raw = b" Fri, 21 Nov 1997 09:55:06 -0600";
    let parsed = parse_header_typed(HeaderForm::Date, raw);
    let dt = match parsed {
        HeaderValueTyped::DateTime(Some(dt)) => dt,
        _ => unreachable!(),
    };
    assert_eq!(format!("{dt}"), dt.to_rfc3339());
    assert_eq!(format!("{dt}"), "1997-11-21T09:55:06-06:00");
}
