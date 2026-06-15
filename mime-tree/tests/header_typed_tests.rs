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
    parse_addresses, parse_date, parse_grouped_addresses, parse_header_typed,
    parse_header_typed_from, parse_message_ids, parse_raw, parse_text, parse_urls, AddressGroup,
    EmailAddress, HeaderForm, HeaderValueTyped, TzSign, UnknownHeaderForm,
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

// ---------------------------------------------------------------------------
// HeaderForm: Display / FromStr round-trip on JMAP form-token strings
// ---------------------------------------------------------------------------

/// Oracle: RFC 8621 §4.1.2 form-token strings: asRaw, asText,
/// asAddresses, asGroupedAddresses, asMessageIds, asDate, asURLs.
#[test]
fn header_form_display_emits_jmap_tokens() {
    assert_eq!(format!("{}", HeaderForm::Raw), "asRaw");
    assert_eq!(format!("{}", HeaderForm::Text), "asText");
    assert_eq!(format!("{}", HeaderForm::Addresses), "asAddresses");
    assert_eq!(
        format!("{}", HeaderForm::GroupedAddresses),
        "asGroupedAddresses"
    );
    assert_eq!(format!("{}", HeaderForm::MessageIds), "asMessageIds");
    assert_eq!(format!("{}", HeaderForm::Date), "asDate");
    assert_eq!(format!("{}", HeaderForm::URLs), "asURLs");
    assert_eq!(HeaderForm::Raw.as_jmap_token(), "asRaw");
}

#[test]
fn header_form_from_str_round_trip() {
    use std::str::FromStr;
    for f in [
        HeaderForm::Raw,
        HeaderForm::Text,
        HeaderForm::Addresses,
        HeaderForm::GroupedAddresses,
        HeaderForm::MessageIds,
        HeaderForm::Date,
        HeaderForm::URLs,
    ] {
        let tok = f.as_jmap_token();
        assert_eq!(
            HeaderForm::from_str(tok).unwrap(),
            f,
            "round-trip for {tok}"
        );
    }
}

#[test]
fn header_form_from_str_rejects_unknown_and_wrong_case() {
    use std::str::FromStr;
    // Unknown token.
    assert_eq!(
        HeaderForm::from_str("asMystery"),
        Err(UnknownHeaderForm("asMystery".to_owned())),
    );
    // The bare variant name without `as` prefix is NOT accepted; JMAP
    // form-tokens are case- and prefix-sensitive per RFC 8621 §4.1.2.
    assert!(HeaderForm::from_str("Raw").is_err());
    assert!(HeaderForm::from_str("addresses").is_err());
    assert!(HeaderForm::from_str("Text").is_err());
}

// ---------------------------------------------------------------------------
// Per-form entry points
// ---------------------------------------------------------------------------

/// Each per-form helper must produce the same value as the corresponding
/// `parse_header_typed` variant, without the boilerplate match.
#[test]
fn per_form_helpers_match_parse_header_typed() {
    let raw_addr = b" Alice <alice@example.com>";
    assert_eq!(
        parse_addresses(raw_addr),
        match parse_header_typed(HeaderForm::Addresses, raw_addr) {
            HeaderValueTyped::Addresses(v) => v,
            _ => unreachable!(),
        }
    );

    let raw_group = b"Friends: alice@example.com, bob@example.com;";
    assert_eq!(
        parse_grouped_addresses(raw_group),
        match parse_header_typed(HeaderForm::GroupedAddresses, raw_group) {
            HeaderValueTyped::GroupedAddresses(v) => v,
            _ => unreachable!(),
        }
    );

    let raw_ids = b"<abc@example.com> <def@example.com>";
    assert_eq!(
        parse_message_ids(raw_ids),
        vec!["abc@example.com", "def@example.com"]
    );

    let raw_date = b" Fri, 21 Nov 1997 09:55:06 -0600";
    let dt = parse_date(raw_date).expect("valid date");
    assert_eq!(dt.year, 1997);

    let raw_urls = b"<https://example.com/>";
    assert_eq!(
        parse_urls(raw_urls),
        vec!["https://example.com/".to_owned()]
    );

    let raw_raw = b"  Subject  ";
    assert_eq!(parse_raw(raw_raw), "Subject");
}

/// Malformed input falls through to empty results for each per-form
/// helper — same contract as `parse_header_typed`.
#[test]
fn per_form_helpers_empty_on_malformed() {
    assert!(parse_addresses(b"").is_empty());
    assert!(parse_grouped_addresses(b"").is_empty());
    assert!(parse_message_ids(b" not-a-message-id").is_empty());
    assert_eq!(parse_date(b" not a date"), None);
    assert!(parse_urls(b"https://example.com (no brackets)").is_empty());
    assert_eq!(parse_raw(b""), "");
    assert_eq!(parse_text(b""), "");
}

// ---------------------------------------------------------------------------
// asText form (RFC 8621 §4.1.2.2)
// ---------------------------------------------------------------------------

/// Oracle: RFC 2047 encoded-word `=?UTF-8?Q?Hello_W=C3=B6rld?=` decodes
/// to "Hello Wörld" (W + LATIN SMALL LETTER O WITH DIAERESIS + rld).
/// Python: `email.header.decode_header(...)` produces the same.
#[test]
fn text_form_decodes_rfc2047_encoded_word() {
    let raw = b" =?UTF-8?Q?Hello_W=C3=B6rld?=";

    let parsed = parse_header_typed(HeaderForm::Text, raw);

    assert_eq!(parsed, HeaderValueTyped::Text("Hello Wörld".to_owned()));
}

/// A plain unstructured header value with no encoded-words passes
/// through (whitespace folded, leading SP stripped, no other change).
#[test]
fn text_form_plain_unencoded_passes_through() {
    let raw = b" Subject of the message";

    let parsed = parse_header_typed(HeaderForm::Text, raw);

    assert_eq!(
        parsed,
        HeaderValueTyped::Text("Subject of the message".to_owned()),
    );
}

/// Oracle: Unicode NFC normalisation. The decomposed sequence
/// `e` (U+0065) + `combining acute` (U+0301) NFC-normalises to the
/// precomposed `é` (U+00E9). Run a single LATIN SMALL LETTER E with
/// COMBINING ACUTE through asText and expect the precomposed form.
#[test]
fn text_form_nfc_normalises_decomposed_combining_marks() {
    // ASCII "caf" + e + combining acute. This is the NFD form.
    let raw: &[u8] = b" caf\x65\xCC\x81";

    let parsed = parse_header_typed(HeaderForm::Text, raw);

    // The precomposed result should be the single code point
    // U+00E9 (é), which in UTF-8 is 0xC3 0xA9.
    assert_eq!(parsed, HeaderValueTyped::Text("café".to_owned()));

    // Double-check: the NFC form must contain the single code point
    // (0xC3 0xA9 bytes), not the two code points (0x65 0xCC 0x81).
    if let HeaderValueTyped::Text(s) = parsed {
        assert!(s.as_bytes().contains(&0xC3));
        assert!(s.as_bytes().contains(&0xA9));
        // Must NOT contain the combining acute byte sequence.
        assert!(!s.as_bytes().windows(2).any(|w| w == [0xCC, 0x81]));
    } else {
        panic!("expected Text variant");
    }
}

/// `parse_text` helper matches the Text variant of `parse_header_typed`.
#[test]
fn parse_text_helper_matches_parse_header_typed() {
    let raw = b" Subject =?UTF-8?Q?with?= encoded";
    let helper = parse_text(raw);
    let full = match parse_header_typed(HeaderForm::Text, raw) {
        HeaderValueTyped::Text(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(helper, full);
}

// ---------------------------------------------------------------------------
// is_addressable filter (MIME-o2c.14)
// ---------------------------------------------------------------------------

#[test]
fn is_addressable_filters_display_name_only_entries() {
    let list = vec![
        EmailAddress::new(
            Some("Alice".to_owned()),
            Some("alice@example.com".to_owned()),
        ),
        EmailAddress::new(Some("Just A Name".to_owned()), None),
        EmailAddress::new(None, None),
        EmailAddress::new(None, Some("bare@example.com".to_owned())),
    ];

    let addressable: Vec<EmailAddress> = list
        .into_iter()
        .filter(EmailAddress::is_addressable)
        .collect();

    assert_eq!(addressable.len(), 2);
    assert_eq!(addressable[0].address.as_deref(), Some("alice@example.com"));
    assert_eq!(addressable[1].address.as_deref(), Some("bare@example.com"));
}

// ---------------------------------------------------------------------------
// parse_header_typed_from: ParsedHeader composition (MIME-o2c.29)
// ---------------------------------------------------------------------------

#[test]
fn parse_header_typed_from_parsed_header() {
    let raw = b"From: Alice <alice@example.com>\r\n\
                Subject: Hello\r\n\
                \r\n\
                Body\r\n";
    let msg = mime_tree::parse(raw).expect("parse");

    let from = msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("From"))
        .expect("From header");

    let typed = parse_header_typed_from(from, HeaderForm::Addresses);

    assert_eq!(
        typed,
        HeaderValueTyped::Addresses(vec![EmailAddress::new(
            Some("Alice".to_owned()),
            Some("alice@example.com".to_owned()),
        )]),
    );
}

/// Oracle: a From: header containing an ISO-8859-1 display name that is
/// NOT valid UTF-8. The byte 0xE9 is "é" in ISO-8859-1 but is invalid as
/// standalone UTF-8.
///
/// Before the fix for MIME-8zt.45, `parse_header_typed_from` fed
/// `header.value.as_bytes()` to the parser, but `value` was built via
/// `String::from_utf8_lossy`, replacing 0xE9 with U+FFFD (3 bytes each).
/// The address parser then saw different bytes (expanded by the 3-byte
/// replacements) which could shift parse boundaries and cause divergence
/// from the direct `parse_header_typed` path. After the fix, `raw_value`
/// is used instead, so both paths feed identical bytes to the parser.
///
/// Note: mail-parser itself returns `Cow<str>` for display names, so
/// non-UTF-8 bytes still become U+FFFD in the final output. The fix
/// ensures the conversion happens once (in mail-parser) not twice
/// (first in extract_headers, then mail-parser sees the 3-byte
/// replacements).
#[test]
fn parse_header_typed_from_non_utf8_display_name_paths_agree() {
    // "Frédéric" in ISO-8859-1: Fr + 0xE9 + d + 0xE9 + ric
    let raw: &[u8] = b"From: Fr\xe9d\xe9ric <fred@example.com>\r\n\r\nBody\r\n";
    let msg = mime_tree::parse(raw).expect("parse");

    let from = msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("From"))
        .expect("From header");

    // The `value` field has lossy UTF-8 — the 0xE9 bytes are U+FFFD.
    assert!(
        from.value.contains('\u{FFFD}'),
        "value should contain replacement chars for non-UTF-8 bytes"
    );

    // The `raw_value` field preserves the original bytes faithfully.
    assert!(
        from.raw_value.contains(&0xE9),
        "raw_value should preserve the original 0xE9 bytes"
    );

    // Direct path: parse the raw header bytes.
    let direct = parse_header_typed(HeaderForm::Addresses, &from.raw_value);

    // Convenience path: parse via ParsedHeader (now uses raw_value).
    let via_from = parse_header_typed_from(from, HeaderForm::Addresses);

    // Both paths must produce identical results — this was the bug.
    assert_eq!(
        direct, via_from,
        "direct and parse_header_typed_from must agree"
    );

    // The addr-spec (pure ASCII) must be recovered regardless.
    let addrs = match &via_from {
        HeaderValueTyped::Addresses(v) => v,
        other => panic!("expected Addresses, got {other:?}"),
    };
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].address.as_deref(), Some("fred@example.com"));
    // Display name is present (may contain U+FFFD from mail-parser's
    // own lossy conversion of the non-UTF-8 bytes).
    assert!(addrs[0].name.is_some(), "display name should be present");
}

/// Regression: non-UTF-8 byte immediately before an angle bracket.
///
/// With the old double-lossy path, 0xE9 (1 byte) was replaced by
/// U+FFFD (3 UTF-8 bytes: EF BF BD) before being fed to the address
/// parser. The 2 extra bytes shifted the `<` position, which could
/// cause mail-parser to misparse on boundary-sensitive inputs.
/// With the fix, the original 1-byte sequence is fed directly.
#[test]
fn parse_header_typed_from_non_utf8_near_angle_bracket() {
    // 0xE9 byte right before the angle bracket
    let raw: &[u8] = b"From: caf\xe9<fred@example.com>\r\n\r\nBody\r\n";
    let msg = mime_tree::parse(raw).expect("parse");

    let from = msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("From"))
        .expect("From header");

    let direct = parse_header_typed(HeaderForm::Addresses, &from.raw_value);
    let via_from = parse_header_typed_from(from, HeaderForm::Addresses);

    assert_eq!(
        direct, via_from,
        "paths must agree even with non-UTF-8 byte adjacent to angle bracket"
    );

    let addrs = match &via_from {
        HeaderValueTyped::Addresses(v) => v,
        other => panic!("expected Addresses, got {other:?}"),
    };
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].address.as_deref(), Some("fred@example.com"));
}
