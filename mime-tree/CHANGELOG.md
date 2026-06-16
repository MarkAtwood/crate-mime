# Changelog

All notable changes to `mime-tree` will be documented here.

## [0.5.0] - 2026-06-16

### Breaking Changes

- **`InlineUUBlock::begin_length` changed from `u32` to `Option<u32>`.**
  `None` indicates the block had an encoding problem and the length could not
  be determined. Update reads of `.begin_length` to handle the `Option`.

### Changed

- Extracted `qp_with_limit()` helper in `decode.rs`, encapsulating the
  three-level QP decode-limited interaction (input pre-truncation,
  false-truncation check, full-body fallback) into a single function.
- Replaced `&mut Option<&mut Vec<String>>` with `AppendTarget` newtype in
  `walk.rs` for clearer RFC 8621 §4.1.4 null-rebind semantics.
- Added explanatory comment in `header_typed.rs` for the unavoidable
  bytes → String → bytes round-trip required by mail-parser's typed API.
- README: added missing `ParsedPart.is_encoding_problem` field, missing
  `HeaderForm::Text` variant, and fixed self-contradictory `TransferEncoding`
  table.

## [0.4.0] - 2026-06-04

### Breaking Changes

- **`HeaderDateTime::tz_before_gmt: bool` replaced by `tz_sign: TzSign`.**
  `TzSign` is a `#[non_exhaustive]` enum with variants `East` (`+HHMM`) and
  `West` (`-HHMM`). Update reads of `.tz_before_gmt` to `.tz_sign == TzSign::West`.
  The serde wire format changes (boolean → enum tag), so any externally stored
  serialized `HeaderDateTime` values must be re-serialized.

- **`HeaderDateTime` and `HeaderForm` no longer implement `Copy`.**
  Use `.clone()` or move semantics where implicit copies were relied on.

- **`EmailAddress` and `AddressGroup` are now `#[non_exhaustive]`.**
  Struct-expression construction is no longer valid outside this crate. Use
  `EmailAddress::new(name, address)` and `AddressGroup::new(name, addresses)`.

### Added

- `TzSign` enum (`East` / `West`), exported from the crate root.
- `HeaderForm::Text` variant — RFC 8621 §4.1.2.2 `asText` form. Unfolds whitespace,
  decodes RFC 2047 encoded-words, and NFC-normalises the result.
- `parse_text(raw_value)` per-form convenience function.
- `parse_header_typed_from(header, form)` — composes directly with `ParsedHeader`.
- `EmailAddress::is_addressable()` — returns `true` when `address` is `Some`.
- `EmailAddress::new()`, `AddressGroup::new()` public constructors.
- `Display` for `EmailAddress` (RFC 5322 §3.4 mailbox form), `AddressGroup`
  (group form), and `HeaderDateTime` (delegates to `to_rfc3339()`).
- `Hash` and `Default` derived for `EmailAddress`, `AddressGroup`, `HeaderDateTime`.
- Per-form standalone functions: `parse_raw`, `parse_addresses`,
  `parse_grouped_addresses`, `parse_message_ids`, `parse_date`, `parse_urls`.
- `HeaderForm`: `Display` (emits JMAP token), `FromStr` (parses JMAP token),
  `as_jmap_token()`.
- `UnknownHeaderForm` now implements `Serialize` and `Deserialize`.

### Fixed

- `MessageIds` form no longer leaks mail-parser's broken-client recovery output
  for malformed input without angle brackets.
- `URLs` form replaced mail-parser's address parser with a dedicated RFC 2369
  bracket tokenizer. Values outside `<…>` pairs are correctly ignored.
- `Raw` form replaces non-UTF-8 bytes with U+FFFD instead of collapsing to empty.
- `decode_body_value`: switched to padding-tolerant base64 engine; missing or
  excess `=` padding no longer sets `is_encoding_problem`.
- `decode_body_value`: quoted-printable errors now return empty bytes (consistent
  with base64 and uuencode error paths).

## [0.3.0] - 2026-05-11

### Breaking Changes

- `ParsedPart::header_range` and `ParsedPart::body_range` changed from `(usize, usize)` to `(u32, u32)`.
  This ensures cross-platform serialization stability when using serde (usize is platform-dependent;
  u32 is stable and sufficient for any realistic message up to 4 GB). Update any code that compares
  or constructs these tuples to use `u32` literals.

### Added

- `ParseError::InvalidRange` — returned by `decode_body_value()` when a part's byte range extends
  beyond the raw message bytes. Previously `ParseError::NoHeaders` was (incorrectly) returned.
- Typed header API for RFC 8621 JMAP `As*` header forms. New public items:
  `parse_header_typed`, `HeaderForm`, `HeaderValueTyped`, `EmailAddress`, `AddressGroup`,
  `HeaderDateTime`. Covers `asAddresses` (§4.1.2.3), `asGroupedAddresses` (§4.1.2.4),
  `asMessageIds` (§4.1.2.5), `asDate` (§4.1.2.6), `asURLs` (§4.1.2.7), and `Raw` (§4.1.2.1).
  Mail-parser remains a private implementation detail — all new types are owned and
  lifetime-free.
