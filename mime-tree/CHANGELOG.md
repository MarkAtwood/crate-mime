# Changelog

All notable changes to `mime-tree` will be documented here.

## [Unreleased]

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
