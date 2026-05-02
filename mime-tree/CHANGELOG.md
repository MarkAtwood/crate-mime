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
