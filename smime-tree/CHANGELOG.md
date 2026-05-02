# Changelog

All notable changes to `smime-tree` will be documented here.

## [Unreleased]

### Breaking Changes

- `RecipientIdentifier` is now an owned type defined in `smime-tree` rather than a re-export of
  `cms::enveloped_data::RecipientIdentifier`. Update implementations of `DecryptionKey::matches_recipient()`
  to use the new `smime_tree::RecipientIdentifier` enum with variants `IssuerAndSerialNumber { issuer_der, serial }`
  and `SubjectKeyIdentifier(Vec<u8>)`.

### Changed

- `verify()` now returns `Err(SmimeError::AllSignersFailed(...))` when all signers fail verification,
  rather than `Ok(VerificationResult { signers: [...] })`. Check the return value with `?` or
  `.is_ok()` — do not assume `Ok` means verified.
- `EnvelopedData.version` is now correctly computed per RFC 5652 §6.1 (V0 for KTRI-only, V2 for KARI).
- P-384 recipients now use AES-256-CBC content encryption and AES-256-KW key wrap per NIST SP 800-57
  security level matching.

### Fixed

- `sign()`: `EncapsulatedContentInfo.econtent` is now correctly absent for `multipart/signed`
  (detached signature). Previously it was populated, causing rejection by strict receivers.
- `verify()`: certificate chain validation is now performed for each signer.
- `verify()`: trust anchor validity period is now checked.
- `verify()`: signer certificate lookup now also searches `trust_anchors` when not found in the CMS bag.
