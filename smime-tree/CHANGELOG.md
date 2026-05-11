# Changelog

All notable changes to `smime-tree` will be documented here.

## [0.3.0] - 2026-05-11

### Added

- `DecryptionKey::agree_ecdh()` default method for ECDH (KARI) decryption.
  Default returns `Err(UnsupportedAlgorithm)` — no change for existing RSA key
  implementations.  Override to support `KeyAgreeRecipientInfo` (P-256/P-384).
- `KariAlgorithm`, `KariKeyAgreement`, `KeyWrapAlgorithm` types describing the
  ECDH scheme and AES-KW variant; passed to `agree_ecdh()`.
- `decrypt()` now handles `KeyAgreeRecipientInfo` entries: it extracts the
  ephemeral public key and UKM, calls `agree_ecdh()`, and returns the CEK.
  Unsupported ECDH OIDs are skipped (not hard errors); static originators
  (rare) are also skipped.

### Breaking Changes

- `SmimeError::Io(String)` renamed to `SmimeError::Other(String)`. The variant was
  used for all sorts of non-I/O errors (parse failures, format mismatches, algorithm
  parameter errors). Update any match arms or direct constructions of `SmimeError::Io`
  to `SmimeError::Other`.

- `verify()` now takes an explicit `now: std::time::SystemTime` parameter for certificate
  validity checking. Pass `SystemTime::now()` for normal use; pass a fixed time in tests
  to validate against certificates with known validity periods.
- `verify()` now takes a `revocation: &dyn RevocationChecker` parameter. Pass
  `&NoRevocationCheck` to retain previous behaviour (no revocation checking). Implement
  `RevocationChecker` to inject OCSP or CRL validation at the call site.
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
- `sign()` now selects the digest algorithm from the signing key's certificate rather than always
  using SHA-256: EC P-256 → SHA-256, EC P-384 → SHA-384, EC P-521 → SHA-512, RSA → SHA-256.
  The key may override this via `SigningKey::preferred_digest_algorithm()`.
  Previously `sign()` always used SHA-256, which produced the wrong `ECDSA_WITH_SHA_256` OID for
  P-384 signing keys (strict receivers would reject the resulting SignedData).

### Added (this release)

- `#[non_exhaustive]` added to all public enums (`SmimeError`, `KeyEncryptionAlgorithm`,
  `KeyWrapAlgorithm`, `KariKeyAgreement`, `DigestAlgorithm`, `EcCurve`, `RecipientIdentifier`)
  and `mime-tree`'s `TransferEncoding` and `ParseError`. Future variants are no longer
  breaking changes.
- Certificate chain validation now checks `KeyUsage::keyCertSign` when the `KeyUsage` extension
  is present, per RFC 5280 §4.2.1.3.

### Fixed

- `sign()`: `EncapsulatedContentInfo.econtent` is now correctly absent for `multipart/signed`
  (detached signature). Previously it was populated, causing rejection by strict receivers.
- `verify()`: certificate chain validation is now performed for each signer.
- `verify()`: trust anchor validity period is now checked.
- `verify()`: signer certificate lookup now also searches `trust_anchors` when not found in the CMS bag.
