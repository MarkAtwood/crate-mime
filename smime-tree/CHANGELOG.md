# Changelog

All notable changes to `smime-tree` will be documented here.

## [0.4.0] - Unreleased

### Breaking Changes

- **Stable RustCrypto dependencies.** `x509-cert` 0.3, `rsa` 0.10,
  `p256`/`p384` 0.14, `elliptic-curve` 0.14, `signature` 3, `aes-gcm` 0.11
  and `ansi-x963-kdf` 0.1 replace the exact pre-release pins, and `cms`
  moves to `=0.3.0-rc.2`. `x509_cert::Certificate` appears in the public
  API, so callers must use `x509-cert` 0.3. 0.3.3 no longer builds from a
  fresh dependency resolution (`rsa` 0.10.0-rc.18 fails against `pkcs1`
  0.8.0).
- Signer certificates whose keyUsage or extKeyUsage does not allow S/MIME
  signing are rejected (see Fixed).

### Added

- `CertChainError::UnsuitableSignerCertificate { subject, reason }`.
- ECDSA signatures with SHA-512, and any pairing of P-256/P-384 with
  SHA-256/384/512, for both message signatures and certificate chains.

### Fixed

- The signer certificate's purpose is checked: when present, keyUsage
  must include digitalSignature or nonRepudiation, and extKeyUsage must
  include emailProtection or anyExtendedKeyUsage. A TLS server
  certificate previously verified as an S/MIME signer.
- ECDSA verification takes the curve from the key, not the signature
  OID. A P-384 key signing with SHA-256 (OpenSSL's default) failed, both
  as the message signer and as a CA in the chain.
- KARI messages whose originator key omits the curve parameter (as
  OpenSSL writes them; RFC 5753 §3.1.1) decrypt. The ephemeral point is
  checked to be on the curve before `agree_ecdh`.
- After a recipient matches, a wrong-length CEK, bad padding, a failed
  GCM tag and `decrypt_cek` errors (other than `UnsupportedAlgorithm` and
  `RngFailure`) all return the same `DecryptionFailed`, removing a
  padding-oracle signal on RSA key transport.
- AES key schedules and the content-encryption key are zeroized on drop,
  including on early error returns.
- Documentation: chain-validation algorithm support; size limits apply
  after DER decoding; only DER, not indefinite-length BER, is accepted;
  `RsaOaep` carries no OAEP parameters.

### Changed

- `base64` 0.23.
- MSRV is now 1.88 (was declared 1.85, which fresh dependency
  resolution no longer builds).
- `rsa` 0.10.0 is not affected by RUSTSEC-2023-0071; the lockfile also
  moves off yanked `crypto-bigint`/`ctutils` versions affected by
  RUSTSEC-2026-0387 / RUSTSEC-2026-0385.

## [0.3.3] - 2026-06-16

### Added

- AES-GCM `AuthEnvelopedData` encrypt and decrypt (RFC 5083). `encrypt()`
  now produces `AuthEnvelopedData` with AES-128-GCM (RSA/P-256 recipients) or
  AES-256-GCM (P-384 recipients). `decrypt()` handles both `EnvelopedData`
  (AES-CBC) and `AuthEnvelopedData` (AES-GCM).
- `sign()` now accepts multiple signing keys (`&[&dyn SigningKey]`).
- `VerificationResult::all_verified()` and `verified_signers()` convenience
  methods.
- `Serialize` / `Deserialize` for `SmimeError`.

### Fixed

- `AllSignersFailed` `Display` now shows all per-signer errors instead of
  only the first.
- ECDH originator curve is validated against the KDF scheme; mismatched
  curves are rejected.
- Oversized ciphertext is rejected before CBC allocation to prevent
  memory exhaustion.
- Padding oracle information leak eliminated in CBC decrypt path.
- Certificate bag and signer count bounded in `verify()` to prevent
  resource exhaustion from adversarial inputs.

### Changed

- Unified `build_p256_recipient` / `build_p384_recipient` into a single
  generic `build_ec_recipient<C, D>()`.
- README corrected: `sign()` signature, AES-GCM algorithm selection,
  `authEnveloped-data` smime-type, P-521 not supported.

## [0.3.2] - 2026-06-04

### Added

- P-384 certificate chain validation now works. `pkix-chain`'s `rustcrypto` feature
  (via `pkix-path` 0.3.1) activates `EcdsaP384Verifier`, so chains with P-384/SHA-384
  CA signatures are accepted. Integration test with OpenSSL-generated P-384 chain added.

### Fixed

- `verify()`: pre-UNIX-epoch `SystemTime` passed as `now` now returns
  `SmimeError::CertChain` immediately instead of silently using epoch-zero.
- `verify()`: `content-type` signed attribute value is now decoded and validated
  per RFC 5652 §11.1. Wrong values are rejected with `SmimeError::MalformedInput`.
- `mime-tree` moved from `[dependencies]` to `[dev-dependencies]` — removes a
  transitive dependency for consumers.

### Changed

- RSA-PSS CA signatures documented as unsupported in `lib.rs` Known Limitations.
  Stale P-384 chain validation caveat removed.
- README: corrected RSA key transport description from RSA-OAEP to RSA PKCS#1 v1.5.

## [0.3.1] - 2026-05-11

### Fixed

- Cargo dep `pkix-chain` bumped from yanked `0.1.1` to current `0.4`.
  smime-tree 0.3.0 (and 0.2.0, 0.1.0) pinned `pkix-chain = "0.1.1"`, which was
  yanked from crates.io on 2026-05-06 along with the entire 0.1.x line. New
  consumers running `cargo add smime-tree` would fail dep resolution. The
  0.3.0/0.2.0/0.1.0 releases have been yanked.

### Changed

- Internal: `cert.rs` switched from struct-expression construction of
  `pkix_chain::ValidationPolicy` to the `ValidationPolicy::new(now_unix)`
  constructor, required because pkix-path 0.3 marks the struct
  `#[non_exhaustive]`. No public API change.

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
