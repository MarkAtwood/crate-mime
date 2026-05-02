# smime-tree

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-orange.svg)](Cargo.toml)

S/MIME sign, verify, encrypt, and decrypt via caller-provided key traits.
Implements RFC 5751 (S/MIME v3.2) over CMS (RFC 5652) with no async, no network
calls, and no commitment to where keys live.

## Why this crate exists

S/MIME libraries typically own the keys — they expect a PKCS#12 file, a software
keystore, or a specific HSM SDK. `smime-tree` inverts this: key operations are
defined by traits (`SigningKey`, `DecryptionKey`) that the caller implements. The
crate handles CMS structure parsing, algorithm dispatch, certificate chain validation,
and MIME formatting; the caller decides where the private key actually lives — in
memory, a hardware token, an HSM, or a remote signing service.

`smime-tree` depends on [`mime-tree`](../mime-tree/) for byte-range extraction:
`verify()` uses `ParsedPart.body_range` to locate the exact signed bytes in the
original message buffer, which is required for correct digest computation.

## Operations

| Function | Input | Output |
|---|---|---|
| `sign(content_mime, key, now)` | Raw MIME bytes + `SigningKey` + current time | `multipart/signed` MIME bytes |
| `verify(signed_content, signature_der, trust_anchors, now, revocation)` | Signed content + DER signature | `VerificationResult` |
| `encrypt(inner_mime, recipients)` | MIME bytes + recipient certificates | `application/pkcs7-mime` bytes |
| `decrypt(enveloped_der, key)` | DER blob + `DecryptionKey` | Inner MIME bytes |

`decrypt` returns raw bytes. Feed them to `mime_tree::parse()` to get the part
tree. If the result is itself S/MIME, loop — this crate does not recurse.

## Implementing the key traits

### `DecryptionKey`

```rust
use smime_tree::{DecryptionKey, KeyEncryptionAlgorithm, RecipientIdentifier, SmimeError};

struct MyKey { /* private key + certificate */ }

impl DecryptionKey for MyKey {
    fn decrypt_cek(
        &self,
        encrypted_key: &[u8],
        algorithm: &KeyEncryptionAlgorithm,
    ) -> Result<Vec<u8>, SmimeError> {
        match algorithm {
            KeyEncryptionAlgorithm::RsaPkcs1v15 => {
                // decrypt encrypted_key with your RSA private key
                // return raw CEK bytes
                todo!()
            }
            _ => Err(SmimeError::UnsupportedAlgorithm("only RSA supported".into())),
        }
    }

    fn matches_recipient(&self, id: &RecipientIdentifier) -> bool {
        match id {
            RecipientIdentifier::IssuerAndSerialNumber { issuer_der, serial } => {
                self.cert_issuer_der() == issuer_der && self.cert_serial() == serial
            }
            RecipientIdentifier::SubjectKeyIdentifier(ski) => {
                self.cert_ski() == ski
            }
        }
    }
}
```

For ECDH (P-256/P-384) decryption, also override `agree_ecdh`. The default
implementation returns `UnsupportedAlgorithm`.

### `SigningKey`

```rust
use smime_tree::{SigningKey, DigestAlgorithm, SmimeError};
use x509_cert::Certificate;

struct MySigner { /* private key + certificate */ }

impl SigningKey for MySigner {
    fn sign(&self, data: &[u8], algorithm: &DigestAlgorithm) -> Result<Vec<u8>, SmimeError> {
        // compute signature over data using algorithm
        // return raw signature bytes
        todo!()
    }

    fn certificate(&self) -> &Certificate {
        &self.cert
    }
}
```

The digest algorithm is derived from the certificate key type by default
(P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512, RSA → SHA-256).
Override `preferred_digest_algorithm()` to force a specific algorithm.

## Verification

```rust
use smime_tree::{verify, NoRevocationCheck};
use std::time::SystemTime;

let result = verify(
    signed_content_bytes,   // exact bytes of the signed MIME part
    signature_der,          // DER bytes of the pkcs7-signature part
    &trust_anchors,         // Vec<Certificate> — your trust store
    SystemTime::now(),
    &NoRevocationCheck,     // or your RevocationChecker impl
)?;

for signer in &result.signers {
    if signer.verified {
        println!("verified: {}", signer.subject.as_deref().unwrap_or("unknown"));
    }
}
```

Use `mime-tree` byte ranges to extract the exact signed bytes from the raw message:

```rust
let signed_part = msg.part_index.find_by_id(&msg.text_body[0]).unwrap();
let (off, len) = signed_part.body_range;
let signed_bytes = &raw[off as usize .. (off + len) as usize];
```

## Revocation checking

`NoRevocationCheck` accepts all certificates. To enforce revocation policy,
implement `RevocationChecker`:

```rust
impl RevocationChecker for MyOcspChecker {
    fn check(&self, cert: &x509_cert::Certificate) -> Result<(), SmimeError> {
        // consult your OCSP responder or CRL cache
        // return Err(SmimeError::CertChain(...)) if revoked
        todo!()
    }
}
```

This crate makes no network calls. Keeping the trust store and revocation data
fresh is the caller's responsibility.

## Design invariants

- **No async.** All operations are synchronous.
- **No network calls.** No OCSP or CRL fetch at runtime.
- **No JMAP dependency.**
- **Key operations are trait-based.** Keys may live in memory, an HSM, or a
  hardware token — the crate does not care.
- **Caller handles recursion.** Decrypted bytes are returned as-is. If they
  contain another S/MIME layer, the caller loops.

## Specification references

| RFC | Title |
|---|---|
| [RFC 5751](https://www.rfc-editor.org/rfc/rfc5751) | S/MIME Version 3.2 Message Specification |
| [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) | Cryptographic Message Syntax (CMS) |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | PKIX Certificate and CRL Profile (certificate chain validation) |
| [RFC 5753](https://www.rfc-editor.org/rfc/rfc5753) | Use of ECC Algorithms in CMS (ECDH P-256/P-384 key agreement) |
| [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) | PKCS#1 v2.2 — RSA Cryptography Standard (RSA key transport) |
| [RFC 3565](https://www.rfc-editor.org/rfc/rfc3565) | AES Algorithm in CMS (AES-128-CBC, AES-256-CBC content encryption) |
| [RFC 5083](https://www.rfc-editor.org/rfc/rfc5083) | AES-GCM in CMS (AuthEnvelopedData) |
| [RFC 2634](https://www.rfc-editor.org/rfc/rfc2634) | Enhanced Security Services (triple-wrap, countersignatures) |

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.
