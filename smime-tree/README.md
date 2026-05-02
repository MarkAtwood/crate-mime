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

## How it works

### Verify

`verify()` takes the raw bytes of the signed MIME part and the DER-encoded
`application/pkcs7-signature` blob. It:

1. Parses the DER blob as a CMS `ContentInfo` → `SignedData`.
2. For each `SignerInfo`, recomputes the message digest over the supplied content
   bytes (RFC 5652 §5.4) and checks it against the `messageDigest` signed attribute.
3. Verifies the `SignerInfo` signature over the DER-encoded `SignedAttributes` SET.
4. Locates the signer's certificate in the `SignedData` certificate bag and walks
   the chain to a caller-supplied trust anchor (RFC 5280 §6.1).
5. Returns a `VerificationResult` with one `SignerResult` per `SignerInfo` — all
   failures are reported, not just the first.

The caller extracts the exact signed bytes using `mime-tree` byte ranges. Using
the wrong byte slice (e.g. re-encoded content) will cause digest mismatch.

### Decrypt

`decrypt()` takes a DER-encoded `ContentInfo` wrapping `EnvelopedData`. It:

1. Iterates the `RecipientInfo` list; for each entry calls
   `DecryptionKey::matches_recipient()` to find the right one.
2. For KTRI (RSA): calls `DecryptionKey::decrypt_cek()` with the encrypted key bytes.
3. For KARI (ECDH): calls `DecryptionKey::agree_ecdh()` with the ephemeral public key,
   UKM, and wrapped CEK; the trait implementation performs the ECDH exchange and key unwrap.
4. Decrypts the content with the recovered CEK (AES-128-CBC or AES-256-CBC).
5. Returns the plaintext bytes. Feed them to `mime_tree::parse()` to get the part tree.

### Sign

`sign()` builds a detached CMS `SignedData` and wraps it in a `multipart/signed`
MIME structure. It:

1. Hashes `content_mime` with the selected digest algorithm.
2. Builds `SignedAttributes`: content-type, message-digest, signing-time (`now`).
3. Calls `SigningKey::sign()` over the DER-encoded `SignedAttributes` SET.
4. Constructs `SignedData` with the signer's certificate embedded in the bag.
5. Base64-encodes the DER blob into the `application/pkcs7-signature` MIME part.

### Encrypt

`encrypt()` builds a CMS `EnvelopedData` with one `RecipientInfo` per certificate:

- RSA certificates → `KeyTransRecipientInfo` (RSA-OAEP key transport).
- EC P-256/P-384 certificates → `KeyAgreeRecipientInfo` (ECDH-ES + AES key wrap).

A random CEK is generated for each message. Content is encrypted with AES-256-CBC.

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
