# smime-tree — Project Instructions for AI Agents

Standalone, published Rust crate. Processes S/MIME (RFC 5751 / CMS RFC 5652): sign,
verify, encrypt, decrypt. Key operations are trait-based — the crate does not commit to
where keys live. No JMAP dependency. No async.

## What This Is

Given a CMS/PKCS#7 blob and a key trait implementation, produces or consumes S/MIME:

- Verify `multipart/signed` → `VerificationResult`
- Decrypt `application/pkcs7-mime; smime-type=enveloped-data` → inner MIME bytes
- Sign MIME content → `multipart/signed` bytes
- Encrypt MIME content → `application/pkcs7-mime` bytes

Decrypted inner bytes are returned to the caller. The caller feeds them to
`mime-tree::parse()` if MIME parsing is needed. If those bytes are themselves S/MIME,
the caller loops — this crate does not recurse.

## Hard Design Invariants

Do not relitigate without explicit user approval.

1. **No JMAP dependency.**
2. **No async.** Key operations are synchronous. A UA or trusted context is assumed —
   keys are available immediately.
3. **Key operations are trait-based.** `DecryptionKey` and `SigningKey` traits abstract
   over key location. The crate does not know or care whether the key is in memory, an
   HSM, or a hardware token.
4. **Caller handles recursion.** Decryption returns inner bytes. If those bytes contain
   another S/MIME structure, the caller loops. Neither this crate nor `mime-tree` recurses
   into the other.
5. **No network calls.** No OCSP, no CRL fetch. Certificate chain validation uses a trust
   store provided by the caller. Keeping it fresh is the caller's responsibility.
6. **CMS parsing via the `cms` crate.** Do not hand-roll DER parsing.
7. **`mime-tree` is a dependency** (path dep in workspace, version dep when published).
   `ParsedPart` byte ranges are used in `verify()` to locate the exact signed bytes.

## CMS Tree Structure

S/MIME structures are trees — that is why the crate is named `smime-tree`:

- `SignedData` contains a collection of `SignerInfo` entries (multiple independent signers)
- Countersignatures: a `SignerInfo` that signs another `SignerInfo`
- Sign-then-encrypt: `EnvelopedData` wrapping `SignedData` wrapping content
- Encrypt-then-sign: `SignedData` wrapping `EnvelopedData` wrapping content
- RFC 2634 triple-wrapping: `SignedData(EnvelopedData(SignedData(content)))`

The processor walks this CMS tree. MIME content bytes are returned to the caller, not
recursed into.

## Key Traits

```rust
pub trait DecryptionKey {
    /// Decrypt an encrypted content-encryption key.
    fn decrypt_cek(
        &self,
        encrypted_key: &[u8],
        algorithm: &KeyEncryptionAlgorithm,
    ) -> Result<Vec<u8>, SmimeError>;

    /// Returns true if this key matches the given RecipientIdentifier.
    fn matches_recipient(&self, id: &RecipientIdentifier) -> bool;
}

pub trait SigningKey {
    /// Sign data and return the raw signature bytes.
    fn sign(&self, data: &[u8], algorithm: &DigestAlgorithm) -> Result<Vec<u8>, SmimeError>;

    /// The signer's X.509 certificate, included in the SignedData.
    fn certificate(&self) -> &Certificate;
}
```

## Processor API

```rust
/// Verify a multipart/signed message.
/// `signed_content` — exact raw bytes of the signed MIME part (use mime-tree byte ranges).
/// `signature_der`  — DER bytes of the application/pkcs7-signature part.
/// `now`            — current time for certificate validity checks; pass SystemTime::now() normally.
pub fn verify(
    signed_content: &[u8],
    signature_der: &[u8],
    trust_anchors: &[Certificate],
    now: std::time::SystemTime,
) -> Result<VerificationResult, SmimeError>;

/// Decrypt an enveloped-data blob. Returns inner MIME bytes.
/// Caller feeds result to mime_tree::parse(), looping if the result is also S/MIME.
pub fn decrypt(
    enveloped_der: &[u8],
    key: &dyn DecryptionKey,
) -> Result<Vec<u8>, SmimeError>;

/// Sign MIME content. Returns multipart/signed outer MIME bytes.
pub fn sign(content_mime: &[u8], key: &dyn SigningKey) -> Result<Vec<u8>, SmimeError>;

/// Encrypt MIME content to one or more recipients.
/// Returns application/pkcs7-mime; smime-type=enveloped-data bytes.
pub fn encrypt(inner_mime: &[u8], recipients: &[Certificate]) -> Result<Vec<u8>, SmimeError>;
```

## Dependencies

| Crate | Role | Leaks into public API? |
|---|---|---|
| `cms` | Parse SignedData, EnvelopedData, ContentInfo (RustCrypto/formats) | No |
| `x509-cert` | Certificate type, chain validation | Yes (`Certificate`) |
| `rsa` | RSA key transport (`KeyTransRecipientInfo`) | No |
| `p256` / `p384` | ECDH key agreement (`KeyAgreeRecipientInfo`) | No |
| `aes` + mode crates | Content encryption (AES-128-CBC, AES-256-CBC, AES-256-GCM) | No |
| `sha2` | Digest algorithms | No |
| `der` | DER encode/decode (transitive from `cms`) | No |
| `mime-tree` | `ParsedPart` byte ranges for `verify()` | Yes (`ParsedPart`) |
| `serde` | `Serialize + Deserialize` on result types | Yes |

No async deps. No tokio. Synchronous only.

## RFC References

All RFC text files live in `~/PROJECT/MIME/standards/` — read from there.
See `~/PROJECT/MIME/standards/README.md` for the full index.

| RFC | File | Covers |
|---|---|---|
| RFC 5751 | rfc5751.txt | S/MIME v3.2 — message specification |
| RFC 5652 | rfc5652.txt | CMS — Cryptographic Message Syntax |
| RFC 2634 | rfc2634.txt | ESS — Enhanced Security Services (triple-wrap, signed receipts, countersigs) |
| RFC 5035 | rfc5035.txt | ESS update |
| RFC 3565 | rfc3565.txt | AES algorithm in CMS |
| RFC 5083 | rfc5083.txt | AES-GCM in CMS |
| RFC 5280 | rfc5280.txt | PKIX Certificate and CRL Profile (chain validation) |
| RFC 5753 | rfc5753.txt | ECC algorithms in CMS (KeyAgreeRecipientInfo, P-256/P-384 ECDH) |
| RFC 8017 | rfc8017.txt | PKCS#1 v2.2 — RSA (KeyTransRecipientInfo) |

## Conventions

- License: MIT OR Apache-2.0
- MSRV: 1.85
- No `unsafe` beyond what RustCrypto crates require transitively
- Error types: defined in `error.rs`, exported from crate root

## Test Integrity

- Never modify, skip, or weaken a failing test. Fix the code.
- Oracles: use OpenSSL (`openssl smime -sign`, `-verify`, `-encrypt`, `-decrypt`) or
  Python pyca/cryptography (`from cryptography.hazmat.primitives.serialization.pkcs7 import ...`)
  to generate S/MIME test fixtures and cross-validate results. Both are valid independent oracles.
- Never derive expected values from this crate.

## Workspace Context

This crate lives in `~/PROJECT/MIME/smime-tree/`.
Workspace CLAUDE.md: `~/PROJECT/MIME/CLAUDE.md`.
Sibling dependency: `mime-tree` (this crate depends on it; not the reverse).
