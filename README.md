# mime / smime workspace

Processing a signed or encrypted email correctly requires two things that most
libraries treat as one: knowing the *exact byte positions* of each MIME part in
the original message (so a cryptographic verifier can hash the right bytes), and
performing the *CMS/PKCS#7 cryptographic operations* without tying you to a
specific key store. These two crates separate those concerns cleanly.

`mime-tree` parses RFC 5322 / MIME messages into a byte-range-indexed part tree.
`smime-tree` performs S/MIME sign/verify/encrypt/decrypt using those byte ranges
and caller-supplied key trait implementations.

No JMAP dependency. No async. No `unsafe` beyond what RustCrypto crates require.

## Crates

### [`mime-tree`](mime-tree/)

RFC 5322 / MIME parser. Given raw message bytes, returns a `ParsedMessage` with:

- A walkable `ParsedPart` tree with IMAP dotted-path IDs
- `(offset, length)` byte ranges per part — into the caller's buffer, not copies
- RFC 8621 §4.1.4-compatible `text_body`, `html_body`, and `attachments` views
- On-demand body decoding: Base64, Quoted-Printable, charset conversion via `encoding_rs`
- `Serialize + Deserialize` on all public types

MSRV: **1.88**

### [`smime-tree`](smime-tree/)

S/MIME sign, verify, encrypt, and decrypt. Key operations are trait-based:
`SigningKey` and `DecryptionKey` are implemented by the caller, so keys may live
in memory, a hardware token, an HSM, or a remote signing service.

- **Verify** `multipart/signed` messages — certificate chain validation included
- **Decrypt** `EnvelopedData` — RSA PKCS#1v15, ECDH P-256/P-384
- **Sign** MIME content → `multipart/signed` output accepted by standard MUAs
- **Encrypt** MIME content → `application/pkcs7-mime; smime-type=enveloped-data`

Uses `mime-tree` byte ranges to locate exact signed bytes for digest verification.

MSRV: **1.88**

## Current status and honest caveats

These crates are published and tested against OpenSSL and Python's `cryptography`
library, but adoption today comes with real limitations worth knowing up front.

**`smime-tree` still depends on one pre-release crate.**
The RustCrypto stack it builds on (`x509-cert` 0.3, `rsa` 0.10, `p256`/`p384`
0.14, `aes-gcm` 0.11, `signature` 3) has shipped stable releases, but `cms` is
still a release candidate and is pinned exactly (`cms = "=0.3.0-rc.2"`). An
exact pre-release pin can conflict with another crate in the same build that
pins a different `cms` pre-release.

**`smime-tree` is ahead of the broader Rust ecosystem for S/MIME.**
At the time of writing there is no other general-purpose S/MIME crate at this
abstraction level. Existing Rust MTA projects (e.g. Stalwart Mail Server) have
hand-rolled their own implementations using different CMS libraries.
`smime-tree` is designed to be the shared solution once the underlying
RustCrypto CMS/X.509 stack stabilizes.

**Message signatures are RSA-PKCS1v15 and ECDSA P-256/P-384 only.**
This is about the `SignerInfo` signature over the message itself: signing
and verifying with RSA-PSS, Ed25519 or P-521 keys is not implemented. File
an issue if you need one.

Certificate chain validation is a separate question and is less limited:
issuer signatures are checked by `pkix_chain::DefaultVerifier`, which
handles RSA-PKCS1v15, RSASSA-PSS, ECDSA P-256/P-384/P-521 and Ed25519.

A chain anchored on a SHA-1 signature will not validate, because no SHA-1
backend is implemented yet. That is an absence rather than a refusal — an
earlier version of this file called it "refused by design", which was
wrong. `pkix-path` plans SHA-1 as a feature-gated, off-by-default
verifier for old chains, since real deployments still carry them
(RSA-PKCS1v15+SHA-1 from pre-2018 government PKI, federal bridge
cross-certs, long-lived enterprise CAs). Verification only: nothing here
signs with SHA-1 and nothing is intended to.

**`mime-tree` is primarily useful as a JMAP body-structure provider.**
For general-purpose MIME parsing, [`mail-parser`](https://crates.io/crates/mail-parser)
— which `mime-tree` wraps internally — is the better direct choice.
`mime-tree` adds value when you specifically need RFC 8621 §4.1.4-compatible
`textBody`/`htmlBody`/`attachments` views and per-part byte ranges for lazy
content retrieval, as in a JMAP or IMAP server.

## Repository

<https://github.com/MarkAtwood/crate-mime>

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
