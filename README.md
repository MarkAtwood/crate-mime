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

MSRV: **1.85**

### [`smime-tree`](smime-tree/)

S/MIME sign, verify, encrypt, and decrypt. Key operations are trait-based:
`SigningKey` and `DecryptionKey` are implemented by the caller, so keys may live
in memory, a hardware token, an HSM, or a remote signing service.

- **Verify** `multipart/signed` messages — certificate chain validation included
- **Decrypt** `EnvelopedData` — RSA PKCS#1v15, RSA-OAEP, ECDH P-256/P-384
- **Sign** MIME content → `multipart/signed` output accepted by standard MUAs
- **Encrypt** MIME content → `application/pkcs7-mime; smime-type=enveloped-data`

Uses `mime-tree` byte ranges to locate exact signed bytes for digest verification.

MSRV: **1.85**

## Current status and honest caveats

These crates are published and tested against OpenSSL and Python's `cryptography`
library, but adoption today comes with real limitations worth knowing up front.

**Ecosystem timing is the main blocker for `smime-tree`.**
Several of its dependencies are pinned to pre-release RustCrypto crates —
`cms = "=0.3.0-pre.2"`, `x509-cert = "=0.3.0-rc.4"`, `p256`/`p384`/`rsa` at
matching rc pins. Until those crates ship stable releases, pinning to specific
pre-release versions is unavoidable and creates downstream resolver conflicts.
The code is ready; the ecosystem is not quite there yet.

**`smime-tree` is ahead of the broader Rust ecosystem for S/MIME.**
At the time of writing there is no other general-purpose S/MIME crate at this
abstraction level. Existing Rust MTA projects (e.g. Stalwart Mail Server) have
hand-rolled their own implementations using different CMS libraries.
`smime-tree` is designed to be the shared solution once the underlying
RustCrypto CMS/X.509 stack stabilizes.

**Certificate chain validation has algorithm gaps.**
`pkix-chain` (used for RFC 5280 path validation) currently supports only
RSA-PKCS1v15-SHA-256 and ECDSA-P-256-SHA-256 for CA certificate signatures.
Chains where an intermediate or root CA uses ECDSA-P-384 — common in modern
PKIs — will fail. See [issue #1](https://github.com/MarkAtwood/crate-mime/issues/1).
There is also a version-bridge overhead (DER round-trip per certificate) until
`pkix-chain` moves to x509-cert 0.3; see [issue #2](https://github.com/MarkAtwood/crate-mime/issues/2).

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
