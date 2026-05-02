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

## Repository

<https://github.com/MarkAtwood/crate-mime>

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
