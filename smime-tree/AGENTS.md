# Agent Instructions — smime-tree

S/MIME processor: sign, verify, encrypt, decrypt. Key ops via traits. No JMAP. No async.
UA/trusted context assumed — keys are available synchronously.

Read `CLAUDE.md` (this directory) and `~/PROJECT/MIME/CLAUDE.md` before doing anything.

## Public API

```rust
// Key traits — callers implement these to provide key material
pub trait DecryptionKey {
    fn decrypt_cek(&self, encrypted_key: &[u8], algorithm: &KeyEncryptionAlgorithm) -> Result<Vec<u8>, SmimeError>;
    fn matches_recipient(&self, id: &RecipientIdentifier) -> bool;
}
pub trait SigningKey {
    fn sign(&self, data: &[u8], algorithm: &DigestAlgorithm) -> Result<Vec<u8>, SmimeError>;
    fn certificate(&self) -> &Certificate;
}

// Four operations — all synchronous, all return owned bytes
pub fn verify(signed_content: &[u8], signature_der: &[u8], trust_anchors: &[Certificate], now: SystemTime, revocation: &dyn RevocationChecker) -> Result<VerificationResult, SmimeError>;
pub fn decrypt(enveloped_der: &[u8], key: &dyn DecryptionKey) -> Result<Vec<u8>, SmimeError>;
pub fn sign(content_mime: &[u8], keys: &[&dyn SigningKey], now: SystemTime) -> Result<Vec<u8>, SmimeError>;
pub fn encrypt(inner_mime: &[u8], recipients: &[Certificate]) -> Result<Vec<u8>, SmimeError>;
```

## Key Rules

- **CMS parsing via `cms` crate only.** Do not hand-roll DER parsing.
- **Return bytes, let caller decide.** `decrypt()` returns inner MIME bytes. Caller feeds
  them to `mime-tree::parse()` and loops if the result is also S/MIME.
- **No network.** No OCSP, no CRL. Caller provides trust anchors.
- **Trait impls are the caller's responsibility.** This crate only defines the traits.

## Crate Structure

```
src/
  lib.rs          — public re-exports
  error.rs        — SmimeError type
  key.rs          — DecryptionKey, SigningKey traits; algorithm enums
  verify.rs       — verify(): parse SignedData, validate cert chain, check signature
  decrypt.rs      — decrypt(): parse EnvelopedData, find recipient, unwrap CEK, decrypt
  sign.rs         — sign(): build SignedData, produce multipart/signed bytes
  encrypt.rs      — encrypt(): build EnvelopedData, encrypt CEK per recipient
  cert.rs         — certificate chain validation utilities
```

## Standards Reference

RFC text files: `~/PROJECT/MIME/standards/`. See README.md there for the index.
Relevant to this crate: rfc5751, rfc5652, rfc2634, rfc5035, rfc3565, rfc5083,
rfc5280, rfc5753, rfc8017.

## Quality Gate

```bash
cargo fmt --all
cargo clippy -p smime-tree -- -D warnings
cargo test -p smime-tree
```

## Fail Fast

If a shell command fails twice with the same error, stop and report the exact error to the
user. Do not try variants. Repeated failure means your model of the problem is wrong.

## Non-Interactive Shell Commands

```bash
cp -f source dest && mv -f source dest && rm -f file && rm -rf dir
```

## Git Commit Policy

git commit and git push require explicit user approval.
Exception: fix/test loops — commit after each fix, ask before push.

## You are a subagent

If you are reading this, you have been spawned to execute one beads issue. Do this:

```bash
bd show <id>                          # read the issue fully before touching code
bd update <id> --claim                # mark in_progress
# do the work described in the issue
cargo fmt --all
cargo clippy -p smime-tree -- -D warnings
cargo test -p smime-tree
bd close <id>
```

Read only the files this issue requires. Do not refactor adjacent code. Do not write
code for issues you are not assigned. If you hit the same error 3 times, stop and report.

For full workflow context (orchestrators): see `~/PROJECT/MIME/AGENTS.md`.
