# Agent Instructions — mime-tree

Standalone Rust crate. Parses RFC 5322 / MIME into a walkable, byte-range-indexed part tree.
Published to crates.io. No JMAP dep. No async. No S/MIME crypto.

Read `CLAUDE.md` (this directory) and `~/PROJECT/MIME/CLAUDE.md` before doing anything.

## Public API Surface

```rust
// Parse raw RFC 5322 bytes into an owned, serializable tree
pub fn parse(raw: &[u8]) -> Result<ParsedMessage, ParseError>;

// Decode one part's content on demand (slice → transfer-decode → charset-convert)
pub fn decode_body_value(
    raw: &[u8],
    part: &ParsedPart,
    max_bytes: Option<usize>,
) -> Result<DecodedBodyValue, ParseError>;

// Public fields on ParsedMessage — access directly, no methods
pub struct ParsedMessage {
    pub part_index: ParsedPart,       // MIME part tree rooted at the message
    pub text_body: Vec<String>,       // Part IDs of text/plain body parts (RFC 8621 §4.1.4)
    pub html_body: Vec<String>,       // Part IDs of text/html body parts (RFC 8621 §4.1.4)
    pub attachments: Vec<String>,     // Part IDs of attachment parts (RFC 8621 §4.1.4)
    pub headers: Vec<ParsedHeader>,   // Top-level message headers
    pub preview: Option<String>,      // First ~256 chars of text content
    pub warnings: Vec<String>,        // Non-fatal parse warnings
}
```

## Key Rules

- **No `mail-parser` types in public API.** Use pointer arithmetic to recover byte offsets
  from `mail-parser`'s sub-slices: `sub.as_ptr() as usize - raw.as_ptr() as usize`.
- **No JMAP types anywhere.**
- **No S/MIME processing.** `application/pkcs7-mime` and `application/pkcs7-signature` are
  opaque binary leaves. Do not attempt to parse or decrypt them.
- **All public types: `Serialize + Deserialize`, owned, no lifetimes.**
- **Best-effort only.** Never `Err` on malformed but parseable input — append to `warnings`.
- The RFC 8621 §4.1.4 algorithm lives here (it's a MIME tree traversal, not JMAP-specific).

## Crate Structure

```
src/
  lib.rs          — public re-exports
  parse.rs        — parse() entry point, drives mail-parser
  part.rs         — ParsedPart, TransferEncoding, ParsedHeader types
  message.rs      — ParsedMessage type + query methods
  walk.rs         — RFC 8621 §4.1.4 body structure algorithm
  decode.rs       — decode_body_value(): slice + transfer-decode + encoding_rs
  error.rs        — ParseError type
```

## Standards Reference

RFC text files: `~/PROJECT/MIME/standards/`. See README.md there for the index.
Relevant to this crate: rfc5322, rfc2045, rfc2046, rfc2047, rfc2183, rfc2231, rfc8621.

## Quality Gate

```bash
cargo fmt --all
cargo clippy -p mime-tree -- -D warnings
cargo test -p mime-tree
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
cargo clippy -p mime-tree -- -D warnings
cargo test -p mime-tree
bd close <id>
```

Read only the files this issue requires. Do not refactor adjacent code. Do not write
code for issues you are not assigned. If you hit the same error 3 times, stop and report.

For full workflow context (orchestrators): see `~/PROJECT/MIME/AGENTS.md`.
