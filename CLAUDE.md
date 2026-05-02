# MIME Workspace — Project Instructions for AI Agents

Two published Rust crates for MIME and S/MIME processing. No JMAP dependency. No async.

## Crates

| Crate | Directory | Purpose |
|---|---|---|
| `mime-tree` | `mime-tree/` | RFC 5322 / MIME parser → walkable, byte-range-indexed part tree |
| `smime-tree` | `smime-tree/` | S/MIME processor: sign, verify, encrypt, decrypt via key traits |

Each crate has its own `CLAUDE.md` and `AGENTS.md`. Read the relevant one before touching that crate.

`smime-tree` depends on `mime-tree` (path dep within workspace). Both are independently
publishable to crates.io.

## Workspace Invariants

Do not relitigate without explicit user approval.

1. **No JMAP dependency in either crate.** `jmap-mail-types` and friends are not deps here.
2. **No async in either crate.** Synchronous only. No tokio, no futures.
3. **No `unsafe`** outside what is transitively required by RustCrypto crates.
4. **Dependency direction is one-way.** `smime-tree` may use `mime-tree` types in its public
   API. `mime-tree` must not depend on `smime-tree`.
5. **Callers handle recursion.** When decryption produces inner MIME bytes, the caller feeds
   them to `mime-tree::parse()`. Neither crate recurses into the other.
6. **Both crates: owned, lifetime-free public types.** All public structs implement
   `Serialize + Deserialize`.

## Build & Test

```bash
# Whole workspace
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all

# Single crate
cargo check -p mime-tree
cargo test -p smime-tree
```

Pre-publish checklist (from global CLAUDE.md):
```bash
cargo fmt --all
typos src/
cargo clippy --all-features -- -D warnings
cargo hack check --feature-powerset --depth 2 --no-dev-deps
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features
cargo +<msrv> test
```

MSRV: 1.75.

## Relation to jmap-mime

`~/PROJECT/JMAP/crate-jmap-mime/` is a thin adapter (not part of this workspace) that
depends on `mime-tree` plus `jmap-mail-types`. It converts `ParsedPart → EmailBodyPart`.
`mime-tree` has no knowledge of JMAP.

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

```bash
cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace
bd close <completed-ids>
git pull --rebase
bd dolt push
git push
git status  # must show "up to date with origin"
```

git commit and git push require explicit user approval except when running a review loop.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
