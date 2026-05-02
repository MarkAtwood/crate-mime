# Agent Instructions — MIME Workspace

Two-crate Cargo workspace: `mime-tree` (MIME parser) and `smime-tree` (S/MIME processor).
Both published standalone to crates.io. No JMAP dep. No async.

Read the crate-specific `CLAUDE.md` and `AGENTS.md` before touching a crate.

## Crate Map

| Directory | Crate | Role |
|---|---|---|
| `mime-tree/` | `mime-tree` | RFC 5322/MIME parser — no S/MIME crypto |
| `smime-tree/` | `smime-tree` | S/MIME sign/verify/encrypt/decrypt via key traits |

## Dependency Direction

```
smime-tree  →  mime-tree  (path dep within workspace)
mime-tree   →  (no workspace deps)
```

Callers handle MIME/S/MIME recursion. Neither crate recurses into the other.

## Standards Reference

RFC text files for all relevant specifications: `~/PROJECT/MIME/standards/`.
See `~/PROJECT/MIME/standards/README.md` for the full index. Read from there.

## Quality Gate

Run before every commit:

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

All three must pass clean.

## Non-Interactive Shell Commands

```bash
cp -f source dest       # NOT: cp source dest
mv -f source dest       # NOT: mv source dest
rm -f file              # NOT: rm file
rm -rf dir              # NOT: rm -r dir
```

## Git Commit Policy

git commit and git push require explicit user approval.

**Exception — fix/test loops**: When operating in a review or fix loop (invoked via a
`~/PROMPT-*.md` prompt or beads workflow), committing after each fix is permitted without
asking. Push to remote still requires explicit user confirmation.

## Fail Fast

If a shell command fails twice with the same error, stop and report the exact error to the
user. Do not try variants. Repeated failure means your model of the problem is wrong.

## Beads Issue Tracker

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
bd dolt push          # Sync beads data
```

Use `bd` for ALL task tracking. Do not use TodoWrite, TaskCreate, or markdown TODO lists.

## Epic Workflow

Any multi-issue feature starts with an epic:

```bash
bd create --type=epic --title="Feature name"
bd create --type=task --parent=<epic-id> --title="Child task"
bd dep add <child-id> <blocker-id>
bd ready               # find unblocked work
bd epic status         # check progress
bd epic close-eligible # close when all children done
```

## Subagents — one per issue

**Each beads issue is executed by a dedicated subagent.** The orchestrating agent plans and
fans out; it does not write code itself.

Subagent lifecycle (every subagent does exactly this):
```
bd show <id>                          # read the issue
bd update <id> --claim                # mark in_progress
# ... do the work ...
cargo fmt --all
cargo clippy -p <crate> -- -D warnings
cargo test -p <crate>
bd close <id>
```

Orchestrator loop:
```
bd ready                              # find unblocked issues
# spawn one subagent per ready issue, in parallel
# wait for completions
# repeat until bd epic close-eligible
```

Rules:
- Each subagent reads only the files relevant to its issue — grep, don't load the whole codebase
- Independent issues are worked in parallel; dependent issues wait for their blockers to close
- If a subagent hits the same error 3 times, it stops and escalates — orchestrator surfaces to user

## Agent Teams

Use `TeamCreate` for independent parallel workstreams (e.g., `mime-tree` and `smime-tree`
scaffolding simultaneously). Each team member is an orchestrator that fans out to per-issue
subagents. Coordinate via beads dependency edges, not shared mutable state.

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
