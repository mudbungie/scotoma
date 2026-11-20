# AGENTS.md (scotoma)

This repo defers to `~/AGENTS.md` for general practices. Project-specific notes follow.

## What scotoma is

A secrets manager for agents: a library and a command. A model gets an opaque handle, the harness substitutes the value at execution and redacts it everywhere else, and every act is logged. Read `docs/DESIGN.md` before changing behaviour; it is the living design and is edited like code.

## Hard rules

- **Only cryptography is a dependency.** The password hash and the cipher, because we must not write those ourselves; nothing else. Adding one is a discussion, not a commit.
- **Only the resident process holds a value.** Everything keyed is in `vault.rs`, `store.rs` and `crypt.rs`, reached through the socket; `client.rs` (the public API) never reads the vault's files.
- **A secret value or grant token never appears in an error, a log line, an argument we accept, or a test name.** Errors name the secret, never quote it.
- **Source files ≤ 300 lines.** `make size`. Split along a real seam; do not shave lines.
- **Test coverage = 100%, lines and regions.** `make cov`. A `?` whose error edge never runs is an uncovered region: either make it fail in a test, or restructure so the fallible steps share one edge (`a.and_then(b).map_err(Error::io(path))`). Nothing is suppressed with an attribute or a `#[cfg]`. A generic function is scored by its best single instantiation, so its tests must drive every path through one concrete type. `make cov-text` (on the build machine: `bl-remote-run cov-text`) writes the annotated source and a JSON export that name the gap. Unit tests live beside their module in `NAME_tests.rs`, not inline: a passing assertion's failure arm is a region no test can reach, and the coverage report leaves test files out.
- **No panic paths, no `unsafe`, no inline `#[allow]`.** The lint table in `Cargo.toml` is the only allow-list.
- **Nothing personal or secret is published.** `make leak-scan` judges the tree, `make package` the files inside the `.crate`, the `commit-msg` hook the message. Use documentation values in examples (`example.com`, `/home/u`, `u@example.com`). If a rule is wrong, fix the rule in `scripts/leak-rules.sh` and its fixture; there is no allowlist.
- **`Cargo.toml` `include` is an allowlist.** A new top-level file is unpublished until it is named there.

## Workflow

Tasks are tracked with `bl` (`bl --skill`). `bl claim` prints a worktree; all edits happen there, never on `main`. `bl close` requires `main` to be merged into the work branch already, runs the `pre-commit` hook on that tree, and squashes it to `main`.

## The gate

`make check` is the complete gate: `size → leak-scan → fmt-check → lint → deny → cov`. `.githooks/pre-commit` refuses direct commits to `main` and then `exec`s `bl-gate` (machine tooling), which obtains a verdict for the staged tree from the build machine rather than compiling here. `.github/workflows/ci.yml` runs the same `make check`; nothing restates a step the Makefile defines. Advisories are deliberately outside the per-commit gate (`make advisories`). Run `make install-hooks` once per clone.

Every gate step sweeps `git ls-files`: `git add -A` before running one locally, or new files are invisible to it.

## Releases

Landing on `main` refreshes one release PR (release-plz); merging it tags `v<version>` and publishes to crates.io. Bumps are PATCH unless a commit message carries a standalone `[minor]` or `[major]`. `CHANGELOG.md` is written by hand: each change adds a bullet under `## [Unreleased]`, and that heading is renamed to the version on the release PR before it is merged.
