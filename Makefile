.PHONY: setup build test fmt fmt-check lint deny cov cov-text size leak-scan package check install-hooks clean doc

# Dev tooling the gate needs beyond the pinned toolchain.
setup:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny@0.20.2 --locked

build:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

lint:
	cargo clippy --all-targets -- -D warnings

# Bans, licenses, sources. Advisories are NOT in the per-commit gate: a fresh
# advisory turns every tree red with no change in it. `make advisories` is the
# on-demand check.
deny:
	cargo deny check bans licenses sources

advisories:
	cargo deny check advisories

# 100% lines AND regions; nothing is excluded.
cov:
	cargo llvm-cov --fail-under-lines 100 --fail-under-regions 100

# The examples in the documentation compile: `cov` does not build them.
doc:
	cargo test --doc

# Where the gap is: the annotated source, uncovered regions marked `^0`.
# `bl-remote-run cov-text` brings it home to .remote/cov-text/.
DIST ?= target/dist
cov-text:
	mkdir -p $(DIST)
	cargo llvm-cov --text --output-path $(DIST)/coverage.txt
	cargo llvm-cov report --json --output-path $(DIST)/coverage.json

# The 300-line cap on every source file. Reads the index: `git add -A` first.
size:
	scripts/source-files.sh | scripts/line-limit.sh

# The disclosure gate. --self-test first: a leak gate dies by matching nothing.
leak-scan:
	@scripts/leak-scan.sh --self-test
	@scripts/leak-scan.sh

# `cargo package`, not `cargo publish --dry-run`: the dry run deletes its
# tarball, and the leak scan must read the files the registry would serve.
package:
	rm -f target/package/scotoma-*.crate
	cargo package --locked
	scripts/leak-scan.sh --crate target/package/scotoma-*.crate

# The complete gate, cheap first. The pre-commit hook and CI both run exactly
# this; nothing restates a step.
check: size leak-scan fmt-check lint deny cov doc

# Seat .githooks/* as symlinks in the repo's own hooks directory. NOT
# `core.hooksPath`: a machine may set that globally to a chain hook that execs
# .git/hooks/<name>; seating the links where git already looks keeps both.
install-hooks:
	@top=$$(git rev-parse --path-format=absolute --show-toplevel) && \
	common=$$(git rev-parse --path-format=absolute --git-common-dir) && \
	if [ "$$common" != "$$top/.git" ]; then \
	  echo "install-hooks: run this in the main checkout, not a linked worktree" >&2; \
	  exit 1; \
	fi; \
	mkdir -p "$$common/hooks"; \
	for h in .githooks/*; do \
	  ln -sfn "$$top/$$h" "$$common/hooks/$${h#.githooks/}"; \
	done; \
	echo "hooks: seated $$(ls .githooks | tr '\n' ' ')in $$common/hooks"

clean:
	cargo clean
