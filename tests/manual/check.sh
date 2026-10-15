#!/bin/bash
# Read-only local checklist. Never run `cargo fmt` here; use --check only.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd /mnt/e/Projects/NyxRoute/apps || exit 9
cargo fmt --check; echo "fmt=$?"
cargo clippy --all-targets --all-features -- -D warnings >/tmp/clippy.log 2>&1; echo "clippy=$?"
grep -E '^(warning|error)' -A8 /tmp/clippy.log | head -40
cargo test >/tmp/test.log 2>&1; echo "test=$?"
grep -E 'test result|FAILED|failed|panicked|^error' -A4 /tmp/test.log | head -40
cargo build --release >/tmp/rel.log 2>&1; echo "release=$?"
cargo run -q -- --help >/tmp/help.log 2>&1; echo "help=$?"
ls -l target/release/ratriyx | awk '{print "binary bytes=" $5}'
