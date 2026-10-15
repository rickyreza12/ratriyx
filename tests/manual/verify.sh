#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
cd /mnt/e/Projects/NyxRoute/apps || exit 9
echo "cargo=$(which cargo)"
cargo fmt --check; echo "fmt=$?"
cargo clippy --all-targets --all-features -- -D warnings 2>&1 | tail -5; echo "clippy=$?"
cargo test 2>&1 | tail -25; echo "test=$?"
cargo build --release 2>&1 | tail -3; echo "release=$?"
./target/release/ratriyx --help | head -5; echo "help=$?"
