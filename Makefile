ci:
	cargo fmt --all -- --check
	cargo clippy --all-features -- -D warnings
	cargo test --all-features -
