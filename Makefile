build:
	cargo build --workspace

test:
	cargo test --workspace

run:
	cargo run -p oauth-broker

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

docker:
	@echo "docker target not yet implemented"
