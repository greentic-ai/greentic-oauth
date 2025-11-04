.PHONY: build test run fmt fmt-check clippy lint check docker

build:
	cargo build --workspace

test:
	cargo test --workspace

run:
	cargo run -p greentic-oauth-broker

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

lint: clippy

check: fmt-check clippy test

docker:
	@echo "docker target not yet implemented"
