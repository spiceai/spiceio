.PHONY: build release check fmt fmt-check clippy doc lint test clean all

all: fmt lint test build

build:
	cargo build --locked --all-targets --all-features

release:
	cargo build --release --locked

check:
	cargo check --locked --all-targets --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --locked --all-targets --all-features -- -D warnings -D clippy::all -D clippy::cargo -A clippy::cargo-common-metadata

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --document-private-items

lint: fmt-check check clippy doc

test: build
	./scripts/test-sccache.sh

clean:
	cargo clean
