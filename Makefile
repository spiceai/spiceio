.PHONY: build release check fmt lint clippy test clean all

all: fmt lint test build

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy -- -W clippy::all

lint: fmt-check clippy

test: build
	./scripts/test-sccache.sh

clean:
	cargo clean
