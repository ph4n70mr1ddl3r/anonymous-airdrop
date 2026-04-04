.PHONY: build test lint clean deploy help

help:
	@echo "Anonymous Airdrop - Available commands:"
	@echo "  make build        Build all Rust crates"
	@echo "  make build-prod   Build for production (real proofs)"
	@echo "  make test         Run all tests"
	@echo "  make test-rust    Run Rust tests only"
	@echo "  make test-solidity Run Solidity tests only"
	@echo "  make lint         Run linters"
	@echo "  make clean        Clean build artifacts"
	@echo "  make image-id     Print the guest program Image ID"
	@echo "  make deploy       Run the deployment script"

build:
	RISC0_DEV_MODE=1 cargo build --release

build-prod:
	RISC0_DEV_MODE=0 cargo build --release

test: test-rust test-solidity

test-rust:
	RISC0_DEV_MODE=1 cargo test --release

test-solidity:
	forge test -vvv --root contracts

lint:
	cargo clippy --release -- -D warnings
	forge fmt --check --root contracts

clean:
	cargo clean
	rm -rf contracts/out contracts/cache

image-id:
	cargo run --release -- image-id

deploy:
	bash scripts/deploy.sh
