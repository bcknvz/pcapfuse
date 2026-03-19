.PHONY: build release test check lint fmt fmt-check clean mount unmount validate all

SOURCE ?= ../pcaps
MOUNT ?= /tmp/pcapfuse-mount
NAME ?= merged.pcapng
EXTRA ?=

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

check:
	cargo check

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

clean:
	cargo clean

mount:
	@mkdir -p $(MOUNT)
	cargo run -- --source $(SOURCE) --mount $(MOUNT) --name $(NAME) $(EXTRA)

unmount:
	fusermount -u $(MOUNT)

validate: release
	@mkdir -p $(MOUNT)
	@echo "=== Mounting $(SOURCE) at $(MOUNT) ==="
	./target/release/pcapfuse --source $(SOURCE) --mount $(MOUNT) --name $(NAME) $(EXTRA) &
	@sleep 2
	@echo "=== Basic parse (10 packets) ==="
	tshark -r $(MOUNT)/$(NAME) -c 10
	@echo "=== Display filter: HTTP requests ==="
	tshark -r $(MOUNT)/$(NAME) -Y "http.request" -c 5 || true
	@echo "=== IO stats ==="
	tshark -r $(MOUNT)/$(NAME) -z io,stat,1 -q -c 1000 || true
	@echo "=== Two-pass seek test ==="
	tshark -r $(MOUNT)/$(NAME) -2 -Y "tcp.analysis.retransmission" -c 5 || true
	@echo "=== Unmounting ==="
	fusermount -u $(MOUNT)
	@echo "=== Validation complete ==="

all: fmt lint test build
