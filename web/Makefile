# Makefile for building app for different WASI runtimes
.PHONY: help spin wasmtime clean run test-env

# Load environment variables from ../.env if it exists
ifneq (,$(wildcard ../.env))
    include ../.env
    export
endif

# Default target
help:
	@echo "Available targets:"
	@echo "  make spin     - Build and run with Spin"
	@echo "  make wasmtime - Build and run with Wasmtime"
	@echo "  make clean    - Clean build artifacts"
	@echo "  make test-env - Print environment variables from .env"

# Run target alias
run: wasmtime


# Build and run with Spin
spin:
	@echo "Building for Spin runtime..."
	@mkdir -p .spin
	WASI_RUNTIME=spin cargo leptos build --release
	WASI_RUNTIME=spin LEPTOS_OUTPUT_NAME=web cargo build --lib --target wasm32-wasip2 --release --no-default-features --features ssr
	@echo "Built: target/wasm32-wasip2/release/web.wasm (for Spin)"
	@echo "Starting Spin..."
	spin up \
		--env RESEND_API_KEY="$(RESEND_API_KEY)" \
		--env RESEND_SENDER="$(RESEND_SENDER)" \
		--env SHOW_LOCAL_TESTING_LINKS="$(SHOW_LOCAL_TESTING_LINKS)"

# Build and run with Wasmtime
wasmtime:
	@echo "Building for Wasmtime runtime..."
	WASI_RUNTIME=wasmtime cargo leptos build --release
	WASI_RUNTIME=wasmtime LEPTOS_OUTPUT_NAME=web cargo build --lib --target wasm32-wasip2 --release --no-default-features --features ssr --target-dir target/wasmtime
	@echo "Built: target/wasmtime/wasm32-wasip2/release/web.wasm (for Wasmtime)"
	@echo "Starting Wasmtime serve..."
	@mkdir -p ./data
	@PORT=4000; \
	while lsof -i :$$PORT >/dev/null 2>&1; do \
		PORT=$$((PORT+1)); \
	done; \
	echo "Serving at http://127.0.0.1:$$PORT"; \
	wasmtime serve \
		-W component-model-async=y \
		-S p3=y \
		-S cli=y \
		-S http=y \
		--dir=./target/site/pkg::/ \
		--dir=./data::/data \
		--env=LEPTOS_OUTPUT_NAME=web \
		--env=LEPTOS_SITE_ROOT=/ \
		--env=LEPTOS_SITE_PKG_DIR=pkg \
		--env=RESEND_API_KEY="$(RESEND_API_KEY)" \
		--env=RESEND_SENDER="$(RESEND_SENDER)" \
		--env=SHOW_LOCAL_TESTING_LINKS="$(SHOW_LOCAL_TESTING_LINKS)" \
		--addr 127.0.0.1:$$PORT \
		target/wasmtime/wasm32-wasip2/release/web.wasm

# Clean target
clean:
	cargo clean
	rm -rf target/site target/wasmtime ./data
	rm -rf .spin

test-env:
	@echo "RESEND_API_KEY: $(RESEND_API_KEY)"
	@echo "RESEND_SENDER: $(RESEND_SENDER)"
	@echo "SHOW_LOCAL_TESTING_LINKS: $(SHOW_LOCAL_TESTING_LINKS)"
