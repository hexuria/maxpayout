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
		--direct-mounts \
		--env RESEND_API_KEY="$(RESEND_API_KEY)" \
		--env RESEND_SENDER="$(RESEND_SENDER)" \
		--env SHOW_LOCAL_TESTING_LINKS="$(SHOW_LOCAL_TESTING_LINKS)" \
		--env OAUTH_REDIRECT_BASE_URL="$(OAUTH_REDIRECT_BASE_URL)" \
		--env GOOGLE_CLIENT_ID="$(GOOGLE_CLIENT_ID)" \
		--env GOOGLE_CLIENT_SECRET="$(GOOGLE_CLIENT_SECRET)" \
		--env APPLE_CLIENT_ID="$(APPLE_CLIENT_ID)" \
		--env APPLE_TEAM_ID="$(APPLE_TEAM_ID)" \
		--env APPLE_KEY_ID="$(APPLE_KEY_ID)" \
		--env APPLE_PRIVATE_KEY_PEM="$(APPLE_PRIVATE_KEY_PEM)" \
		--env MICROSOFT_CLIENT_ID="$(MICROSOFT_CLIENT_ID)" \
		--env MICROSOFT_CLIENT_SECRET="$(MICROSOFT_CLIENT_SECRET)" \
		--env FACEBOOK_CLIENT_ID="$(FACEBOOK_CLIENT_ID)" \
		--env FACEBOOK_CLIENT_SECRET="$(FACEBOOK_CLIENT_SECRET)" \
		--env OAUTH_GOOGLE_AUTH_URL="$(OAUTH_GOOGLE_AUTH_URL)" \
		--env OAUTH_GOOGLE_TOKEN_URL="$(OAUTH_GOOGLE_TOKEN_URL)" \
		--env OAUTH_GOOGLE_JWKS_URL="$(OAUTH_GOOGLE_JWKS_URL)" \
		--env OAUTH_GOOGLE_PROFILE_URL="$(OAUTH_GOOGLE_PROFILE_URL)" \
		--env OAUTH_GOOGLE_ISSUER="$(OAUTH_GOOGLE_ISSUER)" \
		--env OAUTH_GOOGLE_SCOPES="$(OAUTH_GOOGLE_SCOPES)" \
		--env OAUTH_APPLE_AUTH_URL="$(OAUTH_APPLE_AUTH_URL)" \
		--env OAUTH_APPLE_TOKEN_URL="$(OAUTH_APPLE_TOKEN_URL)" \
		--env OAUTH_APPLE_JWKS_URL="$(OAUTH_APPLE_JWKS_URL)" \
		--env OAUTH_APPLE_PROFILE_URL="$(OAUTH_APPLE_PROFILE_URL)" \
		--env OAUTH_APPLE_ISSUER="$(OAUTH_APPLE_ISSUER)" \
		--env OAUTH_APPLE_SCOPES="$(OAUTH_APPLE_SCOPES)" \
		--env OAUTH_MICROSOFT_AUTH_URL="$(OAUTH_MICROSOFT_AUTH_URL)" \
		--env OAUTH_MICROSOFT_TOKEN_URL="$(OAUTH_MICROSOFT_TOKEN_URL)" \
		--env OAUTH_MICROSOFT_JWKS_URL="$(OAUTH_MICROSOFT_JWKS_URL)" \
		--env OAUTH_MICROSOFT_PROFILE_URL="$(OAUTH_MICROSOFT_PROFILE_URL)" \
		--env OAUTH_MICROSOFT_ISSUER="$(OAUTH_MICROSOFT_ISSUER)" \
		--env OAUTH_MICROSOFT_SCOPES="$(OAUTH_MICROSOFT_SCOPES)" \
		--env OAUTH_FACEBOOK_AUTH_URL="$(OAUTH_FACEBOOK_AUTH_URL)" \
		--env OAUTH_FACEBOOK_TOKEN_URL="$(OAUTH_FACEBOOK_TOKEN_URL)" \
		--env OAUTH_FACEBOOK_JWKS_URL="$(OAUTH_FACEBOOK_JWKS_URL)" \
		--env OAUTH_FACEBOOK_PROFILE_URL="$(OAUTH_FACEBOOK_PROFILE_URL)" \
		--env OAUTH_FACEBOOK_ISSUER="$(OAUTH_FACEBOOK_ISSUER)" \
		--env OAUTH_FACEBOOK_SCOPES="$(OAUTH_FACEBOOK_SCOPES)"

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
		--env=OAUTH_REDIRECT_BASE_URL="$(OAUTH_REDIRECT_BASE_URL)" \
		--env=GOOGLE_CLIENT_ID="$(GOOGLE_CLIENT_ID)" \
		--env=GOOGLE_CLIENT_SECRET="$(GOOGLE_CLIENT_SECRET)" \
		--env=APPLE_CLIENT_ID="$(APPLE_CLIENT_ID)" \
		--env=APPLE_TEAM_ID="$(APPLE_TEAM_ID)" \
		--env=APPLE_KEY_ID="$(APPLE_KEY_ID)" \
		--env=APPLE_PRIVATE_KEY_PEM="$(APPLE_PRIVATE_KEY_PEM)" \
		--env=MICROSOFT_CLIENT_ID="$(MICROSOFT_CLIENT_ID)" \
		--env=MICROSOFT_CLIENT_SECRET="$(MICROSOFT_CLIENT_SECRET)" \
		--env=FACEBOOK_CLIENT_ID="$(FACEBOOK_CLIENT_ID)" \
		--env=FACEBOOK_CLIENT_SECRET="$(FACEBOOK_CLIENT_SECRET)" \
		--env=OAUTH_GOOGLE_AUTH_URL="$(OAUTH_GOOGLE_AUTH_URL)" \
		--env=OAUTH_GOOGLE_TOKEN_URL="$(OAUTH_GOOGLE_TOKEN_URL)" \
		--env=OAUTH_GOOGLE_JWKS_URL="$(OAUTH_GOOGLE_JWKS_URL)" \
		--env=OAUTH_GOOGLE_PROFILE_URL="$(OAUTH_GOOGLE_PROFILE_URL)" \
		--env=OAUTH_GOOGLE_ISSUER="$(OAUTH_GOOGLE_ISSUER)" \
		--env=OAUTH_GOOGLE_SCOPES="$(OAUTH_GOOGLE_SCOPES)" \
		--env=OAUTH_APPLE_AUTH_URL="$(OAUTH_APPLE_AUTH_URL)" \
		--env=OAUTH_APPLE_TOKEN_URL="$(OAUTH_APPLE_TOKEN_URL)" \
		--env=OAUTH_APPLE_JWKS_URL="$(OAUTH_APPLE_JWKS_URL)" \
		--env=OAUTH_APPLE_PROFILE_URL="$(OAUTH_APPLE_PROFILE_URL)" \
		--env=OAUTH_APPLE_ISSUER="$(OAUTH_APPLE_ISSUER)" \
		--env=OAUTH_APPLE_SCOPES="$(OAUTH_APPLE_SCOPES)" \
		--env=OAUTH_MICROSOFT_AUTH_URL="$(OAUTH_MICROSOFT_AUTH_URL)" \
		--env=OAUTH_MICROSOFT_TOKEN_URL="$(OAUTH_MICROSOFT_TOKEN_URL)" \
		--env=OAUTH_MICROSOFT_JWKS_URL="$(OAUTH_MICROSOFT_JWKS_URL)" \
		--env=OAUTH_MICROSOFT_PROFILE_URL="$(OAUTH_MICROSOFT_PROFILE_URL)" \
		--env=OAUTH_MICROSOFT_ISSUER="$(OAUTH_MICROSOFT_ISSUER)" \
		--env=OAUTH_MICROSOFT_SCOPES="$(OAUTH_MICROSOFT_SCOPES)" \
		--env=OAUTH_FACEBOOK_AUTH_URL="$(OAUTH_FACEBOOK_AUTH_URL)" \
		--env=OAUTH_FACEBOOK_TOKEN_URL="$(OAUTH_FACEBOOK_TOKEN_URL)" \
		--env=OAUTH_FACEBOOK_JWKS_URL="$(OAUTH_FACEBOOK_JWKS_URL)" \
		--env=OAUTH_FACEBOOK_PROFILE_URL="$(OAUTH_FACEBOOK_PROFILE_URL)" \
		--env=OAUTH_FACEBOOK_ISSUER="$(OAUTH_FACEBOOK_ISSUER)" \
		--env=OAUTH_FACEBOOK_SCOPES="$(OAUTH_FACEBOOK_SCOPES)" \
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
	@echo "OAUTH_REDIRECT_BASE_URL: $(OAUTH_REDIRECT_BASE_URL)"
	@echo "GOOGLE_CLIENT_ID: $(GOOGLE_CLIENT_ID)"
	@echo "GOOGLE_CLIENT_SECRET: $(if $(GOOGLE_CLIENT_SECRET),set,missing)"
	@echo "APPLE_CLIENT_ID: $(APPLE_CLIENT_ID)"
	@echo "APPLE_TEAM_ID: $(APPLE_TEAM_ID)"
	@echo "APPLE_KEY_ID: $(APPLE_KEY_ID)"
	@echo "APPLE_PRIVATE_KEY_PEM: $(if $(APPLE_PRIVATE_KEY_PEM),set,missing)"
	@echo "MICROSOFT_CLIENT_ID: $(MICROSOFT_CLIENT_ID)"
	@echo "MICROSOFT_CLIENT_SECRET: $(if $(MICROSOFT_CLIENT_SECRET),set,missing)"
	@echo "FACEBOOK_CLIENT_ID: $(FACEBOOK_CLIENT_ID)"
	@echo "FACEBOOK_CLIENT_SECRET: $(if $(FACEBOOK_CLIENT_SECRET),set,missing)"
	@echo "OAUTH_GOOGLE_AUTH_URL: $(OAUTH_GOOGLE_AUTH_URL)"
	@echo "OAUTH_APPLE_AUTH_URL: $(OAUTH_APPLE_AUTH_URL)"
	@echo "OAUTH_MICROSOFT_AUTH_URL: $(OAUTH_MICROSOFT_AUTH_URL)"
	@echo "OAUTH_FACEBOOK_AUTH_URL: $(OAUTH_FACEBOOK_AUTH_URL)"
