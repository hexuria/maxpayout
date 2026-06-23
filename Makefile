# MaxPayout Suite Makefile

# List of crates in the workspace
CRATES := flushline matrix sponsor_allocator potbonus

.PHONY: all check clippy fmt test help $(CRATES)

# Default action runs everything on all crates
all: fmt check clippy test

# List of valid actions that can accept positional arguments
ACTIONS := check clippy fmt test

# Capture positional arguments (crates) passed after the action
# e.g., "make check potbonus" -> ACTION = check, CRATE_ARGS = potbonus
FIRST_ARG := $(firstword $(MAKECMDGOALS))
ifneq ($(filter $(FIRST_ARG),$(ACTIONS)),)
  CRATE_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # Define dummy rules for positional arguments to prevent Make from complaining
  $(eval $(CRATE_ARGS):;@:)
endif

# Determine target crates: use CRATE variable if specified, otherwise positional args, fallback to all crates
TARGET_CRATES := $(or $(CRATE),$(CRATE_ARGS))
ifeq ($(TARGET_CRATES),)
  TARGET_CRATES := $(CRATES)
endif

# Check compilation for native, browser WASM, and WASI targets
check:
	@for crate in $(TARGET_CRATES); do \
		if [ -d "$$crate" ]; then \
			echo "=== Checking compilation for: $$crate ==="; \
			(cd $$crate && cargo check --all-targets && cargo check --target wasm32-unknown-unknown && cargo check --target wasm32-wasip1) || exit 1; \
		else \
			echo "Error: Crate '$$crate' does not exist. Available crates: $(CRATES)"; \
			exit 1; \
		fi; \
	done

# Run cargo clippy with strict warnings denial
clippy:
	@for crate in $(TARGET_CRATES); do \
		if [ -d "$$crate" ]; then \
			echo "=== Running Clippy for: $$crate ==="; \
			(cd $$crate && cargo clippy --all-targets --all-features -- -D warnings) || exit 1; \
		else \
			echo "Error: Crate '$$crate' does not exist. Available crates: $(CRATES)"; \
			exit 1; \
		fi; \
	done

# Format code across target crates
fmt:
	@for crate in $(TARGET_CRATES); do \
		if [ -d "$$crate" ]; then \
			echo "=== Formatting: $$crate ==="; \
			(cd $$crate && cargo fmt --all) || exit 1; \
		else \
			echo "Error: Crate '$$crate' does not exist. Available crates: $(CRATES)"; \
			exit 1; \
		fi; \
	done

# Run unit and integration tests
test:
	@for crate in $(TARGET_CRATES); do \
		if [ -d "$$crate" ]; then \
			echo "=== Running Tests for: $$crate ==="; \
			(cd $$crate && cargo test --all-features) || exit 1; \
			echo ""; \
		else \
			echo "Error: Crate '$$crate' does not exist. Available crates: $(CRATES)"; \
			exit 1; \
		fi; \
	done

# Help menu
help:
	@echo "MaxPayout Suite Command Reference"
	@echo ""
	@echo "Usage:"
	@echo "  make <action> [crate]"
	@echo ""
	@echo "Actions:"
	@echo "  fmt     - Format code using cargo fmt"
	@echo "  check   - Compile and verify compilation for native, browser WASM, and WASI targets"
	@echo "  clippy  - Run cargo clippy (fails on warnings)"
	@echo "  test    - Run all unit and integration tests"
	@echo "  all     - Run fmt, check, clippy, and test on target(s)"
	@echo "  help    - Show this help screen"
	@echo ""
	@echo "Crates:"
	@echo "  flushline, matrix, sponsor_allocator, potbonus"
	@echo ""
	@echo "Examples:"
	@echo "  make check                    # Checks compilation for all crates"
	@echo "  make check potbonus           # Checks compilation for potbonus only"
	@echo "  make test matrix              # Runs tests for matrix only"
	@echo "  make fmt sponsor_allocator    # Formats sponsor_allocator only"
	@echo "  make all CRATE=flushline      # Formats, checks, lints, and tests flushline"
