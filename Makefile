# Build recipes for miemietron.
#
# Cargo is the real build system — this Makefile just wraps the musl
# cross-compilation invocations so release artifacts are reproducible
# without remembering flags. Target CPU tuning lives in .cargo/config.toml.

BIN       := miemietron
X86_TGT   := x86_64-unknown-linux-musl
ARM64_TGT := aarch64-unknown-linux-musl
OUT_DIR   := dist

X86_BIN   := target/$(X86_TGT)/release/$(BIN)
ARM64_BIN := target/$(ARM64_TGT)/release/$(BIN)

.PHONY: help all x86_64 aarch64 dist strip-sizes test check fmt clean distclean

help:
	@echo "miemietron build targets:"
	@echo "  make x86_64       Static musl build for x86_64 routers/VMs"
	@echo "  make aarch64      Static musl build for ARM64 (Cortex-A53, RPi, Filogic)"
	@echo "  make all          Build both targets"
	@echo "  make dist         Copy stripped binaries into ./$(OUT_DIR)/"
	@echo "  make strip-sizes  Show artifact sizes"
	@echo "  make test         cargo test"
	@echo "  make check        cargo check"
	@echo "  make fmt          cargo fmt"
	@echo "  make clean        cargo clean"
	@echo "  make distclean    clean + remove ./$(OUT_DIR)/"

all: x86_64 aarch64

x86_64:
	@rustup target list --installed 2>/dev/null | grep -q '^$(X86_TGT)$$' \
	  || rustup target add $(X86_TGT)
	@command -v musl-gcc >/dev/null 2>&1 || { \
	  echo "error: musl-gcc not found in PATH"; \
	  echo "install musl toolchain: pacman -S musl  OR  apt install musl-tools"; \
	  exit 1; }
	cargo build --release --target $(X86_TGT)

# aarch64 uses the host aarch64-linux-gnu-gcc as the linker. rustc bundles the
# musl libc for the target, so the gnu cross-gcc only acts as the link driver
# — no aarch64-linux-musl-gcc needed, no Docker.
aarch64:
	@rustup target list --installed 2>/dev/null | grep -q '^$(ARM64_TGT)$$' \
	  || rustup target add $(ARM64_TGT)
	@command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || { \
	  echo "error: aarch64-linux-gnu-gcc not found in PATH"; \
	  echo "install aarch64 gnu cross-gcc:"; \
	  echo "  Arch:   pacman -S aarch64-linux-gnu-gcc"; \
	  echo "  Debian: apt install gcc-aarch64-linux-gnu"; \
	  exit 1; }
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
	  cargo build --release --target $(ARM64_TGT)

dist: all
	mkdir -p $(OUT_DIR)
	cp $(X86_BIN)   $(OUT_DIR)/$(BIN)-$(X86_TGT)
	cp $(ARM64_BIN) $(OUT_DIR)/$(BIN)-$(ARM64_TGT)
	@$(MAKE) --no-print-directory strip-sizes

strip-sizes:
	@echo "=== artifact sizes ==="
	@for f in $(X86_BIN) $(ARM64_BIN) $(OUT_DIR)/$(BIN)-$(X86_TGT) $(OUT_DIR)/$(BIN)-$(ARM64_TGT); do \
	  [ -f $$f ] && printf "  %-55s %s\n" $$f "$$(du -h $$f | cut -f1)"; \
	done; true

test:
	cargo test

check:
	cargo check

fmt:
	cargo fmt

clean:
	cargo clean

distclean: clean
	rm -rf $(OUT_DIR)
