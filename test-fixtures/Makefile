# Makefile for compiling test fixtures
#
# Supports:
# - Native compilation (default)
# - Cross-compilation to x86_64/arm64 on macOS
# - Cross-compilation to Linux via zig or Docker
# - Multiple optimization levels
#
# Usage:
#   make native           # Build for current platform with -O0
#   make all-configs      # Build all optimization levels
#   make cross            # Cross-compile macOS architectures
#   make linux            # Cross-compile to Linux (requires zig or docker)
#   make ghidra-setup     # Create Ghidra projects for testing

SRCDIR := src
BINDIR := binaries
SCRIPTS := scripts

# Source files
SOURCES := simple_main.c call_graph.c structures.c imports_exports.c

# Detect host platform
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    HOST_OS := macos
    CAN_CROSS_MACOS := yes
else ifeq ($(UNAME_S),Linux)
    HOST_OS := linux
    CAN_CROSS_MACOS := no
else
    HOST_OS := unknown
    CAN_CROSS_MACOS := no
endif

ifeq ($(UNAME_M),x86_64)
    HOST_ARCH := x86_64
    OTHER_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
    HOST_ARCH := arm64
    OTHER_ARCH := x86_64
else ifeq ($(UNAME_M),aarch64)
    HOST_ARCH := arm64
    OTHER_ARCH := x86_64
else
    HOST_ARCH := unknown
    OTHER_ARCH := unknown
endif

# Check for cross-compilation tools
HAS_ZIG := $(shell command -v zig 2>/dev/null)
HAS_DOCKER := $(shell command -v docker 2>/dev/null)

# Compiler settings
CC := clang
CFLAGS_COMMON := -Wall -Wextra -Wno-unused-parameter

# Architecture-specific flags for macOS
ARCH_FLAGS_arm64_macos := -arch arm64 -target arm64-apple-macos11
ARCH_FLAGS_x86_64_macos := -arch x86_64 -target x86_64-apple-macos10.15

# Optimization levels
OPT_O0 := -O0 -g
OPT_O2 := -O2
OPT_O3 := -O3
OPT_Os := -Os
OPT_stripped := -O2 -s

# Default target
.PHONY: all
all: native

# Build for native platform only (fastest for development)
.PHONY: native
native: $(foreach src,$(SOURCES),$(BINDIR)/$(HOST_ARCH)-$(HOST_OS)-O0/$(basename $(src)))
	@echo ""
	@echo "Built native binaries in $(BINDIR)/$(HOST_ARCH)-$(HOST_OS)-O0/"
	@ls -la $(BINDIR)/$(HOST_ARCH)-$(HOST_OS)-O0/

# Build all optimization levels for native platform
.PHONY: all-configs
all-configs: native
all-configs: $(foreach src,$(SOURCES),$(BINDIR)/$(HOST_ARCH)-$(HOST_OS)-O2/$(basename $(src)))
all-configs: $(foreach src,$(SOURCES),$(BINDIR)/$(HOST_ARCH)-$(HOST_OS)-O3/$(basename $(src)))
all-configs: $(foreach src,$(SOURCES),$(BINDIR)/$(HOST_ARCH)-$(HOST_OS)-Os/$(basename $(src)))

# Cross-compile between macOS architectures
.PHONY: cross
ifeq ($(CAN_CROSS_MACOS),yes)
cross: native
cross: $(foreach src,$(SOURCES),$(BINDIR)/$(OTHER_ARCH)-$(HOST_OS)-O0/$(basename $(src)))
	@echo ""
	@echo "Built cross-compiled binaries in $(BINDIR)/$(OTHER_ARCH)-$(HOST_OS)-O0/"
else
cross:
	@echo "macOS cross-compilation not available on this platform"
endif

# Cross-compile to Linux using zig
.PHONY: linux
linux: linux-x86_64 linux-arm64

.PHONY: linux-x86_64
linux-x86_64:
ifdef HAS_ZIG
	@mkdir -p $(BINDIR)/x86_64-linux-O0
	@for src in $(SOURCES); do \
		name=$$(basename $$src .c); \
		echo "Building $(BINDIR)/x86_64-linux-O0/$$name (zig, x86_64-linux)"; \
		zig cc -target x86_64-linux-gnu $(CFLAGS_COMMON) $(OPT_O0) -o $(BINDIR)/x86_64-linux-O0/$$name $(SRCDIR)/$$src; \
	done
	@echo ""
	@echo "Built Linux x86_64 binaries in $(BINDIR)/x86_64-linux-O0/"
else ifdef HAS_DOCKER
	@echo "Building Linux x86_64 binaries via Docker..."
	docker run --rm -v $(PWD):/work -w /work gcc:13 sh -c '\
		mkdir -p $(BINDIR)/x86_64-linux-O0 && \
		for src in $(SOURCES); do \
			name=$$(basename $$src .c); \
			echo "Building $$name"; \
			gcc $(CFLAGS_COMMON) $(OPT_O0) -o $(BINDIR)/x86_64-linux-O0/$$name $(SRCDIR)/$$src; \
		done'
	@echo ""
	@echo "Built Linux x86_64 binaries in $(BINDIR)/x86_64-linux-O0/"
else
	@echo "Error: Linux cross-compilation requires 'zig' or 'docker'"
	@echo "Install zig: brew install zig (macOS) or see https://ziglang.org"
	@echo "Or use Docker: docker must be installed and running"
	@exit 1
endif

.PHONY: linux-arm64
linux-arm64:
ifdef HAS_ZIG
	@mkdir -p $(BINDIR)/arm64-linux-O0
	@for src in $(SOURCES); do \
		name=$$(basename $$src .c); \
		echo "Building $(BINDIR)/arm64-linux-O0/$$name (zig, aarch64-linux)"; \
		zig cc -target aarch64-linux-gnu $(CFLAGS_COMMON) $(OPT_O0) -o $(BINDIR)/arm64-linux-O0/$$name $(SRCDIR)/$$src; \
	done
	@echo ""
	@echo "Built Linux arm64 binaries in $(BINDIR)/arm64-linux-O0/"
else ifdef HAS_DOCKER
	@echo "Building Linux arm64 binaries via Docker..."
	docker run --rm --platform linux/arm64 -v $(PWD):/work -w /work gcc:13 sh -c '\
		mkdir -p $(BINDIR)/arm64-linux-O0 && \
		for src in $(SOURCES); do \
			name=$$(basename $$src .c); \
			echo "Building $$name"; \
			gcc $(CFLAGS_COMMON) $(OPT_O0) -o $(BINDIR)/arm64-linux-O0/$$name $(SRCDIR)/$$src; \
		done'
	@echo ""
	@echo "Built Linux arm64 binaries in $(BINDIR)/arm64-linux-O0/"
else
	@echo "Error: Linux cross-compilation requires 'zig' or 'docker'"
	@exit 1
endif

# Build everything (all platforms)
.PHONY: full
full: all-configs cross linux

# Generic build rule for macOS
define build_binary_macos
$(BINDIR)/$(1)-macos-$(2)/$(3): $(SRCDIR)/$(3).c | $(BINDIR)/$(1)-macos-$(2)
	@echo "Building $$@ ($(1), $(2))"
	$(CC) $(CFLAGS_COMMON) $(4) $(ARCH_FLAGS_$(1)_macos) -o $$@ $$<
endef

# Generic build rule for Linux native
define build_binary_linux
$(BINDIR)/$(1)-linux-$(2)/$(3): $(SRCDIR)/$(3).c | $(BINDIR)/$(1)-linux-$(2)
	@echo "Building $$@ ($(1), $(2))"
	$(CC) $(CFLAGS_COMMON) $(4) -o $$@ $$<
endef

# Generate build rules based on host OS
ifeq ($(HOST_OS),macos)
$(foreach src,$(SOURCES),$(eval $(call build_binary_macos,$(HOST_ARCH),O0,$(basename $(src)),$(OPT_O0))))
$(foreach src,$(SOURCES),$(eval $(call build_binary_macos,$(HOST_ARCH),O2,$(basename $(src)),$(OPT_O2))))
$(foreach src,$(SOURCES),$(eval $(call build_binary_macos,$(HOST_ARCH),O3,$(basename $(src)),$(OPT_O3))))
$(foreach src,$(SOURCES),$(eval $(call build_binary_macos,$(HOST_ARCH),Os,$(basename $(src)),$(OPT_Os))))
ifeq ($(CAN_CROSS_MACOS),yes)
$(foreach src,$(SOURCES),$(eval $(call build_binary_macos,$(OTHER_ARCH),O0,$(basename $(src)),$(OPT_O0))))
endif
else ifeq ($(HOST_OS),linux)
$(foreach src,$(SOURCES),$(eval $(call build_binary_linux,$(HOST_ARCH),O0,$(basename $(src)),$(OPT_O0))))
$(foreach src,$(SOURCES),$(eval $(call build_binary_linux,$(HOST_ARCH),O2,$(basename $(src)),$(OPT_O2))))
$(foreach src,$(SOURCES),$(eval $(call build_binary_linux,$(HOST_ARCH),O3,$(basename $(src)),$(OPT_O3))))
$(foreach src,$(SOURCES),$(eval $(call build_binary_linux,$(HOST_ARCH),Os,$(basename $(src)),$(OPT_Os))))
endif

# Create output directories
$(BINDIR)/%:
	mkdir -p $@

# Setup Ghidra projects
.PHONY: ghidra-setup
ghidra-setup: native
	@echo "Setting up Ghidra projects..."
	@if [ -z "$$GHIDRA_HOME" ]; then \
		echo "Error: GHIDRA_HOME not set"; \
		exit 1; \
	fi
	$(SCRIPTS)/setup-ghidra-projects.sh

# Clean Ghidra projects
.PHONY: ghidra-clean
ghidra-clean:
	$(SCRIPTS)/setup-ghidra-projects.sh --clean

# Clean all
.PHONY: clean
clean:
	rm -rf $(BINDIR)

# Clean everything including Ghidra projects
.PHONY: distclean
distclean: clean ghidra-clean

# List what would be built
.PHONY: list
list:
	@echo "Host platform: $(HOST_ARCH)-$(HOST_OS)"
	@echo "macOS cross-compile: $(CAN_CROSS_MACOS)"
	@echo "Has zig: $(if $(HAS_ZIG),yes,no)"
	@echo "Has docker: $(if $(HAS_DOCKER),yes,no)"
	@echo ""
	@echo "Sources:"
	@$(foreach src,$(SOURCES),echo "  $(src)";)
	@echo ""
	@echo "Native targets ($(HOST_ARCH)-$(HOST_OS)-O0):"
	@$(foreach src,$(SOURCES),echo "  $(BINDIR)/$(HOST_ARCH)-$(HOST_OS)-O0/$(basename $(src))";)
ifeq ($(CAN_CROSS_MACOS),yes)
	@echo ""
	@echo "macOS cross targets ($(OTHER_ARCH)-macos-O0):"
	@$(foreach src,$(SOURCES),echo "  $(BINDIR)/$(OTHER_ARCH)-macos-O0/$(basename $(src))";)
endif
	@echo ""
	@echo "Linux targets (via zig/docker):"
	@$(foreach src,$(SOURCES),echo "  $(BINDIR)/x86_64-linux-O0/$(basename $(src))";)
	@$(foreach src,$(SOURCES),echo "  $(BINDIR)/arm64-linux-O0/$(basename $(src))";)

# Verify binaries exist
.PHONY: verify
verify:
	@echo "Checking test binaries..."
	@for dir in $(BINDIR)/*/; do \
		if [ -d "$$dir" ]; then \
			echo ""; \
			echo "$$dir:"; \
			for bin in $$dir*; do \
				if [ -f "$$bin" ]; then \
					echo "  $$(basename $$bin): $$(file -b $$bin | head -c 60)"; \
				fi; \
			done; \
		fi; \
	done
	@echo ""
	@if [ -d "ghidra-projects" ]; then \
		echo "Ghidra projects:"; \
		for proj in ghidra-projects/*.rep; do \
			if [ -d "$$proj" ]; then \
				echo "  $$(basename $$proj .rep)"; \
			fi; \
		done; \
	fi

.PHONY: help
help:
	@echo "Test Fixtures Build System"
	@echo ""
	@echo "Targets:"
	@echo "  native       - Build with -O0 for current platform (default)"
	@echo "  all-configs  - Build all optimization levels for current platform"
	@echo "  cross        - Cross-compile to other macOS architecture"
	@echo "  linux        - Cross-compile to Linux x86_64 and arm64 (via zig/docker)"
	@echo "  linux-x86_64 - Cross-compile to Linux x86_64 only"
	@echo "  linux-arm64  - Cross-compile to Linux arm64 only"
	@echo "  full         - Build everything (all platforms, all architectures)"
	@echo "  ghidra-setup - Create Ghidra projects for pre-analyzed testing"
	@echo "  ghidra-clean - Remove Ghidra projects"
	@echo "  clean        - Remove built binaries"
	@echo "  distclean    - Remove everything (binaries + Ghidra projects)"
	@echo "  list         - Show what would be built"
	@echo "  verify       - Check built binaries and projects"
	@echo ""
	@echo "Current platform: $(HOST_ARCH)-$(HOST_OS)"
	@echo "macOS cross-compile: $(CAN_CROSS_MACOS)"
	@echo "Linux cross-compile: $(if $(HAS_ZIG),zig,$(if $(HAS_DOCKER),docker,unavailable))"
