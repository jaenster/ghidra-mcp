#!/bin/bash
set -euo pipefail

# Ghidra installer for ghidra-mcp development
# Downloads Ghidra for compilation and testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

GHIDRA_VERSION="12.1"
GHIDRA_DATE="20260513"
GHIDRA_ZIP="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}"
GHIDRA_DIR="$PROJECT_ROOT/ghidra_${GHIDRA_VERSION}_PUBLIC"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_dependencies() {
    info "Checking dependencies..."

    # Check for Java 21+
    if ! command -v java &> /dev/null; then
        error "Java not found. Install JDK 21+ (e.g., 'brew install openjdk@21' on macOS)"
    fi

    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
    if [[ "$JAVA_VERSION" -lt 21 ]]; then
        error "Java 21+ required, found version $JAVA_VERSION"
    fi
    info "Java $JAVA_VERSION found"

    # Check for curl or wget
    if command -v curl &> /dev/null; then
        DOWNLOADER="curl -L -o"
    elif command -v wget &> /dev/null; then
        DOWNLOADER="wget -O"
    else
        error "Neither curl nor wget found"
    fi
    info "Using downloader: ${DOWNLOADER%% *}"

    # Check for unzip
    if ! command -v unzip &> /dev/null; then
        error "unzip not found"
    fi
}

install_ghidra() {
    if [[ -d "$GHIDRA_DIR" ]]; then
        info "Ghidra already installed at $GHIDRA_DIR"
        return
    fi

    info "Downloading Ghidra ${GHIDRA_VERSION}..."
    cd "$PROJECT_ROOT"

    if [[ ! -f "$GHIDRA_ZIP" ]]; then
        $DOWNLOADER "$GHIDRA_ZIP" "$GHIDRA_URL"
    fi

    info "Extracting Ghidra..."
    unzip -q "$GHIDRA_ZIP"
    rm "$GHIDRA_ZIP"

    # Make Ghidra scripts executable
    chmod +x "$GHIDRA_DIR/ghidraRun"
    chmod +x "$GHIDRA_DIR/support/analyzeHeadless"

    info "Ghidra installed to $GHIDRA_DIR"
}

print_setup_instructions() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Ghidra Installation Complete!${NC}"
    echo "=========================================="
    echo ""
    echo "Ghidra installed at: $GHIDRA_DIR"
    echo ""
    echo "To build the ghidra-worker:"
    echo ""
    echo "  export GHIDRA_HOME=\"$GHIDRA_DIR\""
    echo "  cd ghidra-worker && ./gradlew jar"
    echo ""
    echo "To run E2E tests:"
    echo ""
    echo "  export GHIDRA_HOME=\"$GHIDRA_DIR\""
    echo "  npm test"
    echo ""
    echo "Add to your shell profile for persistence:"
    echo ""
    echo "  echo 'export GHIDRA_HOME=\"$GHIDRA_DIR\"' >> ~/.zshrc"
    echo ""
}

main() {
    echo "Ghidra Installer for ghidra-mcp"
    echo "================================"
    echo ""

    check_dependencies
    install_ghidra
    print_setup_instructions
}

main "$@"
