#!/bin/bash
#
# Setup Ghidra projects for E2E testing
#
# This script uses analyzeHeadless to:
# 1. Create a Ghidra project for each test binary
# 2. Import the binary
# 3. Run auto-analysis
# 4. Save the project
#
# Usage: ./setup-ghidra-projects.sh [--clean]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$FIXTURES_DIR")"
BINARIES_DIR="$FIXTURES_DIR/binaries"
PROJECTS_DIR="$FIXTURES_DIR/ghidra-projects"

# Check for GHIDRA_HOME
if [ -z "$GHIDRA_HOME" ]; then
    echo "Error: GHIDRA_HOME not set"
    echo "Please set GHIDRA_HOME to your Ghidra installation directory"
    echo "Example: export GHIDRA_HOME=/path/to/ghidra_12.x_PUBLIC"
    exit 1
fi

ANALYZE_HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"

if [ ! -f "$ANALYZE_HEADLESS" ]; then
    echo "Error: analyzeHeadless not found at $ANALYZE_HEADLESS"
    exit 1
fi

# Detect platform
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Unknown architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s)
case "$OS" in
    Darwin) OS="macos" ;;
    Linux) OS="linux" ;;
    *) echo "Unknown OS: $OS"; exit 1 ;;
esac

PLATFORM_DIR="$BINARIES_DIR/${ARCH}-${OS}-O0"

# Handle --clean flag
if [ "$1" = "--clean" ]; then
    echo "Cleaning Ghidra projects..."
    rm -rf "$PROJECTS_DIR"
    echo "Done"
    exit 0
fi

# Check for binaries
if [ ! -d "$PLATFORM_DIR" ]; then
    echo "Error: No binaries found at $PLATFORM_DIR"
    echo "Run 'make native' in test-fixtures/ first"
    exit 1
fi

# Create projects directory
mkdir -p "$PROJECTS_DIR"

echo "========================================"
echo "Setting up Ghidra projects for testing"
echo "========================================"
echo "GHIDRA_HOME: $GHIDRA_HOME"
echo "Platform: ${ARCH}-${OS}"
echo "Binaries: $PLATFORM_DIR"
echo "Projects: $PROJECTS_DIR"
echo ""

# Process each binary
for BINARY in "$PLATFORM_DIR"/*; do
    if [ ! -f "$BINARY" ]; then
        continue
    fi

    BINARY_NAME=$(basename "$BINARY")
    PROJECT_NAME="${BINARY_NAME}_${ARCH}_${OS}"
    PROJECT_PATH="$PROJECTS_DIR/$PROJECT_NAME"

    # Skip if project already exists and is newer than binary
    if [ -d "$PROJECT_PATH.rep" ] && [ "$PROJECT_PATH.rep" -nt "$BINARY" ]; then
        echo "Skipping $BINARY_NAME (project up to date)"
        continue
    fi

    echo ""
    echo "Processing: $BINARY_NAME"
    echo "  Binary: $BINARY"
    echo "  Project: $PROJECT_PATH"

    # Remove old project if exists
    rm -rf "$PROJECT_PATH" "$PROJECT_PATH.rep" "$PROJECT_PATH.gpr"

    # Create project and import binary
    # -import: Import the binary
    # -postScript: (optional) Run post-import script
    # -deleteProject: Don't delete the project after (we want to keep it!)
    # -analysisTimeoutPerFile: Timeout for analysis
    echo "  Creating project and running analysis..."

    "$ANALYZE_HEADLESS" \
        "$PROJECTS_DIR" \
        "$PROJECT_NAME" \
        -import "$BINARY" \
        -analysisTimeoutPerFile 300 \
        -log "$PROJECT_PATH.log" \
        2>&1 | while read line; do
            # Show progress dots
            echo -n "."
        done

    echo ""

    if [ -d "$PROJECT_PATH.rep" ]; then
        echo "  ✓ Project created successfully"
    else
        echo "  ✗ Failed to create project"
        echo "  Check log: $PROJECT_PATH.log"
    fi
done

echo ""
echo "========================================"
echo "Setup complete!"
echo "========================================"

# List created projects
echo ""
echo "Created projects:"
for PROJECT in "$PROJECTS_DIR"/*.rep; do
    if [ -d "$PROJECT" ]; then
        NAME=$(basename "$PROJECT" .rep)
        SIZE=$(du -sh "$PROJECT" 2>/dev/null | cut -f1)
        echo "  $NAME ($SIZE)"
    fi
done
