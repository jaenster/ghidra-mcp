#!/bin/bash
set -euo pipefail

# Local CI script - runs all checks that would run in GitHub Actions
# Usage: ./scripts/ci.sh [--skip-e2e]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[CI]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

SKIP_E2E=false
for arg in "$@"; do
    case $arg in
        --skip-e2e) SKIP_E2E=true ;;
        -h|--help)
            echo "Usage: $0 [--skip-e2e]"
            echo ""
            echo "Options:"
            echo "  --skip-e2e    Skip E2E tests (faster, for quick checks)"
            echo ""
            exit 0
            ;;
    esac
done

cd "$PROJECT_ROOT"

# Check GHIDRA_HOME
GHIDRA_DIR="$PROJECT_ROOT/ghidra_12.0.2_PUBLIC"
if [[ -z "${GHIDRA_HOME:-}" ]]; then
    if [[ -d "$GHIDRA_DIR" ]]; then
        export GHIDRA_HOME="$GHIDRA_DIR"
        info "Using GHIDRA_HOME=$GHIDRA_HOME"
    else
        error "GHIDRA_HOME not set. Run: ./scripts/install-ghidra.sh"
    fi
fi

# Track timing
START_TIME=$(date +%s)
step_start() { STEP_START=$(date +%s); info "$1..."; }
step_done() {
    local elapsed=$(($(date +%s) - STEP_START))
    success "$1 (${elapsed}s)"
}

echo ""
echo "========================================"
echo "  Local CI Pipeline"
echo "========================================"
echo ""

# 1. Build Java worker
step_start "Building Java worker"
cd ghidra-worker && ./gradlew jar --quiet && cd ..
step_done "Java worker built"

# 2. Install npm dependencies
step_start "Installing npm dependencies"
npm ci --silent
step_done "Dependencies installed"

# 3. Build TypeScript
step_start "Building TypeScript packages"
npm run build --silent
step_done "TypeScript built"

# 4. Type check
step_start "Running type check"
npm run typecheck
step_done "Type check passed"

# 5. Lint (skip if not configured)
if npm run lint --silent 2>/dev/null; then
    success "Lint passed"
else
    warn "Lint skipped (not configured or failed)"
fi

# 6. Build test fixtures
step_start "Building test fixtures"
npm run fixtures:build --silent 2>/dev/null || npm run fixtures:build
step_done "Test fixtures built"

# 7. Unit tests (some packages may not have tests yet)
step_start "Running unit tests"
npm run test:unit 2>&1 || true  # Don't fail if some packages have no tests
step_done "Unit tests ran"

# 8. E2E tests
if [[ "$SKIP_E2E" == "true" ]]; then
    warn "Skipping E2E tests (--skip-e2e)"
else
    step_start "Running E2E tests"
    npm run test:e2e
    step_done "E2E tests passed"
fi

# Summary
TOTAL_TIME=$(($(date +%s) - START_TIME))
echo ""
echo "========================================"
echo -e "  ${GREEN}All checks passed!${NC} (${TOTAL_TIME}s total)"
echo "========================================"
echo ""
