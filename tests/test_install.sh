#!/bin/bash
# Test the installer on different platforms

set -e

echo "Testing AgentDiscover Scanner installer..."

# Test 1: Non-interactive install
echo "Test 1: Non-interactive install (layers 1,4)"
./install.sh --non-interactive --layers 1,4

# Verify installation
if ! command -v agent-discover-scanner >/dev/null 2>&1; then
    echo "FAIL: Scanner not installed"
    exit 1
fi

if ! command -v osqueryi >/dev/null 2>&1; then
    echo "FAIL: osquery not installed"
    exit 1
fi

echo "PASS: Basic installation works"

# Test 2: Run a scan
echo "Test 2: Running test scan"
agent-discover-scanner scan --layers 1,4 --output test_report.md

if [ ! -f "test_report.md" ]; then
    echo "FAIL: Report not generated"
    exit 1
fi

echo "PASS: Scan works"

echo ""
echo "All tests passed!"
