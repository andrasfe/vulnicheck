#!/bin/bash
# Script to run integration tests

echo "Running VulniCheck Integration Tests"
echo "===================================="
echo ""
echo "Note: These tests make real API calls to OSV.dev and NVD."
echo "They require an active internet connection."
echo ""

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run only integration tests
echo "Running integration tests..."
pytest tests/integration/ -v -m integration --tb=short

# Run with coverage if requested
if [ "$1" == "--coverage" ]; then
    echo ""
    echo "Running with coverage report..."
    pytest tests/integration/ -v -m integration --cov=vulnicheck --cov-report=term-missing
fi

# Run slow tests if requested
if [ "$1" == "--all" ]; then
    echo ""
    echo "Running all integration tests (including slow ones)..."
    pytest tests/integration/ -v -m "integration or slow"
fi

echo ""
echo "Integration tests completed!"