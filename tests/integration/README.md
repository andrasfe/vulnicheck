# VulniCheck Integration Tests

This directory contains integration tests that make real API calls to external services.

## Overview

The integration tests verify that VulniCheck works correctly with real vulnerability data from:
- OSV.dev API (Open Source Vulnerabilities)
- NVD API (National Vulnerability Database)

## Test Files

### `test_osv_integration.py`
Tests the OSV client with real API calls:
- Querying vulnerable packages
- Fetching vulnerability details
- Batch queries
- Async operations

### `test_nvd_integration.py`
Tests the NVD client with real API calls:
- Fetching CVE details
- CVSS score parsing
- CVE search functionality
- Date parsing

### `test_server_integration.py`
End-to-end tests for the MCP server:
- Package vulnerability checking
- Dependency file scanning
- CVE detail retrieval
- FastMCP integration

### `test_full_workflow.py`
Real-world usage scenarios:
- Developer workflow (check → scan → investigate)
- Security audit workflow
- Upgrade planning workflow
- End-to-end testing with FastMCP

## Running Integration Tests

### Run all integration tests:
```bash
./run_integration_tests.sh
```

### Run with coverage report:
```bash
./run_integration_tests.sh --coverage
```

### Run including slow tests:
```bash
./run_integration_tests.sh --all
```

### Run specific test file:
```bash
pytest tests/integration/test_osv_integration.py -v -m integration
```

### Skip integration tests (unit tests only):
```bash
pytest -m "not integration"
```

## Test Data

The `test_data/` directory contains:
- `vulnerable_requirements.txt` - Known vulnerable packages
- `mixed_requirements.txt` - Mix of vulnerable and safe packages
- `test_pyproject.toml` - Test pyproject.toml with vulnerabilities

## Requirements

- Active internet connection
- Optional: `NVD_API_KEY` environment variable for higher rate limits

## Notes

- Integration tests are slower than unit tests
- They may fail due to network issues or API rate limits
- Results may vary as vulnerability databases are updated
- Some tests are marked as `@pytest.mark.slow` for particularly long operations

## Best Practices

1. Run integration tests separately from unit tests
2. Be mindful of API rate limits
3. Handle network failures gracefully
4. Don't run integration tests in CI/CD on every commit
5. Consider API rate limits when running frequently
