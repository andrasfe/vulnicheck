"""
Integration test configuration and fixtures.
These tests make real API calls and should be run separately from unit tests.
"""

from pathlib import Path

import pytest


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test (requires network)"
    )
    config.addinivalue_line("markers", "slow: mark test as slow running")


@pytest.fixture
def skip_if_no_network():
    """Skip test if network is not available."""
    import socket

    try:
        socket.create_connection(("api.osv.dev", 443), timeout=5)
    except (TimeoutError, OSError):
        pytest.skip("Network connection required for integration tests")


@pytest.fixture
def test_data_dir():
    """Return path to test data directory."""
    return Path(__file__).parent / "test_data"


@pytest.fixture
def vulnerable_packages():
    """Return a list of known vulnerable packages for testing."""
    return [
        {"name": "numpy", "version": "1.19.0", "has_vulnerabilities": True},
        {"name": "flask", "version": "0.12.0", "has_vulnerabilities": True},
        {"name": "django", "version": "2.2.0", "has_vulnerabilities": True},
        {"name": "requests", "version": "2.6.0", "has_vulnerabilities": True},
        {"name": "pyyaml", "version": "5.3", "has_vulnerabilities": True},
        {"name": "pillow", "version": "6.2.0", "has_vulnerabilities": True},
    ]


@pytest.fixture
def safe_packages():
    """Return a list of packages that should be safe (recent versions)."""
    return [
        {"name": "click", "version": "8.1.0", "has_vulnerabilities": False},
        {"name": "black", "version": "23.0.0", "has_vulnerabilities": False},
    ]


@pytest.fixture
def known_cves():
    """Return a list of known CVEs for testing."""
    return [
        "CVE-2021-41495",  # NumPy vulnerability
        "CVE-2018-1000656",  # Flask vulnerability
        "CVE-2021-33203",  # Django vulnerability
        "CVE-2018-18074",  # Requests vulnerability
    ]
