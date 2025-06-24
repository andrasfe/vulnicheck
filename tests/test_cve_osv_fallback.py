"""Tests for CVE lookup with OSV fallback functionality."""


import pytest

from vulnicheck.osv_client import Vulnerability
from vulnicheck.server import _format_osv_vulnerability


class TestCVEOSVFallback:
    """Test CVE lookup with OSV fallback when not found in NVD."""

    @pytest.fixture
    def mock_osv_vuln_cve(self):
        """Create a mock OSV vulnerability that represents a CVE."""
        return Vulnerability(
            id="CVE-2024-3772",
            summary="Regular expression denial of service in Pydantic < 2.4.0, < 1.10.13",
            details="A vulnerability was discovered in Pydantic's regex parsing.",
            aliases=["GHSA-mr82-8j83-vxmv"],
            published="2024-04-15T20:15:00Z",
            modified="2024-04-16T00:00:00Z",
            affected=[
                {
                    "package": {
                        "ecosystem": "PyPI",
                        "name": "pydantic",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0.0"},
                                {"fixed": "2.4.0"},
                            ],
                        }
                    ],
                    "versions": ["2.0.0", "2.1.0", "2.2.0", "2.3.0"],
                },
                {
                    "package": {
                        "ecosystem": "PyPI",
                        "name": "pydantic",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.10.13"},
                            ],
                        }
                    ],
                }
            ],
            references=[
                {"url": "https://github.com/pydantic/pydantic/pull/7360"},
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3772"},
            ],
        )

    def test_format_osv_vulnerability(self, mock_osv_vuln_cve):
        """Test formatting OSV vulnerability data."""
        result = _format_osv_vulnerability(mock_osv_vuln_cve)

        assert "# CVE-2024-3772" in result
        assert "**Aliases**: GHSA-mr82-8j83-vxmv" in result
        assert "Regular expression denial of service" in result
        assert "pydantic" in result.lower()
        assert "## Affected Versions" in result
        assert "## References" in result

    def test_format_osv_vulnerability_minimal(self):
        """Test formatting OSV vulnerability with minimal data."""
        vuln = Vulnerability(
            id="GHSA-test-test-test",
            summary="Test vulnerability",
            details=None,
            aliases=[],
            published=None,
            modified=None,
            affected=[],
            references=[],
        )

        result = _format_osv_vulnerability(vuln)

        assert "# GHSA-test-test-test" in result
        assert "Test vulnerability" in result
        assert "Unknown" in result  # For published/modified dates

    def test_format_osv_vulnerability_no_description(self):
        """Test formatting OSV vulnerability with no description."""
        vuln = Vulnerability(
            id="GHSA-none-none-none",
            summary=None,
            details=None,
            aliases=[],
            published=None,
            modified=None,
            affected=[],
            references=[],
        )

        result = _format_osv_vulnerability(vuln)

        assert "# GHSA-none-none-none" in result
        assert "No description available" in result
