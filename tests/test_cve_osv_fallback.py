"""Tests for CVE lookup with OSV fallback functionality."""

from unittest.mock import MagicMock, patch

import pytest

from vulnicheck.osv_client import Vulnerability
from vulnicheck.server import _format_osv_vulnerability, cached_get_cve, get_osv_client


class TestCVEOSVFallback:
    """Test CVE lookup with OSV fallback when not found in NVD."""

    @pytest.fixture
    def mock_osv_vuln_cve(self):
        """Mock OSV vulnerability for CVE-2024-3772."""
        return Vulnerability(
            id="CVE-2024-3772",
            summary="Regular expression denial of service in Pydantic < 2.4.0, < 1.10.13",
            details="Detailed description of the vulnerability",
            aliases=["GHSA-mr82-8j83-vxmv"],
            published="2024-04-15T00:00:00",
            modified="2025-02-13T00:00:00",
            affected=[
                {
                    "package": {"name": "pydantic", "ecosystem": "PyPI"},
                    "versions": ["2.0", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1"],
                }
            ],
            references=[
                {"url": "https://github.com/pydantic/pydantic/pull/7360"},
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3772"},
            ],
        )

    @pytest.fixture
    def mock_osv_vuln_ghsa(self):
        """Mock OSV vulnerability for GHSA-mr82-8j83-vxmv."""
        return Vulnerability(
            id="GHSA-mr82-8j83-vxmv",
            summary="Pydantic regular expression denial of service",
            details="Detailed description of the vulnerability",
            aliases=["CVE-2024-3772"],
            published="2024-04-15T00:00:00",
            modified="2025-02-13T00:00:00",
            affected=[
                {
                    "package": {"name": "pydantic", "ecosystem": "PyPI"},
                    "versions": ["2.0", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1"],
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

    @patch('vulnicheck.server.cached_get_cve')
    @patch('vulnicheck.server.get_osv_client')
    def test_cve_osv_fallback_logic(self, mock_get_osv_client, mock_cached_get_cve, mock_osv_vuln_cve):
        """Test the fallback logic when CVE is not in NVD."""
        # Mock NVD returning None (not found)
        mock_cached_get_cve.return_value = None

        # Mock OSV client and vulnerability
        mock_osv_client = MagicMock()
        mock_osv_client.get_vulnerability_by_id.return_value = mock_osv_vuln_cve
        mock_get_osv_client.return_value = mock_osv_client

        # This simulates the logic in get_cve_details for CVE IDs
        cve_id = "CVE-2024-3772"
        cve = cached_get_cve(cve_id)

        if not cve:
            osv_client = get_osv_client()
            vuln = osv_client.get_vulnerability_by_id(cve_id)
            assert vuln is not None
            result = _format_osv_vulnerability(vuln)

            assert "CVE-2024-3772" in result
            assert "GHSA-mr82-8j83-vxmv" in result
            assert "pydantic" in result.lower()

    @patch('vulnicheck.server.cached_get_cve')
    @patch('vulnicheck.server.get_osv_client')
    def test_ghsa_lookup_with_cve_alias(self, mock_get_osv_client, mock_cached_get_cve, mock_osv_vuln_ghsa):
        """Test GHSA lookup that has a CVE alias."""
        # Mock NVD returning None for the CVE alias
        mock_cached_get_cve.return_value = None

        # Mock OSV client and vulnerability
        mock_osv_client = MagicMock()
        mock_osv_client.get_vulnerability_by_id.return_value = mock_osv_vuln_ghsa
        mock_get_osv_client.return_value = mock_osv_client

        # This simulates the logic in get_cve_details for GHSA IDs
        ghsa_id = "GHSA-mr82-8j83-vxmv"
        osv_client = get_osv_client()
        vuln = osv_client.get_vulnerability_by_id(ghsa_id)

        assert vuln is not None
        assert "CVE-2024-3772" in vuln.aliases

        # Try to get CVE details (will fail in this test)
        cve_alias = next((a for a in vuln.aliases if a.startswith("CVE-")), None)
        assert cve_alias == "CVE-2024-3772"

        cve = cached_get_cve(cve_alias)
        if not cve:
            # Fall back to OSV data
            result = _format_osv_vulnerability(vuln)
            assert "GHSA-mr82-8j83-vxmv" in result
            assert "CVE-2024-3772" in result
            assert "pydantic" in result.lower()

    @patch('vulnicheck.server.cached_get_cve')
    @patch('vulnicheck.server.get_osv_client')
    def test_cve_not_found_anywhere(self, mock_get_osv_client, mock_cached_get_cve):
        """Test when CVE is not found in NVD or OSV."""
        # Mock both NVD and OSV returning None
        mock_cached_get_cve.return_value = None

        mock_osv_client = MagicMock()
        mock_osv_client.get_vulnerability_by_id.return_value = None
        mock_get_osv_client.return_value = mock_osv_client

        # Test the lookup
        cve_id = "CVE-2023-99999999"
        cve = cached_get_cve(cve_id)

        if not cve:
            osv_client = get_osv_client()
            vuln = osv_client.get_vulnerability_by_id(cve_id)
            assert vuln is None  # Not found in OSV either
