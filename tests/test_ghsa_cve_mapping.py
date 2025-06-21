"""Tests for GHSA to CVE mapping functionality."""
from datetime import datetime
from unittest.mock import patch

import pytest

from vulnicheck.osv_client import Vulnerability
from vulnicheck.server import _format_osv_vulnerability, get_cve_details


class TestGHSAToCVEMapping:
    """Test GHSA to CVE mapping functionality."""

    @pytest.mark.asyncio
    async def test_get_cve_details_with_ghsa_id(self):
        """Test get_cve_details when given a GHSA ID."""
        # Mock OSV vulnerability with CVE alias
        mock_vuln = Vulnerability(
            id="GHSA-mr82-8j83-vxmv",
            summary="Test vulnerability",
            aliases=["CVE-2024-3772"],
            published=datetime(2024, 1, 1),
            modified=datetime(2024, 1, 2),
            affected=[],
            severity=[],
            references=[],
        )

        with patch("vulnicheck.server.osv_client") as mock_osv_client:
            mock_osv_client.get_vulnerability_by_id.return_value = mock_vuln

            # Mock NVD client to return None (CVE not found)
            with patch("vulnicheck.server.cached_get_cve", return_value=None):
                result = await get_cve_details.fn("GHSA-mr82-8j83-vxmv")

        # Should return OSV data when CVE lookup fails
        assert "GHSA-mr82-8j83-vxmv" in result
        assert "CVE-2024-3772" in result
        assert "Test vulnerability" in result

    @pytest.mark.asyncio
    async def test_get_cve_details_ghsa_no_cve_alias(self):
        """Test get_cve_details with GHSA that has no CVE alias."""
        # Mock OSV vulnerability without CVE alias
        mock_vuln = Vulnerability(
            id="GHSA-test-test-test",
            summary="Test vulnerability without CVE",
            aliases=["PYSEC-2024-123"],  # Non-CVE alias
            published=datetime(2024, 1, 1),
            modified=datetime(2024, 1, 2),
            affected=[],
            severity=[],
            references=[],
        )

        with patch("vulnicheck.server.osv_client") as mock_osv_client:
            mock_osv_client.get_vulnerability_by_id.return_value = mock_vuln

            result = await get_cve_details.fn("GHSA-test-test-test")

        # Should return OSV data
        assert "GHSA-test-test-test" in result
        assert "PYSEC-2024-123" in result
        assert "Test vulnerability without CVE" in result

    @pytest.mark.asyncio
    async def test_get_cve_details_ghsa_not_found(self):
        """Test get_cve_details with GHSA ID that doesn't exist."""
        with patch("vulnicheck.server.osv_client") as mock_osv_client:
            mock_osv_client.get_vulnerability_by_id.return_value = None

            result = await get_cve_details.fn("GHSA-xxxx-xxxx-xxxx")

        assert "not found" in result
        assert "not found in OSV database" in result

    @pytest.mark.asyncio
    async def test_get_cve_details_direct_cve(self):
        """Test get_cve_details with direct CVE ID."""
        with patch("vulnicheck.server.cached_get_cve", return_value=None):
            result = await get_cve_details.fn("CVE-2024-12345")

        assert "not found" in result
        assert "CVE-2024-12345 not found" in result

    def test_format_osv_vulnerability(self):
        """Test formatting of OSV vulnerability data."""
        mock_vuln = Vulnerability(
            id="GHSA-test-test-test",
            summary="Test summary",
            details="Test details",
            aliases=["CVE-2024-123", "PYSEC-2024-456"],
            published=datetime(2024, 1, 1),
            modified=datetime(2024, 1, 2),
            affected=[
                {
                    "package": {"name": "test-package", "ecosystem": "PyPI"},
                    "versions": ["1.0.0", "1.0.1", "1.0.2"],
                }
            ],
            severity=[{"type": "CVSS_V3", "score": 7.5}],
            references=[
                {"url": "https://example.com/advisory"},
                {"url": "https://github.com/test/test"},
            ],
        )

        result = _format_osv_vulnerability(mock_vuln)

        # Check formatting
        assert "# GHSA-test-test-test" in result
        assert "**Aliases**: CVE-2024-123, PYSEC-2024-456" in result
        assert "**Published**: 2024-01-01" in result
        assert "**Modified**: 2024-01-02" in result
        assert "Test summary" in result
        assert "## Severity" in result
        assert "- Level: HIGH" in result
        assert "## Affected Versions" in result
        assert "- test-package: 1.0.0, 1.0.1, 1.0.2" in result
        assert "## References" in result
        assert "- https://example.com/advisory" in result

    def test_format_osv_vulnerability_minimal(self):
        """Test formatting with minimal OSV data."""
        mock_vuln = Vulnerability(
            id="GHSA-minimal",
            summary=None,
            details=None,
            aliases=[],
            published=None,
            modified=None,
            affected=[],
            severity=[],
            references=[],
        )

        result = _format_osv_vulnerability(mock_vuln)

        # Check minimal formatting
        assert "# GHSA-minimal" in result
        assert "**Published**: Unknown" in result
        assert "**Modified**: Unknown" in result
        assert "No description available" in result
        assert "## Severity" not in result  # No severity section if unknown
        assert "## Affected Versions" not in result  # No section if empty
        assert "## References" not in result  # No section if empty

    def test_format_osv_vulnerability_many_versions(self):
        """Test formatting with many affected versions."""
        mock_vuln = Vulnerability(
            id="GHSA-many-versions",
            summary="Many versions affected",
            affected=[
                {
                    "package": {"name": "test-package", "ecosystem": "PyPI"},
                    "versions": [f"1.0.{i}" for i in range(20)],  # 20 versions
                }
            ],
            aliases=[],
            published=datetime.now(),
            modified=datetime.now(),
            severity=[],
            references=[],
        )

        result = _format_osv_vulnerability(mock_vuln)

        # Should truncate to first 10 versions
        assert "- test-package: 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7, 1.0.8, 1.0.9" in result
        assert "... and 10 more versions" in result
