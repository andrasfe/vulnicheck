"""
End-to-end integration tests for the VulniCheck MCP server.
These tests run the full server with real API calls.
"""

from datetime import datetime
from pathlib import Path

import pytest

from vulnicheck.cache import CachedNVDClient, CachedOSVClient
from vulnicheck.nvd_client import NVDClient
from vulnicheck.osv_client import OSVClient
from vulnicheck.scanner import DependencyScanner
from vulnicheck.server import VulniCheckServer  # TODO: Update for FastMCP


@pytest.mark.integration
class TestServerIntegration:
    @pytest.fixture
    def server(self):
        """Create a real server instance."""
        return VulniCheckServer()

    @pytest.fixture
    def test_files_dir(self):
        """Get the test data directory."""
        return Path(__file__).parent / "test_data"

    @pytest.mark.asyncio
    async def test_check_vulnerable_package(self, server, skip_if_no_network):
        """Test checking a known vulnerable package."""
        # Initialize clients
        if not server.osv_client:
            server.osv_client = CachedOSVClient(OSVClient(), server.cache)
        if not server.nvd_client:
            server.nvd_client = CachedNVDClient(NVDClient(), server.cache)

        result = await server._check_package_vulnerabilities(
            {"package_name": "numpy", "version": "1.19.0", "include_details": True}
        )

        assert len(result) == 1
        report = result[0].text

        # Verify report content
        assert "Python Package Security Report: numpy" in report
        assert "Version: 1.19.0" in report
        assert "vulnerabilities" in report.lower()

        # Should find actual vulnerabilities
        assert "CVE-" in report  # Should have CVE IDs
        assert "Severity" in report
        assert "Recommendation" in report

    @pytest.mark.asyncio
    async def test_check_safe_package(self, server, skip_if_no_network):
        """Test checking a package with no known vulnerabilities."""
        # Initialize clients
        if not server.osv_client:
            server.osv_client = CachedOSVClient(OSVClient(), server.cache)

        result = await server._check_package_vulnerabilities(
            {"package_name": "click", "version": "8.1.7", "include_details": False}
        )

        assert len(result) == 1
        report = result[0].text

        # Should indicate no vulnerabilities or very few
        assert "click" in report
        if "No known vulnerabilities" in report:
            assert "✅" in report

    @pytest.mark.asyncio
    async def test_scan_vulnerable_requirements(
        self, server, skip_if_no_network, test_files_dir
    ):
        """Test scanning a requirements file with known vulnerabilities."""
        # Initialize all clients
        if not server.osv_client:
            server.osv_client = CachedOSVClient(OSVClient(), server.cache)
        if not server.nvd_client:
            server.nvd_client = CachedNVDClient(NVDClient(), server.cache)
        if not server.scanner:
            server.scanner = DependencyScanner(server.osv_client, server.nvd_client)

        requirements_path = test_files_dir / "vulnerable_requirements.txt"

        result = await server._scan_dependencies(
            {"file_path": str(requirements_path), "include_details": True}
        )

        assert len(result) == 1
        report = result[0].text

        # Verify scan report
        assert "Dependency Vulnerability Scan Report" in report
        assert "vulnerable_requirements.txt" in report
        assert "Total packages scanned:" in report
        assert "Packages with vulnerabilities:" in report

        # Should find vulnerabilities in known vulnerable packages
        assert "numpy==1.19.0" in report
        assert "flask==0.12.0" in report
        assert "django==2.2.0" in report

        # Should show vulnerability IDs
        assert "GHSA-" in report or "CVE-" in report

    @pytest.mark.asyncio
    async def test_scan_pyproject_toml(
        self, server, skip_if_no_network, test_files_dir
    ):
        """Test scanning a pyproject.toml file."""
        # Initialize all clients
        if not server.osv_client:
            server.osv_client = CachedOSVClient(OSVClient(), server.cache)
        if not server.nvd_client:
            server.nvd_client = CachedNVDClient(NVDClient(), server.cache)
        if not server.scanner:
            server.scanner = DependencyScanner(server.osv_client, server.nvd_client)

        pyproject_path = test_files_dir / "test_pyproject.toml"

        result = await server._scan_dependencies(
            {"file_path": str(pyproject_path), "include_details": False}
        )

        assert len(result) == 1
        report = result[0].text

        # Should process both [project] and [tool.poetry] dependencies
        assert "Total packages scanned:" in report
        assert int(report.split("Total packages scanned: ")[1].split()[0]) >= 7

    @pytest.mark.asyncio
    async def test_get_cve_details(self, server, skip_if_no_network, known_cves):
        """Test fetching detailed CVE information."""
        # Initialize NVD client
        if not server.nvd_client:
            server.nvd_client = CachedNVDClient(NVDClient(), server.cache)

        cve_id = known_cves[0]  # CVE-2021-41495

        result = await server._get_cve_details({"cve_id": cve_id})

        assert len(result) == 1
        report = result[0].text

        # Verify CVE details
        assert f"CVE Details: {cve_id}" in report
        assert "Description" in report
        assert "Status" in report
        assert "Published" in report

        # Should have CVSS information
        assert "Score" in report or "Severity" in report

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_cache_effectiveness(self, server, skip_if_no_network):
        """Test that caching reduces API calls."""
        # Initialize clients
        if not server.osv_client:
            server.osv_client = CachedOSVClient(OSVClient(), server.cache)

        # First call - should hit the API
        start_time = datetime.now()
        result1 = await server._check_package_vulnerabilities(
            {"package_name": "requests", "version": "2.6.0"}
        )
        first_call_time = (datetime.now() - start_time).total_seconds()

        # Second call - should use cache
        start_time = datetime.now()
        result2 = await server._check_package_vulnerabilities(
            {"package_name": "requests", "version": "2.6.0"}
        )
        second_call_time = (datetime.now() - start_time).total_seconds()

        # Cache hit should be much faster
        assert second_call_time < first_call_time / 2

        # Results should be identical
        assert result1[0].text == result2[0].text

    @pytest.mark.asyncio
    async def test_mixed_dependencies_scan(
        self, server, skip_if_no_network, test_files_dir
    ):
        """Test scanning a file with both vulnerable and safe packages."""
        # Initialize all clients
        if not server.osv_client:
            server.osv_client = CachedOSVClient(OSVClient(), server.cache)
        if not server.nvd_client:
            server.nvd_client = CachedNVDClient(NVDClient(), server.cache)
        if not server.scanner:
            server.scanner = DependencyScanner(server.osv_client, server.nvd_client)

        mixed_path = test_files_dir / "mixed_requirements.txt"

        result = await server._scan_dependencies(
            {"file_path": str(mixed_path), "include_details": False}
        )

        assert len(result) == 1
        report = result[0].text

        # Should identify vulnerable packages
        vulnerable_count = report.count("GHSA-") + report.count("CVE-")
        assert vulnerable_count > 0

        # Should have both safe and vulnerable packages
        assert "numpy==1.19.0" in report  # vulnerable
        assert "click>=8.1.0" in report  # safe

    @pytest.mark.asyncio
    async def test_error_handling(self, server):
        """Test error handling for various failure scenarios."""
        # Test with uninitialized clients
        result = await server._check_package_vulnerabilities({"package_name": "test"})

        # Should handle gracefully
        assert len(result) == 1
        assert "Error" in result[0].text or "error" in result[0].text

        # Test with invalid file path
        if not server.scanner:
            server.scanner = DependencyScanner(
                OSVClient() if not server.osv_client else server.osv_client,
                NVDClient() if not server.nvd_client else server.nvd_client,
            )

        result = await server._scan_dependencies(
            {"file_path": "/nonexistent/path/requirements.txt"}
        )

        assert len(result) == 1
        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_vulnerability_severity_reporting(self, server, skip_if_no_network):
        """Test that vulnerability severities are properly reported."""
        # Initialize clients
        if not server.osv_client:
            server.osv_client = CachedOSVClient(OSVClient(), server.cache)
        if not server.nvd_client:
            server.nvd_client = CachedNVDClient(NVDClient(), server.cache)

        result = await server._check_package_vulnerabilities(
            {"package_name": "django", "version": "2.2.0", "include_details": True}
        )

        assert len(result) == 1
        report = result[0].text

        # Should have severity classifications
        severity_found = any(
            sev in report for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
        assert severity_found

        # Should have summary section
        assert "Summary" in report
