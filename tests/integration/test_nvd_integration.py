"""
Integration tests for NVD API client.
These tests make real API calls to NVD (nvd.nist.gov).
"""

import os
from datetime import datetime

import pytest

from vulnicheck.clients.nvd_client import CVEDetail, NVDClient


@pytest.mark.integration
class TestNVDIntegration:
    @pytest.fixture
    def client(self):
        """Create a real NVD client."""
        # Use API key if available in environment
        api_key = os.environ.get("NVD_API_KEY")
        return NVDClient(api_key=api_key, timeout=30)

    def test_get_known_cve(self, client, skip_if_no_network, known_cves):
        """Test fetching a known CVE."""
        # Try multiple CVEs in case some are not available
        cve = None
        tested_cves = []

        # First try a well-known CVE (Log4Shell)
        well_known_cves = ["CVE-2021-44228", "CVE-2021-45046"] + known_cves

        for cve_id in well_known_cves:
            tested_cves.append(cve_id)
            cve = client.get_cve(cve_id)
            if cve:
                break

        if cve is None:
            pytest.skip(f"None of the tested CVEs are available in NVD: {tested_cves}")

        assert isinstance(cve, CVEDetail)
        assert cve.id in well_known_cves

        # Check basic fields
        assert cve.description is not None and len(cve.description) > 0
        assert cve.published is not None
        assert isinstance(cve.published, datetime)

        # Check severity information
        assert cve.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
        assert cve.score >= 0.0

    def test_get_nonexistent_cve(self, client, skip_if_no_network):
        """Test fetching a CVE that doesn't exist."""
        cve = client.get_cve("CVE-9999-99999")

        assert cve is None

    @pytest.mark.asyncio
    async def test_async_get_cve(self, client, skip_if_no_network, known_cves):
        """Test async CVE fetching."""
        # Try multiple CVEs in case some are not available
        cve = None
        well_known_cves = ["CVE-2021-44228", "CVE-2021-45046"] + known_cves

        for cve_id in well_known_cves:
            cve = await client.get_cve_async(cve_id)
            if cve:
                break

        if cve is None:
            pytest.skip("None of the tested CVEs are available in NVD")

        assert cve is not None
        assert cve.id in well_known_cves
        assert isinstance(cve, CVEDetail)

    def test_cvss_scores(self, client, skip_if_no_network):
        """Test that CVSS scores are properly parsed."""
        # CVE with known CVSS v3 score
        cve = client.get_cve("CVE-2021-41495")

        if cve is None:
            pytest.skip("Could not fetch test CVE")

        # Check CVSS data
        if cve.cvss_v3:
            assert cve.cvss_v3.baseScore > 0
            assert cve.cvss_v3.baseSeverity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            assert cve.cvss_v3.vectorString.startswith("CVSS:3")

        # The severity property should work
        assert cve.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]

    def test_cve_references(self, client, skip_if_no_network):
        """Test that CVE references are properly populated."""
        cve = client.get_cve("CVE-2021-33203")  # Django CVE

        if cve is None:
            pytest.skip("Could not fetch test CVE")

        # Most CVEs should have references
        if cve.references:
            assert len(cve.references) > 0

            for ref in cve.references:
                assert hasattr(ref, "url")
                assert ref.url.startswith("http")

    @pytest.mark.slow
    @pytest.mark.skip(reason="NVD search API is unreliable in CI")
    def test_search_cves_by_keyword(self, client, skip_if_no_network):
        """Test searching CVEs by keyword."""
        # Search for Python-related vulnerabilities
        cves = client.search_cves(keyword="python", results_per_page=5)

        assert isinstance(cves, list)
        assert len(cves) <= 5

        if cves:
            # Check that results are CVEDetail objects
            assert all(isinstance(cve, CVEDetail) for cve in cves)

            # Results should contain the keyword in description
            for cve in cves[:2]:  # Check first 2
                assert "python" in cve.description.lower()

    @pytest.mark.skip(reason="NVD search API is unreliable in CI")
    def test_search_cves_by_severity(self, client, skip_if_no_network):
        """Test searching CVEs by severity level."""
        # Search for critical vulnerabilities
        cves = client.search_cves(cvss_v3_severity="CRITICAL", results_per_page=3)

        assert isinstance(cves, list)
        assert len(cves) <= 3

        if cves:
            # All results should be critical severity
            for cve in cves:
                if cve.cvss_v3:
                    assert cve.cvss_v3.baseSeverity == "CRITICAL"

    def test_get_cve_metrics(self, client, skip_if_no_network, known_cves):
        """Test the get_cve_metrics helper method."""
        # Try multiple CVEs
        metrics = None
        well_known_cves = ["CVE-2021-44228"] + known_cves
        used_cve_id = None

        for cve_id in well_known_cves:
            metrics = client.get_cve_metrics(cve_id)
            if metrics and metrics.get("cve_id"):
                used_cve_id = cve_id
                break

        if not metrics or not metrics.get("cve_id"):
            pytest.skip("No CVEs available for metrics testing")

        assert isinstance(metrics, dict)
        assert metrics.get("cve_id") == used_cve_id
        assert "description" in metrics
        assert "severity" in metrics
        assert "score" in metrics

        # Check optional CVSS data
        if "cvss_v3" in metrics:
            assert "base_score" in metrics["cvss_v3"]
            assert "base_severity" in metrics["cvss_v3"]

    @pytest.mark.slow
    def test_multiple_cve_fetch(self, client, skip_if_no_network, known_cves):
        """Test fetching multiple CVEs."""
        results = {}
        well_known_cves = ["CVE-2021-44228", "CVE-2021-45046"] + known_cves[:3]

        for cve_id in well_known_cves:  # Test well-known + first 3
            cve = client.get_cve(cve_id)
            results[cve_id] = {
                "found": cve is not None,
                "severity": cve.severity if cve else None,
                "score": cve.score if cve else None,
            }

        # At least some CVEs should be found
        found_count = sum(1 for r in results.values() if r["found"])
        if found_count == 0:
            pytest.skip(f"No CVEs found in NVD. Tried: {list(results.keys())}")

        assert found_count > 0

        # Found CVEs should have valid data
        for _, data in results.items():
            if data["found"]:
                assert data["severity"] is not None
                assert data["score"] is not None

    def test_cve_dates(self, client, skip_if_no_network):
        """Test that CVE dates are properly parsed."""
        cve = client.get_cve("CVE-2021-41495")

        if cve is None:
            pytest.skip("Could not fetch test CVE")

        # Check date fields
        assert cve.published is not None
        assert isinstance(cve.published, datetime)

        if cve.lastModified:
            assert isinstance(cve.lastModified, datetime)
            # Modified date should be same or after published date
            assert cve.lastModified >= cve.published
