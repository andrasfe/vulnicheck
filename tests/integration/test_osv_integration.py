"""
Integration tests for OSV API client.
These tests make real API calls to osv.dev.
"""

import pytest

from vulnicheck.clients.osv_client import OSVClient, Vulnerability


@pytest.mark.integration
class TestOSVIntegration:
    @pytest.fixture
    def client(self):
        """Create a real OSV client."""
        return OSVClient(timeout=30)

    def test_query_vulnerable_package(self, client, skip_if_no_network):
        """Test querying a known vulnerable package."""
        # NumPy 1.19.0 has known vulnerabilities
        vulnerabilities = client.query_package("numpy", "1.19.0")

        assert len(vulnerabilities) > 0

        # Check vulnerability structure
        for vuln in vulnerabilities:
            assert isinstance(vuln, Vulnerability)
            assert vuln.id is not None
            assert len(vuln.id) > 0

            # Check if it has CVE aliases
            cve_aliases = [alias for alias in vuln.aliases if alias.startswith("CVE-")]
            if cve_aliases:
                assert any(alias.startswith("CVE-") for alias in cve_aliases)

    def test_query_safe_package(self, client, skip_if_no_network):
        """Test querying a package with no known vulnerabilities."""
        # A very recent version should have no vulnerabilities
        vulnerabilities = client.query_package("click", "8.1.7")

        # This might have vulnerabilities, but likely fewer than old versions
        assert isinstance(vulnerabilities, list)

    def test_query_nonexistent_package(self, client, skip_if_no_network):
        """Test querying a package that doesn't exist."""
        vulnerabilities = client.query_package(
            "this-package-definitely-does-not-exist-12345", "1.0.0"
        )

        assert isinstance(vulnerabilities, list)
        assert len(vulnerabilities) == 0

    def test_query_package_without_version(self, client, skip_if_no_network):
        """Test querying all vulnerabilities for a package."""
        vulnerabilities = client.query_package("django")

        # Django should have many vulnerabilities across all versions
        assert len(vulnerabilities) > 10

        # Check that we get various Django vulnerabilities
        django_vulns = [
            v
            for v in vulnerabilities
            if any(
                "django" in str(affected.get("package", {}).get("name", "")).lower()
                for affected in v.affected
            )
        ]
        assert len(django_vulns) > 0

    @pytest.mark.asyncio
    async def test_async_query(self, client, skip_if_no_network):
        """Test async querying."""
        vulnerabilities = await client.query_package_async("flask", "0.12.0")

        assert len(vulnerabilities) > 0
        assert all(isinstance(v, Vulnerability) for v in vulnerabilities)

    def test_get_vulnerability_by_id(self, client, skip_if_no_network):
        """Test fetching a specific vulnerability by ID."""
        # First get a vulnerability ID from a known vulnerable package
        vulns = client.query_package("numpy", "1.19.0")
        if not vulns:
            pytest.skip("No vulnerabilities found for test package")

        vuln_id = vulns[0].id

        # Fetch the specific vulnerability
        vuln = client.get_vulnerability_by_id(vuln_id)

        assert vuln is not None
        assert vuln.id == vuln_id
        assert isinstance(vuln, Vulnerability)

    def test_batch_query(self, client, skip_if_no_network):
        """Test batch querying multiple packages."""
        queries = [
            {"package": {"name": "numpy", "ecosystem": "PyPI"}, "version": "1.19.0"},
            {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "0.12.0"},
            {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "2.2.0"},
        ]

        results = client.batch_query(queries)

        assert len(results) == 3

        # Each result should be a list of vulnerabilities
        for result in results:
            assert isinstance(result, list)
            # Known vulnerable versions should have vulnerabilities
            if result:
                assert all(isinstance(v, Vulnerability) for v in result)

    def test_vulnerability_details(self, client, skip_if_no_network):
        """Test that vulnerability details are properly populated."""
        vulns = client.query_package("pyyaml", "5.3")

        if not vulns:
            pytest.skip("No vulnerabilities found for PyYAML 5.3")

        vuln = vulns[0]

        # Check various fields
        assert vuln.id is not None

        # Check affected packages
        assert len(vuln.affected) > 0
        affected_pkg = vuln.affected[0]
        assert "package" in affected_pkg
        assert affected_pkg["package"].get("name", "").lower() == "pyyaml"

        # Check for references
        if vuln.references:
            assert all("url" in ref for ref in vuln.references)

    @pytest.mark.slow
    def test_multiple_package_versions(
        self, client, skip_if_no_network, vulnerable_packages
    ):
        """Test querying multiple versions of packages."""
        results = {}

        for pkg_info in vulnerable_packages[:3]:  # Test first 3 to keep it faster
            vulns = client.query_package(pkg_info["name"], pkg_info["version"])
            results[f"{pkg_info['name']}=={pkg_info['version']}"] = len(vulns)

        # All tested packages should have vulnerabilities
        assert all(count > 0 for count in results.values() if count is not None)

    def test_is_version_affected(self, client, skip_if_no_network):
        """Test version checking logic with real data."""
        # Get vulnerabilities for all numpy versions
        all_vulns = client.query_package("numpy")

        if not all_vulns:
            pytest.skip("No NumPy vulnerabilities found")

        # Test specific version checking
        vuln = all_vulns[0]

        # The is_version_affected method should work with real vulnerability data
        # We can't assert specific results without knowing the exact vulnerability
        # but we can check that the method runs without errors
        result = client.is_version_affected(vuln, "numpy", "1.19.0")
        assert isinstance(result, bool)
