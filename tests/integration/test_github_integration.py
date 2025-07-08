import os

import pytest

from vulnicheck.github_client import GitHubClient


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("CI") == "true" or not os.environ.get("GITHUB_TOKEN"),
    reason="GitHub API tests require GITHUB_TOKEN to avoid rate limits"
)
class TestGitHubIntegration:
    @pytest.fixture
    def github_client(self):
        # Use token if available to avoid rate limits
        token = os.environ.get("GITHUB_TOKEN")
        return GitHubClient(token=token)

    def test_search_known_vulnerable_package(self, github_client):
        """Test searching for a known vulnerable package."""
        # Using a well-known vulnerability
        advisories = github_client.search_advisories("requests", "2.5.0")

        assert len(advisories) > 0

        # Check that we get valid advisory data
        for advisory in advisories:
            assert advisory.ghsa_id.startswith("GHSA-")
            assert advisory.summary
            assert advisory.severity in [
                "LOW",
                "MODERATE",
                "HIGH",
                "CRITICAL",
                "UNKNOWN",
            ]

    def test_search_with_specific_version(self, github_client):
        """Test that version filtering works correctly."""
        # Django 2.2.0 had vulnerabilities
        advisories_affected = github_client.search_advisories("django", "2.2.0")

        # Django 4.2.7 should have fewer/different vulnerabilities
        advisories_recent = github_client.search_advisories("django", "4.2.7")

        # We expect different results for different versions
        assert advisories_affected != advisories_recent

    def test_get_advisory_by_ghsa_id(self, github_client):
        """Test fetching a specific advisory by GHSA ID."""
        # Using a known GHSA ID (this is a Django SQL injection vulnerability)
        advisory = github_client.get_advisory_by_id("GHSA-xvch-5gv4-984h")

        if advisory:  # May be None if the advisory was removed
            assert advisory.ghsa_id == "GHSA-xvch-5gv4-984h"
            assert "django" in advisory.summary.lower() or any(
                "django" in v.get("package", {}).get("name", "").lower()
                for v in advisory.vulnerabilities
            )
            assert advisory.cve_id  # Should have a CVE ID
            assert advisory.severity
            assert advisory.published_at

    def test_get_nonexistent_advisory(self, github_client):
        """Test that nonexistent advisories return None."""
        advisory = github_client.get_advisory_by_id("GHSA-0000-0000-0000")
        assert advisory is None

    def test_search_nonexistent_package(self, github_client):
        """Test searching for a package with no vulnerabilities."""
        advisories = github_client.search_advisories(
            "totally-nonexistent-package-12345"
        )
        assert len(advisories) == 0

    @pytest.mark.asyncio
    async def test_async_search_advisories(self, github_client):
        """Test async version of search_advisories."""
        advisories = await github_client.search_advisories_async("requests", "2.5.0")

        assert len(advisories) > 0

        # Verify we get the same type of data as sync version
        for advisory in advisories:
            assert advisory.ghsa_id.startswith("GHSA-")
            assert advisory.summary

    @pytest.mark.asyncio
    async def test_async_get_advisory(self, github_client):
        """Test async version of get_advisory_by_id."""
        advisory = await github_client.get_advisory_by_id_async("GHSA-xvch-5gv4-984h")

        if advisory:
            assert advisory.ghsa_id == "GHSA-xvch-5gv4-984h"
            assert advisory.severity

    def test_advisory_data_completeness(self, github_client):
        """Test that advisory data includes all expected fields."""
        advisories = github_client.search_advisories("werkzeug", "0.15.0")

        if advisories:
            advisory = advisories[0]

            # Check basic fields
            assert advisory.id
            assert advisory.ghsa_id
            assert advisory.url
            assert advisory.html_url
            assert advisory.summary
            assert advisory.severity

            # Check optional fields exist (may be None but should be present)
            assert hasattr(advisory, "description")
            assert hasattr(advisory, "cve_id")
            assert hasattr(advisory, "cvss")
            assert hasattr(advisory, "cwes")
            assert hasattr(advisory, "identifiers")
            assert hasattr(advisory, "references")
            assert hasattr(advisory, "published_at")
            assert hasattr(advisory, "updated_at")
            assert hasattr(advisory, "withdrawn_at")

            # Check vulnerabilities structure
            assert isinstance(advisory.vulnerabilities, list)
            if advisory.vulnerabilities:
                vuln = advisory.vulnerabilities[0]
                assert "package" in vuln
                assert "vulnerable_version_range" in vuln
