from unittest.mock import Mock, patch

import pytest

from vulnicheck.clients.github_client import (
    GitHubAdvisory,
    GitHubClient,
)


@pytest.fixture
def github_client():
    return GitHubClient()


@pytest.fixture
def mock_graphql_response():
    return {
        "data": {
            "securityVulnerabilities": {
                "nodes": [
                    {
                        "advisory": {
                            "id": "SA_kwDOAAYABM4Abcde",
                            "ghsaId": "GHSA-1234-5678-9abc",
                            "summary": "Test vulnerability in package",
                            "description": "Detailed description of the vulnerability",
                            "severity": "HIGH",
                            "cvss": {
                                "score": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            },
                            "cwes": {
                                "nodes": [
                                    {"cweId": "CWE-79", "name": "Cross-site Scripting"}
                                ]
                            },
                            "identifiers": [
                                {"type": "GHSA", "value": "GHSA-1234-5678-9abc"},
                                {"type": "CVE", "value": "CVE-2023-12345"},
                            ],
                            "references": [
                                {
                                    "url": "https://github.com/test/repo/security/advisories/GHSA-1234-5678-9abc"
                                },
                                {
                                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
                                },
                            ],
                            "publishedAt": "2023-01-01T00:00:00Z",
                            "updatedAt": "2023-01-02T00:00:00Z",
                            "withdrawnAt": None,
                        },
                        "package": {"ecosystem": "PIP", "name": "test-package"},
                        "vulnerableVersionRange": ">= 1.0.0, < 2.0.0",
                        "firstPatchedVersion": {"identifier": "2.0.0"},
                    }
                ]
            }
        }
    }


@pytest.fixture
def mock_rest_response():
    return {
        "id": "GHSA-1234-5678-9abc",
        "ghsa_id": "GHSA-1234-5678-9abc",
        "summary": "Test vulnerability",
        "description": "Detailed description",
        "severity": "high",
        "cvss": {
            "score": 7.5,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "cwes": [{"cwe_id": "CWE-79", "name": "Cross-site Scripting"}],
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-1234-5678-9abc"},
            {"type": "CVE", "value": "CVE-2023-12345"},
        ],
        "references": [
            "https://github.com/test/repo/security/advisories/GHSA-1234-5678-9abc"
        ],
        "published_at": "2023-01-01T00:00:00Z",
        "updated_at": "2023-01-02T00:00:00Z",
        "withdrawn_at": None,
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "test-package"},
                "vulnerable_version_range": ">= 1.0.0, < 2.0.0",
                "first_patched_version": {"identifier": "2.0.0"},
                "vulnerable_functions": ["vulnerable_function"],
            }
        ],
        "url": "https://api.github.com/advisories/GHSA-1234-5678-9abc",
        "html_url": "https://github.com/advisories/GHSA-1234-5678-9abc",
    }


class TestGitHubClient:
    def test_init_without_token(self):
        client = GitHubClient()
        assert "Authorization" not in client.headers
        assert client.headers["Accept"] == "application/vnd.github+json"

    def test_init_with_token(self):
        client = GitHubClient(token="test-token")
        assert client.headers["Authorization"] == "Bearer test-token"

    def test_context_manager(self):
        with GitHubClient() as client:
            assert isinstance(client, GitHubClient)

    @patch("httpx.Client.post")
    def test_search_advisories(self, mock_post, github_client, mock_graphql_response):
        mock_response = Mock()
        mock_response.json.return_value = mock_graphql_response
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        advisories = github_client.search_advisories("test-package", "1.5.0")

        assert len(advisories) == 1
        advisory = advisories[0]
        assert advisory.ghsa_id == "GHSA-1234-5678-9abc"
        assert advisory.cve_id == "CVE-2023-12345"
        assert advisory.summary == "Test vulnerability in package"
        assert advisory.severity == "HIGH"
        assert len(advisory.vulnerabilities) == 1

    @patch("httpx.Client.post")
    def test_search_advisories_filters_by_version(
        self, mock_post, github_client, mock_graphql_response
    ):
        mock_response = Mock()
        mock_response.json.return_value = mock_graphql_response
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        # Test with affected version
        advisories = github_client.search_advisories("test-package", "1.5.0")
        assert len(advisories) == 1

        # Test with patched version
        advisories = github_client.search_advisories("test-package", "2.0.0")
        assert len(advisories) == 0

    @patch("httpx.Client.get")
    def test_get_advisory_by_id(self, mock_get, github_client, mock_rest_response):
        mock_response = Mock()
        mock_response.json.return_value = mock_rest_response
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        advisory = github_client.get_advisory_by_id("GHSA-1234-5678-9abc")

        assert advisory is not None
        assert advisory.ghsa_id == "GHSA-1234-5678-9abc"
        assert advisory.cve_id == "CVE-2023-12345"
        assert advisory.severity == "high"
        assert len(advisory.vulnerabilities) == 1

    @patch("httpx.Client.get")
    def test_get_advisory_by_id_not_found(self, mock_get, github_client):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        advisory = github_client.get_advisory_by_id("GHSA-nonexistent")
        assert advisory is None

    def test_is_version_affected(self, github_client):
        # Test various version range formats
        assert github_client._is_version_affected("1.5.0", ">= 1.0.0, < 2.0.0")
        assert not github_client._is_version_affected("0.9.0", ">= 1.0.0, < 2.0.0")
        assert not github_client._is_version_affected("2.0.0", ">= 1.0.0, < 2.0.0")

        # Test with first patched version
        assert not github_client._is_version_affected("2.0.0", ">= 1.0.0", "2.0.0")
        assert github_client._is_version_affected("1.9.0", ">= 1.0.0", "2.0.0")

        # Test single operator ranges
        assert github_client._is_version_affected("1.5.0", "< 2.0.0")
        assert github_client._is_version_affected("2.0.0", ">= 2.0.0")
        assert not github_client._is_version_affected("1.9.0", ">= 2.0.0")

    def test_parse_datetime(self, github_client):
        # Test with microseconds
        dt = github_client._parse_datetime("2023-01-01T12:00:00.123456Z")
        assert dt.year == 2023
        assert dt.month == 1
        assert dt.day == 1
        assert dt.hour == 12

        # Test without microseconds
        dt = github_client._parse_datetime("2023-01-01T12:00:00Z")
        assert dt is not None

        # Test invalid datetime
        dt = github_client._parse_datetime("invalid")
        assert dt is None

        # Test None
        dt = github_client._parse_datetime(None)
        assert dt is None


class TestGitHubAdvisory:
    def test_affected_packages(self):
        advisory = GitHubAdvisory(
            id="test",
            ghsa_id="GHSA-test",
            url="https://test.com",
            html_url="https://test.com",
            summary="Test",
            severity="HIGH",
            vulnerabilities=[
                {
                    "package": {"ecosystem": "pip", "name": "test-package"},
                    "vulnerable_version_range": ">= 1.0.0, < 2.0.0",
                },
                {
                    "package": {"ecosystem": "npm", "name": "test-npm"},
                    "vulnerable_version_range": ">= 1.0.0",
                },
            ],
        )

        affected = advisory.affected_packages
        assert len(affected) == 1  # Only pip packages
        assert affected[0].package["name"] == "test-package"


@pytest.mark.asyncio
class TestAsyncMethods:
    @patch("httpx.AsyncClient.post")
    async def test_search_advisories_async(
        self, mock_post, github_client, mock_graphql_response
    ):
        mock_response = Mock()
        mock_response.json.return_value = mock_graphql_response
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        advisories = await github_client.search_advisories_async(
            "test-package", "1.5.0"
        )

        assert len(advisories) == 1
        assert advisories[0].ghsa_id == "GHSA-1234-5678-9abc"

    @patch("httpx.AsyncClient.get")
    async def test_get_advisory_by_id_async(
        self, mock_get, github_client, mock_rest_response
    ):
        mock_response = Mock()
        mock_response.json.return_value = mock_rest_response
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        advisory = await github_client.get_advisory_by_id_async("GHSA-1234-5678-9abc")

        assert advisory is not None
        assert advisory.ghsa_id == "GHSA-1234-5678-9abc"
