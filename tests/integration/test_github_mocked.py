"""
GitHub Advisory API integration tests with mocked HTTP responses.

These tests use unittest.mock to mock GitHub API responses, allowing them to run
reliably in CI without requiring GITHUB_TOKEN credentials.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vulnicheck.clients.github_client import GitHubClient

# Pre-recorded response for requests 2.5.0 advisory search (GraphQL format)
MOCK_REQUESTS_ADVISORIES_GRAPHQL = {
    "data": {
        "securityVulnerabilities": {
            "nodes": [
                {
                    "advisory": {
                        "id": "A_kwDOAi_dqM4E3EFD",
                        "ghsaId": "GHSA-9wx4-h78v-vm56",
                        "summary": "Unintended leak of Proxy-Authorization header in requests",
                        "description": "Since Requests v2.3.0, Proxy-Authorization headers are incorrectly leaked...",
                        "severity": "MODERATE",
                        "publishedAt": "2023-05-22T00:00:00Z",
                        "updatedAt": "2023-05-22T00:00:00Z",
                        "withdrawnAt": None,
                        "cvss": {
                            "score": 6.1,
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"
                        },
                        "cwes": {
                            "nodes": [{"cweId": "CWE-200", "name": "Information Exposure"}]
                        },
                        "identifiers": [
                            {"type": "GHSA", "value": "GHSA-9wx4-h78v-vm56"},
                            {"type": "CVE", "value": "CVE-2023-32681"}
                        ],
                        "references": [
                            {"url": "https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56"}
                        ]
                    },
                    "package": {"ecosystem": "PIP", "name": "requests"},
                    "vulnerableVersionRange": ">= 2.3.0, < 2.31.0",
                    "firstPatchedVersion": {"identifier": "2.31.0"}
                }
            ]
        }
    }
}

# Pre-recorded response for specific GHSA ID (REST API format)
MOCK_ADVISORY_REST = {
    "id": "12345",  # Must be string for Pydantic model
    "ghsa_id": "GHSA-xvch-5gv4-984h",
    "cve_id": "CVE-2021-35042",
    "url": "https://api.github.com/advisories/GHSA-xvch-5gv4-984h",
    "html_url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
    "summary": "Django SQL injection vulnerability",
    "description": "Django SQL injection in QuerySet.order_by()...",
    "severity": "high",
    "cvss": {
        "score": 9.8,
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "cwes": [{"cwe_id": "CWE-89", "name": "SQL Injection"}],
    "identifiers": [
        {"type": "GHSA", "value": "GHSA-xvch-5gv4-984h"},
        {"type": "CVE", "value": "CVE-2021-35042"}
    ],
    "references": [
        "https://github.com/django/django/security/advisories/GHSA-xvch-5gv4-984h"
    ],
    "published_at": "2021-04-06T00:00:00Z",
    "updated_at": "2021-04-06T00:00:00Z",
    "withdrawn_at": None,
    "vulnerabilities": [
        {
            "package": {"ecosystem": "pip", "name": "django"},
            "vulnerable_version_range": ">= 3.0, < 3.1.13",
            "first_patched_version": {"identifier": "3.1.13"}
        }
    ]
}

# Pre-recorded response for non-existent package
MOCK_EMPTY_SEARCH: dict[str, Any] = {
    "data": {
        "securityVulnerabilities": {
            "nodes": []
        }
    }
}


def create_mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    """Create a mock httpx.Response."""
    response = MagicMock(spec=httpx.Response)
    response.json.return_value = json_data
    response.status_code = status_code
    response.raise_for_status = MagicMock()
    return response


class TestGitHubIntegrationMocked:
    """GitHub integration tests with mocked HTTP responses."""

    @pytest.fixture
    def mock_sync_client(self):
        """Create a mock synchronous httpx.Client."""
        mock_client = MagicMock()
        mock_client.timeout = 30
        mock_client.headers = {"Accept": "application/vnd.github+json"}
        return mock_client

    def test_search_known_vulnerable_package(self, mock_sync_client):
        """Test searching for a known vulnerable package with mocked response."""
        mock_sync_client.post.return_value = create_mock_response(
            MOCK_REQUESTS_ADVISORIES_GRAPHQL
        )

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = client.search_advisories("requests", "2.5.0")

            assert len(advisories) > 0
            advisory = advisories[0]
            assert advisory.ghsa_id == "GHSA-9wx4-h78v-vm56"
            assert advisory.summary == "Unintended leak of Proxy-Authorization header in requests"
            assert advisory.severity == "MODERATE"
            assert advisory.cve_id == "CVE-2023-32681"

    def test_get_advisory_by_ghsa_id(self, mock_sync_client):
        """Test fetching a specific advisory by GHSA ID with mocked response."""
        mock_sync_client.get.return_value = create_mock_response(MOCK_ADVISORY_REST)

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisory = client.get_advisory_by_id("GHSA-xvch-5gv4-984h")

            assert advisory is not None
            assert advisory.ghsa_id == "GHSA-xvch-5gv4-984h"
            assert advisory.summary == "Django SQL injection vulnerability"
            assert advisory.severity == "high"
            assert advisory.cve_id == "CVE-2021-35042"
            assert advisory.published_at is not None

    def test_get_nonexistent_advisory(self, mock_sync_client):
        """Test that nonexistent advisories return None with mocked response."""
        mock_response = create_mock_response({}, status_code=404)
        mock_sync_client.get.return_value = mock_response

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisory = client.get_advisory_by_id("GHSA-0000-0000-0000")
            assert advisory is None

    def test_search_nonexistent_package(self, mock_sync_client):
        """Test searching for a package with no vulnerabilities with mocked response."""
        mock_sync_client.post.return_value = create_mock_response(MOCK_EMPTY_SEARCH)

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = client.search_advisories("totally-nonexistent-package-12345")
            assert len(advisories) == 0

    @pytest.mark.asyncio
    async def test_async_search_advisories(self):
        """Test async version of search_advisories with mocked response."""
        mock_response = create_mock_response(MOCK_REQUESTS_ADVISORIES_GRAPHQL)

        mock_async_client = MagicMock()
        mock_async_client.post = AsyncMock(return_value=mock_response)
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "vulnicheck.clients.github_client.httpx.AsyncClient",
            return_value=mock_async_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = await client.search_advisories_async("requests", "2.5.0")

            assert len(advisories) > 0
            advisory = advisories[0]
            assert advisory.ghsa_id == "GHSA-9wx4-h78v-vm56"
            assert advisory.summary == "Unintended leak of Proxy-Authorization header in requests"

    @pytest.mark.asyncio
    async def test_async_get_advisory(self):
        """Test async version of get_advisory_by_id with mocked response."""
        mock_response = create_mock_response(MOCK_ADVISORY_REST)

        mock_async_client = MagicMock()
        mock_async_client.get = AsyncMock(return_value=mock_response)
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "vulnicheck.clients.github_client.httpx.AsyncClient",
            return_value=mock_async_client
        ):
            client = GitHubClient(token="mock-token")
            advisory = await client.get_advisory_by_id_async("GHSA-xvch-5gv4-984h")

            assert advisory is not None
            assert advisory.ghsa_id == "GHSA-xvch-5gv4-984h"
            assert advisory.severity == "high"

    def test_advisory_data_completeness(self, mock_sync_client):
        """Test that advisory data includes all expected fields with mocked response."""
        mock_sync_client.post.return_value = create_mock_response(
            MOCK_REQUESTS_ADVISORIES_GRAPHQL
        )

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = client.search_advisories("requests", "2.5.0")

            assert len(advisories) > 0
            advisory = advisories[0]

            # Check basic fields
            assert advisory.id
            assert advisory.ghsa_id
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

    def test_graphql_error_response(self, mock_sync_client):
        """Test handling of GraphQL error responses."""
        error_response = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": []
                }
            },
            "errors": [
                {"message": "Rate limit exceeded", "type": "RATE_LIMITED"}
            ]
        }
        mock_sync_client.post.return_value = create_mock_response(error_response)

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = client.search_advisories("requests", "2.5.0")
            assert advisories == []

    def test_network_error_raises(self, mock_sync_client):
        """Test that network errors propagate up."""
        mock_sync_client.post.side_effect = httpx.ConnectError("Connection refused")

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            # Network errors should propagate - client doesn't catch them
            with pytest.raises(httpx.ConnectError):
                client.search_advisories("requests", "2.5.0")

    def test_version_filtering(self, mock_sync_client):
        """Test that version filtering returns correct results."""
        mock_response = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "advisory": {
                                "id": "test-1",
                                "ghsaId": "GHSA-test-1234-5678",
                                "summary": "Test vulnerability",
                                "severity": "HIGH",
                                "publishedAt": "2023-01-01T00:00:00Z",
                                "updatedAt": "2023-01-01T00:00:00Z",
                                "cvss": None,
                                "cwes": {"nodes": []},
                                "identifiers": [
                                    {"type": "CVE", "value": "CVE-2023-0001"}
                                ],
                                "references": []
                            },
                            "package": {"ecosystem": "PIP", "name": "test-package"},
                            "vulnerableVersionRange": ">= 1.0.0, < 2.0.0",
                            "firstPatchedVersion": {"identifier": "2.0.0"}
                        }
                    ]
                }
            }
        }
        mock_sync_client.post.return_value = create_mock_response(mock_response)

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")

            # Version within vulnerable range
            advisories = client.search_advisories("test-package", "1.5.0")
            assert len(advisories) == 1

    def test_multiple_advisories(self, mock_sync_client):
        """Test handling multiple advisories."""
        mock_response = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "advisory": {
                                "id": "test-1",
                                "ghsaId": "GHSA-1111-1111-1111",
                                "summary": "First vulnerability",
                                "severity": "HIGH",
                                "publishedAt": "2023-01-01T00:00:00Z",
                                "updatedAt": "2023-01-01T00:00:00Z",
                                "cvss": None,
                                "cwes": {"nodes": []},
                                "identifiers": [
                                    {"type": "CVE", "value": "CVE-2023-0001"}
                                ],
                                "references": []
                            },
                            "package": {"ecosystem": "PIP", "name": "multi-vuln"},
                            "vulnerableVersionRange": ">= 1.0.0",
                            "firstPatchedVersion": {}
                        },
                        {
                            "advisory": {
                                "id": "test-2",
                                "ghsaId": "GHSA-2222-2222-2222",
                                "summary": "Second vulnerability",
                                "severity": "CRITICAL",
                                "publishedAt": "2023-02-01T00:00:00Z",
                                "updatedAt": "2023-02-01T00:00:00Z",
                                "cvss": None,
                                "cwes": {"nodes": []},
                                "identifiers": [
                                    {"type": "CVE", "value": "CVE-2023-0002"}
                                ],
                                "references": []
                            },
                            "package": {"ecosystem": "PIP", "name": "multi-vuln"},
                            "vulnerableVersionRange": ">= 1.0.0",
                            "firstPatchedVersion": {}
                        }
                    ]
                }
            }
        }
        mock_sync_client.post.return_value = create_mock_response(mock_response)

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = client.search_advisories("multi-vuln-package", "1.0.0")

            assert len(advisories) == 2
            ghsa_ids = [a.ghsa_id for a in advisories]
            assert "GHSA-1111-1111-1111" in ghsa_ids
            assert "GHSA-2222-2222-2222" in ghsa_ids

    def test_cvss_score_parsing(self, mock_sync_client):
        """Test that CVSS scores are parsed correctly."""
        mock_sync_client.post.return_value = create_mock_response(
            MOCK_REQUESTS_ADVISORIES_GRAPHQL
        )

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = client.search_advisories("requests", "2.5.0")

            assert len(advisories) > 0
            advisory = advisories[0]
            assert advisory.cvss is not None

    def test_cwe_parsing(self, mock_sync_client):
        """Test that CWE data is parsed correctly."""
        mock_sync_client.post.return_value = create_mock_response(
            MOCK_REQUESTS_ADVISORIES_GRAPHQL
        )

        with patch(
            "vulnicheck.clients.github_client.httpx.Client",
            return_value=mock_sync_client
        ):
            client = GitHubClient(token="mock-token")
            advisories = client.search_advisories("requests", "2.5.0")

            assert len(advisories) > 0
            advisory = advisories[0]
            assert isinstance(advisory.cwes, list)
