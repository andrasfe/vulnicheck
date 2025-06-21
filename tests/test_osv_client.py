from datetime import datetime
from unittest.mock import Mock, patch

import httpx
import pytest
from packaging.version import Version

from vulnicheck.osv_client import OSVClient, Vulnerability


class TestVulnerability:
    def test_vulnerability_model(self):
        vuln_data = {
            "id": "GHSA-test-123",
            "summary": "Test vulnerability",
            "details": "Detailed description",
            "aliases": ["CVE-2023-12345"],
            "modified": "2023-01-01T00:00:00Z",
            "published": "2023-01-01T00:00:00Z",
            "affected": [],
            "severity": [],
            "references": [],
        }

        vuln = Vulnerability(**vuln_data)
        assert vuln.id == "GHSA-test-123"
        assert vuln.summary == "Test vulnerability"
        assert vuln.details == "Detailed description"
        assert vuln.aliases == ["CVE-2023-12345"]
        assert isinstance(vuln.modified, datetime)
        assert isinstance(vuln.published, datetime)


class TestOSVClient:
    @pytest.fixture
    def client(self):
        return OSVClient(timeout=10)

    @pytest.fixture
    def mock_response(self):
        mock = Mock(spec=httpx.Response)
        mock.raise_for_status = Mock()
        return mock

    def test_init(self):
        client = OSVClient(timeout=30)
        assert client.client.timeout.connect == 30
        assert client.BASE_URL == "https://api.osv.dev/v1"

    def test_context_manager(self):
        with OSVClient() as client:
            assert isinstance(client, OSVClient)
            assert not client.client.is_closed

    def test_query_package(self, client, mock_response):
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-123",
                    "summary": "Test vuln",
                    "aliases": ["CVE-2023-12345"],
                    "affected": [],
                    "severity": [],
                    "references": [],
                }
            ]
        }

        with patch.object(
            client.client, "post", return_value=mock_response
        ) as mock_post:
            vulns = client.query_package("numpy", "1.19.0")

            assert len(vulns) == 1
            assert vulns[0].id == "GHSA-123"
            assert vulns[0].summary == "Test vuln"

            mock_post.assert_called_once_with(
                "https://api.osv.dev/v1/query",
                json={
                    "package": {"name": "numpy", "ecosystem": "PyPI"},
                    "version": "1.19.0",
                },
            )

    def test_query_package_no_version(self, client, mock_response):
        mock_response.json.return_value = {"vulns": []}

        with patch.object(
            client.client, "post", return_value=mock_response
        ) as mock_post:
            vulns = client.query_package("flask")

            assert len(vulns) == 0

            mock_post.assert_called_once_with(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": "flask", "ecosystem": "PyPI"}},
            )

    @pytest.mark.asyncio
    async def test_query_package_async(self, client):
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-async",
                    "summary": "Async test",
                    "aliases": [],
                    "affected": [],
                    "severity": [],
                    "references": [],
                }
            ]
        }
        mock_response.raise_for_status = Mock()

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            vulns = await client.query_package_async("django", "3.2.0")

            assert len(vulns) == 1
            assert vulns[0].id == "GHSA-async"

    def test_get_vulnerability_by_id(self, client, mock_response):
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "GHSA-specific",
            "summary": "Specific vulnerability",
            "aliases": [],
            "affected": [],
            "severity": [],
            "references": [],
        }

        with patch.object(client.client, "get", return_value=mock_response):
            vuln = client.get_vulnerability_by_id("GHSA-specific")

            assert vuln is not None
            assert vuln.id == "GHSA-specific"
            assert vuln.summary == "Specific vulnerability"

    def test_get_vulnerability_by_id_not_found(self, client, mock_response):
        mock_response.status_code = 404

        with patch.object(client.client, "get", return_value=mock_response):
            vuln = client.get_vulnerability_by_id("GHSA-notfound")
            assert vuln is None

    def test_batch_query(self, client, mock_response):
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-1",
                            "aliases": [],
                            "affected": [],
                            "severity": [],
                            "references": [],
                        }
                    ]
                },
                {
                    "vulns": [
                        {
                            "id": "GHSA-2",
                            "aliases": [],
                            "affected": [],
                            "severity": [],
                            "references": [],
                        }
                    ]
                },
            ]
        }

        queries = [
            {"package": {"name": "numpy", "ecosystem": "PyPI"}},
            {"package": {"name": "flask", "ecosystem": "PyPI"}},
        ]

        with patch.object(client.client, "post", return_value=mock_response):
            results = client.batch_query(queries)

            assert len(results) == 2
            assert len(results[0]) == 1
            assert results[0][0].id == "GHSA-1"
            assert len(results[1]) == 1
            assert results[1][0].id == "GHSA-2"

    def test_is_version_affected(self, client):
        vuln = Vulnerability(
            id="TEST",
            affected=[
                {
                    "package": {"name": "numpy"},
                    "versions": [
                        "1.19.0",
                        "1.19.1",
                        "1.19.2",
                        "1.19.3",
                        "1.19.4",
                        "1.19.5",
                    ],
                }
            ],
        )

        assert client.is_version_affected(vuln, "numpy", "1.19.5")
        assert not client.is_version_affected(vuln, "numpy", "1.18.0")
        assert not client.is_version_affected(vuln, "numpy", "1.21.0")
        assert not client.is_version_affected(vuln, "numpy", "invalid-version")
        assert not client.is_version_affected(vuln, "flask", "2.0.0")

    def test_check_version_in_range(self, client):
        v = Version("1.19.0")

        assert client._check_version_in_range(v, ">=1.19.0")
        assert client._check_version_in_range(v, ">1.18.0")
        assert client._check_version_in_range(v, "<=1.19.0")
        assert client._check_version_in_range(v, "<1.20.0")
        assert client._check_version_in_range(v, "==1.19.0")
        assert client._check_version_in_range(v, "1.19.0")

        assert not client._check_version_in_range(v, ">1.19.0")
        assert not client._check_version_in_range(v, "<1.19.0")
        assert not client._check_version_in_range(v, "==1.20.0")
        assert not client._check_version_in_range(v, "invalid")
