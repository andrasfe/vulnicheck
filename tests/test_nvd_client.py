from datetime import datetime
from unittest.mock import Mock, patch

import httpx
import pytest

from vulnicheck.nvd_client import (
    CVEDetail,
    CVSSData,
    NVDClient,
)


class TestCVSSData:
    def test_cvss_data_model(self):
        data = {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
            "exploitabilityScore": 3.9,
            "impactScore": 5.9,
        }

        cvss = CVSSData(**data)
        assert cvss.version == "3.1"
        assert cvss.vectorString == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert cvss.baseScore == 9.8
        assert cvss.baseSeverity == "CRITICAL"
        assert cvss.exploitabilityScore == 3.9
        assert cvss.impactScore == 5.9


class TestCVEDetail:
    def test_cve_detail_model(self):
        cve_data = {
            "id": "CVE-2023-12345",
            "sourceIdentifier": "security@example.com",
            "published": "2023-01-01T00:00:00.000",
            "lastModified": "2023-01-02T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "en", "value": "Test vulnerability description"},
                {"lang": "es", "value": "Descripción de vulnerabilidad de prueba"},
            ],
            "metrics": {},
            "references": [
                {
                    "url": "https://example.com/advisory",
                    "source": "CONFIRM",
                    "tags": ["Vendor Advisory"],
                }
            ],
        }

        cve = CVEDetail(**cve_data)
        assert cve.id == "CVE-2023-12345"
        assert cve.description == "Test vulnerability description"
        assert isinstance(cve.published, datetime)
        assert len(cve.references) == 1

    def test_cve_description_fallback(self):
        cve_data = {
            "id": "CVE-2023-12345",
            "descriptions": [{"lang": "es", "value": "Solo español"}],
        }

        cve = CVEDetail(**cve_data)
        assert cve.description == "Solo español"

    def test_cve_no_description(self):
        cve_data = {"id": "CVE-2023-12345", "descriptions": []}
        cve = CVEDetail(**cve_data)
        assert cve.description == ""

    def test_cvss_v3_property(self):
        cve_data = {
            "id": "CVE-2023-12345",
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
        }

        cve = CVEDetail(**cve_data)
        assert cve.cvss_v3 is not None
        assert cve.cvss_v3.baseScore == 7.5
        assert cve.cvss_v3.baseSeverity == "HIGH"

    def test_cvss_v2_property(self):
        cve_data = {
            "id": "CVE-2023-12345",
            "metrics": {
                "cvssMetricV2": [
                    {
                        "cvssData": {
                            "version": "2.0",
                            "vectorString": "AV:N/AC:L",
                            "baseScore": 7.0,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
        }

        cve = CVEDetail(**cve_data)
        assert cve.cvss_v2 is not None
        assert cve.cvss_v2.baseScore == 7.0

    def test_severity_with_cvss_v3(self):
        cve_data = {
            "id": "CVE-2023-12345",
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        }
                    }
                ]
            },
        }

        cve = CVEDetail(**cve_data)
        assert cve.severity == "CRITICAL"

    def test_severity_with_cvss_v2_only(self):
        test_cases = [(9.5, "CRITICAL"), (7.5, "HIGH"), (5.0, "MEDIUM"), (2.0, "LOW")]

        for score, expected_severity in test_cases:
            cve_data = {
                "id": "CVE-2023-12345",
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N",
                                "baseScore": score,
                                "baseSeverity": "N/A",
                            }
                        }
                    ]
                },
            }

            cve = CVEDetail(**cve_data)
            assert cve.severity == expected_severity

    def test_severity_unknown(self):
        cve_data = {"id": "CVE-2023-12345", "metrics": {}}
        cve = CVEDetail(**cve_data)
        assert cve.severity == "UNKNOWN"
        assert cve.score == 0.0


class TestNVDClient:
    @pytest.fixture
    def client(self):
        return NVDClient(timeout=10)

    @pytest.fixture
    def client_with_api_key(self):
        return NVDClient(api_key="test-api-key", timeout=10)

    @pytest.fixture
    def mock_response(self):
        mock = Mock(spec=httpx.Response)
        mock.raise_for_status = Mock()
        return mock

    def test_init_no_api_key(self, client):
        assert client.api_key is None
        assert client.headers == {}
        assert client.BASE_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def test_init_with_api_key(self, client_with_api_key):
        assert client_with_api_key.api_key == "test-api-key"
        assert client_with_api_key.headers == {"apiKey": "test-api-key"}

    def test_context_manager(self):
        with NVDClient() as client:
            assert isinstance(client, NVDClient)
            assert not client.client.is_closed

    def test_get_cve(self, client, mock_response):
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "descriptions": [{"lang": "en", "value": "Test CVE"}],
                        "metrics": {},
                    }
                }
            ]
        }

        with patch.object(client.client, "get", return_value=mock_response) as mock_get:
            cve = client.get_cve("CVE-2023-12345")

            assert cve is not None
            assert cve.id == "CVE-2023-12345"
            assert cve.description == "Test CVE"

            mock_get.assert_called_once_with(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-12345"
            )

    def test_get_cve_not_found(self, client, mock_response):
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not found", request=Mock(), response=Mock(status_code=404)
        )

        with patch.object(client.client, "get", return_value=mock_response):
            cve = client.get_cve("CVE-NOTFOUND")
            assert cve is None

    def test_get_cve_empty_response(self, client, mock_response):
        mock_response.json.return_value = {"vulnerabilities": []}

        with patch.object(client.client, "get", return_value=mock_response):
            cve = client.get_cve("CVE-2023-12345")
            assert cve is None

    @pytest.mark.asyncio
    async def test_get_cve_async(self, client):
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-ASYNC",
                        "descriptions": [{"lang": "en", "value": "Async test"}],
                        "metrics": {},
                    }
                }
            ]
        }
        mock_response.raise_for_status = Mock()

        with patch("httpx.AsyncClient.get", return_value=mock_response):
            cve = await client.get_cve_async("CVE-2023-ASYNC")

            assert cve is not None
            assert cve.id == "CVE-2023-ASYNC"

    def test_search_cves(self, client, mock_response):
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2023-1", "descriptions": [], "metrics": {}}},
                {"cve": {"id": "CVE-2023-2", "descriptions": [], "metrics": {}}},
            ]
        }

        with patch.object(client.client, "get", return_value=mock_response) as mock_get:
            cves = client.search_cves(
                keyword="test",
                cvss_v3_severity="HIGH",
                results_per_page=10,
                start_index=0,
            )

            assert len(cves) == 2
            assert cves[0].id == "CVE-2023-1"
            assert cves[1].id == "CVE-2023-2"

            mock_get.assert_called_once()
            call_args = mock_get.call_args
            assert call_args[1]["params"]["keywordSearch"] == "test"
            assert call_args[1]["params"]["cvssV3Severity"] == "HIGH"
            assert call_args[1]["params"]["resultsPerPage"] == 10

    def test_get_cve_metrics(self, client, mock_response):
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                        "published": "2023-01-01T00:00:00.000",
                        "lastModified": "2023-01-02T00:00:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N",
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }

        with patch.object(client.client, "get", return_value=mock_response):
            metrics = client.get_cve_metrics("CVE-2023-12345")

            assert metrics["cve_id"] == "CVE-2023-12345"
            assert metrics["description"] == "Test vulnerability"
            assert metrics["severity"] == "HIGH"
            assert metrics["score"] == 7.5
            assert "cvss_v3" in metrics
            assert metrics["cvss_v3"]["base_score"] == 7.5

    def test_get_cve_metrics_not_found(self, client, mock_response):
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not found", request=Mock(), response=Mock(status_code=404)
        )

        with patch.object(client.client, "get", return_value=mock_response):
            metrics = client.get_cve_metrics("CVE-NOTFOUND")
            assert metrics == {}
