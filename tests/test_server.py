from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from vulnicheck.server import VulniCheckServer  # TODO: Update for FastMCP


class TestVulniCheckServer:
    @pytest.fixture
    def server(self):
        return VulniCheckServer()

    @pytest.fixture
    def mock_osv_client(self):
        client = Mock()
        client.query_package = Mock(return_value=[])
        return client

    @pytest.fixture
    def mock_nvd_client(self):
        client = Mock()
        client.get_cve = Mock(return_value=None)
        return client

    @pytest.fixture
    def mock_scanner(self):
        scanner = Mock()
        scanner.scan_file = AsyncMock(return_value={})
        return scanner

    def test_init(self, server):
        assert server.server.name == "vulnicheck-mcp"
        assert server.cache is not None
        assert server.osv_client is None
        assert server.nvd_client is None
        assert server.scanner is None

    def test_setup_handlers(self, server):
        # Test that handlers are properly set up
        assert hasattr(server.server, "list_tools")
        assert hasattr(server.server, "call_tool")

    @pytest.mark.asyncio
    async def test_check_package_vulnerabilities_no_vulns(
        self, server, mock_osv_client
    ):
        with patch.object(server, "osv_client", mock_osv_client):
            mock_osv_client.query_package.return_value = []

            result = await server._check_package_vulnerabilities(
                {"package_name": "numpy", "version": "1.21.0", "include_details": True}
            )

            assert len(result) == 1
            assert "No known vulnerabilities found" in result[0].text
            assert "numpy version 1.21.0" in result[0].text

    @pytest.mark.asyncio
    async def test_check_package_vulnerabilities_with_vulns(
        self, server, mock_osv_client, mock_nvd_client
    ):
        mock_vuln = Mock()
        mock_vuln.id = "GHSA-test"
        mock_vuln.summary = "Test vulnerability"
        mock_vuln.aliases = ["CVE-2023-12345"]
        mock_vuln.severity = [{"type": "CVSS_V3", "score": 7.5}]
        mock_vuln.references = [{"url": "https://example.com"}]

        mock_cve = Mock()
        mock_cve.score = 7.5
        mock_cve.description = "Detailed CVE description"

        with patch.object(server, "osv_client", mock_osv_client), patch.object(
            server, "nvd_client", mock_nvd_client
        ):
            mock_osv_client.query_package.return_value = [mock_vuln]
            mock_nvd_client.get_cve.return_value = mock_cve

            result = await server._check_package_vulnerabilities(
                {"package_name": "numpy", "version": "1.19.0", "include_details": True}
            )

            assert len(result) == 1
            text = result[0].text
            assert "Python Package Security Report: numpy" in text
            assert "Found 1 vulnerabilities" in text
            assert "GHSA-test" in text
            assert "Test vulnerability" in text
            assert "CVE-2023-12345" in text

    @pytest.mark.asyncio
    async def test_check_package_vulnerabilities_error(self, server, mock_osv_client):
        with patch.object(server, "osv_client", mock_osv_client):
            mock_osv_client.query_package.side_effect = Exception("API Error")

            result = await server._check_package_vulnerabilities(
                {"package_name": "numpy"}
            )

            assert len(result) == 1
            assert "Error checking numpy" in result[0].text
            assert "API Error" in result[0].text

    @pytest.mark.asyncio
    async def test_scan_dependencies_no_vulns(self, server, mock_scanner):
        with patch.object(server, "scanner", mock_scanner):
            mock_scanner.scan_file.return_value = {
                "numpy==1.21.0": [],
                "flask>=2.0.0": [],
            }

            result = await server._scan_dependencies(
                {"file_path": "/path/to/requirements.txt", "include_details": False}
            )

            assert len(result) == 1
            text = result[0].text
            assert "Dependency Vulnerability Scan Report" in text
            assert "No vulnerabilities found" in text

    @pytest.mark.asyncio
    async def test_scan_dependencies_with_vulns(self, server, mock_scanner):
        mock_vuln = Mock()
        mock_vuln.id = "GHSA-numpy"
        mock_vuln.summary = "NumPy vulnerability"
        mock_vuln.severity = []

        with patch.object(server, "scanner", mock_scanner):
            mock_scanner.scan_file.return_value = {
                "numpy==1.19.0": [mock_vuln],
                "flask>=2.0.0": [],
            }

            result = await server._scan_dependencies(
                {"file_path": "/path/to/requirements.txt", "include_details": True}
            )

            assert len(result) == 1
            text = result[0].text
            assert "Total packages scanned: 2" in text
            assert "Packages with vulnerabilities: 1" in text
            assert "numpy==1.19.0" in text
            assert "GHSA-numpy" in text

    @pytest.mark.asyncio
    async def test_scan_dependencies_error(self, server, mock_scanner):
        with patch.object(server, "scanner", mock_scanner):
            mock_scanner.scan_file.side_effect = FileNotFoundError("File not found")

            result = await server._scan_dependencies(
                {"file_path": "/nonexistent/file.txt"}
            )

            assert len(result) == 1
            assert "Error scanning" in result[0].text
            assert "File not found" in result[0].text

    @pytest.mark.asyncio
    async def test_get_cve_details_found(self, server, mock_nvd_client):
        mock_cve = Mock()
        mock_cve.id = "CVE-2023-12345"
        mock_cve.description = "Test CVE description"
        mock_cve.vulnStatus = "Analyzed"
        mock_cve.published = datetime(2023, 1, 1)
        mock_cve.lastModified = datetime(2023, 1, 2)
        mock_cve.cvss_v3 = Mock(
            baseScore=7.5, baseSeverity="HIGH", vectorString="CVSS:3.1/AV:N"
        )
        mock_cve.references = [Mock(url="https://example.com")]

        with patch.object(server, "nvd_client", mock_nvd_client):
            mock_nvd_client.get_cve.return_value = mock_cve

            result = await server._get_cve_details({"cve_id": "CVE-2023-12345"})

            assert len(result) == 1
            text = result[0].text
            assert "CVE Details: CVE-2023-12345" in text
            assert "Test CVE description" in text
            assert "**Score**: 7.5" in text
            assert "**Severity**: HIGH" in text

    @pytest.mark.asyncio
    async def test_get_cve_details_not_found(self, server, mock_nvd_client):
        with patch.object(server, "nvd_client", mock_nvd_client):
            mock_nvd_client.get_cve.return_value = None

            result = await server._get_cve_details({"cve_id": "CVE-NOTFOUND"})

            assert len(result) == 1
            assert "CVE CVE-NOTFOUND not found" in result[0].text

    @pytest.mark.asyncio
    async def test_get_cve_details_error(self, server, mock_nvd_client):
        with patch.object(server, "nvd_client", mock_nvd_client):
            mock_nvd_client.get_cve.side_effect = Exception("API Error")

            result = await server._get_cve_details({"cve_id": "CVE-2023-12345"})

            assert len(result) == 1
            assert "Error fetching CVE" in result[0].text
            assert "API Error" in result[0].text

    def test_get_vulnerability_severity(self, server):
        # Test with CVSS v3 score
        vuln = Mock()
        vuln.severity = [
            {"type": "CVSS_V3", "score": 9.5},
            {"type": "OTHER", "score": 5.0},
        ]
        assert server._get_vulnerability_severity(vuln) == "CRITICAL"

        vuln.severity = [{"type": "CVSS_V3", "score": 7.5}]
        assert server._get_vulnerability_severity(vuln) == "HIGH"

        vuln.severity = [{"type": "CVSS_V3", "score": 5.0}]
        assert server._get_vulnerability_severity(vuln) == "MEDIUM"

        vuln.severity = [{"type": "CVSS_V3", "score": 2.0}]
        assert server._get_vulnerability_severity(vuln) == "LOW"

        # Test with no CVSS v3 score
        vuln.severity = [{"type": "OTHER", "score": 5.0}]
        assert server._get_vulnerability_severity(vuln) == "UNKNOWN"

        vuln.severity = []
        assert server._get_vulnerability_severity(vuln) == "UNKNOWN"

    def test_format_cve_details(self, server):
        mock_cve = Mock()
        mock_cve.id = "CVE-2023-12345"
        mock_cve.description = "Test description"
        mock_cve.vulnStatus = "Analyzed"
        mock_cve.published = datetime(2023, 1, 1)
        mock_cve.lastModified = datetime(2023, 1, 2)
        mock_cve.cvss_v3 = Mock(
            baseScore=7.5, baseSeverity="HIGH", vectorString="CVSS:3.1/AV:N/AC:L"
        )
        mock_cve.references = [
            Mock(url="https://example1.com"),
            Mock(url="https://example2.com"),
        ]

        result = server._format_cve_details(mock_cve)

        assert "CVE Details: CVE-2023-12345" in result
        assert "Test description" in result
        assert "Published**: 2023-01-01" in result
        assert "**Score**: 7.5" in result
        assert "**Severity**: HIGH" in result
        assert "https://example1.com" in result

    def test_generate_vulnerability_report(self, server):
        mock_vuln = Mock()
        mock_vuln.id = "GHSA-test"
        mock_vuln.summary = "Test vulnerability"
        mock_vuln.aliases = ["CVE-2023-12345"]
        mock_vuln.severity = []
        mock_vuln.references = [{"url": "https://example.com"}]

        # Mock the severity method
        with patch.object(server, "_get_vulnerability_severity", return_value="HIGH"):
            report = server._generate_vulnerability_report(
                "numpy", "1.19.0", [mock_vuln], False
            )

        assert "Python Package Security Report: numpy" in report
        assert "Version: 1.19.0" in report
        assert "Found 1 vulnerabilities" in report
        assert "HIGH: 1" in report
        assert "GHSA-test" in report
        assert "Test vulnerability" in report

    def test_generate_scan_report_no_vulns(self, server):
        results = {"numpy==1.21.0": [], "flask>=2.0.0": []}

        report = server._generate_scan_report(
            "/path/to/requirements.txt", results, False
        )

        assert "Dependency Vulnerability Scan Report" in report
        assert "Total packages scanned: 2" in report
        assert "Packages with vulnerabilities: 0" in report
        assert "No vulnerabilities found" in report

    def test_generate_scan_report_with_vulns(self, server):
        mock_vuln1 = Mock()
        mock_vuln1.id = "GHSA-1"
        mock_vuln1.summary = "Vuln 1"

        mock_vuln2 = Mock()
        mock_vuln2.id = "GHSA-2"
        mock_vuln2.summary = "Vuln 2"

        results = {"numpy==1.19.0": [mock_vuln1, mock_vuln2], "flask>=2.0.0": []}

        with patch.object(server, "_get_vulnerability_severity", return_value="HIGH"):
            report = server._generate_scan_report(
                "/path/to/requirements.txt", results, True
            )

        assert "Total packages scanned: 2" in report
        assert "Packages with vulnerabilities: 1" in report
        assert "Total vulnerabilities found: 2" in report
        assert "numpy==1.19.0" in report
        assert "GHSA-1: HIGH" in report
        assert "Vuln 1" in report

    def test_clients_initialization(self, server):
        # Test that clients are initialized when needed
        assert server.osv_client is None
        assert server.nvd_client is None
        assert server.scanner is None
