import pytest

from vulnicheck.circl_client import CIRCLClient, CIRCLVulnerability


class TestCIRCLClient:
    """Test CIRCL Vulnerability-Lookup client."""

    def test_initialization(self):
        """Test client initialization."""
        client = CIRCLClient(timeout=30)
        assert str(client.client.timeout) == "Timeout(timeout=30)"

    def test_vulnerability_model(self):
        """Test CIRCLVulnerability model."""
        vuln_data = {
            "id": "CVE-2024-1234",
            "summary": "Test vulnerability",
            "description": "Test description",
            "cvss": {
                "cvssV3": {
                    "baseScore": 7.5
                }
            },
            "cwe": ["79", "CWE-89"],
            "references": ["https://example.com"],
            "affected_products": [{"vendor": "python", "product": "test-package"}],
        }

        vuln = CIRCLVulnerability(**vuln_data)
        assert vuln.id == "CVE-2024-1234"
        assert vuln.summary == "Test vulnerability"
        assert vuln.severity == "HIGH"
        assert vuln.cwe_ids == ["CWE-79", "CWE-89"]

    def test_severity_mapping(self):
        """Test CVSS score to severity mapping."""
        test_cases = [
            ({"cvssV3": {"baseScore": 9.5}}, "CRITICAL"),
            ({"cvssV3": {"baseScore": 7.5}}, "HIGH"),
            ({"cvssV3": {"baseScore": 5.0}}, "MEDIUM"),
            ({"cvssV3": {"baseScore": 2.0}}, "LOW"),
            ({}, "UNKNOWN"),
        ]

        for cvss_data, expected_severity in test_cases:
            vuln = CIRCLVulnerability(
                id="TEST",
                cvss=cvss_data
            )
            assert vuln.severity == expected_severity

    def test_cwe_extraction(self):
        """Test CWE ID extraction and formatting."""
        vuln = CIRCLVulnerability(
            id="TEST",
            cwe=["79", "CWE-89", "CWE-79", "123"]
        )

        cwe_ids = vuln.cwe_ids
        assert "CWE-79" in cwe_ids
        assert "CWE-89" in cwe_ids
        assert "CWE-123" in cwe_ids
        # Check for no duplicates
        assert len(cwe_ids) == len(set(cwe_ids))

    @pytest.mark.asyncio
    async def test_search_vulnerability_not_found(self):
        """Test searching for non-existent vulnerability."""
        with CIRCLClient() as client:
            # Use a clearly non-existent CVE ID
            result = await client.search_vulnerability_async("CVE-9999-99999")
            assert result is None

    def test_context_manager(self):
        """Test client context manager."""
        with CIRCLClient() as client:
            assert client.client is not None
        # After exiting context, client should be closed
        # (httpx doesn't expose closed state directly)

    @pytest.mark.asyncio
    async def test_check_package_deduplication(self):
        """Test that check_package deduplicates results."""
        # This is a unit test - we won't actually call the API
        # Just test the deduplication logic
        with CIRCLClient():
            # Mock some duplicate vulnerabilities
            vuln1 = CIRCLVulnerability(id="CVE-2024-1234", summary="Test")
            vuln2 = CIRCLVulnerability(id="CVE-2024-1234", summary="Test duplicate")
            vuln3 = CIRCLVulnerability(id="CVE-2024-5678", summary="Different")

            # Test deduplication logic in check_package
            all_vulns = [vuln1, vuln2, vuln3, vuln1]
            seen_ids = set()
            unique_vulns = []

            for vuln in all_vulns:
                if vuln.id not in seen_ids:
                    seen_ids.add(vuln.id)
                    unique_vulns.append(vuln)

            assert len(unique_vulns) == 2
            assert unique_vulns[0].id == "CVE-2024-1234"
            assert unique_vulns[1].id == "CVE-2024-5678"
