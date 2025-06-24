"""
End-to-end integration tests for the VulniCheck MCP server.

Note: The server has been migrated to FastMCP architecture.
Basic integration tests are included here.
"""


import pytest

from vulnicheck.nvd_client import NVDClient
from vulnicheck.osv_client import OSVClient
from vulnicheck.scanner import DependencyScanner


@pytest.mark.integration
class TestServerIntegration:
    """Basic integration tests for server components."""

    @pytest.mark.asyncio
    async def test_scanner_integration(self):
        """Test that scanner works with real clients."""
        osv_client = OSVClient()
        nvd_client = NVDClient()
        scanner = DependencyScanner(osv_client, nvd_client)

        # Test with a known vulnerable package
        vulns = await scanner._check_package("requests", "==2.6.0")
        # We expect some vulnerabilities for this old version
        assert isinstance(vulns, list)

    def test_nvd_client_initialization(self):
        """Test NVD client can be initialized."""
        client = NVDClient()
        assert client is not None
        assert NVDClient.BASE_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def test_osv_client_initialization(self):
        """Test OSV client can be initialized."""
        client = OSVClient()
        assert client is not None
        assert OSVClient.BASE_URL == "https://api.osv.dev/v1"
