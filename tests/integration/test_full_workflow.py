"""
Full workflow integration tests that simulate real-world usage scenarios.
"""

import os
import tempfile
from pathlib import Path

import pytest

from vulnicheck.cache import CachedNVDClient, CachedOSVClient
from vulnicheck.nvd_client import NVDClient
from vulnicheck.osv_client import OSVClient
from vulnicheck.scanner import DependencyScanner
from vulnicheck.server import VulniCheckServer  # TODO: Update for FastMCP


@pytest.mark.integration
class TestFullWorkflow:
    @pytest.fixture
    def server(self):
        """Create a fully initialized server."""
        server = VulniCheckServer()
        server.osv_client = CachedOSVClient(OSVClient(), server.cache)
        server.nvd_client = CachedNVDClient(NVDClient(), server.cache)
        server.scanner = DependencyScanner(server.osv_client, server.nvd_client)
        return server

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_developer_workflow(self, server, skip_if_no_network):
        """Test a typical developer workflow: check package, scan deps, get CVE details."""
        workflow_results = {}

        # Step 1: Developer checks if a specific package version is vulnerable
        result = await server._check_package_vulnerabilities(
            {"package_name": "pillow", "version": "6.2.0", "include_details": False}
        )
        workflow_results["package_check"] = result[0].text
        assert "pillow" in result[0].text.lower()

        # Step 2: Developer creates a requirements file and scans it
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_requirements.txt", delete=False
        ) as f:
            f.write("""
# Project dependencies
pillow==6.2.0
django==3.2.0
numpy>=1.19.0,<1.20.0
requests~=2.25.0
""")
            temp_file = f.name

        try:
            result = await server._scan_dependencies(
                {"file_path": temp_file, "include_details": True}
            )
            workflow_results["scan"] = result[0].text

            # Should find vulnerabilities
            assert "vulnerabilities" in result[0].text.lower()
            assert "pillow==6.2.0" in result[0].text

            # Step 3: Developer wants details about a specific CVE mentioned
            if "CVE-" in result[0].text:
                # Extract first CVE ID from the report
                cve_start = result[0].text.find("CVE-")
                cve_end = result[0].text.find(" ", cve_start)
                if cve_end == -1:
                    cve_end = result[0].text.find("\n", cve_start)
                cve_id = result[0].text[cve_start:cve_end].strip(",.")

                if cve_id and len(cve_id) < 20:  # Sanity check
                    cve_result = await server._get_cve_details({"cve_id": cve_id})
                    workflow_results["cve_detail"] = cve_result[0].text
                    assert cve_id in cve_result[0].text

        finally:
            os.unlink(temp_file)

        # Verify workflow produced meaningful results
        assert len(workflow_results) >= 2
        assert all(len(v) > 50 for v in workflow_results.values())

    @pytest.mark.asyncio
    async def test_security_audit_workflow(self, server, skip_if_no_network):
        """Test a security audit workflow: scan multiple files and aggregate results."""
        audit_results = {}

        # Create multiple test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Backend requirements
            backend_reqs = tmpdir_path / "backend_requirements.txt"
            backend_reqs.write_text("""
django==2.2.0
djangorestframework==3.11.0
psycopg2==2.8.0
celery==4.4.0
redis==3.3.0
""")

            # Frontend dependencies
            frontend_deps = tmpdir_path / "frontend_pyproject.toml"
            frontend_deps.write_text("""
[project]
name = "frontend"
dependencies = [
    "flask==1.1.0",
    "jinja2==2.10.0",
    "werkzeug==0.16.0",
]
""")

            # ML dependencies
            ml_reqs = tmpdir_path / "ml_requirements.txt"
            ml_reqs.write_text("""
numpy==1.19.0
scipy==1.4.0
scikit-learn==0.22.0
tensorflow==2.0.0
pandas==0.25.0
""")

            # Scan each component
            for component, filepath in [
                ("backend", backend_reqs),
                ("frontend", frontend_deps),
                ("ml", ml_reqs),
            ]:
                result = await server._scan_dependencies(
                    {"file_path": str(filepath), "include_details": False}
                )

                audit_results[component] = {
                    "report": result[0].text,
                    "has_vulns": "vulnerabilities: 0" not in result[0].text,
                }

        # Verify audit results
        assert len(audit_results) == 3

        # All components should have some vulnerabilities (old versions)
        vulnerable_components = sum(1 for r in audit_results.values() if r["has_vulns"])
        assert vulnerable_components >= 2

        # Reports should mention specific packages
        assert "django" in audit_results["backend"]["report"].lower()
        assert "flask" in audit_results["frontend"]["report"].lower()
        assert "numpy" in audit_results["ml"]["report"].lower()

    @pytest.mark.asyncio
    async def test_upgrade_planning_workflow(self, server, skip_if_no_network):
        """Test workflow for planning package upgrades based on vulnerabilities."""
        # Check multiple versions of a package to find safe upgrade target
        package_name = "urllib3"
        versions_to_check = ["1.24.0", "1.25.0", "1.26.0", "1.26.5"]

        version_results = {}

        for version in versions_to_check:
            result = await server._check_package_vulnerabilities(
                {
                    "package_name": package_name,
                    "version": version,
                    "include_details": False,
                }
            )

            report = result[0].text
            vuln_count = 0

            # Count vulnerabilities
            if "No known vulnerabilities" not in report:
                # Rough count based on vulnerability IDs
                vuln_count = report.count("GHSA-") + report.count("CVE-")

            version_results[version] = {"report": report, "vuln_count": vuln_count}

        # Verify that newer versions have fewer vulnerabilities
        vuln_counts = [r["vuln_count"] for r in version_results.values()]

        # At least one version should have vulnerabilities
        assert max(vuln_counts) > 0

        # Generally, newer versions should be safer (not always true but common)
        # This is a loose check as security fixes can be backported
        assert (
            version_results[versions_to_check[-1]]["vuln_count"]
            <= version_results[versions_to_check[0]]["vuln_count"]
        )

    @pytest.mark.asyncio
    async def test_caching_across_operations(self, server, skip_if_no_network):
        """Test that cache is shared across different operations."""
        # Clear cache to start fresh
        server.cache.clear()

        # Operation 1: Check package
        await server._check_package_vulnerabilities(
            {"package_name": "requests", "version": "2.20.0"}
        )

        # Operation 2: Scan file containing the same package
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests==2.20.0\n")
            temp_file = f.name

        try:
            # This should use cached data for requests
            await server._scan_dependencies({"file_path": temp_file})

            # Cache should have entries
            cache_size = len(server.cache.cache)
            assert cache_size > 0

            # Operation 3: Check same package again
            await server._check_package_vulnerabilities(
                {"package_name": "requests", "version": "2.20.0"}
            )

            # Cache size should not increase (using cached data)
            assert len(server.cache.cache) == cache_size

        finally:
            os.unlink(temp_file)
