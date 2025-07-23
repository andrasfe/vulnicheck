from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import httpx
import pytest

from vulnicheck.safety_db_client import SafetyDBClient, SafetyDBVulnerability


class TestSafetyDBClient:
    """Test Safety DB client."""

    def test_initialization(self):
        """Test client initialization."""
        client = SafetyDBClient(timeout=30)
        assert str(client.client.timeout) == "Timeout(timeout=30)"
        assert client._db_cache is None
        assert client._cache_time is None
        assert client._cache_duration == 3600

    def test_vulnerability_model(self):
        """Test SafetyDBVulnerability model."""
        vuln_data = {
            "id": "SAFETY-DJANGO-1",
            "package_name": "django",
            "affected_versions": ["<1.11.29", ">=2.0,<2.2.11"],
            "fixed_in": ["1.11.29", "2.2.11", "3.0.4"],
            "description": "Django SQL injection vulnerability",
            "cve": "CVE-2020-1234",
            "more_info_path": "/vulnerabilities/django/123"
        }

        vuln = SafetyDBVulnerability(**vuln_data)
        assert vuln.id == "SAFETY-DJANGO-1"
        assert vuln.package_name == "django"
        assert vuln.cve == "CVE-2020-1234"
        assert vuln.severity == "UNKNOWN"  # Safety DB doesn't include severity
        assert vuln.cwe_ids == []  # Safety DB doesn't include CWE IDs

    def test_cache_behavior(self):
        """Test database caching behavior."""
        client = SafetyDBClient()

        # Mock database content
        mock_db = {"test-package": [{"v": ["<1.0"], "description": "Test vuln"}]}

        # Set cache
        client._db_cache = mock_db
        client._cache_time = datetime.now()

        # Should use cache
        result = client._load_database()
        assert result == mock_db

        # Expire cache
        client._cache_time = datetime.now() - timedelta(hours=2)

        # Mock HTTP response for expired cache
        with patch.object(client.client, 'get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {"new-package": []}
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            result = client._load_database()
            assert result == {"new-package": []}
            mock_get.assert_called_once()

    def test_query_package_not_found(self):
        """Test querying for package not in database."""
        client = SafetyDBClient()

        # Mock empty database
        with patch.object(client, '_load_database', return_value={}):
            vulns = client.query_package("nonexistent-package")
            assert vulns == []

    def test_query_package_with_vulnerabilities(self):
        """Test querying package with vulnerabilities."""
        client = SafetyDBClient()

        # Mock database with vulnerabilities
        mock_db = {
            "requests": [
                {
                    "v": ["<2.20.0"],
                    "description": "Requests vulnerability",
                    "cve": "CVE-2018-18074",
                    "fixed_in": ["2.20.0"]
                }
            ]
        }

        with patch.object(client, '_load_database', return_value=mock_db):
            vulns = client.query_package("requests")

            assert len(vulns) == 1
            assert vulns[0].id == "SAFETY-REQUESTS-0"
            assert vulns[0].package_name == "requests"
            assert vulns[0].affected_versions == ["<2.20.0"]
            assert vulns[0].cve == "CVE-2018-18074"

    def test_version_affected_checking(self):
        """Test version checking logic."""
        client = SafetyDBClient()

        test_cases = [
            ("1.0.0", "<2.0", True),
            ("2.0.0", "<2.0", False),
            ("2.1.0", ">=2.0,<2.2", True),
            ("1.9.0", ">=2.0,<2.2", False),
            ("2.2.0", ">=2.0,<2.2", False),
            ("1.0.0", "==1.0.0", True),
            ("1.0.1", "==1.0.0", False),
        ]

        for version, spec, expected in test_cases:
            result = client._is_version_affected(version, [spec])
            assert result == expected, f"Version {version} with spec {spec} should be {expected}"

    def test_version_spec_parsing(self):
        """Test various version specification formats."""
        client = SafetyDBClient()
        from packaging.version import Version

        test_version = Version("2.0.0")

        assert client._check_version_spec(test_version, ">=1.0") is True
        assert client._check_version_spec(test_version, ">1.9") is True
        assert client._check_version_spec(test_version, "<=2.0") is True
        assert client._check_version_spec(test_version, "<2.1") is True
        assert client._check_version_spec(test_version, "==2.0.0") is True
        assert client._check_version_spec(test_version, "2.0.0") is True

        # Invalid version specs should return False
        assert client._check_version_spec(test_version, "invalid") is False

    @pytest.mark.asyncio
    async def test_query_package_async(self):
        """Test async package querying."""
        client = SafetyDBClient()

        mock_db = {
            "flask": [
                {
                    "v": ["<0.12.3"],
                    "description": "Flask vulnerability",
                    "fixed_in": ["0.12.3"]
                }
            ]
        }

        with patch.object(client, '_load_database_async', return_value=mock_db):
            vulns = await client.query_package_async("flask")

            assert len(vulns) == 1
            assert vulns[0].package_name == "flask"

    @pytest.mark.asyncio
    async def test_check_package(self):
        """Test check_package method."""
        client = SafetyDBClient()

        with patch.object(client, 'query_package_async', return_value=[]) as mock_query:
            result = await client.check_package("test-package", "1.0.0")
            mock_query.assert_called_once_with("test-package", "1.0.0")
            assert result == []

    def test_context_manager(self):
        """Test client context manager."""
        with SafetyDBClient() as client:
            assert client.client is not None
        # After exiting context, client should be closed

    def test_error_handling(self):
        """Test error handling when loading database fails."""
        client = SafetyDBClient()

        with patch.object(client.client, 'get', side_effect=httpx.HTTPError("Network error")):
            result = client._load_database()
            assert result == {}  # Should return empty dict on error
