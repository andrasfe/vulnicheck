"""Tests for lock file parsing functionality."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from vulnicheck.scanner import DependencyScanner


class TestLockFileParsing:
    """Test lock file parsing functionality."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance with mock clients."""
        osv_client = MagicMock()
        nvd_client = MagicMock()
        return DependencyScanner(osv_client, nvd_client)

    def test_parse_lock_file_pip_compile_format(self, scanner, tmp_path):
        """Test parsing pip-compile style lock files."""
        lock_content = """# This file was autogenerated by pip-compile
# To update, run:
#    pip-compile
certifi==2024.2.2
    # via requests
charset-normalizer==3.3.2
    # via requests
idna==3.6
    # via requests
requests==2.31.0
    # via -r requirements.in
urllib3==2.2.0
    # via requests
"""
        lock_file = tmp_path / "requirements.lock"
        lock_file.write_text(lock_content)

        deps = scanner._parse_lock_file(lock_file)

        assert len(deps) == 5
        assert ("certifi", "==2024.2.2") in deps
        assert ("charset-normalizer", "==3.3.2") in deps
        assert ("idna", "==3.6") in deps
        assert ("requests", "==2.31.0") in deps
        assert ("urllib3", "==2.2.0") in deps

    def test_parse_lock_file_uv_format(self, scanner, tmp_path):
        """Test parsing uv.lock TOML format."""
        lock_content = """version = 1

[[package]]
name = "certifi"
version = "2024.2.2"

[[package]]
name = "requests"
version = "2.31.0"
dependencies = [
    { name = "certifi" },
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "2.2.0"
"""
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(lock_content)

        deps = scanner._parse_lock_file(lock_file)

        assert len(deps) == 3
        assert ("certifi", "==2024.2.2") in deps
        assert ("requests", "==2.31.0") in deps
        assert ("urllib3", "==2.2.0") in deps

    def test_find_lock_versions(self, scanner, tmp_path):
        """Test finding and parsing lock files."""
        # Create a pyproject.toml
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests>=2.0"]')

        # Create a lock file
        lock_content = """requests==2.31.0
certifi==2024.2.2
"""
        lock_file = tmp_path / "requirements.lock"
        lock_file.write_text(lock_content)

        lock_versions = scanner._find_lock_versions(pyproject)

        assert lock_versions["requests"] == "2.31.0"
        assert lock_versions["certifi"] == "2024.2.2"

    def test_find_lock_versions_no_lock_file(self, scanner, tmp_path):
        """Test behavior when no lock file exists."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests>=2.0"]')

        lock_versions = scanner._find_lock_versions(pyproject)

        assert lock_versions == {}

    @pytest.mark.asyncio
    async def test_scan_file_with_lock_file(self, scanner, tmp_path):
        """Test scanning with lock file present."""
        # Create pyproject.toml
        pyproject_content = """[project]
dependencies = [
    "requests>=2.0",
    "certifi>=2020.0",
]
"""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(pyproject_content)

        # Create lock file
        lock_content = """requests==2.31.0
certifi==2024.2.2
"""
        lock_file = tmp_path / "requirements.lock"
        lock_file.write_text(lock_content)

        # Mock the check_package method
        scanner.osv_client.check_package = AsyncMock()
        scanner.osv_client.check_package.return_value = []

        # Mock _check_package to avoid actual API calls
        scanner._check_package = AsyncMock(return_value=[])
        scanner._check_exact_version = AsyncMock(return_value=[])

        results = await scanner.scan_file(str(pyproject))

        # Should use exact versions from lock file
        assert "requests==2.31.0" in results
        assert "certifi==2024.2.2" in results
        # Should not have version ranges
        assert not any(">=" in key for key in results)

    @pytest.mark.asyncio
    async def test_scan_file_without_lock_file(self, scanner, tmp_path):
        """Test scanning without lock file present."""
        # Create pyproject.toml
        pyproject_content = """[project]
dependencies = [
    "requests>=2.0",
    "certifi>=2020.0",
]
"""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(pyproject_content)

        # Mock the check_package method
        scanner._check_package = AsyncMock(return_value=[])

        results = await scanner.scan_file(str(pyproject))

        # Should use version ranges
        assert "requests>=2.0" in results
        assert "certifi>=2020.0" in results
        # Should not have exact versions
        assert not any("==" in key for key in results)

    def test_parse_lock_file_empty(self, scanner, tmp_path):
        """Test parsing empty lock file."""
        lock_file = tmp_path / "requirements.lock"
        lock_file.write_text("")

        deps = scanner._parse_lock_file(lock_file)

        assert deps == []

    def test_parse_lock_file_with_comments_only(self, scanner, tmp_path):
        """Test parsing lock file with only comments."""
        lock_content = """# This is a comment
# Another comment
# No actual dependencies
"""
        lock_file = tmp_path / "requirements.lock"
        lock_file.write_text(lock_content)

        deps = scanner._parse_lock_file(lock_file)

        assert deps == []

    def test_parse_lock_file_malformed_uv(self, scanner, tmp_path):
        """Test parsing malformed uv.lock file."""
        lock_content = """[invalid toml
not valid at all
"""
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(lock_content)

        deps = scanner._parse_lock_file(lock_file)

        # Should handle the error gracefully and return empty list
        assert deps == []
