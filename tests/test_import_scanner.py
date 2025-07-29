from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.scanners.scanner import DependencyScanner


@pytest.fixture
def mock_clients():
    """Create mock clients for testing."""
    osv_client = MagicMock()
    nvd_client = MagicMock()
    github_client = MagicMock()
    return osv_client, nvd_client, github_client


@pytest.fixture
def scanner(mock_clients):
    """Create a scanner instance with mocked clients."""
    osv_client, nvd_client, github_client = mock_clients
    return DependencyScanner(osv_client, nvd_client, github_client)


class TestPythonImportScanning:
    """Test Python import scanning functionality."""

    def test_extract_imports_from_file(self, scanner, tmp_path):
        """Test extracting imports from a Python file."""
        # Create a test Python file with various import styles
        test_file = tmp_path / "test_imports.py"
        test_file.write_text("""
import os
import sys
from pathlib import Path
from typing import List, Dict
import requests
from flask import Flask, render_template
import numpy as np
from pandas.core import DataFrame
import xml.etree.ElementTree as ET
from . import local_module
from ..parent import another_module
""")

        imports = scanner._extract_imports_from_file(test_file)

        # Should extract top-level module names only
        expected = {
            "os",
            "sys",
            "pathlib",
            "typing",
            "requests",
            "flask",
            "numpy",
            "pandas",
            "xml",
        }
        assert imports == expected

    def test_extract_imports_syntax_error(self, scanner, tmp_path):
        """Test handling of files with syntax errors."""
        test_file = tmp_path / "bad_syntax.py"
        test_file.write_text("import requests\nthis is not valid python syntax")

        # Should not raise an exception
        imports = scanner._extract_imports_from_file(test_file)
        assert imports == set()

    def test_extract_imports_encoding_error(self, scanner, tmp_path):
        """Test handling of files with encoding issues."""
        test_file = tmp_path / "bad_encoding.py"
        # Write binary data that's not valid UTF-8
        test_file.write_bytes(b"\xff\xfe\x00\x00import requests")

        # Should not raise an exception
        imports = scanner._extract_imports_from_file(test_file)
        assert imports == set()

    def test_is_stdlib_module(self, scanner):
        """Test identification of standard library modules."""
        # Test stdlib modules
        assert scanner._is_stdlib_module("os")
        assert scanner._is_stdlib_module("sys")
        assert scanner._is_stdlib_module("json")
        assert scanner._is_stdlib_module("typing")
        assert scanner._is_stdlib_module("collections")

        # Test non-stdlib modules
        assert not scanner._is_stdlib_module("requests")
        assert not scanner._is_stdlib_module("flask")
        assert not scanner._is_stdlib_module("numpy")
        assert not scanner._is_stdlib_module("pandas")

    def test_scan_python_imports(self, scanner, tmp_path):
        """Test scanning a directory for Python imports."""
        # Create a directory structure with Python files
        (tmp_path / "subdir").mkdir()

        # File 1: main.py
        (tmp_path / "main.py").write_text("""
import os
import requests
from flask import Flask
""")

        # File 2: subdir/utils.py
        (tmp_path / "subdir" / "utils.py").write_text("""
import json
import numpy as np
from requests import Session
""")

        # File 3: large file (should be skipped)
        large_file = tmp_path / "large.py"
        large_file.write_text("import pandas\n" + "# " * 1024 * 1024)  # > 1MB

        imports = scanner._scan_python_imports(tmp_path)

        # Should include imports from main.py and utils.py but not large.py
        expected = {"os", "requests", "flask", "json", "numpy"}
        assert imports == expected

    def test_scan_python_imports_limit(self, scanner, tmp_path):
        """Test that scanning limits the number of files processed."""
        # Create more than 1000 Python files
        for i in range(1100):
            (tmp_path / f"file_{i}.py").write_text(f"import module_{i}")

        # Mock rglob to verify we process at most 1000 files
        with patch.object(Path, "rglob") as mock_rglob:
            all_files = list(tmp_path.glob("*.py"))
            mock_rglob.return_value = all_files

            imports = scanner._scan_python_imports(tmp_path)

            # Should process at most 1000 files
            assert len(imports) <= 1000

    @pytest.mark.asyncio
    async def test_scan_directory_with_requirements(self, scanner, tmp_path):
        """Test scanning a directory that has requirements.txt."""
        # Create requirements.txt
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\nflask>=2.0.0")

        # Mock the scan_file method
        with patch.object(scanner, "scan_file") as mock_scan:
            mock_scan.return_value = {"requests==2.28.0": [], "flask>=2.0.0": []}

            result = await scanner.scan_directory(str(tmp_path))

            # Should call scan_file with requirements.txt
            mock_scan.assert_called_once_with(str(req_file))
            assert result == {"requests==2.28.0": [], "flask>=2.0.0": []}

    @pytest.mark.asyncio
    async def test_scan_directory_with_pyproject(self, scanner, tmp_path):
        """Test scanning a directory that has pyproject.toml."""
        # Create pyproject.toml
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text("""
[project]
dependencies = ["requests", "flask"]
""")

        # Mock the scan_file method
        with patch.object(scanner, "scan_file") as mock_scan:
            mock_scan.return_value = {"requests": [], "flask": []}

            result = await scanner.scan_directory(str(tmp_path))

            # Should call scan_file with pyproject.toml
            mock_scan.assert_called_once_with(str(pyproject_file))
            assert result == {"requests": [], "flask": []}

    @pytest.mark.asyncio
    async def test_scan_directory_no_requirements(self, scanner, tmp_path):
        """Test scanning a directory without requirements files."""
        # Create Python files
        (tmp_path / "app.py").write_text("""
import os  # stdlib, should be filtered
import requests
from flask import Flask
""")

        # Mock vulnerability data
        mock_vuln = MagicMock()
        mock_vuln.id = "VULN-123"
        mock_vuln.summary = "Test vulnerability"
        mock_vuln.affected = []
        mock_vuln.aliases = []
        mock_vuln.references = []
        mock_vuln.severity = []

        # Mock the check methods
        with patch.object(scanner, "_check_latest_version") as mock_check:
            mock_check.side_effect = (
                lambda pkg: [mock_vuln] if pkg == "requests" else []
            )

            result = await scanner.scan_directory(str(tmp_path))

            # Should have results for requests and flask (latest versions)
            assert "requests (latest)" in result
            assert result["requests (latest)"] == [mock_vuln]
            assert "flask (latest)" not in result  # No vulnerabilities
            assert "os (latest)" not in result  # Stdlib filtered out

    @pytest.mark.asyncio
    async def test_check_latest_version(self, scanner, mock_clients):
        """Test checking latest version vulnerabilities."""
        osv_client, nvd_client, github_client = mock_clients

        # Mock OSV response
        osv_vuln = MagicMock()
        osv_vuln.id = "OSV-123"
        osv_client.check_package = AsyncMock(return_value=[osv_vuln])

        # Mock GitHub response
        github_vuln = MagicMock()
        github_vuln.id = "GHSA-456"
        github_client.search_advisories_async = AsyncMock(return_value=[github_vuln])

        result = await scanner._check_latest_version("requests")

        # Should return vulnerabilities from both sources
        assert len(result) == 2
        assert result[0].id == "OSV-123"
        assert result[1].id == "GHSA-456"

    @pytest.mark.asyncio
    async def test_check_latest_version_github_error(self, scanner, mock_clients):
        """Test handling GitHub API errors gracefully."""
        osv_client, nvd_client, github_client = mock_clients

        # Mock OSV response
        osv_vuln = MagicMock()
        osv_vuln.id = "OSV-123"
        osv_client.check_package = AsyncMock(return_value=[osv_vuln])

        # Mock GitHub error
        github_client.search_advisories_async = AsyncMock(
            side_effect=Exception("API Error")
        )

        result = await scanner._check_latest_version("requests")

        # Should still return OSV results
        assert len(result) == 1
        assert result[0].id == "OSV-123"

    @pytest.mark.asyncio
    async def test_scan_file_directory_input(self, scanner, tmp_path):
        """Test that scan_file redirects to scan_directory for directory input."""
        # Mock scan_directory
        with patch.object(scanner, "scan_directory") as mock_scan_dir:
            mock_scan_dir.return_value = {"test": []}

            result = await scanner.scan_file(str(tmp_path))

            # Should call scan_directory
            mock_scan_dir.assert_called_once_with(str(tmp_path))
            assert result == {"test": []}
