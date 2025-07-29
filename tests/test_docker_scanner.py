"""Tests for Docker vulnerability scanner."""

from unittest.mock import MagicMock, Mock

import pytest

from vulnicheck.scanners.docker_scanner import DockerScanner
from vulnicheck.scanners.scanner import DependencyScanner


@pytest.fixture
def mock_scanner():
    """Create a mock scanner."""
    scanner = Mock(spec=DependencyScanner)
    scanner.check_package = MagicMock(return_value=[])
    return scanner


@pytest.fixture
def docker_scanner(mock_scanner):
    """Create a DockerScanner instance with mock scanner."""
    return DockerScanner(scanner=mock_scanner)


class TestDockerScanner:
    """Test cases for DockerScanner."""

    def test_scan_dockerfile_no_input(self, docker_scanner):
        """Test scanning with no input."""
        result = docker_scanner.scan_dockerfile()
        assert result["error"] == "Either dockerfile_path or dockerfile_content must be provided"
        assert result["packages_found"] == 0

    def test_scan_dockerfile_nonexistent_file(self, docker_scanner):
        """Test scanning a non-existent file."""
        result = docker_scanner.scan_dockerfile(dockerfile_path="/nonexistent/Dockerfile")
        assert "error" in result
        assert "not found" in result["error"]

    def test_extract_pip_install_packages(self, docker_scanner):
        """Test extracting packages from pip install commands."""
        dockerfile_content = """
        FROM python:3.9
        RUN pip install requests==2.28.0
        RUN pip install flask>=2.0.0 django<4.0
        RUN pip install -r requirements.txt
        RUN pip install numpy scipy pandas
        """

        result = docker_scanner.scan_dockerfile(dockerfile_content=dockerfile_content)

        assert result["packages_found"] == 6
        assert "requests" in result["dependencies"]
        assert result["dependencies"]["requests"] == "2.28.0"
        assert "flask" in result["dependencies"]
        assert result["dependencies"]["flask"] == "2.0.0"
        assert "django" in result["dependencies"]
        assert result["dependencies"]["django"] == "4.0"
        assert "numpy" in result["dependencies"]
        assert result["dependencies"]["numpy"] is None

    def test_extract_poetry_packages(self, docker_scanner):
        """Test extracting packages from poetry commands."""
        dockerfile_content = """
        FROM python:3.9
        RUN poetry add requests==2.28.0
        RUN poetry add flask django
        """

        result = docker_scanner.scan_dockerfile(dockerfile_content=dockerfile_content)

        assert result["packages_found"] == 3
        assert "requests" in result["dependencies"]
        assert result["dependencies"]["requests"] == "2.28.0"
        assert "flask" in result["dependencies"]
        assert "django" in result["dependencies"]

    def test_extract_pipenv_packages(self, docker_scanner):
        """Test extracting packages from pipenv commands."""
        dockerfile_content = """
        FROM python:3.9
        RUN pipenv install requests==2.28.0
        RUN pipenv install flask
        """

        result = docker_scanner.scan_dockerfile(dockerfile_content=dockerfile_content)

        assert result["packages_found"] == 2
        assert "requests" in result["dependencies"]
        assert result["dependencies"]["requests"] == "2.28.0"
        assert "flask" in result["dependencies"]

    def test_extract_conda_packages(self, docker_scanner):
        """Test extracting packages from conda commands."""
        dockerfile_content = """
        FROM continuumio/miniconda3
        RUN conda install numpy=1.21.0
        RUN conda install pandas scipy
        """

        result = docker_scanner.scan_dockerfile(dockerfile_content=dockerfile_content)

        assert result["packages_found"] == 3
        assert "numpy" in result["dependencies"]
        assert result["dependencies"]["numpy"] == "1.21.0"
        assert "pandas" in result["dependencies"]
        assert "scipy" in result["dependencies"]

    def test_extract_referenced_files(self, docker_scanner):
        """Test extracting referenced dependency files."""
        dockerfile_content = """
        FROM python:3.9
        COPY requirements.txt /app/
        COPY pyproject.toml /app/
        ADD requirements-dev.txt /app/
        COPY Pipfile Pipfile.lock /app/
        COPY poetry.lock /app/
        """

        result = docker_scanner.scan_dockerfile(dockerfile_content=dockerfile_content)

        assert "requirements.txt" in result["referenced_files"]
        assert "pyproject.toml" in result["referenced_files"]
        assert "requirements-dev.txt" in result["referenced_files"]
        assert "Pipfile" in result["referenced_files"]
        assert "Pipfile.lock" in result["referenced_files"]
        assert "poetry.lock" in result["referenced_files"]

    def test_vulnerability_detection(self, docker_scanner, mock_scanner):
        """Test vulnerability detection in packages."""
        # Mock vulnerability data
        mock_scanner.check_package.side_effect = lambda pkg, ver: [
            {
                "id": "VULN-001",
                "severity": "HIGH",
                "summary": "Test vulnerability",
                "cve_id": "CVE-2021-12345",
                "url": "https://example.com/vuln"
            }
        ] if pkg == "requests" else []

        dockerfile_content = """
        FROM python:3.9
        RUN pip install requests==2.28.0
        RUN pip install flask
        """

        result = docker_scanner.scan_dockerfile(dockerfile_content=dockerfile_content)

        assert result["packages_found"] == 2
        assert result["total_vulnerabilities"] == 1
        assert "requests" in result["vulnerable_packages"]
        assert "flask" not in result["vulnerable_packages"]
        assert result["severity_summary"]["HIGH"] == 1

        # Check vulnerability details
        assert len(result["vulnerabilities"]) == 1
        vuln_info = result["vulnerabilities"][0]
        assert vuln_info["package"] == "requests"
        assert vuln_info["installed_version"] == "2.28.0"
        assert vuln_info["vulnerability"]["id"] == "VULN-001"

    def test_parse_package_spec(self, docker_scanner):
        """Test parsing package specifications."""
        test_cases = [
            ("requests==2.28.0", ("requests", "2.28.0")),
            ("flask>=2.0.0", ("flask", "2.0.0")),
            ("django<4.0", ("django", "4.0")),
            ("numpy", ("numpy", None)),
            ("'pandas==1.3.0'", ("pandas", "1.3.0")),
            ('"scipy>=1.7"', ("scipy", "1.7")),
        ]

        for spec, expected in test_cases:
            result = docker_scanner._parse_package_spec(spec)
            assert result == expected

    def test_skip_comments_and_empty_lines(self, docker_scanner):
        """Test that comments and empty lines are skipped."""
        dockerfile_content = """
        FROM python:3.9
        # This is a comment
        RUN pip install requests

        # Another comment
        RUN pip install flask
        """

        result = docker_scanner.scan_dockerfile(dockerfile_content=dockerfile_content)

        assert result["packages_found"] == 2
        assert "requests" in result["dependencies"]
        assert "flask" in result["dependencies"]

    @pytest.mark.asyncio
    async def test_scan_dockerfile_async(self, docker_scanner):
        """Test async version of scan_dockerfile."""
        dockerfile_content = """
        FROM python:3.9
        RUN pip install requests flask
        """

        result = await docker_scanner.scan_dockerfile_async(
            dockerfile_content=dockerfile_content
        )

        assert result["packages_found"] == 2
        assert "requests" in result["dependencies"]
        assert "flask" in result["dependencies"]
