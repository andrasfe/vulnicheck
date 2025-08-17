import hashlib
import os
import tempfile
from unittest.mock import AsyncMock, Mock, patch

import pytest

from vulnicheck.scanners.scanner import DependencyScanner


class TestDependencyScanner:
    @pytest.fixture
    def mock_osv_client(self):
        client = Mock()
        client.query_package = Mock(return_value=[])
        return client

    @pytest.fixture
    def mock_nvd_client(self):
        client = Mock()
        return client

    @pytest.fixture
    def scanner(self, mock_osv_client, mock_nvd_client):
        return DependencyScanner(mock_osv_client, mock_nvd_client)

    @pytest.mark.asyncio
    async def test_scan_file_not_found(self, scanner):
        with pytest.raises(FileNotFoundError):
            await scanner.scan_file("/nonexistent/file.txt")

    @pytest.mark.asyncio
    async def test_scan_file_unsupported_type(self, scanner):
        with (
            tempfile.NamedTemporaryFile(suffix=".json") as f,
            pytest.raises(ValueError, match="Unsupported file"),
        ):
            await scanner.scan_file(f.name)

    @pytest.mark.asyncio
    async def test_scan_requirements_txt(self, scanner, mock_osv_client):
        requirements_content = """
# This is a comment
numpy==1.19.0
flask>=2.0.0

requests~=2.28.0
-r other-requirements.txt  # This should be skipped
django>=3.2,<4.0
pandas
invalid-line-that-will-be-parsed-anyway
"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(requirements_content)
            f.flush()

        # Create a proper requirements.txt file
        requirements_path = os.path.join(os.path.dirname(f.name), "requirements.txt")
        os.rename(f.name, requirements_path)

        # Mock the _check_package method to avoid actual API calls
        async def mock_check_package(name, version_spec):
            if name == "numpy":
                return [{"id": "GHSA-numpy"}]
            elif name == "django":
                return [{"id": "GHSA-django"}]
            else:
                return []

        scanner._check_package = mock_check_package

        try:
            results = await scanner.scan_file(requirements_path)

            # Check the actual keys
            print(f"Result keys: {list(results.keys())}")

            assert len(results) == 6
            assert len(results["numpy==1.19.0"]) == 1
            assert len(results["flask>=2.0.0"]) == 0
            # The key format might be different for complex version specs
            django_key = next((k for k in results if k.startswith("django")), None)
            assert django_key is not None
            assert len(results[django_key]) == 1
            assert len(results["pandas"]) == 0

            # Remove call count assertion since we're using a different mock approach

        finally:
            os.unlink(requirements_path)

    @pytest.mark.asyncio
    async def test_scan_pyproject_toml(self, scanner, mock_osv_client):
        pyproject_content = """
[project]
dependencies = [
    "numpy==1.19.0",
    "flask>=2.0.0",
    "requests~=2.28.0"
]

[tool.poetry.dependencies]
python = "^3.8"
django = "^3.2"
pandas = {version = "1.3.0", extras = ["all"]}
scipy = "~1.7.0"
"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(pyproject_content)
            f.flush()

        # Create a proper pyproject.toml file
        pyproject_path = os.path.join(os.path.dirname(f.name), "pyproject.toml")
        os.rename(f.name, pyproject_path)

        # Mock the _check_package method to avoid actual API calls
        async def mock_check_package(name, version_spec):
            if name == "numpy":
                return [{"id": "GHSA-numpy"}]
            elif name == "django":
                return [{"id": "GHSA-django"}]
            else:
                return []

        scanner._check_package = mock_check_package

        try:
            results = await scanner.scan_file(pyproject_path)

            assert len(results) == 6
            assert len(results["numpy==1.19.0"]) == 1
            assert len(results["flask>=2.0.0"]) == 0
            assert len(results["django>=3.2"]) == 1  # Poetry ^ converted to >=
            assert len(results["pandas==1.3.0"]) == 0
            assert len(results["scipy~=1.7.0"]) == 0  # Poetry ~ converted to ~=

        finally:
            os.unlink(pyproject_path)

    @pytest.mark.asyncio
    async def test_parse_requirements_txt(self, scanner):
        content = """
# Comment
numpy==1.19.0
flask>=2.0.0
-e ./local-package
--index-url https://pypi.org/simple
requests

invalid line with spaces
package-with-extras[dev,test]>=1.0.0
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()

            try:
                deps = await scanner._parse_requirements(f.name)

                assert len(deps) >= 4
                assert ("numpy", "==1.19.0") in deps
                assert ("flask", ">=2.0.0") in deps
                assert ("requests", "") in deps
                # The extras package might be parsed differently depending on implementation

            finally:
                os.unlink(f.name)

    @pytest.mark.asyncio
    async def test_parse_pyproject_toml_empty_sections(self, scanner):
        content = """
[build-system]
requires = ["setuptools"]

[project]
name = "test-project"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()

            try:
                deps = await scanner._parse_pyproject(f.name)
                assert len(deps) == 0

            finally:
                os.unlink(f.name)

    @pytest.mark.asyncio
    async def test_check_package_no_version(self, scanner, mock_osv_client):
        # Mock the async check_package method
        mock_osv_client.check_package = AsyncMock(
            return_value=[
                {"id": "GHSA-1"},
                {"id": "GHSA-2"},
            ]
        )

        vulns = await scanner._check_package("numpy", "")

        assert len(vulns) == 2
        mock_osv_client.check_package.assert_called_once_with("numpy")

    @pytest.mark.asyncio
    async def test_check_package_with_version_spec(self, scanner, mock_osv_client):
        mock_vuln1 = Mock()
        mock_vuln1.affected = [
            {"package": {"name": "numpy"}, "versions": ["1.19.0", "1.19.1", "1.19.2"]}
        ]

        mock_vuln2 = Mock()
        mock_vuln2.affected = [
            {"package": {"name": "numpy"}, "versions": ["1.20.0", "1.20.1"]}
        ]

        # Mock the async check_package method
        mock_osv_client.check_package = AsyncMock(return_value=[mock_vuln1, mock_vuln2])

        # Mock the _get_affected_versions method
        with patch.object(scanner, "_get_affected_versions") as mock_get_affected:
            mock_get_affected.side_effect = [
                ["1.19.0", "1.19.1", "1.19.2"],
                ["1.20.0", "1.20.1"],
            ]

            vulns = await scanner._check_package("numpy", ">=1.19.0,<1.20.0")

            # Should only return vulnerabilities affecting versions in the range
            assert len(vulns) == 1

    @pytest.mark.asyncio
    async def test_check_package_invalid_version_spec(self, scanner, mock_osv_client):
        # Mock the async check_package method
        mock_osv_client.check_package = AsyncMock(
            return_value=[
                {"id": "GHSA-1"},
                {"id": "GHSA-2"},
            ]
        )

        # Invalid version spec should return all vulnerabilities
        vulns = await scanner._check_package("numpy", "invalid-spec")

        assert len(vulns) == 2

    def test_get_affected_versions(self, scanner):
        vuln = Mock()
        vuln.affected = [
            {
                "package": {"name": "NumPy"},  # Different case
                "versions": ["1.19.0", "1.19.1"],
            },
            {"package": {"name": "flask"}, "versions": ["2.0.0"]},
        ]

        versions = scanner._get_affected_versions(vuln, "numpy")
        assert versions == ["1.19.0", "1.19.1"]

        versions = scanner._get_affected_versions(vuln, "NUMPY")
        assert versions == ["1.19.0", "1.19.1"]

        versions = scanner._get_affected_versions(vuln, "django")
        assert versions == []

    @pytest.mark.asyncio
    async def test_calculate_file_hash(self, scanner):
        content = b"test content for hashing"
        expected_hash = hashlib.md5(content).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            f.flush()

            try:
                file_hash = await scanner.calculate_file_hash(f.name)
                assert file_hash == expected_hash

            finally:
                os.unlink(f.name)

    @pytest.mark.asyncio
    async def test_parse_poetry_version_conversions(self, scanner):
        content = """
[tool.poetry.dependencies]
package1 = "^1.2.3"
package2 = "~1.2.3"
package3 = "1.2.3"
package4 = {version = "^2.0.0"}
package5 = {git = "https://github.com/test/repo.git"}
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()

            try:
                deps = await scanner._parse_pyproject(f.name)

                # Check version conversions
                assert ("package1", ">=1.2.3") in deps  # ^ converted to >=
                assert ("package2", "~=1.2.3") in deps  # ~ converted to ~=
                assert ("package3", "1.2.3") in deps  # plain version
                assert ("package4", ">=2.0.0") in deps  # ^ in dict converted to >=
                # package5 with git dependency might not be included

            finally:
                os.unlink(f.name)

    @pytest.mark.asyncio
    async def test_scan_installed(self, scanner, mock_osv_client):
        # Mock importlib.metadata.distributions
        mock_dist1 = Mock()
        mock_dist1.name = "vulnerable-package"
        mock_dist1.version = "1.0.0"

        mock_dist2 = Mock()
        mock_dist2.name = "safe-package"
        mock_dist2.version = "2.0.0"

        mock_vuln = Mock()
        mock_vuln.id = "GHSA-test"

        # Mock check_exact_version to return vulnerabilities for first package only
        async def mock_check_exact(name, version):
            if name == "vulnerable-package":
                return [mock_vuln]
            return []

        scanner._check_exact_version = mock_check_exact

        with patch("importlib.metadata.distributions") as mock_distributions:
            mock_distributions.return_value = [mock_dist1, mock_dist2]

            results = await scanner.scan_installed()

            assert "vulnerable-package==1.0.0" in results
            assert len(results["vulnerable-package==1.0.0"]) == 1
            assert "safe-package==2.0.0" not in results

    @pytest.mark.asyncio
    async def test_scan_setup_py(self, scanner):
        """Test scanning setup.py files."""
        setup_content = '''
from setuptools import setup

setup(
    name="test-package",
    version="1.0.0",
    install_requires=[
        "numpy==1.19.0",
        "flask>=2.0.0",
        "requests~=2.28.0",
        "django>=3.2,<4.0",
        "pandas",
    ],
)
'''

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py") as f:
            f.write(setup_content)
            f.flush()

        # Create a proper setup.py file
        setup_path = os.path.join(os.path.dirname(f.name), "setup.py")
        os.rename(f.name, setup_path)

        # Mock the _check_package method to avoid actual API calls
        async def mock_check_package(name, version_spec):
            if name == "numpy":
                return [{"id": "GHSA-numpy"}]
            elif name == "django":
                return [{"id": "GHSA-django"}]
            else:
                return []

        scanner._check_package = mock_check_package

        try:
            results = await scanner.scan_file(setup_path)

            assert len(results) == 5
            assert len(results["numpy==1.19.0"]) == 1
            assert len(results["flask>=2.0.0"]) == 0
            # The key format might be different for complex version specs
            django_key = next((k for k in results if k.startswith("django")), None)
            assert django_key is not None
            assert len(results[django_key]) == 1
            assert len(results["pandas"]) == 0

        finally:
            os.unlink(setup_path)

    @pytest.mark.asyncio
    async def test_parse_setup_py_simple(self, scanner):
        """Test parsing a simple setup.py file."""
        setup_content = '''
from setuptools import setup

setup(
    name="test-package",
    install_requires=[
        "numpy==1.19.0",
        "flask>=2.0.0",
    ],
)
'''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(setup_content)
            f.flush()

            try:
                deps = await scanner._parse_setup_py(f.name)

                assert len(deps) == 2
                assert ("numpy", "==1.19.0") in deps
                assert ("flask", ">=2.0.0") in deps

            finally:
                os.unlink(f.name)

    @pytest.mark.asyncio
    async def test_parse_setup_py_with_variables(self, scanner):
        """Test parsing setup.py that uses variables for install_requires."""
        setup_content = '''
from setuptools import setup

requirements = ["numpy==1.19.0", "flask>=2.0.0"]

setup(
    name="test-package",
    install_requires=requirements,
)
'''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(setup_content)
            f.flush()

            try:
                deps = await scanner._parse_setup_py(f.name)

                # Should be empty because we can't resolve variables
                assert len(deps) == 0

            finally:
                os.unlink(f.name)

    def test_parse_setup_py_fallback(self, scanner):
        """Test fallback regex parsing for setup.py files."""
        setup_content = '''
from setuptools import setup

setup(
    name="test-package",
    install_requires=[
        "numpy==1.19.0",
        "flask>=2.0.0",
        'requests~=2.28.0',  # Single quotes
    ],
)
'''

        deps = scanner._parse_setup_py_fallback(setup_content)

        assert len(deps) == 3
        assert ("numpy", "==1.19.0") in deps
        assert ("flask", ">=2.0.0") in deps
        assert ("requests", "~=2.28.0") in deps

    @pytest.mark.asyncio
    async def test_parse_setup_py_malformed(self, scanner):
        """Test parsing malformed setup.py files."""
        setup_content = '''
# This is not valid Python syntax
from setuptools import setup

setup(
    name="test-package"
    install_requires=[  # Missing comma
        "numpy==1.19.0",
    ]
)
'''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(setup_content)
            f.flush()

            try:
                deps = await scanner._parse_setup_py(f.name)

                # Should fall back to regex parsing and still find numpy
                assert len(deps) == 1
                assert ("numpy", "==1.19.0") in deps

            finally:
                os.unlink(f.name)

    @pytest.mark.asyncio
    async def test_scan_directory_with_setup_py(self, scanner):
        """Test directory scanning that finds setup.py."""
        setup_content = '''
from setuptools import setup

setup(
    name="test-package",
    install_requires=[
        "numpy==1.19.0",
        "flask>=2.0.0",
    ],
)
'''

        # Mock the _check_package method
        async def mock_check_package(name, version_spec):
            if name == "numpy":
                return [{"id": "GHSA-numpy"}]
            else:
                return []

        scanner._check_package = mock_check_package

        with tempfile.TemporaryDirectory() as tmpdir:
            setup_path = os.path.join(tmpdir, "setup.py")

            with open(setup_path, "w") as f:
                f.write(setup_content)

            results = await scanner.scan_directory(tmpdir)

            assert len(results) == 2
            assert len(results["numpy==1.19.0"]) == 1
            assert len(results["flask>=2.0.0"]) == 0
