"""Tests for the secrets scanner module."""

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnicheck.scanners.secrets_scanner import SecretsScanner, SecretsScanResult


class TestSecretsScanResult:
    """Test the SecretsScanResult class."""

    def test_init(self) -> None:
        """Test SecretsScanResult initialization."""
        result = SecretsScanResult(
            file_path="/path/to/file.py",
            line_number=42,
            secret_type="AWSKeyDetector",
            hashed_secret="abc123",
            is_verified=True,
        )

        assert result.file_path == "/path/to/file.py"
        assert result.line_number == 42
        assert result.secret_type == "AWSKeyDetector"
        assert result.hashed_secret == "abc123"
        assert result.is_verified is True

    def test_to_dict(self) -> None:
        """Test converting SecretsScanResult to dictionary."""
        result = SecretsScanResult(
            file_path="/path/to/file.py",
            line_number=42,
            secret_type="AWSKeyDetector",
            hashed_secret="abc123",
            is_verified=False,
        )

        expected = {
            "file_path": "/path/to/file.py",
            "line_number": 42,
            "secret_type": "AWSKeyDetector",
            "hashed_secret": "abc123",
            "is_verified": False,
        }

        assert result.to_dict() == expected


class TestSecretsScanner:
    """Test the SecretsScanner class."""

    def test_init(self) -> None:
        """Test SecretsScanner initialization."""
        scanner = SecretsScanner()
        assert scanner.baseline_file == ".secrets.baseline"

    def test_scan_file_not_found(self) -> None:
        """Test scanning a non-existent file."""
        scanner = SecretsScanner()

        with pytest.raises(FileNotFoundError):
            scanner.scan_file("/non/existent/file.py")

    def test_scan_file_too_large(self) -> None:
        """Test scanning a file that's too large."""
        scanner = SecretsScanner()

        with tempfile.NamedTemporaryFile() as f:
            # Write 11MB of data
            f.write(b"x" * (11 * 1024 * 1024))
            f.flush()

            with pytest.raises(ValueError, match="File too large"):
                scanner.scan_file(f.name)

    @patch("subprocess.run")
    def test_scan_file_success(self, mock_run: MagicMock) -> None:
        """Test successful file scanning."""
        scanner = SecretsScanner()

        # Mock detect-secrets output
        mock_output = {
            "results": {
                "/path/to/file.py": [
                    {
                        "type": "AWSKeyDetector",
                        "line_number": 10,
                        "hashed_secret": "abc123",
                        "is_verified": False,
                    }
                ]
            }
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(mock_output),
            stderr="",
        )

        with tempfile.NamedTemporaryFile() as f:
            f.write(b"test content")
            f.flush()

            results = scanner.scan_file(f.name)

        assert len(results) == 1
        assert results[0].file_path == "/path/to/file.py"
        assert results[0].line_number == 10
        assert results[0].secret_type == "AWSKeyDetector"

    def test_scan_directory_not_found(self) -> None:
        """Test scanning a non-existent directory."""
        scanner = SecretsScanner()

        with pytest.raises(NotADirectoryError):
            scanner.scan_directory("/non/existent/dir")

    @patch("subprocess.run")
    def test_scan_directory_success(self, mock_run: MagicMock) -> None:
        """Test successful directory scanning."""
        scanner = SecretsScanner()

        # Mock detect-secrets output
        mock_output = {
            "results": {
                "/test/file1.py": [
                    {
                        "type": "Base64HighEntropyString",
                        "line_number": 5,
                        "hashed_secret": "def456",
                        "is_verified": False,
                    }
                ],
                "/test/file2.py": [
                    {
                        "type": "PrivateKeyDetector",
                        "line_number": 15,
                        "hashed_secret": "ghi789",
                        "is_verified": True,
                    }
                ],
            }
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(mock_output),
            stderr="",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "file1.py").write_text("test content")
            (Path(tmpdir) / "file2.py").write_text("more content")

            results = scanner.scan_directory(tmpdir)

        assert len(results) == 2
        assert results[0].secret_type == "Base64HighEntropyString"
        assert results[1].secret_type == "PrivateKeyDetector"
        assert results[1].is_verified is True

    def test_collect_files(self) -> None:
        """Test file collection logic."""
        scanner = SecretsScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create various files
            (tmpdir_path / "test.py").write_text("python code")
            (tmpdir_path / "config.json").write_text("{}")
            (tmpdir_path / "readme.md").write_text("docs")
            (tmpdir_path / "test.pyc").write_text("compiled")

            # Create subdirectory
            subdir = tmpdir_path / "subdir"
            subdir.mkdir()
            (subdir / "module.py").write_text("more code")

            # Create excluded directory
            venv_dir = tmpdir_path / "venv"
            venv_dir.mkdir()
            (venv_dir / "excluded.py").write_text("should not scan")

            files = scanner._collect_files(tmpdir_path)

            # Convert to relative paths for easier testing
            rel_files = [str(Path(f).relative_to(tmpdir_path)) for f in files]

            assert "test.py" in rel_files
            assert "config.json" in rel_files
            assert "readme.md" in rel_files
            assert "test.pyc" not in rel_files  # excluded extension
            assert str(Path("subdir") / "module.py") in rel_files
            assert str(Path("venv") / "excluded.py") not in rel_files  # excluded dir

    def test_collect_files_with_custom_excludes(self) -> None:
        """Test file collection with custom exclude patterns."""
        scanner = SecretsScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            (tmpdir_path / "include.py").write_text("include me")
            (tmpdir_path / "exclude.py").write_text("exclude me")
            (tmpdir_path / "test_file.py").write_text("test file")

            files = scanner._collect_files(tmpdir_path, ["exclude.py", "test_*"])
            rel_files = [str(Path(f).relative_to(tmpdir_path)) for f in files]

            assert "include.py" in rel_files
            assert "exclude.py" not in rel_files
            assert "test_file.py" not in rel_files

    @patch("subprocess.run")
    def test_run_detect_secrets_timeout(self, mock_run: MagicMock) -> None:
        """Test handling of subprocess timeout."""
        scanner = SecretsScanner()

        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 60)

        results = scanner._run_detect_secrets(["/path/to/file.py"])
        assert results == []

    @patch("subprocess.run")
    def test_run_detect_secrets_json_error(self, mock_run: MagicMock) -> None:
        """Test handling of invalid JSON output."""
        scanner = SecretsScanner()

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="invalid json",
            stderr="",
        )

        results = scanner._run_detect_secrets(["/path/to/file.py"])
        assert results == []

    def test_filter_false_positives(self) -> None:
        """Test filtering of false positive secrets."""
        scanner = SecretsScanner()

        secrets = [
            SecretsScanResult(
                file_path="/project/src/main.py",
                line_number=10,
                secret_type="Base64HighEntropyString",
                hashed_secret="abc123",
            ),
            SecretsScanResult(
                file_path="/project/tests/test_auth.py",
                line_number=20,
                secret_type="AWSKeyDetector",
                hashed_secret="def456",
            ),
            SecretsScanResult(
                file_path="/project/examples/demo.py",
                line_number=30,
                secret_type="PrivateKeyDetector",
                hashed_secret="ghi789",
            ),
            SecretsScanResult(
                file_path="/project/docs/readme.md",
                line_number=40,
                secret_type="GitHubTokenDetector",
                hashed_secret="jkl012",
            ),
        ]

        filtered = scanner.filter_false_positives(secrets)

        # Only the main.py secret should remain
        assert len(filtered) == 1
        assert filtered[0].file_path == "/project/src/main.py"

    def test_get_secret_severity(self) -> None:
        """Test secret severity classification."""
        scanner = SecretsScanner()

        # Test critical types
        assert scanner.get_secret_severity("AWSKeyDetector") == "CRITICAL"
        assert scanner.get_secret_severity("PrivateKeyDetector") == "CRITICAL"
        assert scanner.get_secret_severity("StripeDetector") == "CRITICAL"

        # Test high types
        assert scanner.get_secret_severity("GitHubTokenDetector") == "HIGH"
        assert scanner.get_secret_severity("SlackDetector") == "HIGH"

        # Test medium types
        assert scanner.get_secret_severity("Base64HighEntropyString") == "MEDIUM"
        assert scanner.get_secret_severity("HexHighEntropyString") == "MEDIUM"

        # Test unknown type (defaults to LOW)
        assert scanner.get_secret_severity("UnknownDetector") == "LOW"
