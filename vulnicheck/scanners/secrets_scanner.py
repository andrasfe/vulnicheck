"""Module for scanning files and directories for secrets using detect-secrets."""

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..providers import (
    FileNotFoundError as FileProviderFileNotFoundError,
)
from ..providers import (
    FileSizeLimitExceededError,
)
from ..providers import (
    PermissionError as FileProviderPermissionError,
)
from ..providers.base import FileProvider
from ..providers.factory import create_local_provider

logger = logging.getLogger("vulnicheck.secrets")


class SecretsScanResult:
    """Represents a detected secret."""

    def __init__(
        self,
        file_path: str,
        line_number: int,
        secret_type: str,
        hashed_secret: str,
        is_verified: bool = False,
    ) -> None:
        self.file_path = file_path
        self.line_number = line_number
        self.secret_type = secret_type
        self.hashed_secret = hashed_secret
        self.is_verified = is_verified

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "secret_type": self.secret_type,
            "hashed_secret": self.hashed_secret,
            "is_verified": self.is_verified,
        }


class SecretsScanner:
    """Scanner for detecting secrets in files using detect-secrets."""

    # Common files to exclude from scanning
    EXCLUDED_FILES = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".coverage",
        "*.pyc",
        "*.pyo",
        "*.egg-info",
        "dist",
        "build",
    }

    # File extensions commonly containing secrets
    SCAN_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".go",
        ".rb",
        ".php",
        ".sh",
        ".bash",
        ".zsh",
        ".env",
        ".yml",
        ".yaml",
        ".json",
        ".xml",
        ".ini",
        ".conf",
        ".config",
        ".properties",
        ".toml",
        ".txt",
        ".md",
        ".rst",
    }

    def __init__(self, file_provider: FileProvider | None = None) -> None:
        """Initialize the secrets scanner.

        Args:
            file_provider: FileProvider instance for file operations.
                          Defaults to LocalFileProvider for backward compatibility.
        """
        self.file_provider = file_provider or create_local_provider()
        self.baseline_file = ".secrets.baseline"

    def scan_file(self, file_path: str) -> list[SecretsScanResult]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of detected secrets
        """
        return asyncio.run(self._scan_file_async(file_path))

    async def _scan_file_async(self, file_path: str) -> list[SecretsScanResult]:
        """Async implementation of scan_file."""
        # Check if file exists
        if not await self.file_provider.file_exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Check if it's actually a file
        if not await self.file_provider.is_file(file_path):
            raise FileNotFoundError(f"Path is not a file: {file_path}")

        # Check file size (FileProvider will enforce size limits)
        try:
            file_size = await self.file_provider.get_file_size(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError(f"File too large (max 10MB): {file_path}")
        except FileProviderFileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}") from None
        except FileProviderPermissionError as e:
            raise PermissionError(str(e)) from e
        except FileSizeLimitExceededError as e:
            raise ValueError(str(e)) from e

        return await self._run_detect_secrets_async([file_path])

    def scan_directory(
        self, directory_path: str, exclude_patterns: list[str] | None = None
    ) -> list[SecretsScanResult]:
        """Scan a directory recursively for secrets.

        Args:
            directory_path: Path to the directory to scan
            exclude_patterns: Additional patterns to exclude

        Returns:
            List of detected secrets
        """
        return asyncio.run(self._scan_directory_async(directory_path, exclude_patterns))

    async def _scan_directory_async(
        self, directory_path: str, exclude_patterns: list[str] | None = None
    ) -> list[SecretsScanResult]:
        """Async implementation of scan_directory."""
        # Check if directory exists
        if not await self.file_provider.file_exists(directory_path):
            raise NotADirectoryError(f"Directory not found: {directory_path}")

        # Check if it's actually a directory
        if not await self.file_provider.is_directory(directory_path):
            raise NotADirectoryError(f"Not a directory: {directory_path}")

        # Collect files to scan
        files_to_scan = await self._collect_files_async(directory_path, exclude_patterns)

        if not files_to_scan:
            return []

        return await self._run_detect_secrets_async(files_to_scan)

    async def _collect_files_async(
        self, directory_path: str, exclude_patterns: list[str] | None = None
    ) -> list[str]:
        """Collect files to scan from a directory using FileProvider.

        Args:
            directory_path: Directory to scan
            exclude_patterns: Additional patterns to exclude

        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        exclude_set = self.EXCLUDED_FILES.copy()

        if exclude_patterns:
            exclude_set.update(exclude_patterns)

        try:
            # Get all files recursively
            all_files = await self.file_provider.list_directory(
                directory_path, recursive=True, max_files=2000
            )
        except FileProviderFileNotFoundError:
            raise NotADirectoryError(f"Directory not found: {directory_path}") from None
        except FileProviderPermissionError as e:
            raise PermissionError(str(e)) from e

        for file_path in all_files:
            # Convert to Path for easier manipulation
            path_obj = Path(file_path)

            # Skip if file is in excluded directory
            if any(part in exclude_set for part in path_obj.parts):
                continue

            # Skip if file matches excluded pattern
            if any(path_obj.match(pattern) for pattern in exclude_set):
                continue

            # Check if it's actually a file (not directory)
            try:
                if not await self.file_provider.is_file(file_path):
                    continue

                # Skip files larger than 1MB
                file_size = await self.file_provider.get_file_size(file_path)
                if file_size > 1024 * 1024:
                    continue

                # Check if file extension is in scan list or no extension
                if path_obj.suffix in self.SCAN_EXTENSIONS or not path_obj.suffix:
                    files_to_scan.append(file_path)

            except (FileProviderFileNotFoundError, FileProviderPermissionError):
                # Skip files we can't access
                continue

            # Limit to 1000 files to prevent DoS
            if len(files_to_scan) >= 1000:
                logger.warning(f"Limiting scan to 1000 files in {directory_path}")
                break

        return files_to_scan

    def _collect_files(
        self, directory: Path, exclude_patterns: list[str] | None = None
    ) -> list[str]:
        """Collect files to scan from a directory (sync wrapper for backward compatibility).

        Args:
            directory: Directory to scan
            exclude_patterns: Additional patterns to exclude

        Returns:
            List of file paths to scan
        """
        return asyncio.run(self._collect_files_async(str(directory), exclude_patterns))

    async def _run_detect_secrets_async(self, file_paths: list[str]) -> list[SecretsScanResult]:
        """Run detect-secrets on the given files using FileProvider.

        Args:
            file_paths: List of file paths to scan

        Returns:
            List of detected secrets
        """
        if not file_paths:
            return []

        # Create temporary files with the actual content from FileProvider
        temp_dir = None
        temp_file_mapping = {}  # Maps temp file path to original file path

        try:
            temp_dir = tempfile.mkdtemp(prefix="vulnicheck_secrets_")
            temp_files = []

            # Read files and create temporary files
            for original_path in file_paths:
                try:
                    # Read file content using FileProvider
                    content = await self.file_provider.read_file(original_path)

                    # Create temporary file with same extension for better detection
                    path_obj = Path(original_path)
                    suffix = path_obj.suffix or '.txt'

                    with tempfile.NamedTemporaryFile(
                        mode='w',
                        encoding='utf-8',
                        suffix=suffix,
                        dir=temp_dir,
                        delete=False
                    ) as tmp_file:
                        tmp_file.write(content)
                        temp_files.append(tmp_file.name)
                        temp_file_mapping[tmp_file.name] = original_path

                except (FileProviderFileNotFoundError, FileProviderPermissionError) as e:
                    logger.warning(f"Skipping file {original_path}: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Error reading file {original_path}: {e}")
                    continue

            if not temp_files:
                return []

            # Run detect-secrets scan on temporary files
            cmd = ["detect-secrets", "scan"] + temp_files
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=60
            )

            if result.returncode != 0 and result.stderr:
                logger.error(f"detect-secrets error: {result.stderr}")
                return []

            # Parse the JSON output
            try:
                scan_results = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.error("Failed to parse detect-secrets output")
                return []

            # Convert to SecretsScanResult objects, mapping back to original file paths
            secrets = []
            for temp_file_path, file_results in scan_results.get("results", {}).items():
                original_file_path = temp_file_mapping.get(temp_file_path, temp_file_path)
                for secret_data in file_results:
                    secret = SecretsScanResult(
                        file_path=original_file_path,
                        line_number=secret_data.get("line_number", 0),
                        secret_type=secret_data.get("type", "Unknown"),
                        hashed_secret=secret_data.get("hashed_secret", ""),
                        is_verified=secret_data.get("is_verified", False),
                    )
                    secrets.append(secret)

            return secrets

        except subprocess.TimeoutExpired:
            logger.error("detect-secrets scan timed out")
            return []
        except Exception as e:
            logger.error(f"Error running detect-secrets: {e}")
            return []
        finally:
            # Clean up temporary files and directory
            if temp_dir:
                import shutil
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e}")

    def _run_detect_secrets(self, file_paths: list[str]) -> list[SecretsScanResult]:
        """Run detect-secrets on the given files (sync wrapper for backward compatibility).

        Args:
            file_paths: List of file paths to scan

        Returns:
            List of detected secrets
        """
        return asyncio.run(self._run_detect_secrets_async(file_paths))

    def filter_false_positives(
        self, secrets: list[SecretsScanResult]
    ) -> list[SecretsScanResult]:
        """Filter out likely false positives.

        Args:
            secrets: List of detected secrets

        Returns:
            Filtered list of secrets
        """
        filtered = []
        for secret in secrets:
            # Skip test files
            if any(
                pattern in secret.file_path.lower()
                for pattern in ["test_", "_test.", "/tests/", "/test/"]
            ):
                continue

            # Skip example/sample files
            if any(
                pattern in secret.file_path.lower()
                for pattern in ["example", "sample", "demo", "mock"]
            ):
                continue

            # Skip documentation
            if any(
                pattern in secret.file_path.lower()
                for pattern in ["/docs/", "/documentation/", "readme"]
            ):
                continue

            filtered.append(secret)

        return filtered

    def get_secret_severity(self, secret_type: str) -> str:
        """Get severity level for a secret type.

        Args:
            secret_type: Type of secret detected

        Returns:
            Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        critical_types = {
            "AWSKeyDetector",
            "AzureStorageKeyDetector",
            "PrivateKeyDetector",
            "StripeDetector",
            "TwilioKeyDetector",
            "JwtTokenDetector",
        }

        high_types = {
            "BasicAuthDetector",
            "CloudantDetector",
            "GitHubTokenDetector",
            "NpmDetector",
            "SlackDetector",
            "ArtifactoryDetector",
        }

        medium_types = {
            "Base64HighEntropyString",
            "HexHighEntropyString",
            "KeywordDetector",
        }

        if secret_type in critical_types:
            return "CRITICAL"
        elif secret_type in high_types:
            return "HIGH"
        elif secret_type in medium_types:
            return "MEDIUM"
        else:
            return "LOW"
