"""Module for scanning files and directories for secrets using detect-secrets."""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

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

    def to_dict(self) -> Dict[str, Any]:
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

    def __init__(self) -> None:
        """Initialize the secrets scanner."""
        self.baseline_file = ".secrets.baseline"

    def scan_file(self, file_path: str) -> List[SecretsScanResult]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of detected secrets
        """
        path = Path(file_path).resolve()

        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        # Security: Limit file size to 10MB
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError(f"File too large (max 10MB): {path}")

        return self._run_detect_secrets([str(path)])

    def scan_directory(
        self, directory_path: str, exclude_patterns: Optional[List[str]] = None
    ) -> List[SecretsScanResult]:
        """Scan a directory recursively for secrets.

        Args:
            directory_path: Path to the directory to scan
            exclude_patterns: Additional patterns to exclude

        Returns:
            List of detected secrets
        """
        path = Path(directory_path).resolve()

        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        # Collect files to scan
        files_to_scan = self._collect_files(path, exclude_patterns)

        if not files_to_scan:
            return []

        return self._run_detect_secrets(files_to_scan)

    def _collect_files(
        self, directory: Path, exclude_patterns: Optional[List[str]] = None
    ) -> List[str]:
        """Collect files to scan from a directory.

        Args:
            directory: Directory to scan
            exclude_patterns: Additional patterns to exclude

        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        exclude_set = self.EXCLUDED_FILES.copy()

        if exclude_patterns:
            exclude_set.update(exclude_patterns)

        for file_path in directory.rglob("*"):
            # Skip if file is in excluded directory
            if any(part in exclude_set for part in file_path.parts):
                continue

            # Skip if file matches excluded pattern
            if any(file_path.match(pattern) for pattern in exclude_set):
                continue

            # Only scan regular files
            if not file_path.is_file():
                continue

            # Skip files larger than 1MB
            if file_path.stat().st_size > 1024 * 1024:
                continue

            # Check if file extension is in scan list or no extension
            if file_path.suffix in self.SCAN_EXTENSIONS or not file_path.suffix:
                files_to_scan.append(str(file_path))

            # Limit to 1000 files to prevent DoS
            if len(files_to_scan) >= 1000:
                logger.warning(f"Limiting scan to 1000 files in {directory}")
                break

        return files_to_scan

    def _run_detect_secrets(self, file_paths: List[str]) -> List[SecretsScanResult]:
        """Run detect-secrets on the given files.

        Args:
            file_paths: List of file paths to scan

        Returns:
            List of detected secrets
        """
        if not file_paths:
            return []

        try:
            # Run detect-secrets scan
            cmd = ["detect-secrets", "scan", "--no-keyword-scan"] + file_paths
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

            # Convert to SecretsScanResult objects
            secrets = []
            for file_path, file_results in scan_results.get("results", {}).items():
                for secret_data in file_results:
                    secret = SecretsScanResult(
                        file_path=file_path,
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

    def filter_false_positives(
        self, secrets: List[SecretsScanResult]
    ) -> List[SecretsScanResult]:
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
