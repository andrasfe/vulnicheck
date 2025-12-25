"""Secure zip file handling with extraction and validation.

This module provides secure zip file processing capabilities for VulniCheck,
including zip bomb detection, path traversal prevention, and resource limits.
"""

import asyncio
import base64
import io
import logging
import os
import tempfile
import time
import zipfile
from pathlib import Path

from .exceptions import SecurityError
from .space_manager import SpaceConfig, get_space_manager

logger = logging.getLogger(__name__)


class ZipSecurityError(SecurityError):
    """Raised when zip file violates security constraints.

    Inherits from SecurityError for consistent exception handling.
    """
    pass


class ZipBombDetector:
    """Detects potential zip bombs and suspicious zip files.

    Uses conservative thresholds to prevent zip bomb attacks while still
    allowing legitimate use cases. Implements cumulative size tracking
    to prevent multi-file expansion attacks.
    """

    # Security thresholds - tightened for better protection
    MAX_COMPRESSION_RATIO = 20  # Max 20:1 compression ratio (reduced from 100:1)
    MAX_NESTED_ZIPS = 1  # Maximum nested zip files (reduced from 3)
    MAX_FILES = 5000  # Maximum number of files in zip (reduced from 10000)
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB per file (reduced from 100MB)
    MAX_PATH_LENGTH = 260  # Maximum path length
    MAX_CUMULATIVE_SIZE = 200 * 1024 * 1024  # 200MB cumulative extracted size

    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.msi', '.vbs',
        '.js', '.jar', '.ps1', '.psm1', '.sh', '.bash', '.csh', '.fish'
    }

    def __init__(self, max_extracted_size: int = 500 * 1024 * 1024):
        """Initialize zip bomb detector.

        Args:
            max_extracted_size: Maximum total extracted size in bytes
        """
        self.max_extracted_size = max_extracted_size
        self.total_extracted_size = 0
        self.file_count = 0
        self.nested_zip_count = 0

    def validate_zip_file(self, zip_data: bytes) -> None:
        """Validate zip file for security issues.

        Args:
            zip_data: Raw zip file data

        Raises:
            ZipSecurityError: If zip file violates security constraints
        """
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data), 'r') as zf:
                self._validate_zip_structure(zf)
        except zipfile.BadZipFile:
            raise ZipSecurityError("Invalid or corrupted zip file") from None
        except Exception as e:
            raise ZipSecurityError(f"Zip validation error: {e}") from e

    def _validate_zip_structure(self, zf: zipfile.ZipFile) -> None:
        """Validate the structure of a zip file.

        Args:
            zf: Open ZipFile object

        Raises:
            ZipSecurityError: If structure violates security constraints
        """
        file_list = zf.infolist()

        # Check file count
        if len(file_list) > self.MAX_FILES:
            raise ZipSecurityError(f"Too many files in zip: {len(file_list)} > {self.MAX_FILES}")

        total_compressed = 0
        total_uncompressed = 0

        for info in file_list:
            # Check path traversal
            if self._is_path_traversal(info.filename):
                raise ZipSecurityError(f"Path traversal detected: {info.filename}")

            # Check path length
            if len(info.filename) > self.MAX_PATH_LENGTH:
                raise ZipSecurityError(f"Path too long: {len(info.filename)} > {self.MAX_PATH_LENGTH}")

            # Check file size
            if info.file_size > self.MAX_FILE_SIZE:
                raise ZipSecurityError(f"File too large: {info.file_size} > {self.MAX_FILE_SIZE}")

            # Check for dangerous file extensions
            if self._is_dangerous_file(info.filename):
                raise ZipSecurityError(f"Dangerous file type detected: {info.filename}")

            # Count nested zips
            if info.filename.lower().endswith('.zip'):
                self.nested_zip_count += 1
                if self.nested_zip_count > self.MAX_NESTED_ZIPS:
                    raise ZipSecurityError(f"Too many nested zip files: {self.nested_zip_count}")

            total_compressed += info.compress_size
            total_uncompressed += info.file_size

        # Check compression ratio
        if total_compressed > 0:
            compression_ratio = total_uncompressed / total_compressed
            if compression_ratio > self.MAX_COMPRESSION_RATIO:
                raise ZipSecurityError(
                    f"Suspicious compression ratio: {compression_ratio:.1f}:1 > {self.MAX_COMPRESSION_RATIO}:1"
                )

        # Check cumulative extracted size (additional protection against multi-file attacks)
        if total_uncompressed > self.MAX_CUMULATIVE_SIZE:
            raise ZipSecurityError(
                f"Cumulative extracted size too large: {total_uncompressed} > {self.MAX_CUMULATIVE_SIZE}"
            )

        # Check total extracted size
        if total_uncompressed > self.max_extracted_size:
            raise ZipSecurityError(
                f"Extracted size too large: {total_uncompressed} > {self.max_extracted_size}"
            )

    def _is_path_traversal(self, filename: str) -> bool:
        """Check if filename contains path traversal patterns.

        Args:
            filename: File path to check

        Returns:
            True if path traversal detected
        """
        # Normalize path and check for traversal
        normalized = os.path.normpath(filename)
        return (
            normalized.startswith('../') or
            '/../' in normalized or
            normalized.startswith('/') or
            ':' in normalized  # Windows drive letters
        )

    def _is_dangerous_file(self, filename: str) -> bool:
        """Check if file has dangerous extension.

        Args:
            filename: File name to check

        Returns:
            True if file extension is dangerous
        """
        ext = Path(filename).suffix.lower()
        return ext in self.DANGEROUS_EXTENSIONS


class ZipHandler:
    """Handles secure zip file extraction and management."""

    def __init__(self, space_config: SpaceConfig | None = None):
        """Initialize zip handler.

        Args:
            space_config: Space management configuration
        """
        self.space_manager = get_space_manager(space_config)
        self._extraction_lock = asyncio.Lock()
        self._active_extractions: dict[str, float] = {}  # extraction_id -> start_time

        # Security limits - tightened for better protection
        self.MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50MB (reduced from 100MB)
        self.MAX_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200MB (reduced from 500MB)
        self.EXTRACTION_TIMEOUT = 30  # seconds (reduced from 60)

    async def extract_zip(self, zip_content: str, prefix: str = "vulnicheck_zip") -> tuple[Path, str]:
        """Extract zip content to temporary directory.

        Args:
            zip_content: Base64 encoded zip content
            prefix: Prefix for temporary directory name

        Returns:
            Tuple of (extraction_path, extraction_id)

        Raises:
            ZipSecurityError: If zip file violates security constraints
            ValueError: If input is invalid
        """
        # Generate unique extraction ID
        extraction_id = f"{prefix}_{int(time.time())}_{os.getpid()}"

        async with self._extraction_lock:
            try:
                # Decode base64 content
                try:
                    zip_data = base64.b64decode(zip_content)
                except Exception as e:
                    raise ValueError(f"Invalid base64 content: {e}") from e

                # Check zip file size
                if len(zip_data) > self.MAX_ZIP_SIZE:
                    raise ZipSecurityError(f"Zip file too large: {len(zip_data)} > {self.MAX_ZIP_SIZE}")

                # Security validation
                detector = ZipBombDetector(self.MAX_EXTRACTED_SIZE)
                detector.validate_zip_file(zip_data)

                # Check available space
                estimated_size_mb = len(zip_data) / (1024 * 1024) * 2  # Rough estimate
                can_proceed, message = await self.space_manager.check_space_before_clone(estimated_size_mb)
                if not can_proceed:
                    raise ZipSecurityError(f"Insufficient space: {message}")

                # Create temporary directory
                temp_dir = Path(tempfile.mkdtemp(prefix=f"{prefix}_", dir="/tmp"))

                # Register with space manager
                await self.space_manager.register_temp_directory(temp_dir)

                # Track extraction
                self._active_extractions[extraction_id] = time.time()

                # Extract with timeout protection
                extraction_task = asyncio.create_task(
                    self._extract_with_validation(zip_data, temp_dir, detector)
                )

                try:
                    await asyncio.wait_for(extraction_task, timeout=self.EXTRACTION_TIMEOUT)
                except asyncio.TimeoutError:
                    # Cleanup on timeout
                    extraction_task.cancel()
                    await self._cleanup_extraction(temp_dir, extraction_id)
                    raise ZipSecurityError(f"Extraction timeout ({self.EXTRACTION_TIMEOUT}s)") from None

                logger.info(f"Successfully extracted zip to {temp_dir}")
                return temp_dir, extraction_id

            except Exception:
                # Cleanup on any error
                if 'temp_dir' in locals():
                    await self._cleanup_extraction(temp_dir, extraction_id)
                raise
            finally:
                # Remove from active extractions
                self._active_extractions.pop(extraction_id, None)

    async def _extract_with_validation(self, zip_data: bytes, temp_dir: Path, detector: ZipBombDetector) -> None:
        """Extract zip data with validation.

        Args:
            zip_data: Raw zip data
            temp_dir: Target directory
            detector: Security validator
        """
        import io

        with zipfile.ZipFile(io.BytesIO(zip_data), 'r') as zf:
            for info in zf.infolist():
                # Skip directories
                if info.is_dir():
                    continue

                # Validate file path
                safe_path = self._sanitize_path(info.filename)
                target_path = temp_dir / safe_path

                # Ensure target directory exists
                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract file with size validation
                with zf.open(info) as source, open(target_path, 'wb') as target:
                    copied = 0
                    while True:
                        chunk = source.read(8192)
                        if not chunk:
                            break

                        target.write(chunk)
                        copied += len(chunk)
                        detector.total_extracted_size += len(chunk)

                        # Check size limits during extraction
                        if copied > detector.MAX_FILE_SIZE:
                            raise ZipSecurityError(f"File size exceeded during extraction: {info.filename}")

                        if detector.total_extracted_size > detector.max_extracted_size:
                            raise ZipSecurityError("Total extracted size limit exceeded")

    def _sanitize_path(self, filename: str) -> Path:
        """Sanitize file path for safe extraction.

        Args:
            filename: Original filename from zip

        Returns:
            Sanitized path
        """
        # Remove any path traversal components
        parts = []
        for part in Path(filename).parts:
            if part in ('.', '..'):
                continue
            if part.startswith('/'):
                part = part[1:]
            parts.append(part)

        if not parts:
            raise ZipSecurityError(f"Invalid filename after sanitization: {filename}")

        return Path(*parts)

    async def cleanup_extraction(self, temp_dir: Path, extraction_id: str) -> None:
        """Clean up extracted files.

        Args:
            temp_dir: Directory to clean up
            extraction_id: Extraction ID for tracking
        """
        await self._cleanup_extraction(temp_dir, extraction_id)

    async def _cleanup_extraction(self, temp_dir: Path, extraction_id: str) -> None:
        """Internal cleanup method.

        Args:
            temp_dir: Directory to clean up
            extraction_id: Extraction ID for tracking
        """
        try:
            if temp_dir.exists():
                # Calculate size before cleanup
                size_mb = self.space_manager.get_directory_size_mb(temp_dir)

                # Remove directory
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)

                # Unregister from space manager
                await self.space_manager.unregister_temp_directory(temp_dir)

                logger.info(f"Cleaned up extraction {extraction_id}: {temp_dir} ({size_mb:.1f}MB)")
        except Exception as e:
            logger.warning(f"Error during cleanup of {temp_dir}: {e}")

    async def list_files(self, extraction_dir: Path, pattern: str = "**/*") -> list[Path]:
        """List files in extracted directory.

        Args:
            extraction_dir: Extracted directory path
            pattern: Glob pattern for file matching

        Returns:
            List of file paths
        """
        if not extraction_dir.exists():
            return []

        try:
            files = [f for f in extraction_dir.glob(pattern) if f.is_file()]
            return sorted(files)
        except Exception as e:
            logger.warning(f"Error listing files in {extraction_dir}: {e}")
            return []

    async def find_dependency_files(self, extraction_dir: Path) -> list[Path]:
        """Find dependency files in extracted directory.

        Args:
            extraction_dir: Extracted directory path

        Returns:
            List of dependency file paths
        """
        dependency_patterns = [
            "**/requirements*.txt",
            "**/pyproject.toml",
            "**/setup.py",
            "**/Pipfile",
            "**/Pipfile.lock",
            "**/poetry.lock"
        ]

        files = []
        for pattern in dependency_patterns:
            files.extend(await self.list_files(extraction_dir, pattern))

        return files

    async def find_dockerfiles(self, extraction_dir: Path) -> list[Path]:
        """Find Dockerfiles in extracted directory.

        Args:
            extraction_dir: Extracted directory path

        Returns:
            List of Dockerfile paths
        """
        dockerfile_patterns = [
            "**/Dockerfile*",
            "**/dockerfile*",
            "**/*.dockerfile"
        ]

        files = []
        for pattern in dockerfile_patterns:
            files.extend(await self.list_files(extraction_dir, pattern))

        return files

    async def find_python_files(self, extraction_dir: Path) -> list[Path]:
        """Find Python files in extracted directory.

        Args:
            extraction_dir: Extracted directory path

        Returns:
            List of Python file paths
        """
        return await self.list_files(extraction_dir, "**/*.py")


# Global instance for singleton pattern
_zip_handler: ZipHandler | None = None


def get_zip_handler(space_config: SpaceConfig | None = None) -> ZipHandler:
    """Get or create the global zip handler instance.

    Args:
        space_config: Configuration for space management

    Returns:
        The global ZipHandler instance
    """
    global _zip_handler
    if _zip_handler is None:
        _zip_handler = ZipHandler(space_config)
    return _zip_handler
