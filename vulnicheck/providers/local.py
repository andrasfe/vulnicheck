"""
Local file provider implementation.

This module provides a local file system implementation of the FileProvider
interface for server-side operations like GitHub repository cloning.
"""

import asyncio
import glob
import os
from pathlib import Path

from .base import FileNotFoundError as BaseFileNotFoundError
from .base import (
    FileProvider,
    FileProviderError,
    FileStats,
    PermissionError,
)


class LocalFileProvider(FileProvider):
    """
    Local file system implementation of FileProvider.

    This implementation provides direct access to the local file system,
    suitable for server-side operations like GitHub repository cloning.

    Security features:
    - Path validation and normalization
    - File size limits
    - Directory traversal protection
    - Permission checking
    """

    def __init__(self, base_path: str | None = None):
        """
        Initialize local file provider.

        Args:
            base_path: Optional base path to restrict operations to
        """
        self.base_path = Path(base_path).resolve() if base_path else None

    def _get_absolute_path(self, path: str) -> Path:
        """
        Get absolute path, optionally restricted to base_path.

        Args:
            path: Input path

        Returns:
            Absolute Path object

        Raises:
            FileProviderError: If path is outside base_path
        """
        # Validate and normalize the path first
        validated_path = self._validate_path(path)

        # If we have a base_path, resolve relative to it
        if self.base_path:
            if Path(validated_path).is_absolute():
                abs_path = Path(validated_path).resolve()
                # Check if absolute path is within base_path
                try:
                    abs_path.relative_to(self.base_path)
                except ValueError as e:
                    raise FileProviderError(
                        f"Path {abs_path} is outside allowed base path {self.base_path}"
                    ) from e
            else:
                # Resolve relative path against base_path
                abs_path = (self.base_path / validated_path).resolve()
                # Double-check it's still within base_path after resolution
                try:
                    abs_path.relative_to(self.base_path)
                except ValueError as e:
                    raise FileProviderError(
                        f"Path {abs_path} is outside allowed base path {self.base_path}"
                    ) from e
        else:
            abs_path = Path(validated_path).resolve()

        return abs_path

    async def read_file(
        self,
        file_path: str,
        encoding: str = "utf-8",
        max_size: int | None = None
    ) -> str:
        """Read the contents of a text file."""
        abs_path = self._get_absolute_path(file_path)

        # Check if file exists and is readable
        if not abs_path.is_file():
            raise BaseFileNotFoundError(f"File not found: {abs_path}")

        # Check file size
        try:
            size = abs_path.stat().st_size
            self._check_file_size(size, max_size)
        except OSError as e:
            raise PermissionError(f"Cannot access file {abs_path}: {e}") from e

        # Read file asynchronously
        try:
            # Use asyncio.to_thread for truly async file I/O
            def _read_file():
                with open(abs_path, encoding=encoding) as f:
                    return f.read()

            return await asyncio.to_thread(_read_file)
        except OSError as e:
            raise PermissionError(f"Cannot read file {abs_path}: {e}") from e
        except UnicodeDecodeError as e:
            raise FileProviderError(f"Failed to decode file {abs_path} with encoding {encoding}: {e}") from e

    async def read_file_binary(
        self,
        file_path: str,
        max_size: int | None = None
    ) -> bytes:
        """Read the contents of a binary file."""
        abs_path = self._get_absolute_path(file_path)

        # Check if file exists and is readable
        if not abs_path.is_file():
            raise BaseFileNotFoundError(f"File not found: {abs_path}")

        # Check file size
        try:
            size = abs_path.stat().st_size
            self._check_file_size(size, max_size)
        except OSError as e:
            raise PermissionError(f"Cannot access file {abs_path}: {e}") from e

        # Read file asynchronously
        try:
            def _read_file():
                with open(abs_path, 'rb') as f:
                    return f.read()

            return await asyncio.to_thread(_read_file)
        except OSError as e:
            raise PermissionError(f"Cannot read file {abs_path}: {e}") from e

    async def list_directory(
        self,
        directory_path: str,
        pattern: str | None = None,
        recursive: bool = False,
        max_files: int | None = None
    ) -> list[str]:
        """List files and directories in a directory."""
        abs_path = self._get_absolute_path(directory_path)

        # Check if directory exists
        if not abs_path.is_dir():
            raise BaseFileNotFoundError(f"Directory not found: {abs_path}")

        # Check permissions
        if not os.access(abs_path, os.R_OK):
            raise PermissionError(f"Cannot read directory {abs_path}")

        limit = max_files or self.MAX_DIRECTORY_FILES

        try:
            def _list_directory():
                files = []

                if recursive:
                    if pattern:
                        # Use glob for pattern matching with recursion
                        glob_pattern = str(abs_path / "**" / pattern)
                        for file_path in glob.glob(glob_pattern, recursive=True):
                            files.append(str(Path(file_path).resolve()))
                            if len(files) >= limit:
                                break
                    else:
                        # Use rglob for recursive listing
                        for file_path in abs_path.rglob("*"):
                            files.append(str(file_path.resolve()))
                            if len(files) >= limit:
                                break
                else:
                    if pattern:
                        # Use glob for pattern matching
                        glob_pattern = str(abs_path / pattern)
                        for file_path in glob.glob(glob_pattern):
                            files.append(str(Path(file_path).resolve()))
                            if len(files) >= limit:
                                break
                    else:
                        # List directory contents
                        for item in abs_path.iterdir():
                            files.append(str(item.resolve()))
                            if len(files) >= limit:
                                break

                return files

            return await asyncio.to_thread(_list_directory)
        except OSError as e:
            raise PermissionError(f"Cannot list directory {abs_path}: {e}") from e

    async def file_exists(self, path: str) -> bool:
        """Check if a file or directory exists."""
        try:
            abs_path = self._get_absolute_path(path)
            return abs_path.exists()
        except FileProviderError:
            # Re-raise security-related errors (path validation failures)
            raise
        except OSError:
            # Return False for OS-level errors (permission denied, etc.)
            return False

    async def get_file_stats(self, path: str) -> FileStats:
        """Get file statistics and metadata."""
        abs_path = self._get_absolute_path(path)

        try:
            stat_result = abs_path.stat()
            is_readable = os.access(abs_path, os.R_OK)

            return FileStats.from_stat(
                path=str(abs_path),
                stat_result=stat_result,
                is_readable=is_readable
            )
        except OSError as e:
            if e.errno in (2, 3):  # ENOENT, ESRCH
                raise BaseFileNotFoundError(f"Path not found: {abs_path}") from e
            else:
                raise PermissionError(f"Cannot access path {abs_path}: {e}") from e

    async def calculate_file_hash(
        self,
        file_path: str,
        algorithm: str = "md5",
        chunk_size: int = 4096
    ) -> str:
        """Calculate hash of a file using streaming for large files."""
        import hashlib

        abs_path = self._get_absolute_path(file_path)

        # Check if file exists
        if not abs_path.is_file():
            raise BaseFileNotFoundError(f"File not found: {abs_path}")

        # Check file size
        try:
            size = abs_path.stat().st_size
            self._check_file_size(size)
        except OSError as e:
            raise PermissionError(f"Cannot access file {abs_path}: {e}") from e

        # Calculate hash asynchronously
        try:
            def _calculate_hash():
                hasher = hashlib.new(algorithm)
                with open(abs_path, 'rb') as f:
                    while chunk := f.read(chunk_size):
                        hasher.update(chunk)
                return hasher.hexdigest()

            return await asyncio.to_thread(_calculate_hash)
        except OSError as e:
            raise PermissionError(f"Cannot read file {abs_path}: {e}") from e

    def _validate_path(self, path: str) -> str:
        """
        Validate and normalize a file path with enhanced security checks.

        Args:
            path: Path to validate

        Returns:
            Normalized path

        Raises:
            FileProviderError: If path is invalid or unsafe
        """
        if not path:
            raise FileProviderError("Path cannot be empty")

        # Check for path traversal attempts BEFORE resolving
        suspicious_patterns = ["../", "..\\", "~", "$"]
        for pattern in suspicious_patterns:
            if pattern in path:
                raise FileProviderError(f"Suspicious path pattern detected: {pattern}")

        # Check for parent directory references in path components
        path_obj = Path(path)
        for part in path_obj.parts:
            if part == "..":
                raise FileProviderError("Path traversal attempt detected: '..' in path")

        # Now resolve and do other checks
        normalized = path_obj.resolve()
        path_parts = normalized.parts

        # Check depth
        if len(path_parts) > self.MAX_PATH_DEPTH:
            raise FileProviderError(f"Path too deep (max {self.MAX_PATH_DEPTH} levels)")

        return str(normalized)

    def __repr__(self) -> str:
        """String representation of the provider."""
        base_info = f"base_path={self.base_path}" if self.base_path else "unrestricted"
        return f"LocalFileProvider({base_info})"
