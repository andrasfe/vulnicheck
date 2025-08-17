"""
Base file provider interface and data models.

This module defines the core FileProvider interface that abstracts file system
operations to enable both local and remote (MCP client-delegated) file access.
"""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path


class FileType(Enum):
    """File types supported by the file provider."""
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"


@dataclass(frozen=True)
class FileStats:
    """File statistics and metadata."""
    path: str
    file_type: FileType
    size: int
    modified_time: datetime
    is_readable: bool = True
    is_directory: bool = False

    @classmethod
    def from_stat(cls, path: str, stat_result, is_readable: bool = True) -> "FileStats":
        """Create FileStats from os.stat result."""
        import stat

        if stat.S_ISDIR(stat_result.st_mode):
            file_type = FileType.DIRECTORY
            is_directory = True
        elif stat.S_ISLNK(stat_result.st_mode):
            file_type = FileType.SYMLINK
            is_directory = False
        else:
            file_type = FileType.FILE
            is_directory = False

        return cls(
            path=path,
            file_type=file_type,
            size=stat_result.st_size,
            modified_time=datetime.fromtimestamp(stat_result.st_mtime),
            is_readable=is_readable,
            is_directory=is_directory,
        )


class FileProviderError(Exception):
    """Base exception for file provider errors."""
    pass


class FileNotFoundError(FileProviderError):
    """File or directory not found."""
    pass


class PermissionError(FileProviderError):
    """Permission denied for file operation."""
    pass


class FileSizeLimitExceededError(FileProviderError):
    """File size exceeds the allowed limit."""
    pass


class UnsupportedOperationError(FileProviderError):
    """Operation not supported by this file provider."""
    pass


class FileProvider(ABC):
    """
    Abstract interface for file system operations.
    
    This interface abstracts file operations to enable both local server-side
    file access and remote client-delegated file operations via MCP.
    
    Design principles:
    - All paths are treated as strings to maintain compatibility
    - Security limits are enforced at the interface level
    - Async operations support both sync and async implementations
    - Error handling uses custom exceptions for better control
    """

    # Default security limits
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_DIRECTORY_FILES = 1000  # Prevent DoS
    MAX_PATH_DEPTH = 20  # Prevent path traversal

    @abstractmethod
    async def read_file(
        self,
        file_path: str,
        encoding: str = "utf-8",
        max_size: int | None = None
    ) -> str:
        """
        Read the contents of a text file.
        
        Args:
            file_path: Path to the file to read
            encoding: Text encoding to use (default: utf-8)
            max_size: Maximum file size in bytes (default: MAX_FILE_SIZE)
            
        Returns:
            File contents as string
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
            FileSizeLimitExceededError: If file is too large
        """
        pass

    @abstractmethod
    async def read_file_binary(
        self,
        file_path: str,
        max_size: int | None = None
    ) -> bytes:
        """
        Read the contents of a binary file.
        
        Args:
            file_path: Path to the file to read
            max_size: Maximum file size in bytes (default: MAX_FILE_SIZE)
            
        Returns:
            File contents as bytes
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
            FileSizeLimitExceededError: If file is too large
        """
        pass

    @abstractmethod
    async def list_directory(
        self,
        directory_path: str,
        pattern: str | None = None,
        recursive: bool = False,
        max_files: int | None = None
    ) -> list[str]:
        """
        List files and directories in a directory.
        
        Args:
            directory_path: Path to the directory
            pattern: Glob pattern to filter files (optional)
            recursive: Whether to list recursively
            max_files: Maximum number of files to return (default: MAX_DIRECTORY_FILES)
            
        Returns:
            List of file/directory paths
            
        Raises:
            FileNotFoundError: If directory doesn't exist
            PermissionError: If directory can't be accessed
        """
        pass

    @abstractmethod
    async def file_exists(self, path: str) -> bool:
        """
        Check if a file or directory exists.
        
        Args:
            path: Path to check
            
        Returns:
            True if the path exists, False otherwise
        """
        pass

    @abstractmethod
    async def get_file_stats(self, path: str) -> FileStats:
        """
        Get file statistics and metadata.
        
        Args:
            path: Path to the file or directory
            
        Returns:
            FileStats object with metadata
            
        Raises:
            FileNotFoundError: If path doesn't exist
            PermissionError: If path can't be accessed
        """
        pass

    async def is_directory(self, path: str) -> bool:
        """
        Check if a path is a directory.
        
        Args:
            path: Path to check
            
        Returns:
            True if path is a directory, False otherwise
        """
        try:
            stats = await self.get_file_stats(path)
            return stats.is_directory
        except FileProviderError:
            return False

    async def is_file(self, path: str) -> bool:
        """
        Check if a path is a regular file.
        
        Args:
            path: Path to check
            
        Returns:
            True if path is a file, False otherwise
        """
        try:
            stats = await self.get_file_stats(path)
            return stats.file_type == FileType.FILE
        except FileProviderError:
            return False

    async def get_file_size(self, file_path: str) -> int:
        """
        Get the size of a file in bytes.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File size in bytes
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        stats = await self.get_file_stats(file_path)
        return stats.size

    async def calculate_file_hash(
        self,
        file_path: str,
        algorithm: str = "md5",
        chunk_size: int = 4096
    ) -> str:
        """
        Calculate hash of a file.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (md5, sha1, sha256)
            chunk_size: Size of chunks to read
            
        Returns:
            Hex digest of the file hash
        """
        hasher = hashlib.new(algorithm)
        content = await self.read_file_binary(file_path)

        # Process in chunks to handle large files
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i + chunk_size]
            hasher.update(chunk)

        return hasher.hexdigest()

    async def find_files(
        self,
        directory_path: str,
        patterns: list[str],
        recursive: bool = True,
        max_files: int | None = None
    ) -> list[str]:
        """
        Find files matching patterns in a directory.
        
        Args:
            directory_path: Directory to search
            patterns: List of glob patterns to match
            recursive: Whether to search recursively
            max_files: Maximum number of files to return
            
        Returns:
            List of matching file paths
        """
        import fnmatch

        all_files = await self.list_directory(
            directory_path,
            recursive=recursive,
            max_files=max_files
        )

        matching_files = []
        for file_path in all_files:
            # Check if file is actually a file (not directory)
            if await self.is_file(file_path):
                file_name = Path(file_path).name
                # Check if any pattern matches
                if any(fnmatch.fnmatch(file_name, pattern) for pattern in patterns):
                    matching_files.append(file_path)

        return matching_files

    def _validate_path(self, path: str) -> str:
        """
        Validate and normalize a file path.
        
        Args:
            path: Path to validate
            
        Returns:
            Normalized path
            
        Raises:
            FileProviderError: If path is invalid or unsafe
        """
        if not path:
            raise FileProviderError("Path cannot be empty")

        # Check for path traversal attempts
        normalized = Path(path).resolve()
        path_parts = normalized.parts

        # Check depth
        if len(path_parts) > self.MAX_PATH_DEPTH:
            raise FileProviderError(f"Path too deep (max {self.MAX_PATH_DEPTH} levels)")

        # Check for suspicious patterns
        suspicious_patterns = ["../", "..\\", "~", "$"]
        path_str = str(normalized)
        for pattern in suspicious_patterns:
            if pattern in path_str:
                raise FileProviderError(f"Suspicious path pattern detected: {pattern}")

        return path_str

    def _check_file_size(self, size: int, max_size: int | None = None) -> None:
        """
        Check if file size is within limits.
        
        Args:
            size: File size in bytes
            max_size: Maximum allowed size (default: MAX_FILE_SIZE)
            
        Raises:
            FileSizeLimitExceededError: If file is too large
        """
        limit = max_size or self.MAX_FILE_SIZE
        if size > limit:
            raise FileSizeLimitExceededError(
                f"File size {size} bytes exceeds limit of {limit} bytes"
            )
