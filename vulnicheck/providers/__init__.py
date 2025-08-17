"""
File provider abstractions for VulniCheck.

This package provides interfaces and implementations for file operations,
enabling HTTP-only deployment with client-delegated file operations.
"""

from .base import (
    FileNotFoundError,
    FileProvider,
    FileProviderError,
    FileSizeLimitExceededError,
    FileStats,
    FileType,
    PermissionError,
    UnsupportedOperationError,
)
from .local import LocalFileProvider
from .mcp_client import MCPClientFileProvider

__all__ = [
    "FileProvider",
    "FileStats",
    "FileType",
    "FileProviderError",
    "FileNotFoundError",
    "PermissionError",
    "FileSizeLimitExceededError",
    "UnsupportedOperationError",
    "LocalFileProvider",
    "MCPClientFileProvider",
]
