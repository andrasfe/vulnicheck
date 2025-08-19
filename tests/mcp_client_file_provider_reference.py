"""
Test utilities for MCP client file provider tools testing.
This module provides reference implementations for testing purposes only.
"""

import base64
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FileProviderConfig:
    """Configuration for file provider."""
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_DIRECTORY_FILES: int = 1000
    MAX_PATH_DEPTH: int = 20
    ALLOWED_PATHS: list[str] = field(default_factory=list)
    BLOCKED_PATHS: list[str] = field(default_factory=list)
    ENABLE_PATH_RESTRICTIONS: bool = True

# Global configuration instance
_config = FileProviderConfig()


def configure_file_provider(
    config: FileProviderConfig | None = None,
    max_file_size: int | None = None,
    allowed_paths: list[str] | None = None,
    blocked_paths: list[str] | None = None,
    enable_audit_log: bool | None = None,
    **kwargs: Any
) -> None:
    """Configure the file provider with given settings."""
    global _config

    if config is not None:
        _config = config
        return

    # Update individual fields if provided
    if max_file_size is not None:
        _config.MAX_FILE_SIZE = max_file_size
    if allowed_paths is not None:
        _config.ALLOWED_PATHS = allowed_paths
    if blocked_paths is not None:
        _config.BLOCKED_PATHS = blocked_paths
    # Note: enable_audit_log is accepted for compatibility but ignored in this reference implementation


def validate_path(path: str) -> Path | dict[str, Any]:
    """Validate and resolve a file path."""
    try:
        # Basic path validation
        if not path or path.strip() == "":
            return {"error_type": "FileProviderError", "error": "Empty path provided"}

        # Convert to Path object and resolve
        resolved_path = Path(path).resolve()

        # Check path depth (simple approximation)
        if len(resolved_path.parts) > _config.MAX_PATH_DEPTH:
            return {"error_type": "FileProviderError", "error": f"Path too deep (max {_config.MAX_PATH_DEPTH} levels)"}

        return resolved_path

    except Exception as e:
        return {"error_type": "FileProviderError", "error": f"Invalid path: {e}"}


def check_file_size(size_or_path: int | str, max_size: int | None = None) -> dict[str, Any] | None:
    """Check if file size is within limits."""
    if max_size is None:
        max_size = _config.MAX_FILE_SIZE

    # If passed an integer, check size directly
    if isinstance(size_or_path, int):
        if size_or_path > max_size:
            return {"error": f"Size {size_or_path} exceeds limit {max_size}"}
        return None

    # If passed a string, treat as file path
    try:
        path = Path(size_or_path)
        if path.exists() and path.is_file():
            size = path.stat().st_size
            if size > max_size:
                return {
                    "valid": False,
                    "error": f"File too large: {size} bytes (max {max_size})"
                }
            return {"valid": True, "size": size}
        return {"valid": False, "error": "File does not exist"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


async def read_file(file_path: str, encoding: str = "utf-8", max_size: int | None = None) -> str | dict[str, str]:
    """Read text file contents."""
    path_result = validate_path(file_path)
    if isinstance(path_result, dict):
        return {"error_type": "FileProviderError", "error": path_result["error"]}

    # Check if it's a directory
    if path_result.is_dir():
        return {"error_type": "FileProviderError", "error": "Path is not a file"}

    # Check file size with custom limit if provided
    if max_size is not None:
        size_check = check_file_size(file_path, max_size=max_size)
    else:
        size_check = check_file_size(file_path)

    if size_check is not None and not size_check.get("valid", True):
        if "too large" in size_check["error"].lower():
            return {"error_type": "FileSizeLimitExceededError", "error": size_check["error"]}
        elif "does not exist" in size_check["error"].lower():
            return {"error_type": "FileNotFoundError", "error": size_check["error"]}
        else:
            return {"error_type": "FileProviderError", "error": size_check["error"]}

    try:
        with open(path_result, encoding=encoding) as f:
            return f.read()
    except FileNotFoundError as e:
        return {"error_type": "FileNotFoundError", "error": f"File not found: {e}"}
    except PermissionError as e:
        return {"error_type": "PermissionError", "error": f"Permission denied: {e}"}
    except Exception as e:
        return {"error_type": "FileProviderError", "error": f"Failed to read file: {e}"}


async def read_file_binary(file_path: str) -> str | dict[str, str]:
    """Read binary file and return base64 encoded string."""
    path_result = validate_path(file_path)
    if isinstance(path_result, dict):
        return {"error_type": "FileProviderError", "error": path_result["error"]}

    size_check = check_file_size(file_path)
    if size_check is not None and not size_check["valid"]:
        if "too large" in size_check["error"].lower():
            return {"error_type": "FileSizeLimitExceededError", "error": size_check["error"]}
        elif "does not exist" in size_check["error"].lower():
            return {"error_type": "FileNotFoundError", "error": size_check["error"]}
        else:
            return {"error_type": "FileProviderError", "error": size_check["error"]}

    try:
        with open(path_result, 'rb') as f:
            binary_data = f.read()
            return base64.b64encode(binary_data).decode('ascii')
    except FileNotFoundError as e:
        return {"error_type": "FileNotFoundError", "error": f"File not found: {e}"}
    except PermissionError as e:
        return {"error_type": "PermissionError", "error": f"Permission denied: {e}"}
    except Exception as e:
        return {"error_type": "FileProviderError", "error": f"Failed to read binary file: {e}"}


async def list_directory(
    directory_path: str,
    pattern: str | None = None,
    recursive: bool = False,
    max_files: int | None = None
) -> list[str] | dict[str, str]:
    """List directory contents."""
    path_result = validate_path(directory_path)
    if isinstance(path_result, dict):
        return {"error_type": "FileProviderError", "error": path_result["error"]}

    if not path_result.exists():
        return {"error_type": "FileNotFoundError", "error": "Directory does not exist"}

    if not path_result.is_dir():
        return {"error_type": "FileProviderError", "error": "Path is not a directory"}

    try:
        files: list[str] = []
        max_files = max_files or _config.MAX_DIRECTORY_FILES

        if recursive:
            pattern_glob = f"**/{pattern}" if pattern else "**/*"
            entries = path_result.glob(pattern_glob)
        else:
            pattern_glob = pattern if pattern else "*"
            entries = path_result.glob(pattern_glob)

        for entry in entries:
            if len(files) >= max_files:
                break
            files.append(str(entry))

        return files
    except PermissionError as e:
        return {"error_type": "PermissionError", "error": f"Permission denied: {e}"}
    except Exception as e:
        return {"error_type": "FileProviderError", "error": f"Failed to list directory: {e}"}


async def file_exists(file_path: str) -> bool:
    """Check if file or directory exists."""
    path_result = validate_path(file_path)
    if isinstance(path_result, dict):
        return False
    try:
        return path_result.exists()
    except PermissionError:
        return False


async def get_file_stats(file_path: str) -> dict[str, Any]:
    """Get file statistics."""
    path_result = validate_path(file_path)
    if isinstance(path_result, dict):
        return {"error_type": "FileProviderError", "error": path_result["error"]}

    if not path_result.exists():
        return {"error_type": "FileNotFoundError", "error": "File does not exist"}

    try:
        stat = path_result.stat()
        is_file = path_result.is_file()
        is_dir = path_result.is_dir()

        return {
            "file_type": "file" if is_file else "directory",
            "is_directory": is_dir,
            "size": stat.st_size,
            "modified_time": stat.st_mtime,
            "created": stat.st_ctime,
            "permissions": oct(stat.st_mode)[-3:],
            "is_readable": True,  # Simplified - if we can stat it, we can probably read it
            # Legacy fields for backward compatibility
            "type": "file" if is_file else "directory",
            "modified": stat.st_mtime
        }
    except PermissionError as e:
        return {"error_type": "PermissionError", "error": f"Permission denied: {e}"}
    except Exception as e:
        return {"error_type": "FileProviderError", "error": f"Failed to get file stats: {e}"}


async def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str | dict[str, str]:
    """Calculate file hash."""
    path_result = validate_path(file_path)
    if isinstance(path_result, dict):
        return {"error_type": "FileProviderError", "error": path_result["error"]}

    if not path_result.exists():
        return {"error_type": "FileNotFoundError", "error": "File does not exist"}

    if not path_result.is_file():
        return {"error_type": "FileProviderError", "error": "Path is not a file"}

    try:
        if algorithm.lower() not in ["md5", "sha256"]:
            return {"error_type": "FileProviderError", "error": "Invalid hash algorithm"}

        hash_obj = hashlib.new(algorithm.lower())
        with open(path_result, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()
    except PermissionError as e:
        return {"error_type": "PermissionError", "error": f"Permission denied: {e}"}
    except Exception as e:
        return {"error_type": "FileProviderError", "error": f"Failed to calculate hash: {e}"}


async def find_files(
    directory_path: str,
    patterns: list[str],
    recursive: bool = True,
    max_files: int | None = None
) -> list[str] | dict[str, str]:
    """Find files matching patterns."""
    path_result = validate_path(directory_path)
    if isinstance(path_result, dict):
        return {"error_type": "FileProviderError", "error": path_result["error"]}

    if not path_result.exists():
        return {"error_type": "FileNotFoundError", "error": "Directory does not exist"}

    if not path_result.is_dir():
        return {"error_type": "FileProviderError", "error": "Path is not a directory"}

    try:
        found_files: list[str] = []
        max_files = max_files or _config.MAX_DIRECTORY_FILES

        for pattern in patterns:
            if len(found_files) >= max_files:
                break

            if recursive:
                pattern_glob = f"**/{pattern}"
                entries = path_result.glob(pattern_glob)
            else:
                entries = path_result.glob(pattern)

            for entry in entries:
                if len(found_files) >= max_files:
                    break
                if entry.is_file():
                    found_files.append(str(entry))

        return found_files
    except PermissionError as e:
        return {"error_type": "PermissionError", "error": f"Permission denied: {e}"}
    except Exception as e:
        return {"error_type": "FileProviderError", "error": f"Failed to find files: {e}"}


def get_provider_info() -> dict[str, Any]:
    """Get information about the file provider."""
    return {
        "name": "test_reference",
        "version": "1.0.0",
        "required_tools": [
            "read_file",
            "read_file_binary",
            "list_directory",
            "file_exists",
            "get_file_stats"
        ],
        "optional_tools": [
            "calculate_file_hash",
            "find_files"
        ],
        "security_features": [
            "path_validation",
            "size_limits",
            "permission_checks"
        ],
        "configuration": {
            "max_file_size": _config.MAX_FILE_SIZE,
            "max_directory_files": _config.MAX_DIRECTORY_FILES,
            "max_path_depth": _config.MAX_PATH_DEPTH
        }
    }
