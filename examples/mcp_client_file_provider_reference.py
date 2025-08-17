"""
Reference implementation of MCP client callback tools for VulniCheck file provider.

This module provides a complete, production-ready implementation of the file
callback tools that MCP clients need to support VulniCheck's HTTP-only deployment.

Usage:
    1. Copy the tool implementations to your MCP client
    2. Register them with your MCP server framework
    3. Configure security settings as needed
    4. Test with the provided test suite

Security Features:
    - Path validation and sanitization
    - Configurable file size limits
    - Permission checking
    - Safe error handling that doesn't leak information
    - Optional path restrictions
"""

import base64
import fnmatch
import hashlib
import logging
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Configuration - adjust these values for your security requirements
class FileProviderConfig:
    """Configuration for file provider security settings."""
    
    # File size limits
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB default
    MAX_DIRECTORY_FILES = 1000  # Maximum files in directory listing
    MAX_PATH_DEPTH = 20  # Maximum path depth to prevent DoS
    
    # Timeouts
    OPERATION_TIMEOUT = 30  # seconds
    
    # Security settings
    ENABLE_PATH_RESTRICTIONS = True
    ALLOWED_PATHS: List[str] = []  # Empty = allow all (configure as needed)
    BLOCKED_PATHS: List[str] = ["/etc", "/var", "/sys", "/dev", "/proc"]
    
    # Logging
    ENABLE_AUDIT_LOG = True
    LOG_LEVEL = logging.INFO

# Set up logging
logger = logging.getLogger("vulnicheck_file_provider")
logger.setLevel(FileProviderConfig.LOG_LEVEL)

def validate_path(path: str) -> Union[Path, Dict[str, str]]:
    """
    Validate and sanitize a file path for security.
    
    Args:
        path: Raw path string to validate
        
    Returns:
        Path object if valid, error dict if invalid
    """
    try:
        if not path:
            return {"error": "Path cannot be empty", "error_type": "FileProviderError"}
        
        # Resolve path to absolute form and eliminate .. components
        try:
            path_obj = Path(path).resolve()
        except (OSError, ValueError) as e:
            return {"error": f"Invalid path: {e}", "error_type": "FileProviderError"}
        
        path_str = str(path_obj)
        
        # Check path depth to prevent DoS
        if len(path_obj.parts) > FileProviderConfig.MAX_PATH_DEPTH:
            return {
                "error": f"Path too deep (max {FileProviderConfig.MAX_PATH_DEPTH} levels)",
                "error_type": "FileProviderError"
            }
        
        # Check for suspicious patterns (redundant after resolve(), but defense in depth)
        suspicious_patterns = ["../", "..\\", "~"]
        for pattern in suspicious_patterns:
            if pattern in path_str:
                return {
                    "error": f"Suspicious path pattern detected: {pattern}",
                    "error_type": "FileProviderError"
                }
        
        # Apply path restrictions if enabled
        if FileProviderConfig.ENABLE_PATH_RESTRICTIONS:
            # Check blocked paths
            for blocked in FileProviderConfig.BLOCKED_PATHS:
                if path_str.startswith(blocked):
                    return {
                        "error": "Access to this path is not allowed",
                        "error_type": "PermissionError"
                    }
            
            # Check allowed paths (if configured)
            if FileProviderConfig.ALLOWED_PATHS:
                allowed = any(path_str.startswith(allowed_path) 
                            for allowed_path in FileProviderConfig.ALLOWED_PATHS)
                if not allowed:
                    return {
                        "error": "Access to this path is not allowed",
                        "error_type": "PermissionError"
                    }
        
        return path_obj
        
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        return {"error": "Path validation failed", "error_type": "FileProviderError"}

def check_file_size(size: int, max_size: Optional[int] = None) -> Optional[Dict[str, str]]:
    """
    Check if file size is within limits.
    
    Args:
        size: File size in bytes
        max_size: Maximum allowed size (optional)
        
    Returns:
        Error dict if size exceeded, None if OK
    """
    limit = max_size if max_size is not None else FileProviderConfig.MAX_FILE_SIZE
    if size > limit:
        return {
            "error": f"File size {size} bytes exceeds limit of {limit} bytes",
            "error_type": "FileSizeLimitExceededError"
        }
    return None

def log_operation(operation: str, path: str, success: bool = True, error: str = None):
    """Log file operations for audit purposes."""
    if not FileProviderConfig.ENABLE_AUDIT_LOG:
        return
    
    if success:
        logger.info(f"File operation: {operation} on {path} - SUCCESS")
    else:
        logger.warning(f"File operation: {operation} on {path} - FAILED: {error}")

# Core file provider tools

async def read_file(
    file_path: str, 
    encoding: str = "utf-8", 
    max_size: Optional[int] = None
) -> Union[str, Dict[str, str]]:
    """
    Read the contents of a text file.
    
    This is the primary tool for reading text files. It validates the path,
    checks permissions, enforces size limits, and returns the file content
    as a string.
    
    Args:
        file_path: Absolute path to the file
        encoding: Text encoding to use (default: utf-8)
        max_size: Maximum file size in bytes
        
    Returns:
        File contents as string, or error dict
    """
    try:
        # Validate path
        path_result = validate_path(file_path)
        if isinstance(path_result, dict):  # Error
            log_operation("read_file", file_path, False, path_result["error"])
            return path_result
        
        path = path_result
        
        # Check if file exists
        if not path.exists():
            log_operation("read_file", file_path, False, "File not found")
            return {"error": f"File not found: {file_path}", "error_type": "FileNotFoundError"}
        
        # Check if it's actually a file
        if not path.is_file():
            log_operation("read_file", file_path, False, "Not a file")
            return {"error": f"Path is not a file: {file_path}", "error_type": "FileProviderError"}
        
        # Check permissions
        if not os.access(path, os.R_OK):
            log_operation("read_file", file_path, False, "Permission denied")
            return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
        
        # Check file size
        file_size = path.stat().st_size
        size_error = check_file_size(file_size, max_size)
        if size_error:
            log_operation("read_file", file_path, False, size_error["error"])
            return size_error
        
        # Read file content
        try:
            with open(path, 'r', encoding=encoding) as f:
                content = f.read()
            
            log_operation("read_file", file_path, True)
            return content
            
        except UnicodeDecodeError as e:
            log_operation("read_file", file_path, False, f"Encoding error: {e}")
            return {"error": f"Encoding error: {e}", "error_type": "FileProviderError"}
        
    except PermissionError:
        log_operation("read_file", file_path, False, "Permission denied")
        return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
    except Exception as e:
        logger.error(f"Unexpected error in read_file: {e}")
        log_operation("read_file", file_path, False, str(e))
        return {"error": "Unexpected error occurred", "error_type": "FileProviderError"}

async def read_file_binary(
    file_path: str, 
    max_size: Optional[int] = None
) -> Union[str, Dict[str, str]]:
    """
    Read the contents of a binary file, returning base64-encoded data.
    
    This tool reads binary files and returns them as base64-encoded strings
    for safe transport over MCP. The client must decode the base64 data.
    
    Args:
        file_path: Absolute path to the file
        max_size: Maximum file size in bytes
        
    Returns:
        Base64-encoded binary data as string, or error dict
    """
    try:
        # Validate path
        path_result = validate_path(file_path)
        if isinstance(path_result, dict):  # Error
            log_operation("read_file_binary", file_path, False, path_result["error"])
            return path_result
        
        path = path_result
        
        # Check if file exists
        if not path.exists():
            log_operation("read_file_binary", file_path, False, "File not found")
            return {"error": f"File not found: {file_path}", "error_type": "FileNotFoundError"}
        
        # Check if it's actually a file
        if not path.is_file():
            log_operation("read_file_binary", file_path, False, "Not a file")
            return {"error": f"Path is not a file: {file_path}", "error_type": "FileProviderError"}
        
        # Check permissions
        if not os.access(path, os.R_OK):
            log_operation("read_file_binary", file_path, False, "Permission denied")
            return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
        
        # Check file size
        file_size = path.stat().st_size
        size_error = check_file_size(file_size, max_size)
        if size_error:
            log_operation("read_file_binary", file_path, False, size_error["error"])
            return size_error
        
        # Read binary content and encode as base64
        with open(path, 'rb') as f:
            binary_data = f.read()
        
        encoded_data = base64.b64encode(binary_data).decode('utf-8')
        
        log_operation("read_file_binary", file_path, True)
        return encoded_data
        
    except PermissionError:
        log_operation("read_file_binary", file_path, False, "Permission denied")
        return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
    except Exception as e:
        logger.error(f"Unexpected error in read_file_binary: {e}")
        log_operation("read_file_binary", file_path, False, str(e))
        return {"error": "Unexpected error occurred", "error_type": "FileProviderError"}

async def list_directory(
    directory_path: str,
    pattern: Optional[str] = None,
    recursive: bool = False,
    max_files: Optional[int] = None
) -> Union[List[str], Dict[str, str]]:
    """
    List files and directories in a directory.
    
    This tool lists directory contents with optional pattern filtering and
    recursive traversal. It returns absolute paths for all items.
    
    Args:
        directory_path: Absolute path to the directory
        pattern: Glob pattern to filter files (optional)
        recursive: Whether to list recursively (default: false)
        max_files: Maximum number of files to return
        
    Returns:
        List of absolute file paths, or error dict
    """
    try:
        # Validate path
        path_result = validate_path(directory_path)
        if isinstance(path_result, dict):  # Error
            log_operation("list_directory", directory_path, False, path_result["error"])
            return path_result
        
        path = path_result
        
        # Check if directory exists
        if not path.exists():
            log_operation("list_directory", directory_path, False, "Directory not found")
            return {"error": f"Directory not found: {directory_path}", "error_type": "FileNotFoundError"}
        
        # Check if it's actually a directory
        if not path.is_dir():
            log_operation("list_directory", directory_path, False, "Not a directory")
            return {"error": f"Path is not a directory: {directory_path}", "error_type": "FileProviderError"}
        
        # Check permissions
        if not os.access(path, os.R_OK):
            log_operation("list_directory", directory_path, False, "Permission denied")
            return {"error": f"Permission denied: {directory_path}", "error_type": "PermissionError"}
        
        files = []
        file_limit = max_files or FileProviderConfig.MAX_DIRECTORY_FILES
        
        try:
            if recursive:
                # Use rglob for recursive listing
                if pattern:
                    items = path.rglob(pattern)
                else:
                    items = path.rglob("*")
            else:
                # List immediate children
                items = path.iterdir()
            
            for item in items:
                # Apply pattern filter for non-recursive case
                if not recursive and pattern:
                    if not fnmatch.fnmatch(item.name, pattern):
                        continue
                
                files.append(str(item.absolute()))
                
                # Respect file limit
                if len(files) >= file_limit:
                    logger.warning(f"Directory listing truncated to {file_limit} files")
                    break
            
            log_operation("list_directory", directory_path, True)
            return files
            
        except PermissionError as e:
            log_operation("list_directory", directory_path, False, "Permission denied")
            return {"error": f"Permission denied: {directory_path}", "error_type": "PermissionError"}
        
    except Exception as e:
        logger.error(f"Unexpected error in list_directory: {e}")
        log_operation("list_directory", directory_path, False, str(e))
        return {"error": "Unexpected error occurred", "error_type": "FileProviderError"}

async def file_exists(path: str) -> bool:
    """
    Check if a file or directory exists.
    
    This tool is used for existence checks and should never return errors.
    If any error occurs during the check, it returns False.
    
    Args:
        path: Absolute path to check
        
    Returns:
        True if path exists, False otherwise
    """
    try:
        # Validate path (but don't return error, just log)
        path_result = validate_path(path)
        if isinstance(path_result, dict):  # Error
            log_operation("file_exists", path, False, path_result["error"])
            return False
        
        exists = path_result.exists()
        log_operation("file_exists", path, True)
        return exists
        
    except Exception as e:
        logger.debug(f"Error checking file existence for {path}: {e}")
        return False

async def get_file_stats(path: str) -> Union[Dict[str, Any], Dict[str, str]]:
    """
    Get file statistics and metadata.
    
    This tool returns comprehensive metadata about a file or directory,
    including type, size, modification time, and permissions.
    
    Args:
        path: Absolute path to the file or directory
        
    Returns:
        Dictionary with file stats, or error dict
    """
    try:
        # Validate path
        path_result = validate_path(path)
        if isinstance(path_result, dict):  # Error
            log_operation("get_file_stats", path, False, path_result["error"])
            return path_result
        
        path_obj = path_result
        
        # Check if path exists
        if not path_obj.exists():
            log_operation("get_file_stats", path, False, "Path not found")
            return {"error": f"Path not found: {path}", "error_type": "FileNotFoundError"}
        
        try:
            stat_result = path_obj.stat()
        except PermissionError:
            log_operation("get_file_stats", path, False, "Permission denied")
            return {"error": f"Permission denied: {path}", "error_type": "PermissionError"}
        
        # Determine file type
        if path_obj.is_dir():
            file_type = "directory"
            is_directory = True
        elif path_obj.is_symlink():
            file_type = "symlink"
            is_directory = False
        else:
            file_type = "file"
            is_directory = False
        
        # Check readability
        is_readable = os.access(path_obj, os.R_OK)
        
        # Convert modified time to ISO format
        modified_time = datetime.fromtimestamp(stat_result.st_mtime).isoformat()
        
        stats = {
            "path": str(path_obj.absolute()),
            "file_type": file_type,
            "size": stat_result.st_size,
            "modified_time": modified_time,
            "is_readable": is_readable,
            "is_directory": is_directory
        }
        
        log_operation("get_file_stats", path, True)
        return stats
        
    except Exception as e:
        logger.error(f"Unexpected error in get_file_stats: {e}")
        log_operation("get_file_stats", path, False, str(e))
        return {"error": "Unexpected error occurred", "error_type": "FileProviderError"}

# Optional performance optimization tools

async def calculate_file_hash(
    file_path: str, 
    algorithm: str = "md5"
) -> Union[str, Dict[str, str]]:
    """
    Calculate hash of a file (optional performance optimization).
    
    This tool calculates file hashes using various algorithms. It's optional
    but provides better performance than transferring file content for hashing.
    
    Args:
        file_path: Absolute path to the file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hexadecimal hash digest, or error dict
    """
    try:
        # Validate algorithm
        try:
            hasher = hashlib.new(algorithm)
        except ValueError:
            return {"error": f"Invalid hash algorithm: {algorithm}", "error_type": "FileProviderError"}
        
        # Validate path
        path_result = validate_path(file_path)
        if isinstance(path_result, dict):  # Error
            log_operation("calculate_file_hash", file_path, False, path_result["error"])
            return path_result
        
        path = path_result
        
        # Check if file exists
        if not path.exists():
            log_operation("calculate_file_hash", file_path, False, "File not found")
            return {"error": f"File not found: {file_path}", "error_type": "FileNotFoundError"}
        
        # Check if it's actually a file
        if not path.is_file():
            log_operation("calculate_file_hash", file_path, False, "Not a file")
            return {"error": f"Path is not a file: {file_path}", "error_type": "FileProviderError"}
        
        # Check permissions
        if not os.access(path, os.R_OK):
            log_operation("calculate_file_hash", file_path, False, "Permission denied")
            return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
        
        # Calculate hash in chunks to handle large files
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        hash_digest = hasher.hexdigest()
        
        log_operation("calculate_file_hash", file_path, True)
        return hash_digest
        
    except PermissionError:
        log_operation("calculate_file_hash", file_path, False, "Permission denied")
        return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
    except Exception as e:
        logger.error(f"Unexpected error in calculate_file_hash: {e}")
        log_operation("calculate_file_hash", file_path, False, str(e))
        return {"error": "Unexpected error occurred", "error_type": "FileProviderError"}

async def find_files(
    directory_path: str,
    patterns: List[str],
    recursive: bool = True,
    max_files: Optional[int] = None
) -> Union[List[str], Dict[str, str]]:
    """
    Find files matching patterns (optional performance optimization).
    
    This tool efficiently finds files matching multiple glob patterns.
    It's optional but provides better performance than multiple directory listings.
    
    Args:
        directory_path: Directory to search
        patterns: List of glob patterns to match
        recursive: Whether to search recursively (default: true)
        max_files: Maximum number of files to return
        
    Returns:
        List of matching absolute file paths, or error dict
    """
    try:
        # Validate path
        path_result = validate_path(directory_path)
        if isinstance(path_result, dict):  # Error
            log_operation("find_files", directory_path, False, path_result["error"])
            return path_result
        
        path = path_result
        
        # Check if directory exists
        if not path.exists():
            log_operation("find_files", directory_path, False, "Directory not found")
            return {"error": f"Directory not found: {directory_path}", "error_type": "FileNotFoundError"}
        
        # Check if it's actually a directory
        if not path.is_dir():
            log_operation("find_files", directory_path, False, "Not a directory")
            return {"error": f"Path is not a directory: {directory_path}", "error_type": "FileProviderError"}
        
        # Check permissions
        if not os.access(path, os.R_OK):
            log_operation("find_files", directory_path, False, "Permission denied")
            return {"error": f"Permission denied: {directory_path}", "error_type": "PermissionError"}
        
        matching_files = []
        file_limit = max_files or FileProviderConfig.MAX_DIRECTORY_FILES
        
        try:
            # Choose iteration method based on recursive flag
            if recursive:
                items = path.rglob("*")
            else:
                items = path.iterdir()
            
            for item in items:
                # Only process files, not directories
                if not item.is_file():
                    continue
                
                # Check if any pattern matches
                item_name = item.name
                if any(fnmatch.fnmatch(item_name, pattern) for pattern in patterns):
                    matching_files.append(str(item.absolute()))
                    
                    # Respect file limit
                    if len(matching_files) >= file_limit:
                        logger.warning(f"File search truncated to {file_limit} files")
                        break
            
            log_operation("find_files", directory_path, True)
            return matching_files
            
        except PermissionError:
            log_operation("find_files", directory_path, False, "Permission denied")
            return {"error": f"Permission denied: {directory_path}", "error_type": "PermissionError"}
        
    except Exception as e:
        logger.error(f"Unexpected error in find_files: {e}")
        log_operation("find_files", directory_path, False, str(e))
        return {"error": "Unexpected error occurred", "error_type": "FileProviderError"}

# Configuration and setup utilities

def configure_file_provider(
    max_file_size: Optional[int] = None,
    max_directory_files: Optional[int] = None,
    allowed_paths: Optional[List[str]] = None,
    blocked_paths: Optional[List[str]] = None,
    enable_audit_log: Optional[bool] = None
):
    """
    Configure file provider security settings.
    
    Args:
        max_file_size: Maximum file size in bytes
        max_directory_files: Maximum files per directory listing
        allowed_paths: List of allowed path prefixes
        blocked_paths: List of blocked path prefixes
        enable_audit_log: Whether to enable audit logging
    """
    if max_file_size is not None:
        FileProviderConfig.MAX_FILE_SIZE = max_file_size
    
    if max_directory_files is not None:
        FileProviderConfig.MAX_DIRECTORY_FILES = max_directory_files
    
    if allowed_paths is not None:
        FileProviderConfig.ALLOWED_PATHS = allowed_paths
    
    if blocked_paths is not None:
        FileProviderConfig.BLOCKED_PATHS = blocked_paths
    
    if enable_audit_log is not None:
        FileProviderConfig.ENABLE_AUDIT_LOG = enable_audit_log

def get_provider_info() -> Dict[str, Any]:
    """
    Get information about the file provider implementation.
    
    Returns:
        Dictionary with provider information and capabilities
    """
    return {
        "name": "VulniCheck File Provider Reference Implementation",
        "version": "1.0.0",
        "specification_version": "1.0.0",
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
            "permission_checking",
            "file_size_limits",
            "path_restrictions",
            "audit_logging"
        ],
        "configuration": {
            "max_file_size": FileProviderConfig.MAX_FILE_SIZE,
            "max_directory_files": FileProviderConfig.MAX_DIRECTORY_FILES,
            "max_path_depth": FileProviderConfig.MAX_PATH_DEPTH,
            "path_restrictions_enabled": FileProviderConfig.ENABLE_PATH_RESTRICTIONS,
            "allowed_paths": FileProviderConfig.ALLOWED_PATHS,
            "blocked_paths": FileProviderConfig.BLOCKED_PATHS,
            "audit_logging": FileProviderConfig.ENABLE_AUDIT_LOG
        }
    }

# Example MCP tool registration (adapt to your MCP framework)
"""
Example registration for popular MCP frameworks:

# For FastMCP
@mcp_tool("read_file")
async def read_file_tool(file_path: str, encoding: str = "utf-8", max_size: Optional[int] = None):
    return await read_file(file_path, encoding, max_size)

# For mcp-python
@mcp.tool("read_file")
async def read_file_tool(
    file_path: Annotated[str, "Absolute path to the file"],
    encoding: Annotated[str, "Text encoding"] = "utf-8",
    max_size: Annotated[Optional[int], "Maximum file size in bytes"] = None
):
    return await read_file(file_path, encoding, max_size)

# Similar patterns for other tools...
"""

if __name__ == "__main__":
    # Example usage and testing
    import asyncio
    
    async def test_basic_operations():
        """Test basic file provider operations."""
        
        # Configure for testing (allow access to current directory)
        import os
        current_dir = os.getcwd()
        configure_file_provider(
            allowed_paths=[current_dir],
            enable_audit_log=True
        )
        
        print("File Provider Info:")
        print(get_provider_info())
        
        # Test file existence
        print(f"\nFile exists test: {await file_exists(__file__)}")
        
        # Test reading this file
        try:
            content = await read_file(__file__)
            print(f"\nRead file success: {len(content)} characters")
        except Exception as e:
            print(f"Read file error: {e}")
        
        # Test directory listing
        try:
            files = await list_directory(".", pattern="*.py")
            print(f"\nDirectory listing: {len(files)} Python files found")
        except Exception as e:
            print(f"Directory listing error: {e}")
        
        # Test file stats
        try:
            stats = await get_file_stats(__file__)
            if isinstance(stats, dict) and "error" not in stats:
                print(f"\nFile stats: {stats['size']} bytes, modified {stats['modified_time']}")
            else:
                print(f"File stats error: {stats}")
        except Exception as e:
            print(f"File stats error: {e}")
    
    # Run tests
    asyncio.run(test_basic_operations())