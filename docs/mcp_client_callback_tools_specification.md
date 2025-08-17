# MCP Client Callback Tools Specification

## Overview

This document specifies the callback tools that MCP clients must implement to support VulniCheck's file provider system in HTTP-only deployment scenarios. These tools enable VulniCheck to perform file operations on the client side while maintaining security and consistency.

## Architecture

In HTTP-only deployment, VulniCheck's `MCPClientFileProvider` delegates file operations to the MCP client through these callback tools. This enables zero-trust environments where the server cannot access user files directly.

```
┌─────────────────┐    MCP Protocol    ┌──────────────────┐
│   VulniCheck    │◄─────────────────►│   MCP Client     │
│   Server        │                    │  (Claude Code,   │
│                 │                    │   etc.)          │
│ MCPClientFile   │  Tool Calls        │                  │
│ Provider        │───────────────────►│ File Callback   │
│                 │                    │ Tools            │
│                 │◄───────────────────│                  │
│                 │  File Content      │                  │
└─────────────────┘                    └──────────────────┘
                                               │
                                               │ File System
                                               │ Operations
                                               ▼
                                       ┌──────────────────┐
                                       │ Local File System│
                                       │ User Files       │
                                       │ Project Files    │
                                       └──────────────────┘
```

## Required Tools

### 1. read_file

Read the contents of a text file.

**Tool Name:** `read_file`

**Parameters:**
- `file_path` (string, required): Absolute path to the file
- `encoding` (string, optional): Text encoding to use (default: "utf-8")
- `max_size` (integer, optional): Maximum file size in bytes

**Returns:**
- `string`: File contents as text

**Error Handling:**
Return an error object with the following structure if operation fails:
```json
{
  "error": "Human-readable error message",
  "error_type": "FileNotFoundError|PermissionError|FileSizeLimitExceededError|FileProviderError"
}
```

**Example Implementation:**
```python
async def read_file(file_path: str, encoding: str = "utf-8", max_size: Optional[int] = None) -> Union[str, Dict]:
    try:
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}", "error_type": "FileNotFoundError"}
        
        if not path.is_file():
            return {"error": f"Path is not a file: {file_path}", "error_type": "FileProviderError"}
        
        file_size = path.stat().st_size
        if max_size and file_size > max_size:
            return {
                "error": f"File size {file_size} exceeds limit {max_size}",
                "error_type": "FileSizeLimitExceededError"
            }
        
        with open(path, 'r', encoding=encoding) as f:
            return f.read()
            
    except PermissionError:
        return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
    except UnicodeDecodeError as e:
        return {"error": f"Encoding error: {e}", "error_type": "FileProviderError"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "error_type": "FileProviderError"}
```

### 2. read_file_binary

Read the contents of a binary file, returning base64-encoded data.

**Tool Name:** `read_file_binary`

**Parameters:**
- `file_path` (string, required): Absolute path to the file
- `max_size` (integer, optional): Maximum file size in bytes

**Returns:**
- `string`: Base64-encoded binary data

**Error Handling:**
Same error structure as `read_file`.

**Example Implementation:**
```python
import base64

async def read_file_binary(file_path: str, max_size: Optional[int] = None) -> Union[str, Dict]:
    try:
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}", "error_type": "FileNotFoundError"}
        
        if not path.is_file():
            return {"error": f"Path is not a file: {file_path}", "error_type": "FileProviderError"}
        
        file_size = path.stat().st_size
        if max_size and file_size > max_size:
            return {
                "error": f"File size {file_size} exceeds limit {max_size}",
                "error_type": "FileSizeLimitExceededError"
            }
        
        with open(path, 'rb') as f:
            binary_data = f.read()
            return base64.b64encode(binary_data).decode('utf-8')
            
    except PermissionError:
        return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "error_type": "FileProviderError"}
```

### 3. list_directory

List files and directories in a directory.

**Tool Name:** `list_directory`

**Parameters:**
- `directory_path` (string, required): Absolute path to the directory
- `pattern` (string, optional): Glob pattern to filter files
- `recursive` (boolean, optional): Whether to list recursively (default: false)
- `max_files` (integer, optional): Maximum number of files to return

**Returns:**
- `array[string]`: List of file and directory paths (absolute paths)

**Error Handling:**
Same error structure as `read_file`.

**Example Implementation:**
```python
import fnmatch
from pathlib import Path

async def list_directory(
    directory_path: str, 
    pattern: Optional[str] = None,
    recursive: bool = False,
    max_files: Optional[int] = None
) -> Union[List[str], Dict]:
    try:
        path = Path(directory_path)
        if not path.exists():
            return {"error": f"Directory not found: {directory_path}", "error_type": "FileNotFoundError"}
        
        if not path.is_dir():
            return {"error": f"Path is not a directory: {directory_path}", "error_type": "FileProviderError"}
        
        files = []
        
        if recursive:
            # Use rglob for recursive listing
            glob_pattern = "**/*" if not pattern else f"**/{pattern}"
            for item in path.rglob("*" if not pattern else pattern):
                if max_files and len(files) >= max_files:
                    break
                files.append(str(item.absolute()))
        else:
            # List immediate children
            for item in path.iterdir():
                if pattern and not fnmatch.fnmatch(item.name, pattern):
                    continue
                if max_files and len(files) >= max_files:
                    break
                files.append(str(item.absolute()))
        
        return files
        
    except PermissionError:
        return {"error": f"Permission denied: {directory_path}", "error_type": "PermissionError"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "error_type": "FileProviderError"}
```

### 4. file_exists

Check if a file or directory exists.

**Tool Name:** `file_exists`

**Parameters:**
- `path` (string, required): Absolute path to check

**Returns:**
- `boolean`: True if the path exists, false otherwise

**Error Handling:**
This tool should not return errors. If an error occurs, return `false`.

**Example Implementation:**
```python
async def file_exists(path: str) -> bool:
    try:
        return Path(path).exists()
    except:
        return False
```

### 5. get_file_stats

Get file statistics and metadata.

**Tool Name:** `get_file_stats`

**Parameters:**
- `path` (string, required): Absolute path to the file or directory

**Returns:**
- `object`: File statistics with the following structure:
  ```json
  {
    "path": "string (absolute path)",
    "file_type": "file|directory|symlink",
    "size": "integer (bytes)",
    "modified_time": "string (ISO 8601 format)",
    "is_readable": "boolean",
    "is_directory": "boolean"
  }
  ```

**Error Handling:**
Same error structure as `read_file`.

**Example Implementation:**
```python
import os
import stat
from datetime import datetime

async def get_file_stats(path: str) -> Union[Dict, Dict]:
    try:
        path_obj = Path(path)
        if not path_obj.exists():
            return {"error": f"Path not found: {path}", "error_type": "FileNotFoundError"}
        
        stat_result = path_obj.stat()
        
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
        is_readable = os.access(path, os.R_OK)
        
        # Convert modified time to ISO format
        modified_time = datetime.fromtimestamp(stat_result.st_mtime).isoformat()
        
        return {
            "path": str(path_obj.absolute()),
            "file_type": file_type,
            "size": stat_result.st_size,
            "modified_time": modified_time,
            "is_readable": is_readable,
            "is_directory": is_directory
        }
        
    except PermissionError:
        return {"error": f"Permission denied: {path}", "error_type": "PermissionError"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "error_type": "FileProviderError"}
```

## Optional Tools

### 6. calculate_file_hash

Calculate hash of a file (optional, performance optimization).

**Tool Name:** `calculate_file_hash`

**Parameters:**
- `file_path` (string, required): Absolute path to the file
- `algorithm` (string, optional): Hash algorithm ("md5", "sha1", "sha256", default: "md5")

**Returns:**
- `string`: Hexadecimal hash digest

**Example Implementation:**
```python
import hashlib

async def calculate_file_hash(file_path: str, algorithm: str = "md5") -> Union[str, Dict]:
    try:
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}", "error_type": "FileNotFoundError"}
        
        if not path.is_file():
            return {"error": f"Path is not a file: {file_path}", "error_type": "FileProviderError"}
        
        hasher = hashlib.new(algorithm)
        
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
        
    except PermissionError:
        return {"error": f"Permission denied: {file_path}", "error_type": "PermissionError"}
    except ValueError as e:
        return {"error": f"Invalid hash algorithm: {algorithm}", "error_type": "FileProviderError"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "error_type": "FileProviderError"}
```

### 7. find_files

Find files matching patterns (optional, performance optimization).

**Tool Name:** `find_files`

**Parameters:**
- `directory_path` (string, required): Directory to search
- `patterns` (array[string], required): List of glob patterns to match
- `recursive` (boolean, optional): Whether to search recursively (default: true)
- `max_files` (integer, optional): Maximum number of files to return

**Returns:**
- `array[string]`: List of matching file paths (absolute paths)

**Example Implementation:**
```python
import fnmatch

async def find_files(
    directory_path: str,
    patterns: List[str],
    recursive: bool = True,
    max_files: Optional[int] = None
) -> Union[List[str], Dict]:
    try:
        path = Path(directory_path)
        if not path.exists():
            return {"error": f"Directory not found: {directory_path}", "error_type": "FileNotFoundError"}
        
        if not path.is_dir():
            return {"error": f"Path is not a directory: {directory_path}", "error_type": "FileProviderError"}
        
        matching_files = []
        
        if recursive:
            search_pattern = "**/*"
            items = path.rglob("*")
        else:
            items = path.iterdir()
        
        for item in items:
            if not item.is_file():
                continue
                
            # Check if any pattern matches
            if any(fnmatch.fnmatch(item.name, pattern) for pattern in patterns):
                matching_files.append(str(item.absolute()))
                
                if max_files and len(matching_files) >= max_files:
                    break
        
        return matching_files
        
    except PermissionError:
        return {"error": f"Permission denied: {directory_path}", "error_type": "PermissionError"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "error_type": "FileProviderError"}
```

## Security Considerations

### Path Validation

Clients MUST validate all file paths to prevent:
- Path traversal attacks (`../`, `..\\`)
- Access to sensitive system files
- Symlink attacks

**Example validation:**
```python
def validate_path(path: str) -> bool:
    """Validate that path is safe to access."""
    try:
        # Resolve path and check for suspicious patterns
        resolved_path = Path(path).resolve()
        path_str = str(resolved_path)
        
        # Block suspicious patterns
        suspicious_patterns = ["../", "..\\", "~"]
        if any(pattern in path_str for pattern in suspicious_patterns):
            return False
        
        # Check if path is within allowed directories
        # (implement according to your security policy)
        
        return True
    except:
        return False
```

### File Size Limits

Clients SHOULD enforce reasonable file size limits:
- Default maximum: 10MB per file
- Configurable via client settings
- Return `FileSizeLimitExceededError` when exceeded

### Permission Checking

Clients MUST respect OS-level file permissions:
- Check read permissions before file operations
- Return `PermissionError` for unauthorized access
- Never bypass OS security controls

### Memory Management

For large files, clients SHOULD:
- Use streaming operations when possible
- Implement timeout mechanisms
- Monitor memory usage during operations

### Error Information

Error responses MUST NOT leak sensitive information:
- Avoid exposing internal paths in error messages
- Don't reveal directory structure in errors
- Use generic error messages for security-sensitive failures

## Testing

### Test Cases

Clients should test their implementation with:

1. **Basic Operations**
   - Read text files with various encodings
   - Read binary files and verify base64 encoding
   - List directories with and without patterns
   - Check file existence for files and directories
   - Get file statistics for different file types

2. **Error Conditions**
   - Non-existent files and directories
   - Permission denied scenarios
   - File size limit exceeded
   - Invalid parameters

3. **Security Tests**
   - Path traversal attempts
   - Access to system files
   - Large file handling
   - Symlink handling

4. **Performance Tests**
   - Large file operations
   - Large directory listings
   - Recursive directory traversal

### Mock Implementation

For testing, clients can use this mock implementation:

```python
import tempfile
import shutil
from pathlib import Path

class MockFileProvider:
    def __init__(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.setup_test_files()
    
    def setup_test_files(self):
        # Create test files and directories
        (self.temp_dir / "test.txt").write_text("Hello, World!")
        (self.temp_dir / "binary.bin").write_bytes(b"\x00\x01\x02\x03")
        (self.temp_dir / "subdir").mkdir()
        (self.temp_dir / "subdir" / "nested.py").write_text("print('test')")
    
    def cleanup(self):
        shutil.rmtree(self.temp_dir)
    
    # Implement all required tools using self.temp_dir as base path
```

## Integration Examples

### Claude Code Integration

```python
# Example implementation for Claude Code MCP client

@mcp_tool("read_file")
async def read_file_tool(file_path: str, encoding: str = "utf-8", max_size: Optional[int] = None):
    """Read file contents for VulniCheck file provider."""
    return await read_file(file_path, encoding, max_size)

@mcp_tool("read_file_binary")
async def read_file_binary_tool(file_path: str, max_size: Optional[int] = None):
    """Read binary file contents for VulniCheck file provider."""
    return await read_file_binary(file_path, max_size)

@mcp_tool("list_directory")
async def list_directory_tool(
    directory_path: str,
    pattern: Optional[str] = None,
    recursive: bool = False,
    max_files: Optional[int] = None
):
    """List directory contents for VulniCheck file provider."""
    return await list_directory(directory_path, pattern, recursive, max_files)

@mcp_tool("file_exists")
async def file_exists_tool(path: str):
    """Check if file exists for VulniCheck file provider."""
    return await file_exists(path)

@mcp_tool("get_file_stats")
async def get_file_stats_tool(path: str):
    """Get file statistics for VulniCheck file provider."""
    return await get_file_stats(path)
```

### Configuration

Clients should allow users to:
- Enable/disable file provider tools
- Configure security settings (max file size, allowed paths)
- Set timeouts for file operations

**Example configuration:**
```json
{
  "vulnicheck_file_provider": {
    "enabled": true,
    "max_file_size": 10485760,
    "timeout_seconds": 30,
    "allowed_paths": ["/home/user/projects"],
    "blocked_paths": ["/etc", "/var", "/sys"],
    "enable_optional_tools": true
  }
}
```

## Versioning

This specification follows semantic versioning:

- **Current Version**: 1.0.0
- **Breaking Changes**: Major version bump
- **New Optional Tools**: Minor version bump
- **Bug Fixes**: Patch version bump

Clients should declare which specification version they support in their tool metadata.

## Support

For questions about implementing these tools:
1. Check the reference implementations in this document
2. Review the test cases and examples
3. Consult the VulniCheck source code for `MCPClientFileProvider`
4. Submit issues to the VulniCheck repository

This specification enables secure, efficient file operations for VulniCheck's HTTP-only deployment mode while maintaining compatibility with local deployment scenarios.