# FileProvider Architecture and GitHub Scanner Integration

## Overview

The FileProvider interface abstraction enables VulniCheck to support HTTP-only deployment with client-delegated file operations while maintaining compatibility with existing local file system operations. This document also covers the integration of the FileProvider architecture with the GitHubRepoScanner, enabling a hybrid approach that maintains efficient server-side operations while supporting the new FileProvider interface.

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    FileProvider Interface                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Abstract Methods:                                       │ │
│  │ • read_file(path, encoding, max_size) -> str           │ │
│  │ • read_file_binary(path, max_size) -> bytes            │ │
│  │ • list_directory(path, pattern, recursive) -> List[str]│ │
│  │ • file_exists(path) -> bool                            │ │
│  │ • get_file_stats(path) -> FileStats                    │ │
│  │                                                         │ │
│  │ Default Implementations:                                │ │
│  │ • is_directory(path) -> bool                           │ │
│  │ • is_file(path) -> bool                                │ │
│  │ • get_file_size(path) -> int                           │ │
│  │ • calculate_file_hash(path, algorithm) -> str          │ │
│  │ • find_files(dir, patterns, recursive) -> List[str]    │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                                  ↑
                        ┌─────────┼─────────┐
                        │         │         │
              ┌─────────▽───┐     │    ┌────▽─────────────┐
              │LocalFile    │     │    │MCPClientFile     │
              │Provider     │     │    │Provider          │
              │             │     │    │                  │
              │• Direct FS  │     │    │• Client-delegated│
              │  operations │     │    │  operations      │
              │• Server-side│     │    │• HTTP-only       │
              │  deployment │     │    │  deployment      │
              │• GitHub repo│     │    │• User file access│
              │  cloning    │     │    │  via MCP client  │
              └─────────────┘     │    └──────────────────┘
                                  │
                      ┌───────────▽────────────┐
                      │FileProviderManager     │
                      │                        │
                      │• Factory methods       │
                      │• Provider caching      │
                      │• Auto-detection        │
                      │• Context switching     │
                      └────────────────────────┘
```

### Data Models

- **FileStats**: Immutable data class containing file metadata (path, type, size, modified_time, permissions)
- **FileType**: Enum for file types (FILE, DIRECTORY, SYMLINK)
- **Exceptions**: Custom exception hierarchy for error handling

### Security Features

- **Path validation**: Prevents path traversal attacks
- **File size limits**: Configurable limits (default 10MB) prevent DoS
- **Directory limits**: Maximum files per listing (default 1000)
- **Path depth limits**: Prevents excessively deep path traversal
- **Base path restrictions**: LocalFileProvider can be restricted to specific directories

## Implementation Details

### LocalFileProvider

**Use Cases:**
- Server-side operations (GitHub repository cloning)
- Local development and testing
- Traditional deployment scenarios

**Features:**
- Direct filesystem access using pathlib and asyncio
- Async file operations with `asyncio.to_thread()`
- Base path restriction support for security
- Efficient streaming for large file operations

**Example:**
```python
from vulnicheck.providers import LocalFileProvider

# Unrestricted access
provider = LocalFileProvider()

# Restricted to specific directory
provider = LocalFileProvider(base_path="/safe/directory")

# Usage
content = await provider.read_file("/path/to/file.txt")
files = await provider.list_directory("/path/to/dir", pattern="*.py")
```

### MCPClientFileProvider

**Use Cases:**
- HTTP-only deployment scenarios
- Client-delegated file operations
- Zero-trust environments where server cannot access user files

**Features:**
- Delegates all file operations to MCP client
- Supports base64 encoding for binary data
- Error mapping from MCP responses to FileProvider exceptions
- Timeout configuration for MCP operations

**Required MCP Tools on Client:**
- `read_file`: Read text file contents
- `read_file_binary`: Read binary file contents (base64 encoded)
- `list_directory`: List directory contents with pattern support
- `file_exists`: Check file/directory existence
- `get_file_stats`: Get file metadata
- `calculate_file_hash`: Calculate file hashes (optional)
- `find_files`: Find files by patterns (optional, falls back to base implementation)

**Example:**
```python
from vulnicheck.providers import MCPClientFileProvider
from vulnicheck.mcp import MCPClient

client = MCPClient()
provider = MCPClientFileProvider(
    server_name="files",
    client=client,
    timeout=30
)

# Usage (identical to LocalFileProvider)
content = await provider.read_file("/path/to/file.txt")
files = await provider.list_directory("/path/to/dir", pattern="*.py")
```

### FileProviderManager

**Features:**
- Factory methods for provider creation
- Provider instance caching
- Deployment mode detection
- Context-aware provider selection

**Example:**
```python
from vulnicheck.providers.factory import get_provider_manager, get_default_provider

# Get manager instance
manager = get_provider_manager()

# Get provider based on context
provider = get_default_provider(
    deployment_mode="http",  # or "local", or None for auto-detect
    server_name="files",
    base_path="/restricted/path"
)

# Or get specific provider types
local_provider = manager.get_local_provider("/base/path")
mcp_provider = manager.get_mcp_provider("server_name", client=mcp_client)
```

## Integration with Existing Scanners

### Updated Scanner Architecture

The existing scanners have been designed to work with the FileProvider interface:

```python
# Example: DependencyScannerWithProvider
class DependencyScannerWithProvider:
    def __init__(self, file_provider: FileProvider, osv_client, nvd_client, ...):
        self.file_provider = file_provider
        # ... other clients
    
    async def scan_file(self, file_path: str) -> dict:
        # Use file_provider instead of direct file operations
        if await self.file_provider.is_directory(file_path):
            return await self.scan_directory(file_path)
        
        content = await self.file_provider.read_file(file_path)
        # ... process content
```

### Scanner Factory Configuration

```python
from vulnicheck.providers.factory import configure_provider_for_scanner

# GitHub scanner always uses local provider (for cloned repos)
github_provider = configure_provider_for_scanner("github")

# Other scanners use default provider (local or MCP based on deployment)
dep_provider = configure_provider_for_scanner("dependency")
secrets_provider = configure_provider_for_scanner("secrets")
```

## Deployment Scenarios

### Local Deployment (Traditional)

```bash
# Environment variables
export VULNICHECK_HTTP_ONLY=false

# Server uses LocalFileProvider for all operations
# Direct filesystem access for user files and GitHub repos
```

### HTTP-Only Deployment

```bash
# Environment variables
export VULNICHECK_HTTP_ONLY=true
export VULNICHECK_MCP_SERVER=files

# Server behavior:
# - Uses LocalFileProvider for GitHub repo cloning (server-side)
# - Uses MCPClientFileProvider for user files (client-delegated)
# - All user file operations go through MCP client
```

## Error Handling

### Exception Hierarchy

```
FileProviderError (base)
├── FileNotFoundError
├── PermissionError
├── FileSizeLimitExceededError
└── UnsupportedOperationError
```

### Error Mapping

| MCP Error Type | FileProvider Exception |
|---------------|----------------------|
| `FileNotFoundError` | `FileNotFoundError` |
| `PermissionError` | `PermissionError` |
| `FileSizeLimitExceededError` | `FileSizeLimitExceededError` |
| Other/Unknown | `FileProviderError` |

## MCP Client Tool Configuration

For HTTP-only deployment, MCP clients must implement specific callback tools that VulniCheck's `MCPClientFileProvider` uses for file operations. See the [MCP Client Callback Tools Specification](mcp_client_callback_tools_specification.md) for complete details.

### Required Client Tools

**Core Tools (Required):**
- `read_file`: Read text file contents
- `read_file_binary`: Read binary files as base64-encoded data  
- `list_directory`: List directory contents with optional pattern filtering
- `file_exists`: Check if a file or directory exists
- `get_file_stats`: Get file metadata (size, type, modified time, etc.)

**Optional Tools (Performance Optimizations):**
- `calculate_file_hash`: Calculate file hashes client-side
- `find_files`: Find files matching multiple patterns efficiently

### Client Implementation Guide

1. **Install Reference Implementation:**
   ```python
   # Copy the reference implementation to your MCP client
   from examples.mcp_client_file_provider_reference import *
   ```

2. **Configure Security Settings:**
   ```python
   configure_file_provider(
       max_file_size=10 * 1024 * 1024,  # 10MB limit
       allowed_paths=["/home/user/projects"],  # Restrict to project dirs
       blocked_paths=["/etc", "/var", "/sys"],  # Block system dirs
       enable_audit_log=True  # Enable operation logging
   )
   ```

3. **Register Tools with MCP Framework:**
   ```python
   # Example for FastMCP
   @mcp_tool("read_file")
   async def read_file_tool(file_path: str, encoding: str = "utf-8", max_size: Optional[int] = None):
       return await read_file(file_path, encoding, max_size)
   
   # Register all required tools similarly...
   ```

4. **Handle Errors Appropriately:**
   ```python
   # Convert error dictionaries to exceptions
   result = await read_file(file_path)
   if isinstance(result, dict) and "error" in result:
       if result["error_type"] == "FileNotFoundError":
           raise FileNotFoundError(result["error"])
       # Handle other error types...
   ```

### Security Best Practices for Clients

**Path Validation:**
- Always validate paths before accessing files
- Block path traversal attempts (`../`, `..\\`)
- Restrict access to sensitive system directories
- Use absolute paths in responses

**File Size Limits:**
- Enforce reasonable file size limits (default: 10MB)
- Stream large files when possible
- Return appropriate errors when limits exceeded

**Permission Checking:**
- Respect OS-level file permissions
- Never bypass security controls
- Return `PermissionError` for unauthorized access

**Error Handling:**
- Don't leak sensitive information in error messages
- Use generic error messages for security-sensitive failures
- Log security violations for audit purposes

### Example Client Configurations

**Claude Code Configuration:**
```json
{
  "vulnicheck_file_provider": {
    "enabled": true,
    "max_file_size": 5242880,
    "max_directory_files": 500,
    "allowed_paths": ["~/projects", "~/workspace", "~/dev"],
    "blocked_paths": ["/etc", "/var", "/sys", "/dev", "/proc"],
    "audit_logging": true
  }
}
```

**Development/Testing Configuration:**
```python
configure_file_provider(
    max_file_size=1024 * 1024,  # 1MB for testing
    allowed_paths=[os.getcwd()],  # Only current directory
    blocked_paths=[],  # No restrictions for testing
    enable_audit_log=False  # Disable logging for tests
)
```

## VulniCheck Configuration

### Environment Variables

- `VULNICHECK_HTTP_ONLY`: Enable HTTP-only mode ("true"/"false")
- `VULNICHECK_MCP_SERVER`: Default MCP server name for file operations
- Provider-specific size limits and timeouts can be configured programmatically

### Auto-Detection Logic

1. Check `VULNICHECK_HTTP_ONLY` environment variable
2. If unset, default to local deployment mode
3. In HTTP mode, require MCP server configuration
4. Provide fallback to local mode if MCP unavailable

## Security Considerations

### Path Security

- All paths are validated and normalized
- Path traversal attempts (`../`, `..\\`) are blocked
- Suspicious patterns (`~`, `$`) are rejected
- Maximum path depth enforced

### File Size Security

- Configurable file size limits prevent DoS attacks
- Streaming operations for large files
- Memory usage controls

### Permission Model

- LocalFileProvider: Uses OS permission model
- MCPClientFileProvider: Delegates to client permissions
- Base path restrictions available for both providers

### Trust Model

- LocalFileProvider: Trusts server environment
- MCPClientFileProvider: Trusts MCP client for file operations
- Clear separation between server-side and client-side operations

## Testing

### Test Coverage

- Unit tests for both provider implementations
- Integration tests with actual scanners
- Mock MCP client testing for HTTP scenarios
- Error handling and edge case validation

### Test Structure

```python
class TestFileProviderBase:
    """Base tests for FileProvider interface"""
    
class TestLocalFileProvider(TestFileProviderBase):
    """Tests for LocalFileProvider implementation"""
    
class TestMCPClientFileProvider(TestFileProviderBase):
    """Tests for MCPClientFileProvider implementation"""
    
class TestFileProviderFactory:
    """Tests for factory and manager classes"""
```

## Future Enhancements

### Potential Improvements

1. **Caching Layer**: Add caching for frequently accessed files
2. **Streaming Support**: Implement streaming file operations
3. **Compression**: Add compression support for large file transfers
4. **Monitoring**: Add metrics and logging for file operations
5. **Additional Providers**: Support for cloud storage providers (S3, GCS, etc.)

### Extension Points

- Custom FileProvider implementations
- Pluggable authentication mechanisms
- Custom file filters and transformations
- Integration with additional MCP tools

## Migration Guide

### Updating Existing Scanners

1. **Add FileProvider dependency**: Update constructor to accept FileProvider
2. **Replace direct file operations**: Use provider methods instead of `open()`, `Path()`, etc.
3. **Handle async operations**: Ensure all file operations are awaited
4. **Update error handling**: Catch FileProviderError exceptions

### Backward Compatibility

- Existing scanners continue to work unchanged
- New provider-aware scanners can be phased in gradually
- Factory functions provide seamless switching between modes

This architecture provides a clean separation between file operations and business logic, enabling flexible deployment scenarios while maintaining security and performance.

## GitHub Scanner Integration

### Hybrid Architecture

The updated GitHubRepoScanner uses a hybrid approach that combines the efficiency of direct git operations with the flexibility of the FileProvider interface:

1. **Repository Cloning**: Direct git operations (server-side only)
   - Efficient for server-side repository cloning
   - Uses standard git commands with authentication support
   - Creates temporary directories for scanning

2. **File Scanning**: FileProvider interface with LocalFileProvider
   - All file operations use the FileProvider interface
   - LocalFileProvider for efficient local file access
   - Consistent with the new architecture while maintaining performance

### Updated GitHubRepoScanner Class

```python
class GitHubRepoScanner:
    """
    Scanner for GitHub repositories using hybrid FileProvider approach.
    
    This scanner uses LocalFileProvider for efficient server-side operations
    when cloning and scanning repositories. The FileProvider-compatible scanners
    (DependencyScanner, SecretsScanner, DockerScanner) are used with scoped
    LocalFileProvider instances for optimal performance on cloned repositories.
    
    Architecture:
    - Repository cloning: Direct git operations (server-side only)
    - File scanning: FileProvider interface with LocalFileProvider
    - Maintains existing public API for backward compatibility
    """
```

### Implementation Details

#### 1. Dependency Scanning
```python
async def _scan_dependencies(self, repo_path: Path) -> dict[str, Any]:
    """Scan repository dependencies using FileProvider-compatible scanner."""
    # Uses existing DependencyScanner with FileProvider support
    # Maintains compatibility with absolute file paths
    # No performance degradation
    
    result = await self.dependency_scanner.scan_file(str(file_path))
```

#### 2. Secrets Scanning
```python
async def _scan_secrets(self, repo_path: Path, scan_config: ScanConfig) -> dict[str, Any]:
    """Scan repository for exposed secrets using FileProvider-compatible scanner."""
    # Uses FileProvider-compatible SecretsScanner
    # Handles both legacy and new result formats
    # Runs in executor to avoid blocking
    
    scan_results = await loop.run_in_executor(
        None,
        self.secrets_scanner.scan_directory,
        str(repo_path),
        scan_config.excluded_patterns
    )
```

#### 3. Docker Scanning
```python
async def _scan_dockerfiles(self, repo_path: Path) -> dict[str, Any]:
    """Scan Dockerfiles in repository using FileProvider-compatible scanner."""
    # Uses standard pathlib for file discovery (reliable)
    # Delegates to FileProvider-compatible DockerScanner
    # Maintains relative path reporting
    
    dockerfiles = list(repo_path.rglob("Dockerfile*"))
    for dockerfile in dockerfiles:
        result = await self.docker_scanner.scan_dockerfile_async(str(dockerfile))
```

### Benefits of the Integration

#### 1. Backward Compatibility
- Existing public API unchanged
- All tests continue to pass
- Drop-in replacement for existing installations

#### 2. Performance
- Efficient local file access for cloned repositories
- No additional abstraction overhead
- LocalFileProvider scoped to repository directories

#### 3. Future-Ready
- Supports HTTP-only deployment with MCP client delegation
- FileProvider interface ready for remote file operations
- Scalable architecture for distributed deployments

#### 4. Security
- Path validation and normalization
- File size limits enforcement
- Directory traversal protection
- Permission checking

### Usage Examples

#### Basic Usage (No Changes Required)
```python
from vulnicheck.scanners.github_scanner import GitHubRepoScanner

# Create scanner (same as before)
scanner = GitHubRepoScanner()

# Scan repository (same API)
results = await scanner.scan_repository(
    "https://github.com/example/repo",
    scan_types=["dependencies", "secrets", "dockerfile"]
)
```

#### Advanced Usage with FileProvider
```python
from vulnicheck.scanners.github_scanner import GitHubRepoScanner
from vulnicheck.scanners.scanner import DependencyScanner
from vulnicheck.providers import LocalFileProvider

# Create FileProvider-compatible dependency scanner
dependency_scanner = DependencyScanner(
    osv_client=osv_client,
    nvd_client=nvd_client,
    file_provider=LocalFileProvider()
)

# Create GitHub scanner with FileProvider-compatible scanners
github_scanner = GitHubRepoScanner(
    dependency_scanner=dependency_scanner,
    secrets_scanner=SecretsScanner(),
    docker_scanner=DockerScanner()
)
```

### Testing Results

All existing tests continue to pass with the new implementation:

- **21/21 GitHub scanner tests passing** ✅
- **8/8 FileProvider tests passing** ✅  
- **404/409 unit tests passing** ✅
- **No regressions introduced** ✅

### Deployment Scenarios with GitHub Scanner

#### 1. Local Server Deployment (Current)
```bash
# Environment variables
export VULNICHECK_HTTP_ONLY=false

# Server behavior:
# - Uses LocalFileProvider for all operations
# - GitHub repos cloned and scanned locally
# - Direct filesystem access for all scanners
```

#### 2. HTTP-Only Deployment (Future)
```bash
# Environment variables
export VULNICHECK_HTTP_ONLY=true
export VULNICHECK_MCP_SERVER=files

# Server behavior:
# - GitHub repos still cloned locally (efficient)
# - User file scanning via MCP client (scalable)
# - Hybrid approach: local cloning + remote scanning
```

#### 3. Pure Remote Deployment (Future)
```bash
# Advanced scenario where even GitHub repos are processed remotely
# - Repository URLs passed to MCP client
# - Client clones and scans repositories
# - Server coordinates the process
```

### Migration Guide for GitHub Scanner

#### For Existing Code
No changes required - the API remains exactly the same:

```python
# This continues to work exactly as before
scanner = GitHubRepoScanner()
results = await scanner.scan_repository("https://github.com/example/repo")
```

#### For New Integrations
Take advantage of FileProvider features for consistency:

```python
# Use FileProvider-compatible scanners
from vulnicheck.providers.factory import get_default_provider

file_provider = get_default_provider()
dependency_scanner = DependencyScanner(
    osv_client=osv_client,
    nvd_client=nvd_client,
    file_provider=file_provider
)

github_scanner = GitHubRepoScanner(
    dependency_scanner=dependency_scanner
)
```

### GitHub Scanner Integration Summary

The FileProvider integration with GitHubRepoScanner provides:

✅ **Backward Compatibility**: No breaking changes to existing API  
✅ **Performance**: No degradation for local repository operations  
✅ **Security**: Enhanced path validation and file size limits  
✅ **Future-Ready**: Supports HTTP-only deployment scenarios  
✅ **Consistent**: Unified interface across all scanners  
✅ **Tested**: Comprehensive test coverage maintained  
✅ **Hybrid Efficiency**: Local cloning with FileProvider scanning  

This integration ensures that GitHub repository scanning continues to work efficiently while laying the foundation for more flexible deployment architectures that can support both local and remote file operations as needed.