# FileProvider Integration Summary

This document summarizes the hybrid FileProvider integration implemented in VulniCheck server.py to support HTTP-only deployment mode.

## Overview

The VulniCheck MCP server now supports two deployment modes:

1. **Local Mode** (default): Traditional deployment where the server has direct filesystem access
2. **HTTP Mode**: HTTP-only deployment where client files are accessed via MCP callback tools

## Changes Made

### 1. FileProvider Architecture Integration

- Added imports for `FileProvider`, `LocalFileProvider`, `MCPClientFileProvider` and factory functions
- Integrated existing FileProvider-enabled scanners: `SecretsScanner`, `DockerScanner`, and `DependencyScannerWithProvider`

### 2. Deployment Mode Detection

Added intelligent detection logic in `_detect_deployment_mode()`:

```python
# Checks environment variables
VULNICHECK_HTTP_ONLY=true/1/yes  # Explicit HTTP mode
MCP_TRANSPORT=http/sse           # Transport-based detection

# Defaults to "local" for backward compatibility
```

### 3. Tool Updates

Updated client-delegated scanning tools to use appropriate FileProviders:

- **`scan_dependencies`**: Now uses `DependencyScannerWithProvider` with client FileProvider
- **`scan_for_secrets`**: Uses `SecretsScanner` with async FileProvider methods  
- **`scan_dockerfile`**: Uses `DockerScanner` with client FileProvider

### 4. Hybrid Provider Strategy

- **Client operations** (scan_dependencies, scan_for_secrets, scan_dockerfile): Use `MCPClientFileProvider` in HTTP mode, `LocalFileProvider` in local mode
- **Server operations** (scan_github_repo): Always use `LocalFileProvider` for cloned repositories
- **API operations** (check_package_vulnerabilities, get_cve_details): No file operations needed

## Environment Variables

- `VULNICHECK_HTTP_ONLY`: Set to "true"/"1"/"yes" to force HTTP mode
- `VULNICHECK_MCP_SERVER`: MCP server name for client file operations (default: "files")

## Backward Compatibility

- **100% backward compatible** with existing MCP configurations
- Defaults to local mode when no HTTP indicators are present
- Traditional scanners remain available for compatibility
- All existing tool signatures unchanged

## Testing

The integration has been tested for:

- ✅ Successful imports and initialization
- ✅ Local mode deployment (default)
- ✅ HTTP mode deployment with MCPClientFileProvider  
- ✅ FileProvider type assignment per scanner
- ✅ Tool accessibility and function signatures
- ✅ Graceful fallback when MCP servers are unavailable

## Implementation Details

### Initialization Flow

```python
def _ensure_clients_initialized():
    # 1. Initialize vulnerability clients (OSV, NVD, GitHub, etc.)
    # 2. Initialize traditional scanners (backward compatibility)
    # 3. Detect deployment mode (local vs http)
    # 4. Create appropriate FileProviders
    # 5. Initialize FileProvider-enabled scanners
    # 6. Initialize remote operation scanners (GitHub)
```

### FileProvider Selection Logic

```python
# Client operations (scan user files)
if deployment_mode == "http":
    client_file_provider = MCPClientFileProvider(server_name)
else:
    client_file_provider = LocalFileProvider()

# Server operations (clone repos, etc.)
local_file_provider = LocalFileProvider()  # Always local
```

## Benefits

1. **Seamless HTTP deployment**: VulniCheck can now run in HTTP-only environments
2. **Client-delegated file access**: No need for shared filesystems or file uploads
3. **Zero breaking changes**: Existing configurations continue to work
4. **Intelligent provider selection**: Automatic selection based on deployment context
5. **Hybrid architecture**: Combines local and remote operations optimally

## Future Considerations

- Tool performance in HTTP mode depends on MCP client file operations
- Large directory scans may be slower over MCP compared to local filesystem
- Error handling may vary between LocalFileProvider and MCPClientFileProvider
- Consider caching strategies for frequently accessed files in HTTP mode