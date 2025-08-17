# MCP Client Integration Guide for VulniCheck

This guide helps MCP client developers integrate the file provider callback tools required for VulniCheck's HTTP-only deployment mode.

## Quick Start

1. **Copy the reference implementation** to your MCP client codebase:
   ```bash
   curl -O https://raw.githubusercontent.com/your-org/vulnicheck/main/examples/mcp_client_file_provider_reference.py
   ```

2. **Install dependencies**:
   ```bash
   pip install fastmcp  # or your preferred MCP framework
   ```

3. **Register the tools** with your MCP server (see framework-specific examples below)

4. **Configure security settings** appropriate for your environment

5. **Test the implementation** using the provided test suite

## What Are These Tools For?

VulniCheck's HTTP-only deployment mode enables zero-trust environments where:
- The VulniCheck server runs without file system access
- All file operations are delegated to the MCP client  
- Users maintain full control over their files
- No sensitive files are transmitted to remote servers

This is essential for:
- Enterprise environments with strict data policies
- Security-conscious users
- Compliance requirements (SOC2, HIPAA, etc.)
- Air-gapped or restricted networks

## Required Tools Overview

### Core Tools (Must Implement)

| Tool | Purpose | Returns |
|------|---------|---------|
| `read_file` | Read text files | File content as string |
| `read_file_binary` | Read binary files | Base64-encoded binary data |
| `list_directory` | List directory contents | Array of absolute file paths |
| `file_exists` | Check file existence | Boolean |
| `get_file_stats` | Get file metadata | Object with file statistics |

### Optional Tools (Performance Optimizations)

| Tool | Purpose | Benefits |
|------|---------|----------|
| `calculate_file_hash` | Calculate file hashes client-side | Avoids transferring large files for hashing |
| `find_files` | Find files by patterns | More efficient than multiple directory listings |

## Framework-Specific Integration

### FastMCP Integration

```python
from fastmcp import FastMCP, mcp_tool
from mcp_client_file_provider_reference import *

app = FastMCP(name="vulnicheck-file-provider")

@app.startup
async def startup():
    configure_file_provider(
        max_file_size=10 * 1024 * 1024,
        allowed_paths=["/home/user/projects"],
        blocked_paths=["/etc", "/var", "/sys"]
    )

@mcp_tool("read_file")
async def read_file_tool(file_path: str, encoding: str = "utf-8", max_size: Optional[int] = None):
    result = await read_file(file_path, encoding, max_size)
    if isinstance(result, dict) and "error" in result:
        raise RuntimeError(result["error"])
    return result

# Register other tools similarly...
```

### mcp-python Integration

```python
import mcp
from mcp_client_file_provider_reference import *

@mcp.tool("read_file")
async def read_file_tool(
    file_path: str,
    encoding: str = "utf-8", 
    max_size: Optional[int] = None
) -> str:
    result = await read_file(file_path, encoding, max_size)
    if isinstance(result, dict) and "error" in result:
        raise ValueError(result["error"])
    return result
```

### Custom MCP Server

```python
# For custom MCP implementations
class VulniCheckFileProvider:
    def __init__(self):
        configure_file_provider(
            max_file_size=5 * 1024 * 1024,  # 5MB
            allowed_paths=[os.path.expanduser("~/projects")],
            enable_audit_log=True
        )
    
    async def handle_tool_call(self, tool_name: str, parameters: dict):
        if tool_name == "read_file":
            return await read_file(**parameters)
        elif tool_name == "read_file_binary":
            return await read_file_binary(**parameters)
        # Handle other tools...
```

## Security Configuration

### Recommended Settings by Environment

**Development Environment:**
```python
configure_file_provider(
    max_file_size=1024 * 1024,  # 1MB
    allowed_paths=[os.getcwd()],  # Current directory only
    blocked_paths=[],  # No restrictions
    enable_audit_log=False  # Disable logging
)
```

**Production Environment:**
```python
configure_file_provider(
    max_file_size=10 * 1024 * 1024,  # 10MB
    allowed_paths=[
        "/home/user/projects",
        "/home/user/workspace",
        "/opt/user/data"
    ],
    blocked_paths=[
        "/etc", "/var", "/sys", "/dev", "/proc", "/root",
        "/usr/bin", "/usr/sbin", "/sbin", "/bin"
    ],
    enable_audit_log=True  # Enable audit logging
)
```

**High-Security Environment:**
```python
configure_file_provider(
    max_file_size=1024 * 1024,  # 1MB strict limit
    allowed_paths=["/restricted/project/path"],  # Single allowed path
    blocked_paths=["/"],  # Block everything by default
    enable_audit_log=True
)
```

## Error Handling Best Practices

### Convert Error Dictionaries to Exceptions

The reference implementation returns error dictionaries instead of raising exceptions to maintain compatibility with different MCP frameworks. Your tool wrappers should convert these:

```python
@mcp_tool("read_file")
async def read_file_tool(file_path: str, encoding: str = "utf-8", max_size: Optional[int] = None):
    result = await read_file(file_path, encoding, max_size)
    
    # Handle error responses
    if isinstance(result, dict) and "error" in result:
        error_type = result.get("error_type", "FileProviderError")
        error_msg = result["error"]
        
        # Map to appropriate exceptions
        if error_type == "FileNotFoundError":
            raise FileNotFoundError(error_msg)
        elif error_type == "PermissionError":
            raise PermissionError(error_msg)
        elif error_type == "FileSizeLimitExceededError":
            raise ValueError(f"File too large: {error_msg}")
        else:
            raise RuntimeError(f"File operation failed: {error_msg}")
    
    return result
```

### Security Error Handling

Never expose sensitive information in error messages:

```python
# Good - Generic error message
{"error": "Access denied", "error_type": "PermissionError"}

# Bad - Exposes system information
{"error": "Cannot access /etc/shadow: Permission denied", "error_type": "PermissionError"}
```

## Testing Your Implementation

### Unit Tests

Use the provided test suite to validate your implementation:

```bash
# Copy the test suite
curl -O https://raw.githubusercontent.com/your-org/vulnicheck/main/tests/test_mcp_client_file_provider_tools.py

# Run tests
pytest test_mcp_client_file_provider_tools.py -v
```

### Integration Testing

Test with actual VulniCheck operations:

```python
# Test basic functionality
@mcp_tool("test_file_provider")
async def test_file_provider_tool():
    results = {}
    
    # Test file existence
    results["file_exists"] = await file_exists_tool(__file__)
    
    # Test directory listing
    current_dir = os.path.dirname(__file__)
    results["list_directory"] = await list_directory_tool(current_dir)
    
    # Test file reading
    if results["file_exists"]:
        content = await read_file_tool(__file__)
        results["read_success"] = len(content) > 0
    
    return results
```

### VulniCheck Integration Test

Test with actual VulniCheck HTTP-only deployment:

```bash
# Set up HTTP-only mode
export VULNICHECK_HTTP_ONLY=true
export VULNICHECK_MCP_SERVER=your_server_name

# Start your MCP server with file provider tools
fastmcp run your_module:app --port 3001

# Start VulniCheck server
vulnicheck --mcp-server your_server_name

# Test a scan
curl -X POST http://localhost:3000/v1/scan_dependencies \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/path/to/requirements.txt"}'
```

## Troubleshooting

### Common Issues

**"Tool not found" errors:**
- Ensure all required tools are registered with your MCP server
- Check tool name spelling (must match exactly)
- Verify your MCP server is properly configured

**Permission denied errors:**
- Check your `allowed_paths` and `blocked_paths` configuration
- Ensure the user has appropriate OS-level permissions
- Verify paths are absolute, not relative

**File size limit errors:**
- Adjust `max_file_size` configuration if needed
- Consider streaming for large files
- Check if binary files are being read as text

**Path validation errors:**
- Ensure paths are absolute
- Check for path traversal attempts (`../`)
- Verify path depth doesn't exceed limits

### Debug Mode

Enable debug logging to troubleshoot issues:

```python
import logging

# Enable debug logging for file provider
logger = logging.getLogger("vulnicheck_file_provider")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
logger.addHandler(handler)

# Enable audit logging
configure_file_provider(enable_audit_log=True)
```

### Performance Issues

**Slow directory listings:**
- Reduce `max_directory_files` limit
- Use pattern filtering to reduce results
- Implement the optional `find_files` tool for better performance

**Large file handling:**
- Adjust `max_file_size` limits
- Consider implementing streaming (advanced)
- Use binary reading for non-text files

## Advanced Topics

### Custom Path Validation

Override the default path validation logic:

```python
def custom_validate_path(path: str):
    """Custom path validation for your environment."""
    # Add your custom validation logic
    if not path.startswith("/approved/"):
        return {"error": "Path not in approved directory", "error_type": "PermissionError"}
    
    # Call default validation
    return validate_path(path)

# Monkey patch if needed (not recommended for production)
import mcp_client_file_provider_reference
mcp_client_file_provider_reference.validate_path = custom_validate_path
```

### Performance Monitoring

Add performance monitoring to your tools:

```python
import time

@mcp_tool("read_file")
async def read_file_tool_with_monitoring(file_path: str, encoding: str = "utf-8", max_size: Optional[int] = None):
    start_time = time.time()
    
    result = await read_file(file_path, encoding, max_size)
    
    duration = time.time() - start_time
    logger.info(f"read_file took {duration:.3f}s for {file_path}")
    
    return result
```

### Multi-User Support

Support multiple user contexts:

```python
class MultiUserFileProvider:
    def __init__(self):
        self.user_configs = {}
    
    def configure_for_user(self, user_id: str, config: dict):
        """Configure file provider for specific user."""
        self.user_configs[user_id] = config
    
    async def read_file_for_user(self, user_id: str, file_path: str, **kwargs):
        """Read file with user-specific configuration."""
        # Switch to user configuration
        old_config = get_current_config()
        apply_user_config(self.user_configs.get(user_id, {}))
        
        try:
            return await read_file(file_path, **kwargs)
        finally:
            # Restore original configuration
            apply_config(old_config)
```

## Support and Resources

- **Full API Specification**: [MCP Client Callback Tools Specification](mcp_client_callback_tools_specification.md)
- **Reference Implementation**: [examples/mcp_client_file_provider_reference.py](../examples/mcp_client_file_provider_reference.py)
- **Integration Examples**: [examples/claude_code_integration_example.py](../examples/claude_code_integration_example.py)
- **Test Suite**: [tests/test_mcp_client_file_provider_tools.py](../tests/test_mcp_client_file_provider_tools.py)
- **Architecture Overview**: [docs/file_provider_architecture.md](file_provider_architecture.md)

## Contributing

Help improve this integration:

1. **Report Issues**: If you encounter problems implementing these tools
2. **Share Examples**: Contribute integration examples for other MCP frameworks
3. **Security Reviews**: Help identify and fix security issues
4. **Performance Improvements**: Suggest optimizations for large-scale deployments

## License and Security Notice

This implementation is provided under the same license as VulniCheck. It includes security measures but should be reviewed and tested thoroughly before production deployment.

**Security Disclaimer**: File system access inherently involves security risks. Always:
- Validate paths and permissions
- Implement appropriate access controls  
- Monitor for suspicious activity
- Follow the principle of least privilege
- Keep audit logs for compliance

The file provider tools enable powerful functionality but require careful implementation to maintain security.