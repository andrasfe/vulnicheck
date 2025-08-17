"""
Example integration for Claude Code MCP client.

This example shows how to integrate the VulniCheck file provider callback tools
into Claude Code's MCP client architecture using FastMCP framework.

Usage:
    1. Install FastMCP: pip install fastmcp
    2. Copy this code into your Claude Code MCP client
    3. Configure the security settings as needed
    4. Register the tools with your MCP server
    5. Test with VulniCheck's HTTP-only deployment mode

Security Configuration:
    - Restricts access to user's project directories
    - Blocks system directories (/etc, /sys, etc.)
    - Configurable file size limits
    - Audit logging for all operations
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

# Import FastMCP (or your MCP framework)
try:
    from fastmcp import FastMCP, mcp_tool
    from fastmcp.types import TextContent, ImageContent
except ImportError:
    print("FastMCP not available. Install with: pip install fastmcp")
    # Define stub decorators for demonstration
    def mcp_tool(name: str):
        def decorator(func):
            return func
        return decorator
    
    class FastMCP:
        pass

# Import the reference implementation
from mcp_client_file_provider_reference import (
    read_file,
    read_file_binary,
    list_directory,
    file_exists,
    get_file_stats,
    calculate_file_hash,
    find_files,
    configure_file_provider,
    get_provider_info,
    FileProviderConfig
)

# Claude Code specific configuration
class ClaudeCodeConfig:
    """Configuration specific to Claude Code integration."""
    
    # User directory settings
    HOME_DIR = Path.home()
    ALLOWED_PROJECT_DIRS = [
        str(HOME_DIR / "projects"),
        str(HOME_DIR / "workspace"),
        str(HOME_DIR / "dev"),
        str(HOME_DIR / "code"),
        str(HOME_DIR / "git")
    ]
    
    # Security settings for Claude Code
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB for Claude Code
    MAX_FILES_PER_LISTING = 500  # Conservative limit
    
    # Logging
    LOG_FILE = HOME_DIR / ".claude" / "vulnicheck_file_provider.log"

def setup_claude_code_file_provider():
    """Configure file provider for Claude Code environment."""
    
    # Ensure Claude config directory exists
    claude_dir = ClaudeCodeConfig.HOME_DIR / ".claude"
    claude_dir.mkdir(exist_ok=True)
    
    # Configure file provider with Claude Code specific settings
    configure_file_provider(
        max_file_size=ClaudeCodeConfig.MAX_FILE_SIZE,
        max_directory_files=ClaudeCodeConfig.MAX_FILES_PER_LISTING,
        allowed_paths=ClaudeCodeConfig.ALLOWED_PROJECT_DIRS,
        blocked_paths=[
            "/etc", "/var", "/sys", "/dev", "/proc", "/root",
            "/usr/bin", "/usr/sbin", "/sbin", "/bin"
        ],
        enable_audit_log=True
    )
    
    # Set up logging to Claude directory
    logger = logging.getLogger("vulnicheck_file_provider")
    handler = logging.FileHandler(ClaudeCodeConfig.LOG_FILE)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    print(f"VulniCheck file provider configured for Claude Code")
    print(f"Audit log: {ClaudeCodeConfig.LOG_FILE}")
    print(f"Allowed directories: {ClaudeCodeConfig.ALLOWED_PROJECT_DIRS}")

# Initialize Claude Code MCP server
app = FastMCP(
    name="claude-code-vulnicheck-file-provider",
    version="1.0.0",
    description="File provider tools for VulniCheck HTTP-only deployment"
)

@app.startup
async def startup():
    """Initialize file provider on startup."""
    setup_claude_code_file_provider()

# Core required tools

@mcp_tool("read_file")
async def read_file_tool(
    file_path: str,
    encoding: str = "utf-8",
    max_size: Optional[int] = None
) -> str:
    """
    Read file contents for VulniCheck file provider.
    
    Args:
        file_path: Absolute path to the file to read
        encoding: Text encoding to use (default: utf-8)
        max_size: Maximum file size in bytes
    
    Returns:
        File contents as string
    
    Raises:
        Exception: If file cannot be read or other errors occur
    """
    result = await read_file(file_path, encoding, max_size)
    
    # Handle error responses by raising exceptions for FastMCP
    if isinstance(result, dict) and "error" in result:
        error_type = result.get("error_type", "FileProviderError")
        error_msg = result["error"]
        
        # Map to appropriate Python exceptions
        if error_type == "FileNotFoundError":
            raise FileNotFoundError(error_msg)
        elif error_type == "PermissionError":
            raise PermissionError(error_msg)
        elif error_type == "FileSizeLimitExceededError":
            raise ValueError(error_msg)  # Or custom exception
        else:
            raise RuntimeError(error_msg)
    
    return result

@mcp_tool("read_file_binary")
async def read_file_binary_tool(
    file_path: str,
    max_size: Optional[int] = None
) -> str:
    """
    Read binary file contents for VulniCheck file provider.
    
    Args:
        file_path: Absolute path to the file to read
        max_size: Maximum file size in bytes
    
    Returns:
        Base64-encoded binary data
    """
    result = await read_file_binary(file_path, max_size)
    
    if isinstance(result, dict) and "error" in result:
        error_type = result.get("error_type", "FileProviderError")
        error_msg = result["error"]
        
        if error_type == "FileNotFoundError":
            raise FileNotFoundError(error_msg)
        elif error_type == "PermissionError":
            raise PermissionError(error_msg)
        elif error_type == "FileSizeLimitExceededError":
            raise ValueError(error_msg)
        else:
            raise RuntimeError(error_msg)
    
    return result

@mcp_tool("list_directory")
async def list_directory_tool(
    directory_path: str,
    pattern: Optional[str] = None,
    recursive: bool = False,
    max_files: Optional[int] = None
) -> List[str]:
    """
    List directory contents for VulniCheck file provider.
    
    Args:
        directory_path: Absolute path to the directory
        pattern: Glob pattern to filter files (optional)
        recursive: Whether to list recursively
        max_files: Maximum number of files to return
    
    Returns:
        List of absolute file paths
    """
    result = await list_directory(directory_path, pattern, recursive, max_files)
    
    if isinstance(result, dict) and "error" in result:
        error_type = result.get("error_type", "FileProviderError")
        error_msg = result["error"]
        
        if error_type == "FileNotFoundError":
            raise FileNotFoundError(error_msg)
        elif error_type == "PermissionError":
            raise PermissionError(error_msg)
        else:
            raise RuntimeError(error_msg)
    
    return result

@mcp_tool("file_exists")
async def file_exists_tool(path: str) -> bool:
    """
    Check if file exists for VulniCheck file provider.
    
    Args:
        path: Absolute path to check
    
    Returns:
        True if file exists, False otherwise
    """
    return await file_exists(path)

@mcp_tool("get_file_stats")
async def get_file_stats_tool(path: str) -> Dict[str, Any]:
    """
    Get file statistics for VulniCheck file provider.
    
    Args:
        path: Absolute path to the file or directory
    
    Returns:
        Dictionary with file statistics
    """
    result = await get_file_stats(path)
    
    if isinstance(result, dict) and "error" in result:
        error_type = result.get("error_type", "FileProviderError")
        error_msg = result["error"]
        
        if error_type == "FileNotFoundError":
            raise FileNotFoundError(error_msg)
        elif error_type == "PermissionError":
            raise PermissionError(error_msg)
        else:
            raise RuntimeError(error_msg)
    
    return result

# Optional performance optimization tools

@mcp_tool("calculate_file_hash")
async def calculate_file_hash_tool(
    file_path: str,
    algorithm: str = "md5"
) -> str:
    """
    Calculate file hash for VulniCheck file provider (optional optimization).
    
    Args:
        file_path: Absolute path to the file
        algorithm: Hash algorithm (md5, sha1, sha256)
    
    Returns:
        Hexadecimal hash digest
    """
    result = await calculate_file_hash(file_path, algorithm)
    
    if isinstance(result, dict) and "error" in result:
        error_type = result.get("error_type", "FileProviderError")
        error_msg = result["error"]
        
        if error_type == "FileNotFoundError":
            raise FileNotFoundError(error_msg)
        elif error_type == "PermissionError":
            raise PermissionError(error_msg)
        else:
            raise RuntimeError(error_msg)
    
    return result

@mcp_tool("find_files")
async def find_files_tool(
    directory_path: str,
    patterns: List[str],
    recursive: bool = True,
    max_files: Optional[int] = None
) -> List[str]:
    """
    Find files matching patterns for VulniCheck file provider (optional optimization).
    
    Args:
        directory_path: Directory to search
        patterns: List of glob patterns to match
        recursive: Whether to search recursively
        max_files: Maximum number of files to return
    
    Returns:
        List of matching absolute file paths
    """
    result = await find_files(directory_path, patterns, recursive, max_files)
    
    if isinstance(result, dict) and "error" in result:
        error_type = result.get("error_type", "FileProviderError")
        error_msg = result["error"]
        
        if error_type == "FileNotFoundError":
            raise FileNotFoundError(error_msg)
        elif error_type == "PermissionError":
            raise PermissionError(error_msg)
        else:
            raise RuntimeError(error_msg)
    
    return result

# Management and utility tools

@mcp_tool("get_file_provider_info")
async def get_file_provider_info_tool() -> Dict[str, Any]:
    """
    Get information about the file provider implementation.
    
    Returns:
        Dictionary with provider information and configuration
    """
    return get_provider_info()

@mcp_tool("configure_file_provider")
async def configure_file_provider_tool(
    max_file_size: Optional[int] = None,
    max_directory_files: Optional[int] = None,
    allowed_paths: Optional[List[str]] = None
) -> str:
    """
    Configure file provider settings (Claude Code admin tool).
    
    Args:
        max_file_size: Maximum file size in bytes
        max_directory_files: Maximum files per directory listing
        allowed_paths: List of allowed path prefixes
    
    Returns:
        Configuration status message
    """
    try:
        # Only allow users to modify certain settings
        if max_file_size and max_file_size <= 10 * 1024 * 1024:  # Max 10MB
            configure_file_provider(max_file_size=max_file_size)
        
        if max_directory_files and max_directory_files <= 1000:  # Max 1000 files
            configure_file_provider(max_directory_files=max_directory_files)
        
        if allowed_paths:
            # Validate that allowed paths are within user's home directory
            home_str = str(ClaudeCodeConfig.HOME_DIR)
            validated_paths = [
                path for path in allowed_paths 
                if path.startswith(home_str)
            ]
            if validated_paths:
                configure_file_provider(allowed_paths=validated_paths)
        
        return "File provider configuration updated successfully"
        
    except Exception as e:
        return f"Configuration error: {e}"

# Claude Code specific helpers

@mcp_tool("test_file_provider")
async def test_file_provider_tool() -> Dict[str, Any]:
    """
    Test file provider functionality (debugging tool).
    
    Returns:
        Test results
    """
    results = {
        "provider_info": get_provider_info(),
        "tests": {}
    }
    
    try:
        # Test current directory access
        current_dir = str(Path.cwd())
        exists = await file_exists(current_dir)
        results["tests"]["current_dir_exists"] = exists
        
        if exists:
            # Test directory listing
            files = await list_directory(current_dir, max_files=10)
            if isinstance(files, list):
                results["tests"]["directory_listing"] = f"Success: {len(files)} items"
            else:
                results["tests"]["directory_listing"] = f"Error: {files}"
        
        # Test file reading (this file)
        this_file = __file__
        if await file_exists(this_file):
            stats = await get_file_stats(this_file)
            if isinstance(stats, dict) and "error" not in stats:
                results["tests"]["file_stats"] = f"Success: {stats['size']} bytes"
            else:
                results["tests"]["file_stats"] = f"Error: {stats}"
        
    except Exception as e:
        results["tests"]["error"] = str(e)
    
    return results

# Example usage for Claude Code deployment

async def main():
    """Example main function for running the file provider server."""
    
    print("Starting VulniCheck File Provider for Claude Code...")
    
    # Test the configuration
    test_results = await test_file_provider_tool()
    print("Test Results:")
    for test_name, result in test_results["tests"].items():
        print(f"  {test_name}: {result}")
    
    # If using FastMCP, run the server
    try:
        # This would typically be done with: fastmcp run claude_code_integration_example:app
        print("File provider tools ready. Start with: fastmcp run this_module:app")
        print(f"Available tools: {[tool.__name__ for tool in [read_file_tool, read_file_binary_tool, list_directory_tool, file_exists_tool, get_file_stats_tool]]}")
    except Exception as e:
        print(f"Server error: {e}")

if __name__ == "__main__":
    asyncio.run(main())

# Configuration file template for Claude Code users
CLAUDE_CODE_CONFIG_TEMPLATE = """
# Claude Code VulniCheck File Provider Configuration
# Place this in ~/.claude/vulnicheck_file_provider.json

{
  "file_provider": {
    "enabled": true,
    "security": {
      "max_file_size": 5242880,
      "max_directory_files": 500,
      "allowed_paths": [
        "~/projects",
        "~/workspace",
        "~/dev",
        "~/code",
        "~/git"
      ],
      "blocked_paths": [
        "/etc",
        "/var",
        "/sys",
        "/dev",
        "/proc",
        "/root"
      ]
    },
    "logging": {
      "enabled": true,
      "level": "INFO",
      "file": "~/.claude/vulnicheck_file_provider.log"
    },
    "tools": {
      "required": [
        "read_file",
        "read_file_binary",
        "list_directory", 
        "file_exists",
        "get_file_stats"
      ],
      "optional": [
        "calculate_file_hash",
        "find_files"
      ]
    }
  }
}
"""