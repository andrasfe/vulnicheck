"""
MCP client file provider implementation.

This module provides an MCP client-delegated implementation of the FileProvider
interface for HTTP-only deployment scenarios where file operations are
delegated to the client.
"""

import logging
from typing import Any

from ..mcp.mcp_client import MCPClient
from .base import FileNotFoundError as BaseFileNotFoundError
from .base import (
    FileProvider,
    FileProviderError,
    FileSizeLimitExceededError,
    FileStats,
    FileType,
    PermissionError,
    UnsupportedOperationError,
)

logger = logging.getLogger(__name__)


class MCPClientFileProvider(FileProvider):
    """
    MCP client-delegated implementation of FileProvider.
    
    This implementation delegates file operations to an MCP client,
    enabling HTTP-only deployment where the client performs file operations
    on behalf of the server.
    
    Required MCP tools on client:
    - read_file: Read file contents
    - read_file_binary: Read binary file contents  
    - list_directory: List directory contents
    - file_exists: Check if file exists
    - get_file_stats: Get file statistics
    
    Security considerations:
    - Client-side file access requires trust in the client
    - File size limits are still enforced server-side
    - Path validation is performed before client calls
    """

    def __init__(
        self,
        server_name: str,
        client: MCPClient | None = None,
        timeout: int = 30
    ):
        """
        Initialize MCP client file provider.
        
        Args:
            server_name: Name of the MCP server to connect to
            client: Optional existing MCPClient instance
            timeout: Timeout for MCP operations in seconds
        """
        self.server_name = server_name
        self.client = client
        self.timeout = timeout
        self._client_initialized = False

    async def _ensure_client(self) -> MCPClient:
        """Ensure MCP client is initialized."""
        if self.client is None:
            # In a real implementation, this would get the client from
            # a connection pool or factory
            raise UnsupportedOperationError(
                "MCPClient must be provided during initialization"
            )
        return self.client

    async def _call_tool(
        self,
        tool_name: str,
        parameters: dict[str, Any]
    ) -> Any:
        """
        Call an MCP tool with error handling.
        
        Args:
            tool_name: Name of the tool to call
            parameters: Parameters for the tool
            
        Returns:
            Tool result
            
        Raises:
            FileProviderError: For various file operation errors
        """
        try:
            client = await self._ensure_client()
            result = await client.call_tool(
                server_name=self.server_name,
                tool_name=tool_name,
                parameters=parameters,
                timeout=self.timeout
            )

            # Check for error in result
            if isinstance(result, dict) and "error" in result:
                error_msg = result["error"]
                error_type = result.get("error_type", "FileProviderError")

                # Map error types to appropriate exceptions
                if error_type == "FileNotFoundError":
                    raise BaseFileNotFoundError(error_msg)
                elif error_type == "PermissionError":
                    raise PermissionError(error_msg)
                elif error_type == "FileSizeLimitExceededError":
                    raise FileSizeLimitExceededError(error_msg)
                else:
                    raise FileProviderError(error_msg)

            return result

        except ConnectionError as e:
            raise FileProviderError(f"MCP connection error: {e}")
        except TimeoutError as e:
            raise FileProviderError(f"MCP operation timed out: {e}")
        except Exception as e:
            logger.error(f"Unexpected error calling MCP tool {tool_name}: {e}")
            raise FileProviderError(f"MCP tool call failed: {e}")

    async def read_file(
        self,
        file_path: str,
        encoding: str = "utf-8",
        max_size: int | None = None
    ) -> str:
        """Read the contents of a text file via MCP client."""
        # Validate path before sending to client
        validated_path = self._validate_path(file_path)

        parameters = {
            "file_path": validated_path,
            "encoding": encoding,
        }
        if max_size is not None:
            parameters["max_size"] = max_size

        result = await self._call_tool("read_file", parameters)

        # Validate result
        if not isinstance(result, str):
            raise FileProviderError("Invalid response from read_file tool")

        # Check size limit on returned content
        content_size = len(result.encode(encoding))
        self._check_file_size(content_size, max_size)

        return result

    async def read_file_binary(
        self,
        file_path: str,
        max_size: int | None = None
    ) -> bytes:
        """Read the contents of a binary file via MCP client."""
        # Validate path before sending to client
        validated_path = self._validate_path(file_path)

        parameters = {
            "file_path": validated_path,
        }
        if max_size is not None:
            parameters["max_size"] = max_size

        result = await self._call_tool("read_file_binary", parameters)

        # Handle base64-encoded binary data
        if isinstance(result, str):
            import base64
            try:
                binary_data = base64.b64decode(result)
            except Exception as e:
                raise FileProviderError(f"Failed to decode binary data: {e}")
        elif isinstance(result, bytes):
            binary_data = result
        else:
            raise FileProviderError("Invalid response from read_file_binary tool")

        # Check size limit
        self._check_file_size(len(binary_data), max_size)

        return binary_data

    async def list_directory(
        self,
        directory_path: str,
        pattern: str | None = None,
        recursive: bool = False,
        max_files: int | None = None
    ) -> list[str]:
        """List files and directories via MCP client."""
        # Validate path before sending to client
        validated_path = self._validate_path(directory_path)

        parameters = {
            "directory_path": validated_path,
            "recursive": recursive,
        }
        if pattern is not None:
            parameters["pattern"] = pattern
        if max_files is not None:
            parameters["max_files"] = max_files

        result = await self._call_tool("list_directory", parameters)

        # Validate result
        if not isinstance(result, list):
            raise FileProviderError("Invalid response from list_directory tool")

        # Validate each item is a string
        for item in result:
            if not isinstance(item, str):
                raise FileProviderError("Invalid file path in directory listing")

        # Limit number of files
        limit = max_files or self.MAX_DIRECTORY_FILES
        if len(result) > limit:
            logger.warning(f"Directory listing truncated to {limit} files")
            result = result[:limit]

        return result

    async def file_exists(self, path: str) -> bool:
        """Check if a file or directory exists via MCP client."""
        try:
            # Validate path before sending to client
            validated_path = self._validate_path(path)

            result = await self._call_tool("file_exists", {"path": validated_path})

            if not isinstance(result, bool):
                raise FileProviderError("Invalid response from file_exists tool")

            return result
        except FileProviderError:
            # If there's an error, assume file doesn't exist
            return False

    async def get_file_stats(self, path: str) -> FileStats:
        """Get file statistics via MCP client."""
        # Validate path before sending to client
        validated_path = self._validate_path(path)

        result = await self._call_tool("get_file_stats", {"path": validated_path})

        # Validate and parse result
        if not isinstance(result, dict):
            raise FileProviderError("Invalid response from get_file_stats tool")

        try:
            return FileStats(
                path=result["path"],
                file_type=FileType(result["file_type"]),
                size=result["size"],
                modified_time=result["modified_time"],  # Should be datetime or ISO string
                is_readable=result.get("is_readable", True),
                is_directory=result.get("is_directory", False),
            )
        except (KeyError, ValueError, TypeError) as e:
            raise FileProviderError(f"Invalid file stats format: {e}")

    async def calculate_file_hash(
        self,
        file_path: str,
        algorithm: str = "md5",
        chunk_size: int = 4096
    ) -> str:
        """
        Calculate file hash via MCP client.
        
        Note: chunk_size is ignored for MCP clients as the calculation
        is performed client-side.
        """
        # Validate path before sending to client
        validated_path = self._validate_path(file_path)

        parameters = {
            "file_path": validated_path,
            "algorithm": algorithm,
        }

        result = await self._call_tool("calculate_file_hash", parameters)

        if not isinstance(result, str):
            raise FileProviderError("Invalid response from calculate_file_hash tool")

        # Validate hash format (should be hex)
        try:
            int(result, 16)
        except ValueError:
            raise FileProviderError("Invalid hash format received from client")

        return result

    async def find_files(
        self,
        directory_path: str,
        patterns: list[str],
        recursive: bool = True,
        max_files: int | None = None
    ) -> list[str]:
        """
        Find files matching patterns via MCP client.
        
        This method can be optimized by implementing a dedicated
        find_files tool on the client side.
        """
        # Try to use a dedicated find_files tool if available
        try:
            validated_path = self._validate_path(directory_path)

            parameters = {
                "directory_path": validated_path,
                "patterns": patterns,
                "recursive": recursive,
            }
            if max_files is not None:
                parameters["max_files"] = max_files

            result = await self._call_tool("find_files", parameters)

            if isinstance(result, list):
                return result
        except FileProviderError:
            # Fall back to base implementation if dedicated tool not available
            pass

        # Fallback: use base class implementation
        return await super().find_files(directory_path, patterns, recursive, max_files)

    def __repr__(self) -> str:
        """String representation of the provider."""
        return f"MCPClientFileProvider(server={self.server_name}, timeout={self.timeout})"
