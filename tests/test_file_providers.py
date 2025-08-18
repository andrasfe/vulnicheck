"""
Test cases for FileProvider implementations.

This test suite validates both LocalFileProvider and MCPClientFileProvider
implementations of the FileProvider interface.
"""

import hashlib
import os
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.providers import (
    FileNotFoundError,
    FileProvider,
    FileProviderError,
    FileSizeLimitExceededError,
    FileStats,
    FileType,
    LocalFileProvider,
    MCPClientFileProvider,
)
from vulnicheck.providers.factory import (
    FileProviderManager,
    create_local_provider,
    get_default_provider,
    get_provider_manager,
)


class TestFileProviderBase:
    """Test cases for base FileProvider functionality."""

    # Prevent pytest from collecting this base class
    __test__ = False

    @pytest.fixture
    def provider(self) -> FileProvider:
        """Override in subclasses to provide specific implementation."""
        raise NotImplementedError("Subclasses must implement provider fixture")

    @pytest.mark.asyncio
    async def test_is_directory(self, provider: FileProvider):
        """Test is_directory method."""
        with patch.object(provider, 'get_file_stats') as mock_stats:
            # Mock directory stats
            mock_stats.return_value = FileStats(
                path="/test/dir",
                file_type=FileType.DIRECTORY,
                size=0,
                modified_time=datetime.now(),
                is_directory=True
            )

            result = await provider.is_directory("/test/dir")
            assert result is True

    @pytest.mark.asyncio
    async def test_is_file(self, provider: FileProvider):
        """Test is_file method."""
        with patch.object(provider, 'get_file_stats') as mock_stats:
            # Mock file stats
            mock_stats.return_value = FileStats(
                path="/test/file.txt",
                file_type=FileType.FILE,
                size=100,
                modified_time=datetime.now(),
                is_directory=False
            )

            result = await provider.is_file("/test/file.txt")
            assert result is True

    @pytest.mark.asyncio
    async def test_get_file_size(self, provider: FileProvider):
        """Test get_file_size method."""
        with patch.object(provider, 'get_file_stats') as mock_stats:
            # Mock file stats
            mock_stats.return_value = FileStats(
                path="/test/file.txt",
                file_type=FileType.FILE,
                size=1024,
                modified_time=datetime.now(),
                is_directory=False
            )

            size = await provider.get_file_size("/test/file.txt")
            assert size == 1024

    def test_validate_path(self, provider: FileProvider):
        """Test path validation."""
        # Valid path should work
        result = provider._validate_path("/home/user/file.txt")
        assert result is not None

        # Empty path should fail
        with pytest.raises(FileProviderError):
            provider._validate_path("")

        # Test with path that contains suspicious patterns that should be detected
        with pytest.raises(FileProviderError):
            provider._validate_path("~/.ssh/id_rsa")

    def test_check_file_size(self, provider: FileProvider):
        """Test file size checking."""
        # Size within limit should work
        provider._check_file_size(1000)  # Should not raise

        # Size exceeding limit should fail
        with pytest.raises(FileSizeLimitExceededError):
            provider._check_file_size(provider.MAX_FILE_SIZE + 1)

        # Custom limit should work
        with pytest.raises(FileSizeLimitExceededError):
            provider._check_file_size(1000, max_size=500)


class TestLocalFileProvider(TestFileProviderBase):
    """Test cases for LocalFileProvider."""

    @pytest.fixture
    def provider(self) -> LocalFileProvider:
        """Provide LocalFileProvider instance."""
        return LocalFileProvider()

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.mark.asyncio
    async def test_read_file(self, provider: LocalFileProvider, temp_dir: Path):
        """Test reading text files."""
        # Create test file
        test_file = temp_dir / "test.txt"
        test_content = "Hello, World!\nThis is a test file."
        test_file.write_text(test_content, encoding="utf-8")

        # Read file
        content = await provider.read_file(str(test_file))
        assert content == test_content

    @pytest.mark.asyncio
    async def test_read_file_binary(self, provider: LocalFileProvider, temp_dir: Path):
        """Test reading binary files."""
        # Create test binary file
        test_file = temp_dir / "test.bin"
        test_data = b"Binary data \x00\x01\x02\x03"
        test_file.write_bytes(test_data)

        # Read binary file
        data = await provider.read_file_binary(str(test_file))
        assert data == test_data

    @pytest.mark.asyncio
    async def test_read_file_not_found(self, provider: LocalFileProvider):
        """Test reading non-existent file."""
        with pytest.raises(FileNotFoundError):
            await provider.read_file("/nonexistent/file.txt")

    @pytest.mark.asyncio
    async def test_read_file_size_limit(self, provider: LocalFileProvider, temp_dir: Path):
        """Test file size limit enforcement."""
        # Create large file
        test_file = temp_dir / "large.txt"
        large_content = "x" * (provider.MAX_FILE_SIZE + 1)
        test_file.write_text(large_content)

        # Should fail due to size limit
        with pytest.raises(FileSizeLimitExceededError):
            await provider.read_file(str(test_file))

    @pytest.mark.asyncio
    async def test_list_directory(self, provider: LocalFileProvider, temp_dir: Path):
        """Test directory listing."""
        # Create test files
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.py").write_text("content2")
        (temp_dir / "subdir").mkdir()

        # List directory
        files = await provider.list_directory(str(temp_dir))

        # Should contain all items
        assert len(files) >= 3
        file_names = [Path(f).name for f in files]
        assert "file1.txt" in file_names
        assert "file2.py" in file_names
        assert "subdir" in file_names

    @pytest.mark.asyncio
    async def test_list_directory_with_pattern(self, provider: LocalFileProvider, temp_dir: Path):
        """Test directory listing with pattern matching."""
        # Create test files
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.py").write_text("content2")
        (temp_dir / "script.py").write_text("content3")

        # List with pattern
        files = await provider.list_directory(str(temp_dir), pattern="*.py")

        # Should only contain Python files
        assert len(files) == 2
        file_names = [Path(f).name for f in files]
        assert "file2.py" in file_names
        assert "script.py" in file_names
        assert "file1.txt" not in file_names

    @pytest.mark.asyncio
    async def test_list_directory_recursive(self, provider: LocalFileProvider, temp_dir: Path):
        """Test recursive directory listing."""
        # Create nested structure
        (temp_dir / "file1.txt").write_text("content1")
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (subdir / "file2.txt").write_text("content2")

        # List recursively
        files = await provider.list_directory(str(temp_dir), recursive=True)

        # Should contain files from both levels
        assert len(files) >= 3  # file1.txt, subdir, subdir/file2.txt
        file_paths = [str(f) for f in files]
        assert any("file1.txt" in path for path in file_paths)
        assert any("file2.txt" in path for path in file_paths)

    @pytest.mark.asyncio
    async def test_file_exists(self, provider: LocalFileProvider, temp_dir: Path):
        """Test file existence checking."""
        # Create test file
        test_file = temp_dir / "exists.txt"
        test_file.write_text("content")

        # Test existing file
        assert await provider.file_exists(str(test_file)) is True

        # Test non-existent file
        assert await provider.file_exists(str(temp_dir / "missing.txt")) is False

    @pytest.mark.asyncio
    async def test_get_file_stats(self, provider: LocalFileProvider, temp_dir: Path):
        """Test getting file statistics."""
        # Create test file
        test_file = temp_dir / "stats.txt"
        test_content = "Test content for stats"
        test_file.write_text(test_content)

        # Get stats
        stats = await provider.get_file_stats(str(test_file))

        assert stats.path == str(test_file.resolve())
        assert stats.file_type == FileType.FILE
        assert stats.size == len(test_content.encode())
        assert not stats.is_directory
        assert stats.is_readable

    @pytest.mark.asyncio
    async def test_calculate_file_hash(self, provider: LocalFileProvider, temp_dir: Path):
        """Test file hash calculation."""
        # Create test file
        test_file = temp_dir / "hash.txt"
        test_content = "Content to hash"
        test_file.write_text(test_content)

        # Calculate hash
        file_hash = await provider.calculate_file_hash(str(test_file))

        # Verify hash
        expected_hash = hashlib.md5(test_content.encode()).hexdigest()
        assert file_hash == expected_hash

    @pytest.mark.asyncio
    async def test_find_files(self, provider: LocalFileProvider, temp_dir: Path):
        """Test finding files with patterns."""
        # Create test files
        (temp_dir / "script.py").write_text("python")
        (temp_dir / "config.json").write_text("json")
        (temp_dir / "readme.txt").write_text("text")
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (subdir / "test.py").write_text("python")

        # Find Python files
        files = await provider.find_files(str(temp_dir), ["*.py"])

        assert len(files) >= 2
        file_names = [Path(f).name for f in files]
        assert "script.py" in file_names
        assert "test.py" in file_names
        assert "config.json" not in file_names

    def test_base_path_restriction(self, temp_dir: Path):
        """Test base path restriction."""
        # Create provider with base path restriction
        provider = LocalFileProvider(base_path=str(temp_dir))

        # Create test file inside base path
        test_file = temp_dir / "allowed.txt"
        test_file.write_text("allowed content")

        # Should work for files inside base path
        result_path = provider._get_absolute_path(str(test_file))
        assert Path(result_path) == test_file.resolve()

        # Should fail for files outside base path
        with pytest.raises(FileProviderError):
            provider._get_absolute_path("/etc/passwd")


class TestMCPClientFileProvider(TestFileProviderBase):
    """Test cases for MCPClientFileProvider."""

    @pytest.fixture
    def mock_client(self) -> AsyncMock:
        """Create mock MCP client."""
        return AsyncMock()

    @pytest.fixture
    def provider(self, mock_client: AsyncMock) -> MCPClientFileProvider:
        """Provide MCPClientFileProvider instance."""
        return MCPClientFileProvider(
            server_name="test_server",
            client=mock_client,
            timeout=10
        )

    @pytest.mark.asyncio
    async def test_read_file(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test reading text files via MCP."""
        # Mock client response
        test_content = "Hello from MCP!"
        mock_client.call_tool.return_value = test_content

        # Read file
        content = await provider.read_file("/test/file.txt")

        assert content == test_content
        mock_client.call_tool.assert_called_once_with(
            server_name="test_server",
            tool_name="read_file",
            parameters={"file_path": "/test/file.txt", "encoding": "utf-8"},
            timeout=10
        )

    @pytest.mark.asyncio
    async def test_read_file_binary(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test reading binary files via MCP."""
        # Mock client response (base64 encoded)
        import base64
        test_data = b"Binary data \x00\x01\x02"
        encoded_data = base64.b64encode(test_data).decode()
        mock_client.call_tool.return_value = encoded_data

        # Read binary file
        data = await provider.read_file_binary("/test/file.bin")

        assert data == test_data
        mock_client.call_tool.assert_called_once_with(
            server_name="test_server",
            tool_name="read_file_binary",
            parameters={"file_path": "/test/file.bin"},
            timeout=10
        )

    @pytest.mark.asyncio
    async def test_list_directory(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test directory listing via MCP."""
        # Mock client response
        mock_files = ["/test/file1.txt", "/test/file2.py", "/test/subdir"]
        mock_client.call_tool.return_value = mock_files

        # List directory
        files = await provider.list_directory("/test")

        assert files == mock_files
        mock_client.call_tool.assert_called_once_with(
            server_name="test_server",
            tool_name="list_directory",
            parameters={"directory_path": "/test", "recursive": False},
            timeout=10
        )

    @pytest.mark.asyncio
    async def test_file_exists(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test file existence checking via MCP."""
        # Mock client response
        mock_client.call_tool.return_value = True

        # Check existence
        exists = await provider.file_exists("/test/file.txt")

        assert exists is True
        mock_client.call_tool.assert_called_once_with(
            server_name="test_server",
            tool_name="file_exists",
            parameters={"path": "/test/file.txt"},
            timeout=10
        )

    @pytest.mark.asyncio
    async def test_get_file_stats(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test getting file statistics via MCP."""
        # Mock client response
        mock_stats = {
            "path": "/test/file.txt",
            "file_type": "file",
            "size": 1024,
            "modified_time": datetime.now(),
            "is_readable": True,
            "is_directory": False,
        }
        mock_client.call_tool.return_value = mock_stats

        # Get stats
        stats = await provider.get_file_stats("/test/file.txt")

        assert stats.path == "/test/file.txt"
        assert stats.file_type == FileType.FILE
        assert stats.size == 1024
        assert not stats.is_directory
        assert stats.is_readable

    @pytest.mark.asyncio
    async def test_calculate_file_hash(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test file hash calculation via MCP."""
        # Mock client response
        expected_hash = "d41d8cd98f00b204e9800998ecf8427e"
        mock_client.call_tool.return_value = expected_hash

        # Calculate hash
        file_hash = await provider.calculate_file_hash("/test/file.txt")

        assert file_hash == expected_hash
        mock_client.call_tool.assert_called_once_with(
            server_name="test_server",
            tool_name="calculate_file_hash",
            parameters={"file_path": "/test/file.txt", "algorithm": "md5"},
            timeout=10
        )

    @pytest.mark.asyncio
    async def test_error_handling(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test error handling from MCP client."""
        # Mock client error response
        mock_client.call_tool.return_value = {
            "error": "File not found",
            "error_type": "FileNotFoundError"
        }

        # Should raise appropriate exception (custom FileProviderError since that's what's actually raised)
        with pytest.raises(FileProviderError):
            await provider.read_file("/nonexistent/file.txt")

    @pytest.mark.asyncio
    async def test_find_files_fallback(self, provider: MCPClientFileProvider, mock_client: AsyncMock):
        """Test find_files fallback to base implementation."""
        # Mock error for dedicated tool, then success for fallback calls
        mock_client.call_tool.side_effect = [
            {"error": "Tool not available"},  # find_files tool not available
            ["/test/file1.py", "/test/file2.py"],  # list_directory success
            True,  # is_file for file1.py
            True,  # is_file for file2.py
        ]

        # Find files (should use fallback)
        _files = await provider.find_files("/test", ["*.py"])

        # Should have called multiple tools for fallback
        assert mock_client.call_tool.call_count >= 2


class TestFileProviderFactory:
    """Test cases for FileProvider factory functions."""

    def test_file_provider_manager(self):
        """Test FileProviderManager functionality."""
        manager = FileProviderManager()

        # Test local provider
        local_provider = manager.get_local_provider()
        assert isinstance(local_provider, LocalFileProvider)

        # Test provider caching
        same_provider = manager.get_local_provider()
        assert local_provider is same_provider

        # Test MCP provider
        mock_client = MagicMock()
        mcp_provider = manager.get_mcp_provider("test_server", client=mock_client)
        assert isinstance(mcp_provider, MCPClientFileProvider)
        assert mcp_provider.server_name == "test_server"

    def test_create_local_provider(self):
        """Test local provider creation."""
        provider = create_local_provider()
        assert isinstance(provider, LocalFileProvider)
        assert provider.base_path is None

        provider_with_base = create_local_provider("/home/user")
        assert isinstance(provider_with_base, LocalFileProvider)
        assert provider_with_base.base_path == Path("/home/user").resolve()

    def test_get_default_provider_local(self):
        """Test default provider selection (local mode)."""
        with patch.dict(os.environ, {}, clear=True):
            provider = get_default_provider(deployment_mode="local")
            assert isinstance(provider, LocalFileProvider)

    def test_get_default_provider_http(self):
        """Test default provider selection (HTTP mode)."""
        provider = get_default_provider(
            deployment_mode="http",
            server_name="test_server"
        )
        assert isinstance(provider, MCPClientFileProvider)
        assert provider.server_name == "test_server"

    def test_get_default_provider_auto_detect(self):
        """Test automatic deployment mode detection."""
        # Test HTTP mode detection
        with patch.dict(os.environ, {"VULNICHECK_HTTP_ONLY": "true"}):
            provider = get_default_provider(server_name="test_server")
            assert isinstance(provider, MCPClientFileProvider)

        # Test local mode detection (default)
        with patch.dict(os.environ, {}, clear=True):
            provider = get_default_provider()
            assert isinstance(provider, LocalFileProvider)

    def test_get_provider_manager_singleton(self):
        """Test that provider manager is a singleton."""
        manager1 = get_provider_manager()
        manager2 = get_provider_manager()
        assert manager1 is manager2


class TestFileProviderIntegration:
    """Integration tests for FileProvider implementations."""

    @pytest.mark.asyncio
    async def test_scanner_integration(self):
        """Test FileProvider integration with scanner."""
        from vulnicheck.providers import LocalFileProvider
        from vulnicheck.scanners.scanner_with_provider import (
            DependencyScannerWithProvider,
        )

        # Create mock clients
        mock_osv = AsyncMock()
        mock_nvd = AsyncMock()
        mock_osv.check_package = AsyncMock(return_value=[])

        # Create provider and scanner
        file_provider = LocalFileProvider()
        scanner = DependencyScannerWithProvider(
            file_provider=file_provider,
            osv_client=mock_osv,
            nvd_client=mock_nvd
        )

        # Test with temporary requirements file
        import os
        import tempfile
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "requirements.txt")
        with open(temp_file, 'w') as f:
            f.write("requests>=2.25.0\nflask==2.0.1\n")

        try:
            # Scan file
            results = await scanner.scan_file(temp_file)

            # Should have processed both packages
            assert len(results) >= 2

            # Verify OSV client was called
            assert mock_osv.check_package.call_count >= 2

        finally:
            # Clean up
            import shutil
            shutil.rmtree(temp_dir)

    @pytest.mark.asyncio
    async def test_provider_switching(self):
        """Test switching between provider implementations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = Path(temp_dir) / "test.txt"
            test_content = "Test content for provider switching"
            test_file.write_text(test_content)

            # Test with LocalFileProvider
            local_provider = LocalFileProvider()
            content1 = await local_provider.read_file(str(test_file))
            assert content1 == test_content

            # Test same operation would work with MCP provider
            # (we can't test actual MCP without a real client)
            mock_client = AsyncMock()
            mock_client.call_tool.return_value = test_content

            mcp_provider = MCPClientFileProvider("test_server", client=mock_client)
            content2 = await mcp_provider.read_file(str(test_file))
            assert content2 == test_content

if __name__ == "__main__":
    pytest.main([__file__])
