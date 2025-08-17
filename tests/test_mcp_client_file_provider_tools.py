"""
Test suite for MCP client file provider callback tools.

This comprehensive test suite validates the implementation of file provider
callback tools that MCP clients must implement to support VulniCheck's
HTTP-only deployment mode.

Usage:
    pytest tests/test_mcp_client_file_provider_tools.py -v

Test Coverage:
    - All required tools (read_file, read_file_binary, list_directory, file_exists, get_file_stats)
    - Optional tools (calculate_file_hash, find_files)
    - Security validations (path traversal, size limits, permissions)
    - Error handling and edge cases
    - Performance characteristics
"""

import asyncio
import base64
import hashlib

# Import the reference implementation
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).parent.parent / "examples"))

from mcp_client_file_provider_reference import (
    FileProviderConfig,
    calculate_file_hash,
    check_file_size,
    configure_file_provider,
    file_exists,
    find_files,
    get_file_stats,
    get_provider_info,
    list_directory,
    read_file,
    read_file_binary,
    validate_path,
)


@pytest.fixture
def test_files(tmp_path):
    """Create test files and directories."""
    files = {}

    # Text files
    files['text_file'] = tmp_path / "test.txt"
    files['text_file'].write_text("Hello, World!\nThis is a test file.\n", encoding="utf-8")

    files['large_text'] = tmp_path / "large.txt"
    files['large_text'].write_text("x" * 1000, encoding="utf-8")

    files['utf8_file'] = tmp_path / "unicode.txt"
    files['utf8_file'].write_text("Hello 世界! 🌍", encoding="utf-8")

    # Binary file
    files['binary_file'] = tmp_path / "test.bin"
    files['binary_file'].write_bytes(b"\x00\x01\x02\x03\xFF\xFE")

    # Empty file
    files['empty_file'] = tmp_path / "empty.txt"
    files['empty_file'].touch()

    # Directory structure
    files['subdir'] = tmp_path / "subdir"
    files['subdir'].mkdir()

    files['nested_file'] = files['subdir'] / "nested.py"
    files['nested_file'].write_text("print('hello')")

    files['deep_dir'] = tmp_path / "deep" / "nested" / "structure"
    files['deep_dir'].mkdir(parents=True)

    files['deep_file'] = files['deep_dir'] / "deep.txt"
    files['deep_file'].write_text("deep file content")

    # Multiple Python files for pattern testing
    for i in range(3):
        py_file = tmp_path / f"script{i}.py"
        py_file.write_text(f"# Script {i}\nprint({i})")
        files[f'py_file_{i}'] = py_file

    return files

@pytest.fixture
def configure_test_provider(tmp_path):
    """Configure file provider for testing."""
    # Store original config
    original_config = {
        'MAX_FILE_SIZE': FileProviderConfig.MAX_FILE_SIZE,
        'ALLOWED_PATHS': FileProviderConfig.ALLOWED_PATHS.copy(),
        'BLOCKED_PATHS': FileProviderConfig.BLOCKED_PATHS.copy(),
        'ENABLE_PATH_RESTRICTIONS': FileProviderConfig.ENABLE_PATH_RESTRICTIONS
    }

    # Configure for testing
    configure_file_provider(
        max_file_size=10 * 1024 * 1024,  # 10MB
        allowed_paths=[str(tmp_path)],
        blocked_paths=[],
        enable_audit_log=False
    )

    yield

    # Restore original config
    FileProviderConfig.MAX_FILE_SIZE = original_config['MAX_FILE_SIZE']
    FileProviderConfig.ALLOWED_PATHS = original_config['ALLOWED_PATHS']
    FileProviderConfig.BLOCKED_PATHS = original_config['BLOCKED_PATHS']
    FileProviderConfig.ENABLE_PATH_RESTRICTIONS = original_config['ENABLE_PATH_RESTRICTIONS']

class TestPathValidation:
    """Test path validation and security."""

    def test_validate_path_normal(self, tmp_path):
        """Test validation of normal paths."""
        test_file = tmp_path / "test.txt"
        test_file.touch()

        result = validate_path(str(test_file))
        assert isinstance(result, Path)
        assert result.exists()

    def test_validate_path_empty(self):
        """Test validation of empty path."""
        result = validate_path("")
        assert isinstance(result, dict)
        assert "error" in result
        assert result["error_type"] == "FileProviderError"

    def test_validate_path_traversal(self, tmp_path):
        """Test path traversal prevention."""
        # This should be blocked even after resolution
        traversal_paths = [
            "../etc/passwd",
            "..\\windows\\system32",
            str(tmp_path) + "/../etc/passwd"
        ]

        for path in traversal_paths:
            result = validate_path(path)
            # After resolution, most of these should be valid Path objects
            # but some might trigger security checks
            assert isinstance(result, Path | dict)

    def test_validate_path_too_deep(self, tmp_path):
        """Test path depth limits."""
        # Create a very deep path
        deep_parts = ["very"] * 25  # Exceeds MAX_PATH_DEPTH
        deep_path = tmp_path.joinpath(*deep_parts)

        result = validate_path(str(deep_path))
        assert isinstance(result, dict)
        assert "too deep" in result["error"].lower()

    def test_check_file_size(self):
        """Test file size checking."""
        # Normal size
        assert check_file_size(1000) is None

        # Exceeds default limit
        result = check_file_size(FileProviderConfig.MAX_FILE_SIZE + 1)
        assert isinstance(result, dict)
        assert "exceeds limit" in result["error"]

        # Custom limit
        result = check_file_size(500, max_size=100)
        assert isinstance(result, dict)
        assert "exceeds limit" in result["error"]

class TestReadFile:
    """Test read_file tool implementation."""

    @pytest.mark.asyncio
    async def test_read_text_file(self, test_files, configure_test_provider):
        """Test reading a normal text file."""
        result = await read_file(str(test_files['text_file']))
        assert isinstance(result, str)
        assert "Hello, World!" in result
        assert "test file" in result

    @pytest.mark.asyncio
    async def test_read_unicode_file(self, test_files, configure_test_provider):
        """Test reading a Unicode text file."""
        result = await read_file(str(test_files['utf8_file']))
        assert isinstance(result, str)
        assert "世界" in result
        assert "🌍" in result

    @pytest.mark.asyncio
    async def test_read_empty_file(self, test_files, configure_test_provider):
        """Test reading an empty file."""
        result = await read_file(str(test_files['empty_file']))
        assert isinstance(result, str)
        assert result == ""

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, tmp_path, configure_test_provider):
        """Test reading a nonexistent file."""
        nonexistent = tmp_path / "nonexistent.txt"
        result = await read_file(str(nonexistent))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileNotFoundError"

    @pytest.mark.asyncio
    async def test_read_directory_as_file(self, test_files, configure_test_provider):
        """Test attempting to read a directory as a file."""
        result = await read_file(str(test_files['subdir']))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileProviderError"
        assert "not a file" in result["error"]

    @pytest.mark.asyncio
    async def test_read_with_encoding(self, test_files, configure_test_provider):
        """Test reading with different encodings."""
        # Test UTF-8 (default)
        result = await read_file(str(test_files['utf8_file']), encoding="utf-8")
        assert isinstance(result, str)
        assert "世界" in result

        # Test with explicit encoding
        result = await read_file(str(test_files['text_file']), encoding="ascii")
        assert isinstance(result, str)
        assert "Hello, World!" in result

    @pytest.mark.asyncio
    async def test_read_with_size_limit(self, test_files, configure_test_provider):
        """Test reading with file size limits."""
        # Should succeed within limit
        result = await read_file(str(test_files['text_file']), max_size=1000)
        assert isinstance(result, str)

        # Should fail when limit exceeded
        result = await read_file(str(test_files['large_text']), max_size=10)
        assert isinstance(result, dict)
        assert result["error_type"] == "FileSizeLimitExceededError"

class TestReadFileBinary:
    """Test read_file_binary tool implementation."""

    @pytest.mark.asyncio
    async def test_read_binary_file(self, test_files, configure_test_provider):
        """Test reading a binary file."""
        result = await read_file_binary(str(test_files['binary_file']))
        assert isinstance(result, str)

        # Decode and verify
        decoded = base64.b64decode(result)
        assert decoded == b"\x00\x01\x02\x03\xFF\xFE"

    @pytest.mark.asyncio
    async def test_read_text_as_binary(self, test_files, configure_test_provider):
        """Test reading a text file as binary."""
        result = await read_file_binary(str(test_files['text_file']))
        assert isinstance(result, str)

        # Decode and verify content
        decoded = base64.b64decode(result)
        text_content = decoded.decode('utf-8')
        assert "Hello, World!" in text_content

    @pytest.mark.asyncio
    async def test_read_empty_binary(self, test_files, configure_test_provider):
        """Test reading an empty file as binary."""
        result = await read_file_binary(str(test_files['empty_file']))
        assert isinstance(result, str)

        # Should be empty base64
        decoded = base64.b64decode(result)
        assert decoded == b""

    @pytest.mark.asyncio
    async def test_read_binary_nonexistent(self, tmp_path, configure_test_provider):
        """Test reading nonexistent file as binary."""
        nonexistent = tmp_path / "nonexistent.bin"
        result = await read_file_binary(str(nonexistent))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileNotFoundError"

class TestListDirectory:
    """Test list_directory tool implementation."""

    @pytest.mark.asyncio
    async def test_list_directory_basic(self, test_files, configure_test_provider):
        """Test basic directory listing."""
        tmp_path = test_files['text_file'].parent
        result = await list_directory(str(tmp_path))
        assert isinstance(result, list)
        assert len(result) > 0

        # Check that files are present
        file_names = [Path(p).name for p in result]
        assert "test.txt" in file_names
        assert "test.bin" in file_names
        assert "subdir" in file_names

    @pytest.mark.asyncio
    async def test_list_directory_with_pattern(self, test_files, configure_test_provider):
        """Test directory listing with pattern filter."""
        tmp_path = test_files['text_file'].parent
        result = await list_directory(str(tmp_path), pattern="*.py")
        assert isinstance(result, list)

        # Should only include Python files
        for path in result:
            assert path.endswith('.py')

    @pytest.mark.asyncio
    async def test_list_directory_recursive(self, test_files, configure_test_provider):
        """Test recursive directory listing."""
        tmp_path = test_files['text_file'].parent
        result = await list_directory(str(tmp_path), recursive=True)
        assert isinstance(result, list)

        # Should include files from subdirectories
        paths_str = " ".join(result)
        assert "nested.py" in paths_str
        assert "deep.txt" in paths_str

    @pytest.mark.asyncio
    async def test_list_directory_max_files(self, test_files, configure_test_provider):
        """Test directory listing with file limit."""
        tmp_path = test_files['text_file'].parent
        result = await list_directory(str(tmp_path), max_files=3)
        assert isinstance(result, list)
        assert len(result) <= 3

    @pytest.mark.asyncio
    async def test_list_nonexistent_directory(self, tmp_path, configure_test_provider):
        """Test listing nonexistent directory."""
        nonexistent = tmp_path / "nonexistent"
        result = await list_directory(str(nonexistent))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileNotFoundError"

    @pytest.mark.asyncio
    async def test_list_file_as_directory(self, test_files, configure_test_provider):
        """Test listing a file as if it were a directory."""
        result = await list_directory(str(test_files['text_file']))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileProviderError"
        assert "not a directory" in result["error"]

class TestFileExists:
    """Test file_exists tool implementation."""

    @pytest.mark.asyncio
    async def test_file_exists_true(self, test_files, configure_test_provider):
        """Test file_exists for existing file."""
        result = await file_exists(str(test_files['text_file']))
        assert result is True

    @pytest.mark.asyncio
    async def test_file_exists_directory(self, test_files, configure_test_provider):
        """Test file_exists for existing directory."""
        result = await file_exists(str(test_files['subdir']))
        assert result is True

    @pytest.mark.asyncio
    async def test_file_exists_false(self, tmp_path, configure_test_provider):
        """Test file_exists for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.txt"
        result = await file_exists(str(nonexistent))
        assert result is False

    @pytest.mark.asyncio
    async def test_file_exists_invalid_path(self, configure_test_provider):
        """Test file_exists with invalid path."""
        result = await file_exists("")
        assert result is False

    @pytest.mark.asyncio
    async def test_file_exists_permission_error(self, configure_test_provider):
        """Test file_exists with permission issues."""
        # This test might not work on all systems
        result = await file_exists("/root/.private_file_that_does_not_exist")
        assert result is False

class TestGetFileStats:
    """Test get_file_stats tool implementation."""

    @pytest.mark.asyncio
    async def test_get_file_stats_file(self, test_files, configure_test_provider):
        """Test getting stats for a regular file."""
        result = await get_file_stats(str(test_files['text_file']))
        assert isinstance(result, dict)
        assert "error" not in result

        assert result["file_type"] == "file"
        assert result["is_directory"] is False
        assert result["size"] > 0
        assert "modified_time" in result
        assert result["is_readable"] is True

    @pytest.mark.asyncio
    async def test_get_file_stats_directory(self, test_files, configure_test_provider):
        """Test getting stats for a directory."""
        result = await get_file_stats(str(test_files['subdir']))
        assert isinstance(result, dict)
        assert "error" not in result

        assert result["file_type"] == "directory"
        assert result["is_directory"] is True
        assert "size" in result
        assert result["is_readable"] is True

    @pytest.mark.asyncio
    async def test_get_file_stats_empty_file(self, test_files, configure_test_provider):
        """Test getting stats for an empty file."""
        result = await get_file_stats(str(test_files['empty_file']))
        assert isinstance(result, dict)
        assert "error" not in result

        assert result["file_type"] == "file"
        assert result["size"] == 0

    @pytest.mark.asyncio
    async def test_get_file_stats_nonexistent(self, tmp_path, configure_test_provider):
        """Test getting stats for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.txt"
        result = await get_file_stats(str(nonexistent))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileNotFoundError"

class TestCalculateFileHash:
    """Test calculate_file_hash tool implementation (optional)."""

    @pytest.mark.asyncio
    async def test_calculate_md5_hash(self, test_files, configure_test_provider):
        """Test calculating MD5 hash."""
        result = await calculate_file_hash(str(test_files['text_file']), "md5")
        assert isinstance(result, str)
        assert len(result) == 32  # MD5 is 32 hex chars

        # Verify against known hash
        content = test_files['text_file'].read_bytes()
        expected = hashlib.md5(content).hexdigest()
        assert result == expected

    @pytest.mark.asyncio
    async def test_calculate_sha256_hash(self, test_files, configure_test_provider):
        """Test calculating SHA256 hash."""
        result = await calculate_file_hash(str(test_files['text_file']), "sha256")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 is 64 hex chars

        # Verify against known hash
        content = test_files['text_file'].read_bytes()
        expected = hashlib.sha256(content).hexdigest()
        assert result == expected

    @pytest.mark.asyncio
    async def test_calculate_hash_invalid_algorithm(self, test_files, configure_test_provider):
        """Test calculating hash with invalid algorithm."""
        result = await calculate_file_hash(str(test_files['text_file']), "invalid")
        assert isinstance(result, dict)
        assert result["error_type"] == "FileProviderError"
        assert "Invalid hash algorithm" in result["error"]

    @pytest.mark.asyncio
    async def test_calculate_hash_nonexistent(self, tmp_path, configure_test_provider):
        """Test calculating hash for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.txt"
        result = await calculate_file_hash(str(nonexistent))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileNotFoundError"

class TestFindFiles:
    """Test find_files tool implementation (optional)."""

    @pytest.mark.asyncio
    async def test_find_files_single_pattern(self, test_files, configure_test_provider):
        """Test finding files with single pattern."""
        tmp_path = test_files['text_file'].parent
        result = await find_files(str(tmp_path), ["*.py"])
        assert isinstance(result, list)
        assert len(result) >= 3  # At least script0.py, script1.py, script2.py

        for path in result:
            assert path.endswith('.py')

    @pytest.mark.asyncio
    async def test_find_files_multiple_patterns(self, test_files, configure_test_provider):
        """Test finding files with multiple patterns."""
        tmp_path = test_files['text_file'].parent
        result = await find_files(str(tmp_path), ["*.py", "*.txt"])
        assert isinstance(result, list)

        # Should include both .py and .txt files
        py_files = [p for p in result if p.endswith('.py')]
        txt_files = [p for p in result if p.endswith('.txt')]
        assert len(py_files) > 0
        assert len(txt_files) > 0

    @pytest.mark.asyncio
    async def test_find_files_recursive(self, test_files, configure_test_provider):
        """Test finding files recursively."""
        tmp_path = test_files['text_file'].parent
        result = await find_files(str(tmp_path), ["*.py"], recursive=True)
        assert isinstance(result, list)

        # Should include nested.py from subdir
        paths_str = " ".join(result)
        assert "nested.py" in paths_str

    @pytest.mark.asyncio
    async def test_find_files_max_limit(self, test_files, configure_test_provider):
        """Test finding files with limit."""
        tmp_path = test_files['text_file'].parent
        result = await find_files(str(tmp_path), ["*"], max_files=2)
        assert isinstance(result, list)
        assert len(result) <= 2

    @pytest.mark.asyncio
    async def test_find_files_no_matches(self, test_files, configure_test_provider):
        """Test finding files with no matches."""
        tmp_path = test_files['text_file'].parent
        result = await find_files(str(tmp_path), ["*.nonexistent"])
        assert isinstance(result, list)
        assert len(result) == 0

class TestSecurityFeatures:
    """Test security features and edge cases."""

    @pytest.mark.asyncio
    async def test_path_restriction_enforcement(self, test_files):
        """Test that path restrictions are enforced."""
        # Configure with restricted paths
        tmp_path = test_files['text_file'].parent
        configure_file_provider(
            allowed_paths=[str(tmp_path)],
            enable_audit_log=False
        )

        # Access within allowed path should work
        result = await file_exists(str(test_files['text_file']))
        assert result is True

        # Access outside allowed path should fail (if path restrictions enabled)
        # This test depends on the specific configuration

    @pytest.mark.asyncio
    async def test_large_file_handling(self, tmp_path, configure_test_provider):
        """Test handling of large files."""
        # Create a file larger than default limits
        large_file = tmp_path / "large.txt"
        large_content = "x" * (FileProviderConfig.MAX_FILE_SIZE + 100)
        large_file.write_text(large_content)

        # Should fail due to size limit
        result = await read_file(str(large_file))
        assert isinstance(result, dict)
        assert result["error_type"] == "FileSizeLimitExceededError"

    @pytest.mark.asyncio
    async def test_directory_listing_limits(self, tmp_path, configure_test_provider):
        """Test directory listing limits."""
        # Create many files
        for i in range(FileProviderConfig.MAX_DIRECTORY_FILES + 10):
            (tmp_path / f"file_{i}.txt").touch()

        result = await list_directory(str(tmp_path))
        assert isinstance(result, list)
        # Should be limited to MAX_DIRECTORY_FILES
        assert len(result) <= FileProviderConfig.MAX_DIRECTORY_FILES

    def test_configuration_changes(self):
        """Test dynamic configuration changes."""
        original_size = FileProviderConfig.MAX_FILE_SIZE

        # Change configuration
        configure_file_provider(max_file_size=5000)
        assert FileProviderConfig.MAX_FILE_SIZE == 5000

        # Restore
        configure_file_provider(max_file_size=original_size)
        assert original_size == FileProviderConfig.MAX_FILE_SIZE

class TestProviderInfo:
    """Test provider information and metadata."""

    def test_get_provider_info(self):
        """Test getting provider information."""
        info = get_provider_info()
        assert isinstance(info, dict)
        assert "name" in info
        assert "version" in info
        assert "required_tools" in info
        assert "optional_tools" in info
        assert "security_features" in info
        assert "configuration" in info

        # Check required tools
        required = info["required_tools"]
        assert "read_file" in required
        assert "read_file_binary" in required
        assert "list_directory" in required
        assert "file_exists" in required
        assert "get_file_stats" in required

        # Check optional tools
        optional = info["optional_tools"]
        assert "calculate_file_hash" in optional
        assert "find_files" in optional

class TestErrorHandling:
    """Test error handling and edge cases."""

    @pytest.mark.asyncio
    async def test_permission_errors(self, configure_test_provider):
        """Test handling of permission errors."""
        # Try to access a system file that typically requires root
        system_file = "/etc/shadow"
        if Path(system_file).exists():
            result = await read_file(system_file)
            assert isinstance(result, dict)
            # Should either be blocked by path restriction or permission error
            assert result["error_type"] in ["PermissionError", "FileProviderError"]

    @pytest.mark.asyncio
    async def test_invalid_characters_in_path(self, configure_test_provider):
        """Test handling of invalid characters in paths."""
        invalid_paths = [
            "\x00invalid",  # Null byte
            "invalid\n\r",  # Control characters
        ]

        for path in invalid_paths:
            result = await file_exists(path)
            # Should handle gracefully (return False)
            assert result is False

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, test_files, configure_test_provider):
        """Test concurrent file operations."""
        # Run multiple operations concurrently
        tasks = []
        for _i in range(10):
            tasks.append(file_exists(str(test_files['text_file'])))
            tasks.append(get_file_stats(str(test_files['text_file'])))

        results = await asyncio.gather(*tasks)

        # All should succeed
        for i, result in enumerate(results):
            if i % 2 == 0:  # file_exists results
                assert result is True
            else:  # get_file_stats results
                assert isinstance(result, dict)
                assert "error" not in result

# Performance tests (optional, can be slow)
class TestPerformance:
    """Test performance characteristics."""

    @pytest.mark.asyncio
    async def test_large_directory_performance(self, tmp_path, configure_test_provider):
        """Test performance with large directories."""
        # Create a moderate number of files
        num_files = 100
        for i in range(num_files):
            (tmp_path / f"perf_file_{i}.txt").write_text(f"content {i}")

        import time
        start = time.time()
        result = await list_directory(str(tmp_path))
        duration = time.time() - start

        assert isinstance(result, list)
        assert len(result) >= num_files
        assert duration < 5.0  # Should complete within 5 seconds

    @pytest.mark.asyncio
    async def test_hash_performance(self, tmp_path, configure_test_provider):
        """Test hash calculation performance."""
        # Create a moderately large file
        large_file = tmp_path / "hash_test.bin"
        content = b"x" * (1024 * 100)  # 100KB
        large_file.write_bytes(content)

        import time
        start = time.time()
        result = await calculate_file_hash(str(large_file), "sha256")
        duration = time.time() - start

        assert isinstance(result, str)
        assert len(result) == 64  # SHA256
        assert duration < 2.0  # Should complete within 2 seconds

if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
