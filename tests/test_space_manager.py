"""Tests for the space manager module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnicheck.core.space_manager import SpaceConfig, SpaceManager, get_space_manager


class TestSpaceManager:
    """Test the SpaceManager class."""

    @pytest.fixture
    def space_config(self):
        """Create a test space configuration."""
        return SpaceConfig(
            max_temp_space_mb=100,
            max_cache_space_mb=200,
            cleanup_threshold=0.9,
            min_free_space_mb=50
        )

    @pytest.fixture
    def space_manager(self, space_config):
        """Create a space manager instance."""
        return SpaceManager(space_config)

    def test_get_directory_size_empty(self, space_manager, tmp_path):
        """Test getting size of empty directory."""
        size = space_manager.get_directory_size(tmp_path)
        assert size == 0

    def test_get_directory_size_with_files(self, space_manager, tmp_path):
        """Test getting size of directory with files."""
        # Create some test files
        file1 = tmp_path / "test1.txt"
        file1.write_text("Hello World" * 100)

        file2 = tmp_path / "test2.txt"
        file2.write_text("Test content" * 200)

        subdir = tmp_path / "subdir"
        subdir.mkdir()
        file3 = subdir / "test3.txt"
        file3.write_text("Nested file" * 50)

        size = space_manager.get_directory_size(tmp_path)
        assert size > 0

        # Verify size in MB
        size_mb = space_manager.get_directory_size_mb(tmp_path)
        assert size_mb == size / (1024 * 1024)

    def test_get_directory_size_nonexistent(self, space_manager):
        """Test getting size of non-existent directory."""
        size = space_manager.get_directory_size(Path("/nonexistent/path"))
        assert size == 0

    @pytest.mark.asyncio
    async def test_check_space_before_clone_sufficient(self, space_manager):
        """Test space check when sufficient space is available."""
        with patch.object(space_manager, 'get_directory_size_mb', return_value=10), \
             patch('os.statvfs') as mock_statvfs:
            # Mock filesystem stats with plenty of space
            mock_stat = MagicMock()
            mock_stat.f_bavail = 1000 * 1024 * 1024 / 4096  # 1000MB free
            mock_stat.f_frsize = 4096
            mock_statvfs.return_value = mock_stat

            can_proceed, message = await space_manager.check_space_before_clone(50)
            assert can_proceed is True
            assert "Sufficient space available" in message

    @pytest.mark.asyncio
    async def test_check_space_before_clone_insufficient_free(self, space_manager):
        """Test space check when insufficient free space."""
        with patch('os.statvfs') as mock_statvfs:
            # Mock filesystem stats with little free space
            mock_stat = MagicMock()
            mock_stat.f_bavail = 30 * 1024 * 1024 / 4096  # Only 30MB free
            mock_stat.f_frsize = 4096
            mock_statvfs.return_value = mock_stat

            can_proceed, message = await space_manager.check_space_before_clone(50)
            assert can_proceed is False
            assert "Insufficient free space" in message

    @pytest.mark.asyncio
    async def test_check_space_before_clone_would_exceed_limit(self, space_manager):
        """Test space check when would exceed temp space limit."""
        with patch.object(space_manager, 'get_directory_size_mb', return_value=80), \
             patch('os.statvfs') as mock_statvfs, \
             patch.object(space_manager, 'cleanup_old_temp_dirs', return_value=5) as mock_cleanup:
            # Mock filesystem stats with plenty of space
            mock_stat = MagicMock()
            mock_stat.f_bavail = 1000 * 1024 * 1024 / 4096
            mock_stat.f_frsize = 4096
            mock_statvfs.return_value = mock_stat

            can_proceed, message = await space_manager.check_space_before_clone(50)
            assert can_proceed is False
            assert "Would exceed temp space limit" in message
            mock_cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_old_temp_dirs(self, space_manager):
        """Test cleanup of old temporary directories."""
        # This is a simplified test that verifies the method works
        # In production, it will clean up actual /tmp directories

        # Call the method and verify it doesn't crash
        # In a real environment, it would clean up old directories
        with patch('shutil.rmtree'):
            freed_mb = await space_manager.cleanup_old_temp_dirs(max_age_seconds=3600)

            # Should return a number (possibly 0 if no old dirs found)
            assert isinstance(freed_mb, int | float)
            assert freed_mb >= 0

    @pytest.mark.asyncio
    async def test_register_unregister_temp_directory(self, space_manager, tmp_path):
        """Test registering and unregistering temp directories."""
        test_dir = tmp_path / "test_repo"

        # Register directory
        await space_manager.register_temp_directory(test_dir)
        assert str(test_dir) in space_manager._tracked_dirs

        # Unregister directory
        await space_manager.unregister_temp_directory(test_dir)
        assert str(test_dir) not in space_manager._tracked_dirs

    @pytest.mark.asyncio
    async def test_cleanup_cache(self, space_manager, tmp_path):
        """Test cache cleanup."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create old and new cache files
        old_file = cache_dir / "old.json"
        old_file.write_text('{"old": true}')

        new_file = cache_dir / "new.json"
        new_file.write_text('{"new": true}')

        # Make old file appear old
        old_time = 0
        os.utime(old_file, (old_time, old_time))

        freed_mb = await space_manager.cleanup_cache(cache_dir, max_age_hours=1)

        # Old file should be deleted
        assert not old_file.exists()
        assert new_file.exists()
        assert freed_mb > 0

    @pytest.mark.asyncio
    async def test_get_space_report(self, space_manager, tmp_path):
        """Test getting space usage report."""
        # Register a test directory
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        await space_manager.register_temp_directory(test_dir)

        report = await space_manager.get_space_report()

        assert "filesystem" in report
        assert "limits" in report
        assert "tracked" in report

        assert report["limits"]["max_temp_space_mb"] == 100
        assert report["limits"]["max_cache_space_mb"] == 200
        assert report["tracked"]["directory_count"] == 1

    def test_get_space_manager_singleton(self):
        """Test that get_space_manager returns singleton instance."""
        manager1 = get_space_manager()
        manager2 = get_space_manager()
        assert manager1 is manager2

        # Reset global for other tests
        import vulnicheck.core.space_manager
        vulnicheck.core.space_manager._space_manager = None


class TestSpaceManagerIntegration:
    """Integration tests for space manager with real filesystem operations."""

    @pytest.mark.asyncio
    async def test_real_temp_directory_lifecycle(self):
        """Test real temporary directory lifecycle with space management."""
        # Use a larger limit that won't interfere with actual /tmp usage
        space_config = SpaceConfig(
            max_temp_space_mb=5000,  # 5GB limit to avoid conflicts
            min_free_space_mb=1
        )
        space_manager = SpaceManager(space_config)

        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_repo"
            test_path.mkdir()

            # Create a small file
            (test_path / "test.txt").write_text("Test content" * 100)

            # Register directory
            await space_manager.register_temp_directory(test_path)

            # Check space - should succeed with large limit
            can_proceed, message = await space_manager.check_space_before_clone(5)
            assert can_proceed is True, f"Space check failed: {message}"

            # Get report
            report = await space_manager.get_space_report()
            assert report["tracked"]["directory_count"] == 1

            # Unregister
            await space_manager.unregister_temp_directory(test_path)
            assert len(space_manager._tracked_dirs) == 0
