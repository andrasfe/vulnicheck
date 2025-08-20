"""Disk space management for temporary directories.

This module provides utilities to manage disk space usage in temporary directories,
ensuring that repository cloning and caching operations don't exceed configured limits.
"""

import asyncio
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SpaceConfig:
    """Configuration for space management."""

    max_temp_space_mb: int = 100  # Maximum space for temporary clones
    max_cache_space_mb: int = 200  # Maximum space for cache
    cleanup_threshold: float = 0.9  # Cleanup when usage exceeds 90% of limit
    min_free_space_mb: int = 50  # Minimum free space to maintain


class SpaceManager:
    """Manages disk space for temporary and cache directories."""

    def __init__(self, config: SpaceConfig | None = None):
        """Initialize the space manager.

        Args:
            config: Space management configuration
        """
        self.config = config or SpaceConfig()
        self._lock = asyncio.Lock()
        self._tracked_dirs: dict[str, float] = {}  # path -> last_access_time

    def get_directory_size(self, path: Path) -> int:
        """Get the total size of a directory in bytes.

        Args:
            path: Directory path to measure

        Returns:
            Total size in bytes
        """
        if not path.exists():
            return 0

        total_size = 0
        try:
            for dirpath, _dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    # Skip symbolic links
                    if not os.path.islink(filepath):
                        try:
                            total_size += os.path.getsize(filepath)
                        except OSError:
                            # File might have been deleted
                            continue
        except OSError as e:
            logger.warning(f"Error calculating directory size for {path}: {e}")

        return total_size

    def get_directory_size_mb(self, path: Path) -> float:
        """Get directory size in megabytes.

        Args:
            path: Directory path to measure

        Returns:
            Size in megabytes
        """
        return self.get_directory_size(path) / (1024 * 1024)

    async def check_space_before_clone(self, estimated_size_mb: float = 50) -> tuple[bool, str]:
        """Check if there's enough space before cloning a repository.

        Args:
            estimated_size_mb: Estimated size of the repository in MB

        Returns:
            Tuple of (can_proceed, message)
        """
        async with self._lock:
            # Check /tmp usage
            tmp_path = Path("/tmp")
            current_usage_mb = self.get_directory_size_mb(tmp_path)

            # Get filesystem stats
            stat = os.statvfs(tmp_path)
            free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)

            # Check if we have enough free space
            if free_mb < self.config.min_free_space_mb:
                return False, f"Insufficient free space: {free_mb:.1f}MB available, need {self.config.min_free_space_mb}MB"

            # Check if adding this repo would exceed our limit
            if current_usage_mb + estimated_size_mb > self.config.max_temp_space_mb:
                # Try to cleanup old temp directories
                await self.cleanup_old_temp_dirs()
                new_usage_mb = self.get_directory_size_mb(tmp_path)

                if new_usage_mb + estimated_size_mb > self.config.max_temp_space_mb:
                    return False, (
                        f"Would exceed temp space limit: current={new_usage_mb:.1f}MB, "
                        f"estimated={estimated_size_mb:.1f}MB, limit={self.config.max_temp_space_mb}MB"
                    )

            return True, "Sufficient space available"

    async def cleanup_old_temp_dirs(self, max_age_seconds: int = 3600) -> float:
        """Clean up old temporary directories.

        Args:
            max_age_seconds: Maximum age in seconds before cleanup

        Returns:
            Amount of space freed in MB
        """
        freed_mb = 0.0
        tmp_path = Path("/tmp")
        current_time = time.time()

        try:
            # Look for temporary directories created by tempfile
            for item in tmp_path.iterdir():
                if item.is_dir() and (
                    item.name.startswith("tmp") or
                    item.name.startswith("vulnicheck_") or
                    "repo" in item.name.lower()
                ):
                    try:
                        # Check directory age
                        stat = item.stat()
                        age = current_time - stat.st_mtime

                        if age > max_age_seconds:
                            # Calculate size before deletion
                            size_mb = self.get_directory_size_mb(item)

                            # Remove the directory
                            shutil.rmtree(item, ignore_errors=True)
                            freed_mb += size_mb
                            logger.info(f"Cleaned up old temp directory: {item} ({size_mb:.1f}MB)")
                    except OSError as e:
                        logger.warning(f"Error cleaning up {item}: {e}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

        return freed_mb

    async def register_temp_directory(self, path: Path) -> None:
        """Register a temporary directory for tracking.

        Args:
            path: Path to the temporary directory
        """
        async with self._lock:
            self._tracked_dirs[str(path)] = time.time()

    async def unregister_temp_directory(self, path: Path) -> None:
        """Unregister a temporary directory.

        Args:
            path: Path to the temporary directory
        """
        async with self._lock:
            self._tracked_dirs.pop(str(path), None)

    async def cleanup_cache(self, cache_dir: Path, max_age_hours: int = 24) -> float:
        """Clean up old cache entries.

        Args:
            cache_dir: Cache directory path
            max_age_hours: Maximum age in hours before cleanup

        Returns:
            Amount of space freed in MB
        """
        if not cache_dir.exists():
            return 0.0

        freed_mb = 0.0
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600

        async with self._lock:
            try:
                for item in cache_dir.iterdir():
                    if item.is_file():
                        try:
                            stat = item.stat()
                            age = current_time - stat.st_mtime

                            if age > max_age_seconds:
                                size_mb = item.stat().st_size / (1024 * 1024)
                                item.unlink()
                                freed_mb += size_mb
                                logger.info(f"Cleaned up old cache file: {item.name} ({size_mb:.1f}MB)")
                        except OSError as e:
                            logger.warning(f"Error cleaning up cache file {item}: {e}")
            except Exception as e:
                logger.error(f"Error during cache cleanup: {e}")

        return freed_mb

    async def get_space_report(self) -> dict:
        """Get a report of current space usage.

        Returns:
            Dictionary with space usage information
        """
        tmp_path = Path("/tmp")
        stat = os.statvfs(tmp_path)

        # Calculate various metrics
        total_mb = (stat.f_blocks * stat.f_frsize) / (1024 * 1024)
        free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
        used_mb = total_mb - free_mb

        # Count tracked directories
        tracked_count = len(self._tracked_dirs)
        tracked_size_mb = sum(
            self.get_directory_size_mb(Path(p))
            for p in self._tracked_dirs
            if Path(p).exists()
        )

        return {
            "filesystem": {
                "total_mb": round(total_mb, 2),
                "used_mb": round(used_mb, 2),
                "free_mb": round(free_mb, 2),
                "usage_percent": round((used_mb / total_mb) * 100, 1)
            },
            "limits": {
                "max_temp_space_mb": self.config.max_temp_space_mb,
                "max_cache_space_mb": self.config.max_cache_space_mb,
                "min_free_space_mb": self.config.min_free_space_mb
            },
            "tracked": {
                "directory_count": tracked_count,
                "total_size_mb": round(tracked_size_mb, 2)
            }
        }


# Global instance for singleton pattern
_space_manager: SpaceManager | None = None


def get_space_manager(config: SpaceConfig | None = None) -> SpaceManager:
    """Get or create the global space manager instance.

    Args:
        config: Configuration for the space manager (used only on first call)

    Returns:
        The global SpaceManager instance
    """
    global _space_manager
    if _space_manager is None:
        _space_manager = SpaceManager(config)
    return _space_manager
