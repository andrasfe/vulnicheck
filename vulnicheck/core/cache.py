"""Caching utilities with TTL support for vulnerability data.

This module provides a TTL-aware cache decorator that automatically expires
cached data after a configurable time period. This is critical for vulnerability
data which is updated frequently (hourly in most databases).
"""

import os
import threading
import time
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

# Default TTL from environment or 15 minutes
DEFAULT_CACHE_TTL = int(os.environ.get("CACHE_TTL", 900))

# Type variable for generic function types
F = TypeVar("F", bound=Callable[..., Any])


class TTLCache:
    """Thread-safe cache with TTL expiration.

    Entries automatically expire after the configured TTL period.
    Uses a dictionary for O(1) lookup with periodic cleanup.
    """

    def __init__(self, maxsize: int = 1000, ttl_seconds: int = DEFAULT_CACHE_TTL):
        """Initialize TTL cache.

        Args:
            maxsize: Maximum number of entries to store
            ttl_seconds: Time-to-live in seconds for cache entries
        """
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self._cache: dict[str, tuple[Any, float]] = {}  # key -> (value, expire_time)
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> tuple[bool, Any]:
        """Get a value from the cache.

        Args:
            key: Cache key

        Returns:
            Tuple of (found, value). If found is False, value is None.
        """
        with self._lock:
            if key in self._cache:
                value, expire_time = self._cache[key]
                if time.time() < expire_time:
                    self._hits += 1
                    return True, value
                else:
                    # Expired - remove and return miss
                    del self._cache[key]

            self._misses += 1
            return False, None

    def set(self, key: str, value: Any) -> None:
        """Set a value in the cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        with self._lock:
            # Evict oldest entries if at capacity
            if len(self._cache) >= self.maxsize:
                self._evict_expired()
                # If still at capacity after evicting expired, remove oldest
                if len(self._cache) >= self.maxsize:
                    self._evict_oldest()

            expire_time = time.time() + self.ttl_seconds
            self._cache[key] = (value, expire_time)

    def _evict_expired(self) -> int:
        """Remove all expired entries.

        Returns:
            Number of entries removed
        """
        now = time.time()
        expired_keys = [k for k, (_, exp) in self._cache.items() if exp <= now]
        for key in expired_keys:
            del self._cache[key]
        return len(expired_keys)

    def _evict_oldest(self) -> None:
        """Remove the oldest entry (earliest expiration time)."""
        if not self._cache:
            return

        oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
        del self._cache[oldest_key]

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> dict[str, int | float]:
        """Get cache statistics.

        Returns:
            Dictionary with hits, misses, size, and hit rate
        """
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            return {
                "hits": self._hits,
                "misses": self._misses,
                "size": len(self._cache),
                "maxsize": self.maxsize,
                "ttl_seconds": self.ttl_seconds,
                "hit_rate_percent": round(hit_rate, 2),
            }


def cache_with_ttl(
    maxsize: int = 1000, ttl_seconds: int = DEFAULT_CACHE_TTL
) -> Callable[[F], F]:
    """Decorator to cache function results with TTL expiration.

    Similar to @lru_cache but with automatic expiration of entries.
    Thread-safe and suitable for vulnerability data caching.

    Args:
        maxsize: Maximum number of entries to cache
        ttl_seconds: Time-to-live in seconds

    Returns:
        Decorated function with caching

    Example:
        @cache_with_ttl(maxsize=500, ttl_seconds=300)
        def query_vulnerabilities(package_name: str) -> list:
            # Expensive API call
            return api.query(package_name)
    """
    cache = TTLCache(maxsize=maxsize, ttl_seconds=ttl_seconds)

    def decorator(func: F) -> F:
        """Wrap a function with TTL-based caching."""

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Execute function with caching based on arguments."""
            # Create cache key from function arguments
            # Use repr for better handling of complex types
            key_parts = [repr(arg) for arg in args]
            key_parts.extend(f"{k}={repr(v)}" for k, v in sorted(kwargs.items()))
            cache_key = f"{func.__name__}:{':'.join(key_parts)}"

            # Try to get from cache
            found, value = cache.get(cache_key)
            if found:
                return value

            # Call function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result)
            return result

        # Add cache management methods to the wrapper
        wrapper.cache_clear = cache.clear  # type: ignore[attr-defined]
        wrapper.cache_stats = cache.stats  # type: ignore[attr-defined]

        return wrapper  # type: ignore[return-value]

    return decorator


# Deprecated stub for backwards compatibility
class VulnerabilityCache:
    """Deprecated stub for backwards compatibility.

    Use cache_with_ttl decorator instead.
    """

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 900) -> None:
        import warnings

        warnings.warn(
            "VulnerabilityCache is deprecated, use cache_with_ttl decorator instead",
            DeprecationWarning,
            stacklevel=2,
        )
        self._cache = TTLCache(maxsize=max_size, ttl_seconds=ttl_seconds)

    def get(self, key: str) -> Any | None:
        """Get a value from the cache by key.

        Args:
            key: The cache key to look up.

        Returns:
            The cached value, or None if not found or expired.
        """
        found, value = self._cache.get(key)
        return value if found else None

    def set(self, key: str, value: Any) -> None:
        """Store a value in the cache.

        Args:
            key: The cache key.
            value: The value to cache.
        """
        self._cache.set(key, value)

    def clear(self) -> None:
        """Clear all entries from the cache."""
        self._cache.clear()
