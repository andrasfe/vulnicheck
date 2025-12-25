"""Tests for caching utilities.

VulnerabilityCache is now a proper implementation using TTLCache
with deprecation warning. Tests verify actual caching behavior.
"""

import time
import warnings

import pytest

from vulnicheck.core.cache import TTLCache, VulnerabilityCache, cache_with_ttl


class TestTTLCache:
    """Test the TTLCache class."""

    def test_init(self):
        """Test cache initialization."""
        cache = TTLCache(maxsize=100, ttl_seconds=60)
        assert cache.maxsize == 100
        assert cache.ttl_seconds == 60

    def test_get_set(self):
        """Test basic get/set operations."""
        cache = TTLCache(maxsize=10, ttl_seconds=60)

        # Set and get a value
        cache.set("key1", "value1")
        found, value = cache.get("key1")
        assert found is True
        assert value == "value1"

    def test_get_missing_key(self):
        """Test get returns (False, None) for missing key."""
        cache = TTLCache(maxsize=10, ttl_seconds=60)
        found, value = cache.get("nonexistent")
        assert found is False
        assert value is None

    def test_ttl_expiration(self):
        """Test that entries expire after TTL."""
        cache = TTLCache(maxsize=10, ttl_seconds=1)

        cache.set("key1", "value1")
        found, _ = cache.get("key1")
        assert found is True

        # Wait for expiration
        time.sleep(1.1)
        found, _ = cache.get("key1")
        assert found is False

    def test_stats(self):
        """Test cache statistics."""
        cache = TTLCache(maxsize=10, ttl_seconds=60)

        # Generate some hits and misses
        cache.set("key1", "value1")
        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("nonexistent")  # Miss

        stats = cache.stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["size"] == 1

    def test_clear(self):
        """Test clearing the cache."""
        cache = TTLCache(maxsize=10, ttl_seconds=60)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()

        found1, _ = cache.get("key1")
        found2, _ = cache.get("key2")
        assert found1 is False
        assert found2 is False


class TestVulnerabilityCache:
    """Test the VulnerabilityCache for backwards compatibility.

    VulnerabilityCache now wraps TTLCache and emits a deprecation warning.
    """

    @pytest.fixture
    def cache(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return VulnerabilityCache(max_size=10, ttl_seconds=60)

    def test_init_emits_deprecation_warning(self):
        """Test cache initialization emits deprecation warning."""
        with pytest.warns(DeprecationWarning, match="VulnerabilityCache is deprecated"):
            VulnerabilityCache(max_size=100, ttl_seconds=60)

    def test_get_returns_none_for_missing(self, cache):
        """Test that get returns None for missing keys."""
        assert cache.get("any_key") is None
        assert cache.get("another_key") is None

    def test_set_and_get(self, cache):
        """Test that set and get work correctly."""
        cache.set("key1", "value1")
        cache.set("key2", {"data": "value2"})
        # VulnerabilityCache now properly caches values
        assert cache.get("key1") == "value1"
        assert cache.get("key2") == {"data": "value2"}

    def test_clear(self, cache):
        """Test that clear removes all entries."""
        cache.set("key1", "value1")
        cache.clear()
        assert cache.get("key1") is None


class TestCacheWithTTL:
    """Test the cache_with_ttl decorator."""

    def test_basic_caching(self):
        """Test that decorator caches function results."""
        call_count = 0

        @cache_with_ttl(maxsize=10, ttl_seconds=60)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call
        result1 = expensive_function(5)
        assert result1 == 10
        assert call_count == 1

        # Second call with same argument - should use cache
        result2 = expensive_function(5)
        assert result2 == 10
        assert call_count == 1  # Not incremented

        # Third call with different argument
        result3 = expensive_function(6)
        assert result3 == 12
        assert call_count == 2

    def test_cache_clear(self):
        """Test cache_clear method on decorated function."""
        call_count = 0

        @cache_with_ttl(maxsize=10, ttl_seconds=60)
        def my_function(x):
            nonlocal call_count
            call_count += 1
            return x

        my_function(1)
        assert call_count == 1

        my_function(1)  # Cached
        assert call_count == 1

        my_function.cache_clear()

        my_function(1)  # Not cached anymore
        assert call_count == 2

    def test_cache_stats(self):
        """Test cache_stats method on decorated function."""
        @cache_with_ttl(maxsize=10, ttl_seconds=60)
        def my_function(x):
            return x

        my_function(1)  # Miss
        my_function(1)  # Hit
        my_function(2)  # Miss

        stats = my_function.cache_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 2


# Note: CachedOSVClient and CachedNVDClient have been removed
# as caching is now handled by cache_with_ttl decorator in server.py
