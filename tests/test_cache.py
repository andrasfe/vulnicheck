import pytest

from vulnicheck.core.cache import VulnerabilityCache


class TestVulnerabilityCache:
    """Test the stub VulnerabilityCache for backwards compatibility."""

    @pytest.fixture
    def cache(self):
        return VulnerabilityCache(max_size=10, ttl_seconds=2)

    def test_init(self):
        """Test cache initialization."""
        cache = VulnerabilityCache(max_size=100, ttl_seconds=60)
        # The stub doesn't actually store these values, just accepts them
        assert cache is not None

    def test_get_returns_none(self, cache):
        """Test that get always returns None (stub behavior)."""
        assert cache.get("any_key") is None
        assert cache.get("another_key") is None

    def test_set_does_nothing(self, cache):
        """Test that set doesn't raise errors (stub behavior)."""
        cache.set("key1", "value1")
        cache.set("key2", {"data": "value2"})
        # Should not raise any errors
        assert cache.get("key1") is None  # Still returns None

    def test_clear_does_nothing(self, cache):
        """Test that clear doesn't raise errors (stub behavior)."""
        cache.set("key1", "value1")
        cache.clear()
        # Should not raise any errors
        assert cache.get("key1") is None


# Note: CachedOSVClient and CachedNVDClient have been removed
# as caching is now handled by functools.lru_cache in server.py
