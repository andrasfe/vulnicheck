import time
from unittest.mock import Mock

import pytest

from vulnicheck.cache import CachedNVDClient, CachedOSVClient, VulnerabilityCache


class TestVulnerabilityCache:
    @pytest.fixture
    def cache(self):
        return VulnerabilityCache(max_size=10, ttl_seconds=2)

    def test_init(self):
        cache = VulnerabilityCache(max_size=100, ttl_seconds=60)
        assert cache.cache.maxsize == 100
        assert cache.cache.ttl == 60

    def test_generate_key(self, cache):
        key1 = cache._generate_key("test", 123, foo="bar")
        key2 = cache._generate_key("test", 123, foo="bar")
        key3 = cache._generate_key("test", 456, foo="bar")

        assert key1 == key2  # Same inputs produce same key
        assert key1 != key3  # Different inputs produce different key
        assert len(key1) == 32  # MD5 hex digest length

    def test_get_set(self, cache):
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        assert cache.get("nonexistent") is None

    def test_ttl_expiration(self, cache):
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

        time.sleep(2.5)  # Wait for TTL to expire
        assert cache.get("key1") is None

    def test_clear(self, cache):
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        assert cache.get("key1") == "value1"
        assert cache.get("key2") == "value2"

        cache.clear()

        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_get_or_fetch(self, cache):
        fetch_count = 0

        def fetch_func(value):
            nonlocal fetch_count
            fetch_count += 1
            return f"fetched_{value}"

        # First call should fetch
        result1 = cache.get_or_fetch("key1", fetch_func, "test")
        assert result1 == "fetched_test"
        assert fetch_count == 1

        # Second call should return cached value
        result2 = cache.get_or_fetch("key1", fetch_func, "test")
        assert result2 == "fetched_test"
        assert fetch_count == 1  # Not incremented

    def test_cache_osv_query(self, cache):
        key1 = cache.cache_osv_query("numpy", "1.19.0", "PyPI")
        key2 = cache.cache_osv_query("numpy", "1.19.0", "PyPI")
        key3 = cache.cache_osv_query("flask", "2.0.0", "PyPI")

        assert key1 == key2
        assert key1 != key3

    def test_cache_nvd_cve(self, cache):
        key1 = cache.cache_nvd_cve("CVE-2023-12345")
        key2 = cache.cache_nvd_cve("CVE-2023-12345")
        key3 = cache.cache_nvd_cve("CVE-2023-67890")

        assert key1 == key2
        assert key1 != key3

    def test_cache_batch_scan(self, cache):
        key1 = cache.cache_batch_scan("/path/to/file", "hash123")
        key2 = cache.cache_batch_scan("/path/to/file", "hash123")
        key3 = cache.cache_batch_scan("/path/to/file", "hash456")

        assert key1 == key2
        assert key1 != key3

    def test_thread_safety(self, cache):
        import threading

        results = []

        def worker(i):
            cache.set(f"key{i}", f"value{i}")
            time.sleep(0.01)
            value = cache.get(f"key{i}")
            results.append(value == f"value{i}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert all(results)


class TestCachedOSVClient:
    @pytest.fixture
    def mock_osv_client(self):
        client = Mock()
        client.query_package = Mock(return_value=["vuln1", "vuln2"])
        client.get_vulnerability_by_id = Mock(return_value="vuln_detail")
        client.other_method = Mock(return_value="other_result")
        return client

    @pytest.fixture
    def cached_client(self, mock_osv_client):
        cache = VulnerabilityCache()
        return CachedOSVClient(mock_osv_client, cache)

    def test_query_package_cached(self, cached_client, mock_osv_client):
        # First call
        result1 = cached_client.query_package("numpy", "1.19.0")
        assert result1 == ["vuln1", "vuln2"]
        assert mock_osv_client.query_package.call_count == 1

        # Second call should use cache
        result2 = cached_client.query_package("numpy", "1.19.0")
        assert result2 == ["vuln1", "vuln2"]
        assert mock_osv_client.query_package.call_count == 1  # Not incremented

        # Different parameters should trigger new call
        _ = cached_client.query_package("flask", "2.0.0")
        assert mock_osv_client.query_package.call_count == 2

    def test_get_vulnerability_by_id_cached(self, cached_client, mock_osv_client):
        # First call
        result1 = cached_client.get_vulnerability_by_id("GHSA-123")
        assert result1 == "vuln_detail"
        assert mock_osv_client.get_vulnerability_by_id.call_count == 1

        # Second call should use cache
        result2 = cached_client.get_vulnerability_by_id("GHSA-123")
        assert result2 == "vuln_detail"
        assert mock_osv_client.get_vulnerability_by_id.call_count == 1

    def test_getattr_forwarding(self, cached_client, mock_osv_client):
        # Methods not explicitly cached should be forwarded
        result = cached_client.other_method("arg1", "arg2")
        assert result == "other_result"
        mock_osv_client.other_method.assert_called_once_with("arg1", "arg2")


class TestCachedNVDClient:
    @pytest.fixture
    def mock_nvd_client(self):
        client = Mock()
        client.get_cve = Mock(return_value="cve_detail")
        client.get_cve_metrics = Mock(return_value={"score": 7.5})
        client.search_cves = Mock(return_value=["cve1", "cve2"])
        return client

    @pytest.fixture
    def cached_client(self, mock_nvd_client):
        cache = VulnerabilityCache()
        return CachedNVDClient(mock_nvd_client, cache)

    def test_get_cve_cached(self, cached_client, mock_nvd_client):
        # First call
        result1 = cached_client.get_cve("CVE-2023-12345")
        assert result1 == "cve_detail"
        assert mock_nvd_client.get_cve.call_count == 1

        # Second call should use cache
        result2 = cached_client.get_cve("CVE-2023-12345")
        assert result2 == "cve_detail"
        assert mock_nvd_client.get_cve.call_count == 1  # Not incremented

        # Different CVE should trigger new call
        _ = cached_client.get_cve("CVE-2023-67890")
        assert mock_nvd_client.get_cve.call_count == 2

    def test_get_cve_metrics_cached(self, cached_client, mock_nvd_client):
        # First call
        result1 = cached_client.get_cve_metrics("CVE-2023-12345")
        assert result1 == {"score": 7.5}
        assert mock_nvd_client.get_cve_metrics.call_count == 1

        # Second call should use cache
        result2 = cached_client.get_cve_metrics("CVE-2023-12345")
        assert result2 == {"score": 7.5}
        assert mock_nvd_client.get_cve_metrics.call_count == 1

    def test_getattr_forwarding(self, cached_client, mock_nvd_client):
        # Methods not explicitly cached should be forwarded
        result = cached_client.search_cves(keyword="test")
        assert result == ["cve1", "cve2"]
        mock_nvd_client.search_cves.assert_called_once_with(keyword="test")
