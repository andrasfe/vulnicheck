# This file is kept for backwards compatibility with tests
# The actual caching is now done using functools.lru_cache in server.py

from typing import Any, Optional


class VulnerabilityCache:
    """Stub for backwards compatibility."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 900) -> None:
        pass

    def get(self, key: str) -> Optional[Any]:
        return None

    def set(self, key: str, value: Any) -> None:
        pass

    def clear(self) -> None:
        pass
