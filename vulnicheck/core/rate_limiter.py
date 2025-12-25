"""
Rate limiting utilities for API calls.

Uses collections.deque for O(1) operations instead of list filtering
which is O(n) per call and creates copies.
"""

import time
from collections import deque
from threading import Lock


class RateLimiter:
    """Thread-safe rate limiter for API calls.

    Uses a deque for O(1) append/popleft operations instead of O(n)
    list filtering. Timestamps are stored in order, allowing efficient
    cleanup from the left side.
    """

    def __init__(self, calls: int, period: float):
        """Initialize rate limiter.

        Args:
            calls: Number of calls allowed in the period
            period: Time period in seconds
        """
        self.calls = calls
        self.period = period
        self._timestamps: deque[float] = deque(maxlen=calls * 2)  # Extra capacity for efficiency
        self._lock = Lock()

    def wait_if_needed(self) -> None:
        """Wait if necessary to respect rate limit.

        This method is thread-safe and uses O(1) deque operations
        instead of O(n) list filtering.
        """
        with self._lock:
            now = time.time()
            cutoff = now - self.period

            # Remove expired timestamps from the left (O(1) per removal)
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()

            # If we're at the limit, wait until the oldest timestamp expires
            if len(self._timestamps) >= self.calls:
                oldest = self._timestamps[0]
                wait_time = self.period - (now - oldest) + 0.1  # Add small buffer
                if wait_time > 0:
                    time.sleep(wait_time)
                    now = time.time()
                    cutoff = now - self.period
                    # Clean up again after waiting
                    while self._timestamps and self._timestamps[0] < cutoff:
                        self._timestamps.popleft()

            # Record this call (O(1) append)
            self._timestamps.append(now)

    @property
    def timestamps(self) -> list[float]:
        """Get current timestamps as a list (for backwards compatibility)."""
        with self._lock:
            return list(self._timestamps)


class APIRateLimiters:
    """Manage rate limiters for different APIs."""

    def __init__(self) -> None:
        self.limiters: dict[str, RateLimiter] = {}
        self.lock = Lock()

    def get_limiter(self, api_name: str, calls: int, period: float) -> RateLimiter:
        """Get or create a rate limiter for an API."""
        with self.lock:
            if api_name not in self.limiters:
                self.limiters[api_name] = RateLimiter(calls, period)
            return self.limiters[api_name]


# Global rate limiters instance
rate_limiters = APIRateLimiters()


def get_nvd_rate_limiter(has_api_key: bool) -> RateLimiter:
    """Get the appropriate NVD rate limiter."""
    if has_api_key:
        # With API key: 50 requests per 30 seconds
        return rate_limiters.get_limiter("nvd_with_key", 50, 30.0)
    else:
        # Without API key: 5 requests per 30 seconds
        return rate_limiters.get_limiter("nvd_no_key", 5, 30.0)
