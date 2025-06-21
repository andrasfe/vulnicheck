"""
Rate limiting utilities for API calls.
"""

import time
from threading import Lock
from typing import Dict


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, calls: int, period: float):
        """
        Initialize rate limiter.

        Args:
            calls: Number of calls allowed
            period: Time period in seconds
        """
        self.calls = calls
        self.period = period
        self.timestamps: list[float] = []
        self.lock = Lock()

    def wait_if_needed(self) -> None:
        """Wait if necessary to respect rate limit."""
        with self.lock:
            now = time.time()

            # Remove timestamps older than the period
            self.timestamps = [ts for ts in self.timestamps if now - ts < self.period]

            # If we're at the limit, wait until the oldest timestamp expires
            if len(self.timestamps) >= self.calls:
                oldest = self.timestamps[0]
                wait_time = self.period - (now - oldest) + 0.1  # Add small buffer
                if wait_time > 0:
                    time.sleep(wait_time)
                    now = time.time()
                    self.timestamps = [
                        ts for ts in self.timestamps if now - ts < self.period
                    ]

            # Record this call
            self.timestamps.append(now)


class APIRateLimiters:
    """Manage rate limiters for different APIs."""

    def __init__(self) -> None:
        self.limiters: Dict[str, RateLimiter] = {}
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
