"""Rate Limiting Security Layer.

Implements an in-memory sliding window rate limiter per client IP.
Prevents resource exhaustion, credential brute-forcing, and denial-of-service.
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple

from backend.app.config import settings


class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, requests_per_minute: int = 60, burst_limit: int = 15):
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit
        self.window_seconds = 60
        self._history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> Tuple[bool, Dict[str, int]]:
        """Check if request from client_id is allowed.

        Returns (is_allowed, rate_limit_headers).
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old timestamps
        timestamps = self._history[client_id]
        timestamps = [ts for ts in timestamps if ts > window_start]
        self._history[client_id] = timestamps

        remaining = max(0, self.requests_per_minute - len(timestamps))
        headers = {
            "X-RateLimit-Limit": str(self.requests_per_minute),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(window_start + self.window_seconds)),
        }

        if len(timestamps) >= self.requests_per_minute:
            return False, headers

        # Check burst within last 5 seconds
        burst_start = now - 5.0
        burst_count = sum(1 for ts in timestamps if ts > burst_start)
        if burst_count >= self.burst_limit:
            return False, headers

        # Record this request
        self._history[client_id].append(now)
        return True, headers

    def reset(self) -> None:
        """Clear rate limit history (for testing)."""
        self._history.clear()


# Default singleton instance
rate_limiter = SlidingWindowRateLimiter(
    requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
    burst_limit=settings.RATE_LIMIT_BURST,
)
