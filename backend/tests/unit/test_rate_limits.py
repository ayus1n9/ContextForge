"""Unit Tests for Rate Limiting Layer."""

import pytest
from backend.app.security.rate_limits import SlidingWindowRateLimiter


def test_normal_requests_allowed():
    limiter = SlidingWindowRateLimiter(requests_per_minute=10, burst_limit=5)
    allowed, headers = limiter.is_allowed("client-1")
    assert allowed is True
    assert headers["X-RateLimit-Limit"] == "10"
    assert headers["X-RateLimit-Remaining"] == "10"


def test_burst_limit_triggers():
    limiter = SlidingWindowRateLimiter(requests_per_minute=100, burst_limit=3)
    client = "client-burst"
    # Send 3 requests
    for _ in range(3):
        allowed, _ = limiter.is_allowed(client)
        assert allowed is True

    # 4th request in same 5-second burst window should be denied
    allowed, _ = limiter.is_allowed(client)
    assert allowed is False


def test_window_limit_triggers():
    limiter = SlidingWindowRateLimiter(requests_per_minute=3, burst_limit=10)
    client = "client-window"
    for _ in range(3):
        allowed, _ = limiter.is_allowed(client)
        assert allowed is True

    # 4th request exceeds requests_per_minute
    allowed, _ = limiter.is_allowed(client)
    assert allowed is False
