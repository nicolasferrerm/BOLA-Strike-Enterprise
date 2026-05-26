"""
BOLA Strike Enterprise — API Security Module (v7.0)
Implements API Key authentication and rate limiting for the backend API.
Addresses: F-001 (Hardcoded Secrets), F-002 (Missing Auth & Rate Limiting)
"""

import os
import time
import hmac
import logging
from collections import defaultdict
from fastapi import HTTPException, Security, Request
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

# --- API Key Authentication ---
# The API key is read from environment variables. In development, a default is provided.
# In production, BOLA_API_KEY MUST be set to a strong, unique value.
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Startup check: in production, fail hard if default key is used.
if os.environ.get("ENV", "development") != "development":
    if not os.environ.get("BOLA_API_KEY") or os.environ.get("BOLA_API_KEY") == "dev-only-change-me-in-production":
        raise RuntimeError("[CRITICAL] Default BOLA_API_KEY used in production! Refusing to start.")

def _get_api_key() -> str:
    """Retrieve the configured API key from environment."""
    key = os.environ.get("BOLA_API_KEY")
    if not key or key == "dev-only-change-me-in-production":
        return "dev-only-change-me-in-production"
    return key

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    """
    FastAPI dependency that validates the X-API-Key header.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header. Authentication required."
        )
    
    expected_key = _get_api_key()
    if not hmac.compare_digest(api_key.encode('utf-8', 'ignore'), expected_key.encode('utf-8', 'ignore')):
        logger.warning("[SecurityModule] Rejected invalid API key attempt.")
        raise HTTPException(
            status_code=403,
            detail="Invalid API Key. Access denied."
        )
    return api_key


# --- In-Memory Rate Limiter (Sliding Window) ---
class RateLimiter:
    """
    Simple in-memory sliding window rate limiter.
    No external dependencies required. For distributed deployments, replace with Redis-based limiter.
    """
    def __init__(self, max_requests: int = 10, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
    
    def _cleanup(self, key: str):
        """Remove expired timestamps from the window."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
    
    def is_allowed(self, key: str) -> bool:
        """Check if a request from the given key is allowed."""
        self._cleanup(key)
        if len(self._requests[key]) >= self.max_requests:
            return False
        self._requests[key].append(time.time())
        return True
    
    def remaining(self, key: str) -> int:
        """Return the number of remaining requests in the current window."""
        self._cleanup(key)
        return max(0, self.max_requests - len(self._requests[key]))


# Global rate limiter instance: 10 scan starts per hour per IP
scan_rate_limiter = RateLimiter(max_requests=10, window_seconds=3600)


async def check_scan_rate_limit(request: Request):
    """
    FastAPI dependency that enforces rate limiting on scan endpoints.
    Uses client IP as the rate limit key.
    """
    client_ip = request.client.host if request.client else "unknown"
    
    if not scan_rate_limiter.is_allowed(client_ip):
        scan_rate_limiter.remaining(client_ip)
        logger.warning(f"[RateLimiter] Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {scan_rate_limiter.max_requests} scans per hour. Try again later.",
            headers={"Retry-After": str(scan_rate_limiter.window_seconds)}
        )
    return True
