"""
Software Provenance Tracker — Redis Connection Manager

Manages the Redis cache layer used to store API responses
and reduce redundant calls to GitHub, PyPI, and npm registries.

Cache usage:
  - GitHub API responses (commit history, contributor data)
  - PyPI package metadata (dependency info, versions)
  - npm registry metadata (dependency info, versions)
  - Rate limit counters for GitHub API (5000 req/hr)
"""

import json
import logging
from typing import Any

import redis.asyncio as aioredis

logger = logging.getLogger("provenance.db.redis")


class RedisManager:
    """
    Async Redis connection manager with structured caching
    for API responses. Handles serialization, TTL management,
    and key namespacing automatically.
    """

    # Key prefixes for organized namespacing
    PREFIX_PYPI = "pypi"
    PREFIX_NPM = "npm"
    PREFIX_GITHUB = "github"
    PREFIX_RATE_LIMIT = "ratelimit"

    def __init__(self):
        self._client: aioredis.Redis | None = None

    async def connect(self, url: str) -> None:
        """Create the async Redis connection and verify it works."""
        self._client = aioredis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
        # Verify connection immediately
        await self._client.ping()
        logger.info("Redis connected and verified")

    async def disconnect(self) -> None:
        """Close the Redis connection."""
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")

    async def health_check(self) -> None:
        """Verify Redis is reachable."""
        if not self._client:
            raise RuntimeError("Redis client not initialized")
        await self._client.ping()

    # ─── Generic Cache Operations ─────────────────────────────

    async def get_raw(self, key: str) -> str | None:
        """Get a raw string value without automatic deserialization."""
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")
        val = await self._client.get(key)
        return val if val else None

    async def set_raw(self, key: str, value: str, ttl_seconds: int = 3600) -> None:
        """Set a raw string value without automatic serialization."""
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")
        await self._client.setex(key, ttl_seconds, value)

    async def get_cached(self, prefix: str, key: str) -> dict | list | None:
        """
        Retrieve a cached value by prefix and key.
        Returns None if the key doesn't exist or has expired.
        """
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")

        full_key = f"{prefix}:{key}"
        raw = await self._client.get(full_key)
        if raw is None:
            return None

        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning(f"Failed to deserialize cached value for {full_key}")
            await self._client.delete(full_key)
            return None

    async def set_cached(self, prefix: str, key: str, value: Any,
                         ttl_seconds: int = 3600) -> None:
        """
        Cache a value with a TTL. Value is JSON-serialized.
        """
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")

        full_key = f"{prefix}:{key}"
        serialized = json.dumps(value, default=str)
        await self._client.set(full_key, serialized, ex=ttl_seconds)

    async def delete_cached(self, prefix: str, key: str) -> None:
        """Delete a specific cached entry."""
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")

        full_key = f"{prefix}:{key}"
        await self._client.delete(full_key)

    async def clear_prefix(self, prefix: str) -> int:
        """
        Delete all cached entries under a specific prefix.
        Returns the number of keys deleted.
        Uses SCAN to avoid blocking Redis on large datasets.
        """
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")

        count = 0
        async for key in self._client.scan_iter(match=f"{prefix}:*", count=100):
            await self._client.delete(key)
            count += 1

        logger.info(f"Cleared {count} keys under prefix '{prefix}'")
        return count

    # ─── PyPI Cache Helpers ───────────────────────────────────

    async def get_pypi_package(self, package_name: str) -> dict | None:
        """Get cached PyPI package metadata."""
        return await self.get_cached(self.PREFIX_PYPI, package_name.lower())

    async def set_pypi_package(self, package_name: str, data: dict,
                                ttl_seconds: int = 3600) -> None:
        """Cache PyPI package metadata."""
        await self.set_cached(self.PREFIX_PYPI, package_name.lower(), data, ttl_seconds)

    # ─── npm Cache Helpers ────────────────────────────────────

    async def get_npm_package(self, package_name: str) -> dict | None:
        """Get cached npm package metadata."""
        return await self.get_cached(self.PREFIX_NPM, package_name.lower())

    async def set_npm_package(self, package_name: str, data: dict,
                               ttl_seconds: int = 3600) -> None:
        """Cache npm package metadata."""
        await self.set_cached(self.PREFIX_NPM, package_name.lower(), data, ttl_seconds)

    # ─── GitHub Cache Helpers ─────────────────────────────────

    async def get_github_data(self, key: str) -> dict | list | None:
        """Get cached GitHub API response."""
        return await self.get_cached(self.PREFIX_GITHUB, key)

    async def set_github_data(self, key: str, data: Any,
                               ttl_seconds: int = 1800) -> None:
        """Cache GitHub API response (default 30min TTL)."""
        await self.set_cached(self.PREFIX_GITHUB, key, data, ttl_seconds)

    # ─── Rate Limit Tracking ─────────────────────────────────

    async def get_rate_limit_remaining(self, api: str = "github") -> int:
        """
        Get the remaining API call count for rate limit tracking.
        Returns -1 if no rate limit info is cached (treat as unknown).
        """
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")

        key = f"{self.PREFIX_RATE_LIMIT}:{api}:remaining"
        val = await self._client.get(key)
        return int(val) if val is not None else -1

    async def set_rate_limit_remaining(self, remaining: int,
                                        reset_timestamp: int,
                                        api: str = "github") -> None:
        """
        Store the remaining API call count and when it resets.
        TTL is set to the time until the rate limit resets.
        """
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")

        import time
        ttl = max(reset_timestamp - int(time.time()), 60)

        key_remaining = f"{self.PREFIX_RATE_LIMIT}:{api}:remaining"
        key_reset = f"{self.PREFIX_RATE_LIMIT}:{api}:reset"

        await self._client.set(key_remaining, str(remaining), ex=ttl)
        await self._client.set(key_reset, str(reset_timestamp), ex=ttl)

    # ─── Cache Stats ──────────────────────────────────────────

    async def get_cache_stats(self) -> dict:
        """Get cache statistics for monitoring/dashboard."""
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")

        info = await self._client.info("memory")
        db_size = await self._client.dbsize()

        # Count keys per prefix
        prefix_counts = {}
        for prefix in [self.PREFIX_PYPI, self.PREFIX_NPM,
                       self.PREFIX_GITHUB, self.PREFIX_RATE_LIMIT]:
            count = 0
            async for _ in self._client.scan_iter(match=f"{prefix}:*", count=100):
                count += 1
            prefix_counts[prefix] = count

        return {
            "total_keys": db_size,
            "memory_used_mb": round(info.get("used_memory", 0) / (1024 * 1024), 2),
            "memory_max_mb": round(info.get("maxmemory", 0) / (1024 * 1024), 2),
            "keys_by_prefix": prefix_counts,
        }
