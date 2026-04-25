"""
Software Provenance Tracker — API Key Authentication

Provides API key verification via the X-API-Key header.
Keys are stored in a Redis set for fast lookups.
On startup, a default key from .env is seeded into Redis.
"""

import logging
import os
import uuid
import hashlib

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from db.redis_conn import RedisManager

logger = logging.getLogger("provenance.auth")

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

REDIS_KEY_SET = "api_keys"
DEFAULT_KEY_ENV = "DEFAULT_API_KEY"
DEFAULT_KEY_FALLBACK = "sdpt-dev-key-2024"

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Module-level reference, set by setup_auth()
_redis: RedisManager | None = None


async def setup_auth(redis: RedisManager) -> None:
    """
    Seed the default API key into Redis on startup.
    Called from main.py lifespan.
    """
    global _redis
    _redis = redis

    default_key = os.getenv(DEFAULT_KEY_ENV, DEFAULT_KEY_FALLBACK)

    if default_key == "sdpt-dev-key-2024":
        logger.warning(
            "DEFAULT_API_KEY is set to the insecure default value. "
            "Change it in .env before deploying to production."
        )

    if not redis._client:
        raise RuntimeError("Redis not connected. Cannot set up auth.")

    exists = await redis._client.sismember(REDIS_KEY_SET, _hash_key(default_key))
    if not exists:
        await redis._client.sadd(REDIS_KEY_SET, _hash_key(default_key))
        logger.info("Default API key seeded into Redis")
    else:
        logger.info("Default API key already present in Redis")


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    FastAPI dependency that validates the X-API-Key header
    against the Redis set of valid keys.
    Raises 401 if missing or invalid.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide it via the X-API-Key header.",
        )

    if not _redis or not _redis._client:
        raise HTTPException(
            status_code=503,
            detail="Auth service unavailable. Server may still be starting.",
        )

    key_hash = _hash_key(api_key)
    is_valid = await _redis._client.sismember(REDIS_KEY_SET, key_hash)
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
        )

    return api_key


async def create_api_key(redis: RedisManager) -> str:
    """
    Generate a new UUID4 API key, store it in Redis, and return it.
    """
    if not redis._client:
        raise RuntimeError("Redis not connected.")

    new_key = f"sdpt-{uuid.uuid4().hex}"
    await redis._client.sadd(REDIS_KEY_SET, _hash_key(new_key))
    logger.info(f"New API key created: {new_key[:12]}...")
    return new_key


async def revoke_api_key(redis: RedisManager, key: str) -> bool:
    """
    Remove an API key from Redis. Returns True if the key existed.
    """
    if not redis._client:
        raise RuntimeError("Redis not connected.")

    removed = await redis._client.srem(REDIS_KEY_SET, _hash_key(key))
    if removed:
        logger.info(f"API key revoked: {key[:12]}...")
    return bool(removed)


async def list_api_keys(redis: RedisManager) -> list[str]:
    """
    List all active API keys from Redis (masked for security).
    Returns keys with only the first 12 and last 4 characters visible.
    """
    if not redis._client:
        raise RuntimeError("Redis not connected.")

    keys = await redis._client.smembers(REDIS_KEY_SET)
    members = [k.decode('utf-8') if isinstance(k, bytes) else str(k) for k in keys]
    return [h[:16] + "..." for h in members]
