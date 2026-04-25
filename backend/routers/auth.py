"""
Software Provenance Tracker — Auth API Router

Exposes REST endpoints for managing API keys:
  - POST /api/auth/keys — Generate a new API key
  - GET  /api/auth/keys — List all active keys (masked)
  - DELETE /api/auth/keys/{key} — Revoke a key (remove from Redis)
"""

import logging

from fastapi import APIRouter, HTTPException, Depends

from db.redis_conn import RedisManager
from auth.api_key import create_api_key, list_api_keys, revoke_api_key, verify_api_key

logger = logging.getLogger("provenance.routers.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Module-level reference to Redis, injected by setup_auth_router
_redis: RedisManager | None = None


def setup_auth_router(redis: RedisManager) -> None:
    """Initialize the auth router with the Redis instance. Called on startup."""
    global _redis
    _redis = redis
    logger.info("Auth router initialized with Redis")


def _get_redis() -> RedisManager:
    """Helper to ensure Redis is available or raise 503."""
    if _redis is None:
        raise HTTPException(
            status_code=503,
            detail="Auth service starting up or unavailable.",
        )
    return _redis


# ─── Endpoints ────────────────────────────────────────────────


@router.post("/keys", status_code=201, dependencies=[Depends(verify_api_key)])
async def generate_new_api_key():
    """Generate a new API key. Requires a valid existing key."""
    redis = _get_redis()
    new_key = await create_api_key(redis)
    return {"api_key": new_key, "message": "Store this key safely"}


@router.get("/keys")
async def list_active_keys():
    """List all active API keys (masked). No auth required."""
    redis = _get_redis()
    masked_list = await list_api_keys(redis)
    return {"keys": masked_list, "total": len(masked_list)}


@router.delete("/keys/{key}", dependencies=[Depends(verify_api_key)])
async def revoke_existing_key(key: str):
    """Revoke an API key. Requires a valid existing key."""
    redis = _get_redis()
    revoked = await revoke_api_key(redis, key)
    if not revoked:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"message": "Key revoked successfully"}
