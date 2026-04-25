"""
Software Provenance Tracker — Typosquat API Router

Exposes REST endpoints for typosquatting detection:
  - POST /check        — check a list of packages for typosquatting
  - POST /check/single — check a single package name
  - POST /cache/refresh — force-refresh the top package cache
  - GET  /cache/info   — cache status for both ecosystems
"""

import logging

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

from typosquat.typosquat_detector import TyposquatDetector
from db.redis_conn import RedisManager
from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.typosquat")

router = APIRouter(
    prefix="/api/typosquat",
    tags=["typosquat"],
    dependencies=[Depends(verify_api_key)],
)

# ─── Engine Instance ──────────────────────────────────────────

_detector: TyposquatDetector | None = None


def setup_typosquat_engine(redis: RedisManager) -> None:
    """Initialize the typosquat detector. Called during app startup."""
    global _detector
    _detector = TyposquatDetector(redis=redis)
    logger.info("Typosquat engine initialized")


async def cleanup_typosquat_engine() -> None:
    """Close the typosquat detector. Called during app shutdown."""
    global _detector
    if _detector:
        await _detector.close()
        _detector = None
    logger.info("Typosquat engine closed")


def _get_detector() -> TyposquatDetector:
    """Get the detector instance, raising if not initialized."""
    if _detector is None:
        raise HTTPException(
            status_code=503,
            detail="Typosquat engine not initialized",
        )
    return _detector


def get_typosquat_detector() -> TyposquatDetector | None:
    """Return the shared TyposquatDetector instance (or None if not yet initialized)."""
    return _detector


# ─── Request / Response Models ────────────────────────────────

class PackageEntry(BaseModel):
    """A single package to check."""
    name: str = Field(..., description="Package name")
    version: str = Field(default="", description="Package version (optional)")


class BatchCheckRequest(BaseModel):
    """Request body for batch typosquat checking."""
    packages: list[PackageEntry] = Field(
        ...,
        description="List of packages to check",
        min_length=1,
    )
    ecosystem: str = Field(
        default="pypi",
        description="Package ecosystem: 'pypi' or 'npm'",
    )


class SingleCheckRequest(BaseModel):
    """Request body for checking a single package name."""
    package_name: str = Field(..., description="Package name to check")
    ecosystem: str = Field(
        default="pypi",
        description="Package ecosystem: 'pypi' or 'npm'",
    )


# ─── Endpoints ────────────────────────────────────────────────

@router.post("/check")
async def check_packages(request: BatchCheckRequest):
    """
    Check a batch of packages for potential typosquatting.

    Compares each package name against the top 5000 PyPI or
    top 1000 npm packages using Levenshtein distance.

    - Distance 1 → severity: critical
    - Distance 2 → severity: high
    - Exact match → safe (not flagged)

    Top package lists are cached in Redis with a 24-hour TTL.
    """
    detector = _get_detector()

    if request.ecosystem not in ("pypi", "npm"):
        raise HTTPException(
            status_code=400,
            detail="Ecosystem must be 'pypi' or 'npm'",
        )

    try:
        packages = [
            {"name": p.name, "version": p.version}
            for p in request.packages
        ]

        result = await detector.check_packages(
            packages=packages,
            ecosystem=request.ecosystem,
        )
        return result

    except Exception as e:
        logger.error(f"Typosquat batch check failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Typosquat check failed: {str(e)}",
        )


@router.post("/check/single")
async def check_single_package(request: SingleCheckRequest):
    """
    Check a single package name for potential typosquatting.

    Returns whether the name is suspiciously close to a
    top package, with match details and severity.
    """
    detector = _get_detector()

    if request.ecosystem not in ("pypi", "npm"):
        raise HTTPException(
            status_code=400,
            detail="Ecosystem must be 'pypi' or 'npm'",
        )

    try:
        result = await detector.check_single(
            package_name=request.package_name,
            ecosystem=request.ecosystem,
        )
        return result

    except Exception as e:
        logger.error(
            f"Typosquat check failed for {request.package_name}: {e}"
        )
        raise HTTPException(
            status_code=500,
            detail=f"Typosquat check failed: {str(e)}",
        )


@router.post("/cache/refresh")
async def refresh_cache(
    ecosystem: str = Query(
        default="pypi",
        description="Ecosystem to refresh: 'pypi' or 'npm'",
    ),
):
    """
    Force-refresh the top package cache for an ecosystem.

    Deletes the existing Redis cache entry and re-fetches
    the full list from the upstream source.
    """
    detector = _get_detector()

    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(
            status_code=400,
            detail="Ecosystem must be 'pypi' or 'npm'",
        )

    try:
        count = await detector.refresh_cache(ecosystem)
        return {
            "ecosystem": ecosystem,
            "packages_loaded": count,
            "message": f"Cache refreshed with {count} top {ecosystem} packages",
        }

    except Exception as e:
        logger.error(f"Cache refresh failed for {ecosystem}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Cache refresh failed: {str(e)}",
        )


@router.get("/cache/info")
async def cache_info():
    """
    Get the current cache status for both PyPI and npm
    top-package lists. Shows whether each list is cached
    and how many entries it contains.
    """
    detector = _get_detector()

    try:
        return await detector.get_cache_info()

    except Exception as e:
        logger.error(f"Cache info retrieval failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Cache info retrieval failed: {str(e)}",
        )
