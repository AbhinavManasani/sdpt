"""
Software Provenance Tracker — Diff API Router

Exposes REST endpoints for multi-version diff analysis:
  - GET /api/diff/{ecosystem}/{package_name}/{version_from}/{version_to}
      Full diff report between two package versions
  - GET /api/diff/history/{ecosystem}/{package_name}
      Last 20 diff results for a package
  - GET /api/diff/stats
      Aggregate diff statistics
"""

import logging

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, func, desc

from db.postgres import PostgresManager, DiffResult
from db.redis_conn import RedisManager
from diff.version_differ import VersionDiffer

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.diff")

router = APIRouter(
    prefix="/api/diff",
    tags=["diff"],
    dependencies=[Depends(verify_api_key)],
)

_VALID_ECOSYSTEMS = {"pypi", "npm"}


# ─── Engine Lifecycle ─────────────────────────────────────────

_differ: VersionDiffer | None = None


def setup_diff_engine(redis: RedisManager, postgres: PostgresManager) -> None:
    """Initialize the VersionDiffer. Called during app startup."""
    global _differ
    _differ = VersionDiffer(redis=redis, postgres=postgres)
    logger.info("Diff router engine initialized")


async def cleanup_diff_engine() -> None:
    """Clean up the VersionDiffer. Called during app shutdown."""
    global _differ
    if _differ:
        await _differ.close()
    _differ = None


def get_differ() -> VersionDiffer | None:
    """
    Get the VersionDiffer singleton.
    Returns None if not yet initialized — callers must check.
    """
    return _differ


def _require_differ() -> VersionDiffer:
    """Internal helper that raises 503 if the differ is not ready."""
    differ = get_differ()
    if differ is None:
        raise HTTPException(
            status_code=503,
            detail="Diff engine not initialized. Server may still be starting up.",
        )
    return differ


def _validate_ecosystem(ecosystem: str) -> str:
    """Validate and normalise the ecosystem parameter."""
    eco = ecosystem.lower().strip()
    if eco not in _VALID_ECOSYSTEMS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported ecosystem '{ecosystem}'. Must be one of: {', '.join(sorted(_VALID_ECOSYSTEMS))}",
        )
    return eco


# ─── Endpoints ────────────────────────────────────────────────


@router.get("/stats")
async def diff_stats():
    """
    Aggregate diff statistics across all packages.

    Returns:
      - total_diffs
      - high_risk_diffs (risk_score >= 50)
      - packages_with_maintainer_changes
      - packages_with_new_scripts
    """
    differ = _require_differ()

    try:
        async with differ._postgres.get_session() as session:
            # Total diffs
            total_result = await session.execute(
                select(func.count(DiffResult.id))
            )
            total_diffs = total_result.scalar() or 0

            # High-risk diffs (risk_score >= 50)
            high_risk_result = await session.execute(
                select(func.count(DiffResult.id))
                .where(DiffResult.risk_score >= 50.0)
            )
            high_risk_diffs = high_risk_result.scalar() or 0

            # Distinct packages with maintainer changes
            maintainer_result = await session.execute(
                select(func.count(func.distinct(DiffResult.package_name)))
                .where(DiffResult.maintainer_changed == True)
            )
            packages_with_maintainer_changes = maintainer_result.scalar() or 0

            # Distinct packages with install scripts added
            scripts_result = await session.execute(
                select(func.count(func.distinct(DiffResult.package_name)))
                .where(DiffResult.install_scripts_added == True)
            )
            packages_with_new_scripts = scripts_result.scalar() or 0

        return {
            "total_diffs": total_diffs,
            "high_risk_diffs": high_risk_diffs,
            "packages_with_maintainer_changes": packages_with_maintainer_changes,
            "packages_with_new_scripts": packages_with_new_scripts,
        }

    except Exception as exc:
        logger.error(f"Diff stats query failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/history/{ecosystem}/{package_name:path}")
async def diff_history(ecosystem: str, package_name: str):
    """
    Return the last 20 diff results for a given package.

    Path parameters:
      - ecosystem: "pypi" or "npm"
      - package_name: the package name (supports scoped npm names)
    """
    eco = _validate_ecosystem(ecosystem)
    differ = _require_differ()

    try:
        async with differ._postgres.get_session() as session:
            result = await session.execute(
                select(DiffResult)
                .where(
                    DiffResult.package_name == package_name,
                    DiffResult.ecosystem == eco,
                )
                .order_by(desc(DiffResult.created_at))
                .limit(20)
            )
            rows = result.scalars().all()

        if not rows:
            raise HTTPException(
                status_code=404,
                detail=f"No diff history found for {eco}/{package_name}",
            )

        return {
            "package_name": package_name,
            "ecosystem": eco,
            "count": len(rows),
            "history": [
                {
                    "id": r.id,
                    "version_from": r.version_from,
                    "version_to": r.version_to,
                    "risk_score": r.risk_score,
                    "version_jump": r.version_jump,
                    "install_scripts_added": r.install_scripts_added,
                    "binary_files_added": r.binary_files_added,
                    "maintainer_changed": r.maintainer_changed,
                    "dependency_count_delta": r.dependency_count_delta,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ],
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Diff history query failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{ecosystem}/{package_name:path}/{version_from}/{version_to}")
async def compare_versions(
    ecosystem: str,
    package_name: str,
    version_from: str,
    version_to: str,
):
    """
    Compare two versions of a package and return a full diff report.

    Path parameters:
      - ecosystem: "pypi" or "npm"
      - package_name: the package name (supports scoped npm names)
      - version_from: the older version (e.g. "2.28.0")
      - version_to: the newer version (e.g. "2.31.0")

    Checks Redis cache first (24h TTL), otherwise fetches from
    the registry, computes the diff, persists, and caches.
    """
    eco = _validate_ecosystem(ecosystem)
    differ = _require_differ()

    try:
        report = await differ.diff(
            package_name=package_name,
            ecosystem=eco,
            version_from=version_from,
            version_to=version_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error(f"Diff comparison failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    return report
