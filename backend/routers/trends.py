"""
Software Provenance Tracker — Trends API Router

Exposes REST endpoints for historical trending analysis:
  - POST /api/trends/record          — record a score snapshot
  - GET  /api/trends/timeline        — score history for one entity
  - GET  /api/trends/top-movers      — biggest score changes
  - GET  /api/trends/risk-breakdown  — entities per risk level
  - GET  /api/trends/stats           — aggregate dashboard stats
"""

import logging

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from db.postgres import PostgresManager
from trends.trend_analyzer import TrendAnalyzer

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.trends")

router = APIRouter(
    prefix="/api/trends",
    tags=["trends"],
    dependencies=[Depends(verify_api_key)],
)


# ─── Request Models ───────────────────────────────────────────

class RecordTrendRequest(BaseModel):
    """Record a score snapshot for an entity."""
    entity_type: str = Field(
        ...,
        description="'package' or 'contributor'",
        pattern="^(package|contributor)$",
    )
    entity_name: str = Field(..., min_length=1, max_length=255)
    ecosystem: str | None = Field(
        default=None,
        description="'pypi' or 'npm' (null for contributors)",
    )
    anomaly_score: float | None = Field(default=None, ge=0, le=100)
    trust_score: float | None = Field(default=None, ge=0, le=100)
    risk_level: str = Field(
        ...,
        description="'critical', 'high', 'medium', or 'low'",
        pattern="^(critical|high|medium|low)$",
    )
    triggered_rules: list[str] | None = Field(default=None)


# ─── Engine Lifecycle ─────────────────────────────────────────

_analyzer: TrendAnalyzer | None = None


def setup_trends_engine(postgres: PostgresManager) -> None:
    """Initialize the TrendAnalyzer. Called during app startup."""
    global _analyzer
    _analyzer = TrendAnalyzer(postgres=postgres)
    logger.info("Trends router engine initialized")


def cleanup_trends_engine() -> None:
    """Clean up the TrendAnalyzer. Called during app shutdown."""
    global _analyzer
    _analyzer = None


def get_trend_analyzer() -> TrendAnalyzer | None:
    """
    Get the TrendAnalyzer singleton.
    Returns None if not yet initialized — callers must check.
    """
    return _analyzer


def _require_analyzer() -> TrendAnalyzer:
    """Internal helper that raises 503 if the analyzer is not ready."""
    analyzer = get_trend_analyzer()
    if analyzer is None:
        raise HTTPException(
            status_code=503,
            detail="Trend analyzer not initialized. Server may still be starting up.",
        )
    return analyzer


# ─── Endpoints ────────────────────────────────────────────────


@router.post("/record")
async def record_trend(request: RecordTrendRequest):
    """
    Record a score snapshot for a package or contributor.

    Called automatically after anomaly scoring passes, or
    manually via API for ad-hoc recording.
    """
    analyzer = _require_analyzer()

    try:
        result = await analyzer.record(
            entity_type=request.entity_type,
            entity_name=request.entity_name,
            ecosystem=request.ecosystem,
            anomaly_score=request.anomaly_score,
            trust_score=request.trust_score,
            risk_level=request.risk_level,
            triggered_rules=request.triggered_rules,
        )
    except Exception as exc:
        logger.error(f"Failed to record trend: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    return result


@router.get("/timeline")
async def get_timeline(
    entity_type: str = Query(
        ...,
        description="'package' or 'contributor'",
        pattern="^(package|contributor)$",
    ),
    entity_name: str = Query(..., min_length=1, max_length=255),
    days: int = Query(default=90, ge=1, le=365),
    limit: int = Query(default=500, ge=1, le=2000),
):
    """
    Fetch the score timeline for a single entity.

    Returns data points sorted oldest → newest,
    ready for front-end charting.
    """
    analyzer = _require_analyzer()

    try:
        result = await analyzer.timeline(
            entity_type=entity_type,
            entity_name=entity_name,
            days=days,
            limit=limit,
        )
    except Exception as exc:
        logger.error(f"Timeline query failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    if not result.get("timeline"):
        raise HTTPException(
            status_code=404,
            detail=f"No trend data found for {entity_type}/{entity_name} "
                   f"in the last {days} days.",
        )

    return result


@router.get("/top-movers")
async def get_top_movers(
    entity_type: str = Query(
        default="package",
        description="'package' or 'contributor'",
        pattern="^(package|contributor)$",
    ),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=20, ge=1, le=100),
):
    """
    Find entities whose anomaly scores changed the most over
    the last N days.

    Returns sorted by absolute score delta descending.
    """
    analyzer = _require_analyzer()

    try:
        movers = await analyzer.top_movers(
            entity_type=entity_type,
            days=days,
            limit=limit,
        )
    except Exception as exc:
        logger.error(f"Top movers query failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "entity_type": entity_type,
        "window_days": days,
        "count": len(movers),
        "movers": movers,
    }


@router.get("/risk-breakdown")
async def get_risk_breakdown(
    entity_type: str = Query(
        default="package",
        description="'package' or 'contributor'",
        pattern="^(package|contributor)$",
    ),
    days: int = Query(default=7, ge=1, le=365),
):
    """
    Count distinct entities per risk level based on their
    most recent score within the given window.
    """
    analyzer = _require_analyzer()

    try:
        result = await analyzer.risk_breakdown(
            entity_type=entity_type,
            days=days,
        )
    except Exception as exc:
        logger.error(f"Risk breakdown query failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    return result


@router.get("/stats")
async def get_trend_stats(
    range: str = Query(default="30d", pattern="^(7d|30d|90d|all)$")
):
    """
    High-level trending statistics for the dashboard.

    Returns total snapshots, distinct packages/contributors,
    7-day average anomaly score, and high-risk event count.
    """
    analyzer = _require_analyzer()

    cutoff = None
    if range == "7d":
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(days=7)
    elif range == "30d":
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(days=30)
    elif range == "90d":
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(days=90)

    try:
        stats = await analyzer.stats(cutoff=cutoff)
    except Exception as exc:
        logger.error(f"Trend stats query failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    return stats
