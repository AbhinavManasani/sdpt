"""
Software Provenance Tracker — AI API Router

Exposes REST endpoints for AI-powered features:
  - POST /explain/{alert_id}  — explain a single alert
  - POST /explain/batch       — explain multiple alerts
  - DELETE /cache/{alert_id}  — clear cached explanation
  - DELETE /cache             — clear all cached explanations
"""

import logging

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from ai.explainer import AlertExplainer
from db.redis_conn import RedisManager
from db.postgres import PostgresManager, Alert
from auth.api_key import verify_api_key

from sqlalchemy import select

logger = logging.getLogger("provenance.routers.ai")

router = APIRouter(
    prefix="/api/ai",
    tags=["ai"],
    dependencies=[Depends(verify_api_key)],
)

# ─── Engine Instance ──────────────────────────────────────────

_explainer: AlertExplainer | None = None
_postgres: PostgresManager | None = None


def setup_ai_engine(redis: RedisManager, postgres: PostgresManager) -> None:
    """Initialize the AI explainer. Called during app startup."""
    global _explainer, _postgres
    _explainer = AlertExplainer(redis=redis)
    _postgres = postgres
    logger.info("AI engine initialized")


async def cleanup_ai_engine() -> None:
    """Close the AI explainer. Called during app shutdown."""
    global _explainer
    if _explainer:
        await _explainer.close()
        _explainer = None
    logger.info("AI engine closed")


def _get_explainer() -> AlertExplainer:
    """Get the explainer instance, raising if not initialized."""
    if _explainer is None:
        raise HTTPException(
            status_code=503,
            detail="AI engine not initialized",
        )
    return _explainer


# ─── Request Models ───────────────────────────────────────────

class PackageContext(BaseModel):
    """Optional additional context about a package."""
    ecosystem: str | None = Field(default=None)
    repo_url: str | None = Field(default=None)
    author: str | None = Field(default=None)
    license: str | None = Field(default=None)
    dependency_count: int | None = Field(default=None)


class ExplainRequest(BaseModel):
    """Request body for explaining a single alert with optional context."""
    package_context: PackageContext | None = Field(
        default=None,
        description="Optional additional context about the package",
    )


class BatchExplainRequest(BaseModel):
    """Request body for explaining multiple alerts."""
    alert_ids: list[int] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="Alert IDs to explain (max 10)",
    )


# ─── Helper ──────────────────────────────────────────────────

async def _load_alert(alert_id: int) -> dict:
    """Load an alert from PostgreSQL and return as dict."""
    if not _postgres:
        raise HTTPException(status_code=503, detail="Database not configured")

    async with _postgres.get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=404, detail=f"Alert #{alert_id} not found"
        )

    return {
        "id": alert.id,
        "severity": alert.severity,
        "alert_type": alert.alert_type,
        "package_name": alert.package_name,
        "package_version": alert.package_version,
        "contributor_username": alert.contributor_username,
        "title": alert.title,
        "description": alert.description,
        "baseline_summary": alert.baseline_summary,
        "evidence": alert.evidence,
        "status": alert.status,
    }


# ─── Endpoints ────────────────────────────────────────────────

@router.post("/explain/{alert_id}")
async def explain_alert(alert_id: int, request: ExplainRequest = None):
    """
    Generate a plain-English explanation of a security alert
    using Groq.

    The explanation covers:
      - What the threat is (in simple terms)
      - Why it matters (real-world impact)
      - What to do about it (concrete action items)

    Explanations are cached in Redis for 1 hour.
    """
    explainer = _get_explainer()

    # Load the alert from the database
    alert_data = await _load_alert(alert_id)

    # Build package context dict if provided
    pkg_context = None
    if request and request.package_context:
        pkg_context = request.package_context.model_dump(exclude_none=True)

    try:
        result = await explainer.explain_alert(
            alert=alert_data,
            package_context=pkg_context,
        )
        return result

    except Exception as e:
        logger.error(f"AI explain failed for alert {alert_id}: {e}")
        return {
            "explanation": "AI explanation temporarily unavailable. Please try again later.",
            "cached": False,
            "fallback": True,
        }


@router.post("/explain-batch")
async def explain_batch(request: BatchExplainRequest):
    """
    Generate explanations for multiple alerts.

    Processes sequentially to respect Groq rate limits.
    Maximum 10 alerts per request.
    """
    explainer = _get_explainer()

    # Load all alerts
    alerts = []
    for alert_id in request.alert_ids:
        alert_data = await _load_alert(alert_id)
        alerts.append(alert_data)

    try:
        results = await explainer.explain_batch(alerts)
        return {
            "total": len(results),
            "explanations": results,
        }

    except Exception as e:
        logger.error(f"AI batch explain failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"AI batch explanation failed: {str(e)}",
        )


@router.delete("/cache/{alert_id}")
async def clear_alert_cache(alert_id: int):
    """Clear the cached explanation for a specific alert."""
    explainer = _get_explainer()

    try:
        count = await explainer.clear_cache(alert_id=alert_id)
        return {
            "alert_id": alert_id,
            "cleared": count,
            "message": f"Cache cleared for alert {alert_id}",
        }

    except Exception as e:
        logger.error(f"Cache clear failed for alert {alert_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Cache clear failed: {str(e)}",
        )


@router.delete("/cache")
async def clear_all_cache():
    """Clear all cached AI explanations."""
    explainer = _get_explainer()

    try:
        count = await explainer.clear_cache()
        return {
            "cleared": count,
            "message": f"Cleared {count} cached explanation(s)",
        }

    except Exception as e:
        logger.error(f"Cache clear all failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Cache clear failed: {str(e)}",
        )
