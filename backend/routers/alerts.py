"""
Software Provenance Tracker — Alerts API Router

Exposes REST endpoints for the alert system:
  - Generate alerts from anomaly scores
  - Generate alerts from contributor analysis
  - Get / list / filter alerts
  - Update alert status
  - Bulk status updates
  - Dashboard statistics
"""

import logging

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from db.postgres import PostgresManager
from alerts.alert_manager import AlertManager

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.alerts")

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(verify_api_key)])


# ─── Request Models ───────────────────────────────────────────

class GenerateFromAnomalyRequest(BaseModel):
    """Generate alerts from an anomaly detection result."""
    anomaly_result: dict = Field(..., description="Full result from /api/anomaly/score")
    package_name: str = Field(..., min_length=1, max_length=255)
    package_version: str | None = Field(default=None, max_length=100)
    contributor_username: str | None = Field(default=None, max_length=255)


class GenerateFromContributorRequest(BaseModel):
    """Generate alerts from a contributor analysis result."""
    analysis_result: dict = Field(..., description="Full result from /api/contributors/analyze")
    package_name: str | None = Field(default=None, max_length=255)


class UpdateStatusRequest(BaseModel):
    """Update the status of an alert."""
    status: str = Field(
        ...,
        description="New status: open, investigating, resolved, dismissed",
    )


class BulkUpdateRequest(BaseModel):
    """Bulk update status for multiple alerts."""
    alert_ids: list[int] = Field(..., min_length=1, description="List of alert IDs")
    status: str = Field(
        ...,
        description="New status: open, investigating, resolved, dismissed",
    )


# ─── Manager Instance ────────────────────────────────────────

_manager: AlertManager | None = None


def setup_alerts_engine(postgres: PostgresManager) -> None:
    """Initialize the AlertManager. Called during app startup."""
    global _manager
    _manager = AlertManager(postgres=postgres)
    logger.info("Alerts router engine initialized")


def cleanup_alerts_engine() -> None:
    """Clean up the AlertManager. Called during app shutdown."""
    global _manager
    _manager = None


def _get_manager() -> AlertManager:
    """Get the manager instance, raising if not initialized."""
    if _manager is None:
        raise HTTPException(
            status_code=503,
            detail="Alert manager not initialized. Server may still be starting up.",
        )
    return _manager


# ─── Endpoints ────────────────────────────────────────────────


@router.post("/generate/anomaly")
async def generate_from_anomaly(request: GenerateFromAnomalyRequest):
    """
    Generate alerts from an anomaly detection result.

    Pass the full result from POST /api/anomaly/score along
    with the package name. Creates one alert per triggered rule.
    """
    manager = _get_manager()

    try:
        alerts = await manager.generate_from_anomaly(
            anomaly_result=request.anomaly_result,
            package_name=request.package_name,
            package_version=request.package_version,
            contributor_username=request.contributor_username,
        )
    except Exception as e:
        logger.error(f"Alert generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "generated_count": len(alerts),
        "alerts": alerts,
    }


@router.post("/generate/contributor")
async def generate_from_contributor(request: GenerateFromContributorRequest):
    """
    Generate alerts from a contributor analysis result.

    Pass the full result from POST /api/contributors/analyze.
    Creates one alert per deviation found.
    """
    manager = _get_manager()

    try:
        alerts = await manager.generate_from_contributor(
            analysis_result=request.analysis_result,
            package_name=request.package_name,
        )
    except Exception as e:
        logger.error(f"Contributor alert generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "generated_count": len(alerts),
        "alerts": alerts,
    }


@router.get("/")
async def list_alerts(
    status: str | None = Query(default=None, description="Filter: open, investigating, resolved, dismissed"),
    severity: str | None = Query(default=None, description="Filter: critical, high, medium, low"),
    package_name: str | None = Query(default=None, description="Filter by package name"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """
    List alerts with optional filtering and pagination.
    Returns total count + paginated results.
    """
    manager = _get_manager()

    result = await manager.get_alerts(
        status=status,
        severity=severity,
        package_name=package_name,
        limit=limit,
        offset=offset,
    )

    return result


@router.get("/stats")
async def get_alert_stats():
    """
    Get alert statistics for the dashboard.
    Totals by status, severity, type, plus recent alerts.
    """
    manager = _get_manager()

    try:
        stats = await manager.get_stats()
    except Exception as e:
        logger.error(f"Alert stats failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return stats


@router.get("/{alert_id}")
async def get_alert(alert_id: int):
    """Get a single alert by ID."""
    manager = _get_manager()

    alert = await manager.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    return alert


@router.patch("/{alert_id}/status")
async def update_alert_status(alert_id: int, request: UpdateStatusRequest):
    """
    Update alert status.
    Valid statuses: open, investigating, resolved, dismissed.
    """
    manager = _get_manager()

    valid = {"open", "investigating", "resolved", "dismissed"}
    if request.status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid))}",
        )

    try:
        alert = await manager.update_status(alert_id, request.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    return alert


@router.patch("/bulk/status")
async def bulk_update_status(request: BulkUpdateRequest):
    """
    Bulk update status for multiple alerts.
    Useful for dismissing or resolving groups of related alerts.
    """
    manager = _get_manager()

    valid = {"open", "investigating", "resolved", "dismissed"}
    if request.status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid))}",
        )

    try:
        count = await manager.bulk_update_status(request.alert_ids, request.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "updated_count": count,
        "new_status": request.status,
    }
