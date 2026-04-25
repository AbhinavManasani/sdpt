"""
Software Provenance Tracker — Feed Monitor API Router

Exposes REST endpoints for the real-time PyPI feed monitor:
  - GET  /api/monitor/feed      — recent feed entries (scored)
  - GET  /api/monitor/status    — monitor running state
  - POST /api/monitor/start     — manually start the monitor
  - POST /api/monitor/stop      — manually stop the monitor

The monitor itself is started/stopped automatically via the
FastAPI lifespan, but the manual endpoints allow runtime control.
"""

import logging

from fastapi import APIRouter, HTTPException, Query, Depends

from db.redis_conn import RedisManager
from db.postgres import PostgresManager
from ml.anomaly_detector import AnomalyDetector
from monitor.feed_monitor import FeedMonitor

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.monitor")

router = APIRouter(
    prefix="/api/monitor",
    tags=["monitor"],
    dependencies=[Depends(verify_api_key)],
)


# ─── Engine Lifecycle ─────────────────────────────────────────

_monitor: FeedMonitor | None = None


def setup_monitor_engine(
    redis: RedisManager,
    postgres: PostgresManager,
    detector: AnomalyDetector,
) -> None:
    """Initialize the FeedMonitor. Called during app startup."""
    global _monitor
    _monitor = FeedMonitor(redis=redis, postgres=postgres, detector=detector)
    logger.info("Monitor router engine initialized")


async def start_monitor() -> None:
    """Start the background polling task. Called during app startup."""
    if _monitor is None:
        logger.error("Cannot start monitor — engine not initialized")
        return
    await _monitor.start()


async def stop_monitor() -> None:
    """Stop the background polling task. Called during app shutdown."""
    if _monitor is None:
        return
    await _monitor.stop()


async def cleanup_monitor_engine() -> None:
    """Full cleanup: stop polling + release reference."""
    global _monitor
    await stop_monitor()
    _monitor = None
    logger.info("Monitor router engine cleaned up")


def get_feed_monitor() -> FeedMonitor | None:
    """
    Get the FeedMonitor singleton.
    Returns None if not yet initialized — callers must check.
    """
    return _monitor


def _require_monitor() -> FeedMonitor:
    """Internal helper that raises 503 if the monitor is not ready."""
    if _monitor is None:
        raise HTTPException(
            status_code=503,
            detail="Feed monitor not initialized. Server may still be starting up.",
        )
    return _monitor


# ─── Endpoints ────────────────────────────────────────────────


@router.get("/feed")
async def get_feed(
    limit: int = Query(default=50, ge=1, le=200, description="Max entries to return"),
):
    """
    Get the most recently processed feed entries.

    Each entry includes:
      - package_name, package_version
      - anomaly_score (0-100)
      - risk_level (low/medium/high/critical)
      - triggered_rules
      - published timestamp from PyPI
      - processed_at timestamp from our pipeline

    Results are sorted newest-first.
    """
    monitor = _require_monitor()
    entries = monitor.get_recent(limit=limit)
    return {
        "count": len(entries),
        "entries": entries,
    }


@router.get("/status")
async def get_monitor_status():
    """
    Get the current status of the feed monitor.

    Returns whether the monitor is running, the feed URL,
    poll interval, and buffer utilization.
    """
    monitor = _require_monitor()
    return monitor.get_status()


@router.post("/start")
async def start_monitor_endpoint():
    """
    Manually start the feed monitor.

    The monitor starts automatically on app startup via lifespan,
    but this endpoint allows restarting it if it was stopped.
    """
    monitor = _require_monitor()

    if monitor.get_status()["running"]:
        return {"message": "Feed monitor is already running"}

    await monitor.start()
    return {"message": "Feed monitor started"}


@router.post("/stop")
async def stop_monitor_endpoint():
    """
    Manually stop the feed monitor.

    The monitor will stop polling the RSS feed. It can be
    restarted via POST /api/monitor/start.
    """
    monitor = _require_monitor()

    if not monitor.get_status()["running"]:
        return {"message": "Feed monitor is already stopped"}

    await monitor.stop()
    return {"message": "Feed monitor stopped"}
