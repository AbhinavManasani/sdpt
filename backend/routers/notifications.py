"""
Software Provenance Tracker — Notifications API Router

Exposes REST endpoints for the notification system:
  - POST /api/notifications/test/slack   — send a test Slack message
  - POST /api/notifications/test/email   — send a test email
  - POST /api/notifications/send         — manually trigger notification for an alert
  - GET  /api/notifications/status       — check channel configuration status
"""

import logging

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from db.redis_conn import RedisManager
from notifications.notification_manager import NotificationManager

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.notifications")

router = APIRouter(
    prefix="/api/notifications",
    tags=["notifications"],
    dependencies=[Depends(verify_api_key)],
)


# ─── Request Models ───────────────────────────────────────────

class SendNotificationRequest(BaseModel):
    """Manually trigger a notification for a given alert."""
    alert: dict = Field(
        ...,
        description="Full alert dict (as returned by GET /api/alerts/{id})",
    )
    force: bool = Field(
        default=False,
        description="If true, bypass the severity gate (still respects dedup)",
    )


class TestMessageRequest(BaseModel):
    """Send a test message to verify channel configuration."""
    message: str = Field(
        default="Test alert from Software Provenance Tracker",
        max_length=500,
    )


# ─── Manager Instance ────────────────────────────────────────

_manager: NotificationManager | None = None


def setup_notifications_engine(redis: RedisManager) -> None:
    """Initialize the NotificationManager. Called during app startup."""
    global _manager
    _manager = NotificationManager(redis=redis)
    logger.info("Notifications router engine initialized")


async def cleanup_notifications_engine() -> None:
    """Clean up the NotificationManager. Called during app shutdown."""
    global _manager
    if _manager:
        await _manager.close()
    _manager = None


def get_notification_manager() -> NotificationManager | None:
    """
    Get the NotificationManager singleton.
    Exported so alert_manager.py (and other modules) can call
    notify() after creating an alert.
    Returns None if not yet initialized — callers must check.
    """
    return _manager


# ─── Endpoints ────────────────────────────────────────────────


@router.get("/status")
async def notification_status():
    """
    Check which notification channels are configured and ready.
    Useful for the settings page / health dashboard.
    """
    manager = get_notification_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="Notification manager not initialized.")

    slack_configured = bool(manager._slack._webhook_url)
    email_configured = all([
        manager._email._user,
        manager._email._password,
        manager._email._recipient,
    ])

    return {
        "channels": {
            "slack": {
                "configured": slack_configured,
                "webhook_set": slack_configured,
            },
            "email": {
                "configured": email_configured,
                "smtp_host": manager._email._host,
                "smtp_port": manager._email._port,
                "recipient": manager._email._recipient if email_configured else None,
            },
        },
    }


@router.post("/send")
async def send_notification(request: SendNotificationRequest):
    """
    Manually trigger a notification for a specific alert.

    By default, respects the severity gate (only CRITICAL/HIGH).
    Set force=true to bypass the severity check (dedup still applies).
    """
    manager = get_notification_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="Notification manager not initialized.")
    alert = request.alert

    if request.force:
        # Bypass severity gate by temporarily overriding severity
        original_severity = alert.get("severity")
        alert["severity"] = "critical"
        result = await manager.notify(alert)
        alert["severity"] = original_severity  # restore
    else:
        result = await manager.notify(alert)

    return {
        "alert_id": alert.get("id"),
        "notification": result,
    }


@router.post("/test/slack")
async def test_slack(request: TestMessageRequest):
    """
    Send a test message to Slack to verify webhook configuration.
    """
    manager = get_notification_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="Notification manager not initialized.")

    if not manager._slack._webhook_url:
        raise HTTPException(
            status_code=400,
            detail="SLACK_WEBHOOK_URL is not configured in .env",
        )

    # Build a test alert dict
    test_alert = {
        "id": 0,
        "severity": "medium",
        "alert_type": "test",
        "package_name": "test-package",
        "title": f"🧪 Test Notification: {request.message}",
        "description": request.message,
        "evidence": {
            "anomaly_score": 42,
            "similar_attacks": [],
        },
        "status": "open",
        "created_at": "now",
    }

    success = await manager._slack.send_alert(test_alert)

    if not success:
        raise HTTPException(
            status_code=502,
            detail="Slack webhook call failed. Check the webhook URL and Slack logs.",
        )

    return {"status": "sent", "channel": "slack"}


@router.post("/test/email")
async def test_email(request: TestMessageRequest):
    """
    Send a test email to verify SMTP configuration.
    """
    manager = get_notification_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="Notification manager not initialized.")

    if not all([
        manager._email._user,
        manager._email._password,
        manager._email._recipient,
    ]):
        raise HTTPException(
            status_code=400,
            detail="SMTP settings (SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO) "
                   "are not fully configured in .env",
        )

    test_alert = {
        "id": 0,
        "severity": "medium",
        "alert_type": "test",
        "package_name": "test-package",
        "title": f"🧪 Test Notification: {request.message}",
        "description": request.message,
        "evidence": {
            "anomaly_score": 42,
            "similar_attacks": [],
        },
        "status": "open",
        "created_at": "now",
    }

    success = await manager._email.send_alert(test_alert)

    if not success:
        raise HTTPException(
            status_code=502,
            detail="SMTP send failed. Check SMTP_HOST, SMTP_PORT, credentials, and server logs.",
        )

    return {"status": "sent", "channel": "email"}
