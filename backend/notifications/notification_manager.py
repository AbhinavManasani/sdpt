"""
Software Provenance Tracker — Notification Manager

Orchestrates alert notifications across all configured channels
(Slack, Email). Responsibilities:

  1. Redis deduplication — prevents the same alert from triggering
     duplicate notifications within a 1-hour window.
     Key format: notif:{alert_id}   TTL: 3600 s

  2. Severity gating — only CRITICAL and HIGH alerts fire
     external notifications.

  3. Fan-out — dispatches to every enabled transport in parallel.

  4. Lifecycle — exposes setup/cleanup for main.py lifespan.
"""

import asyncio
import logging

from db.redis_conn import RedisManager
from notifications.slack_notifier import SlackNotifier
from notifications.email_notifier import EmailNotifier

logger = logging.getLogger("provenance.notifications.manager")

# Redis key prefix for deduplication
_DEDUP_PREFIX = "notif"

# Dedup window: 1 hour
_DEDUP_TTL_SECONDS = 3600

# Only these severities trigger external notifications
_NOTIFIABLE_SEVERITIES = {"critical", "high"}


class NotificationManager:
    """
    Central dispatcher for alert notifications.

    Usage (inside alert_manager.py after creating an alert):
        await notification_manager.notify(alert_dict)
    """

    def __init__(
        self,
        redis: RedisManager,
        slack: SlackNotifier | None = None,
        email: EmailNotifier | None = None,
    ):
        self._redis = redis
        self._slack = slack or SlackNotifier()
        self._email = email or EmailNotifier()

    # ─── Public API ───────────────────────────────────────────

    async def notify(self, alert: dict) -> dict:
        """
        Evaluate an alert and send notifications if appropriate.

        Steps:
          1. Check severity — skip if below threshold.
          2. Check Redis dedup key — skip if already notified.
          3. Fan-out to all enabled channels.
          4. Set dedup key on success.

        Args:
            alert: Alert dict from AlertManager._alert_to_dict().

        Returns:
            A summary dict:
              {
                "notified": bool,
                "reason": str,          # why it was skipped (if any)
                "channels": {
                  "slack": bool,
                  "email": bool,
                },
              }
        """
        alert_id = alert.get("id")
        severity = (alert.get("severity") or "").lower()
        package_name = alert.get("package_name", "unknown")

        # ── Severity gate ─────────────────────────────────────
        if severity not in _NOTIFIABLE_SEVERITIES:
            logger.debug(
                f"Alert #{alert_id} severity '{severity}' below notification "
                f"threshold — skipping."
            )
            return {
                "notified": False,
                "reason": f"severity '{severity}' below threshold",
                "channels": {"slack": False, "email": False},
            }

        # ── Deduplication check ───────────────────────────────
        if await self._is_duplicate(alert_id):
            logger.info(
                f"Alert #{alert_id} already notified within the last hour "
                f"— skipping duplicate."
            )
            return {
                "notified": False,
                "reason": "duplicate (already notified within 1 hour)",
                "channels": {"slack": False, "email": False},
            }

        # ── Fan-out to all channels ───────────────────────────
        logger.info(
            f"Sending notifications for alert #{alert_id}: "
            f"[{severity.upper()}] {package_name}"
        )

        slack_ok, email_ok = await asyncio.gather(
            self._send_slack(alert),
            self._send_email(alert),
        )

        # Mark as notified if at least one channel succeeded
        if slack_ok or email_ok:
            await self._mark_notified(alert_id)

        return {
            "notified": slack_ok or email_ok,
            "reason": "sent" if (slack_ok or email_ok) else "all channels failed",
            "channels": {
                "slack": slack_ok,
                "email": email_ok,
            },
        }

    async def close(self) -> None:
        """Release resources held by transport clients."""
        await self._slack.close()
        await self._email.close()
        logger.info("NotificationManager transports closed.")

    # ─── Redis Deduplication ──────────────────────────────────

    async def _is_duplicate(self, alert_id: int | str) -> bool:
        """Check if this alert was already notified within the dedup window."""
        existing = await self._redis.get_cached(_DEDUP_PREFIX, str(alert_id))
        return existing is not None

    async def _mark_notified(self, alert_id: int | str) -> None:
        """Set the dedup key so this alert won't re-notify for 1 hour."""
        await self._redis.set_cached(
            _DEDUP_PREFIX,
            str(alert_id),
            {"notified": True},
            ttl_seconds=_DEDUP_TTL_SECONDS,
        )
        logger.debug(f"Dedup key set: {_DEDUP_PREFIX}:{alert_id} (TTL {_DEDUP_TTL_SECONDS}s)")

    # ─── Channel Dispatchers ──────────────────────────────────

    async def _send_slack(self, alert: dict) -> bool:
        """Send to Slack, catching all errors to avoid breaking fan-out."""
        try:
            return await self._slack.send_alert(alert)
        except Exception as exc:
            logger.error(f"Slack notification error: {exc}", exc_info=True)
            return False

    async def _send_email(self, alert: dict) -> bool:
        """Send email, catching all errors to avoid breaking fan-out."""
        try:
            return await self._email.send_alert(alert)
        except Exception as exc:
            logger.error(f"Email notification error: {exc}", exc_info=True)
            return False
