"""
Software Provenance Tracker — Slack Notifier

Sends concise alert notifications to a Slack channel
via an incoming webhook URL configured in .env.

Posts a single mrkdwn summary line containing:
  - Severity and title
  - Package name and version
  - Anomaly score, rule, and status

Deduplication is handled upstream by NotificationManager;
this module is a pure delivery transport.
"""

import logging
import os

import httpx

logger = logging.getLogger("provenance.notifications.slack")

SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")


class SlackNotifier:
    """
    Sends alert payloads to Slack via an incoming webhook.

    Usage:
        notifier = SlackNotifier()
        await notifier.send_alert(alert_dict)
    """

    def __init__(self, webhook_url: str | None = None):
        self._webhook_url = webhook_url or SLACK_WEBHOOK_URL
        self._client = httpx.AsyncClient(timeout=15.0)

        if not self._webhook_url:
            logger.warning(
                "SLACK_WEBHOOK_URL is not set. "
                "Slack notifications will be skipped."
            )

    # ─── Public API ───────────────────────────────────────────

    async def send_alert(self, alert: dict) -> bool:
        """
        Format and POST an alert to Slack.

        Args:
            alert: Alert dict as produced by AlertManager._alert_to_dict().

        Returns:
            True if the message was accepted by Slack, False otherwise.
        """
        if not self._webhook_url:
            logger.debug("Slack webhook not configured — skipping.")
            return False

        payload = self._build_payload(alert)

        try:
            response = await self._client.post(
                self._webhook_url,
                json=payload,
            )

            if response.status_code == 200 and response.text == "ok":
                logger.info(
                    f"Slack alert sent: [{alert.get('severity', '').upper()}] "
                    f"{alert.get('package_name')} (alert #{alert.get('id')})"
                )
                return True

            logger.error(
                f"Slack webhook returned {response.status_code}: "
                f"{response.text[:200]}"
            )
            return False

        except httpx.HTTPError as exc:
            logger.error(f"Slack webhook request failed: {exc}")
            return False

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        await self._client.aclose()

    # ─── Payload Builder ──────────────────────────────────────

    @staticmethod
    def _build_payload(alert: dict) -> dict:
        """
        Build a concise Slack mrkdwn summary payload from an alert dict.

        Produces a single plain-text summary line containing:
          • Severity and title
          • Package name and version
          • Anomaly score
          • Alert rule / type
          • Current status
        """
        severity = alert.get("severity", "medium")
        title = alert.get("title", "Security Alert")
        package_name = alert.get("package_name", "unknown")
        package_version = alert.get("package_version") or "N/A"
        alert_type = alert.get("alert_type", "unknown")
        status = alert.get("status", "open")

        # Extract anomaly score from evidence if present
        evidence = alert.get("evidence") or {}
        anomaly_score = evidence.get("anomaly_score", "N/A")

        message = (
            f"🚨 *{severity.upper()} Alert* — {title}\n"
            f"Package: {package_name} v{package_version}\n"
            f"Score: {anomaly_score}/100\n"
            f"Rule: {alert_type}\n"
            f"Status: {status}"
        )

        return {"text": message}

