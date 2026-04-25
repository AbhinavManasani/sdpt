"""
Software Provenance Tracker — Email Notifier

Sends HTML-formatted alert emails via SMTP using aiosmtplib.
All SMTP settings are loaded from .env:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO

Produces a styled HTML email containing:
  - Severity badge with colour coding
  - Package name, alert type, anomaly score
  - Top attack similarity match
  - Direct link to the alert dashboard page

Deduplication is handled upstream by NotificationManager;
this module is a pure delivery transport.
"""

import logging
import os
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

logger = logging.getLogger("provenance.notifications.email")

# ─── SMTP Configuration from .env ────────────────────────────
SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")
FRONTEND_BASE_URL: str = os.getenv(
    "FRONTEND_BASE_URL", "http://localhost:5173"
)

# Severity → colour for HTML badge
_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#2563eb",
}


class EmailNotifier:
    """
    Sends alert emails via SMTP using aiosmtplib.

    Usage:
        notifier = EmailNotifier()
        await notifier.send_alert(alert_dict)
    """

    def __init__(
        self,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        recipient: str | None = None,
    ):
        self._host = smtp_host or SMTP_HOST
        self._port = smtp_port or SMTP_PORT
        self._user = smtp_user or SMTP_USER
        self._password = smtp_password or SMTP_PASSWORD
        self._recipient = recipient or ALERT_EMAIL_TO

        if not all([self._user, self._password, self._recipient]):
            logger.warning(
                "SMTP credentials or ALERT_EMAIL_TO not fully configured. "
                "Email notifications will be skipped."
            )

    # ─── Public API ───────────────────────────────────────────

    async def send_alert(self, alert: dict) -> bool:
        """
        Build and send an HTML alert email.

        Args:
            alert: Alert dict as produced by AlertManager._alert_to_dict().

        Returns:
            True if the email was sent successfully, False otherwise.
        """
        if not all([self._user, self._password, self._recipient]):
            logger.debug("SMTP not configured — skipping email.")
            return False

        severity = alert.get("severity", "medium").upper()
        package_name = alert.get("package_name", "unknown")
        alert_id = alert.get("id", "?")
        title = alert.get("title", "Security Alert")

        # Build the MIME message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{severity}] Provenance Alert: {package_name} (#{alert_id})"
        msg["From"] = self._user
        msg["To"] = self._recipient

        # Plain-text fallback
        plain_body = self._build_plain_text(alert)
        msg.attach(MIMEText(plain_body, "plain", "utf-8"))

        # HTML body
        html_body = self._build_html(alert)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            await aiosmtplib.send(
                msg,
                hostname=self._host,
                port=self._port,
                username=self._user,
                password=self._password,
                start_tls=True,
            )

            logger.info(
                f"Email alert sent to {self._recipient}: "
                f"[{severity}] {package_name} (alert #{alert_id})"
            )
            return True

        except aiosmtplib.SMTPException as exc:
            logger.error(f"SMTP send failed: {exc}")
            return False
        except Exception as exc:
            logger.error(f"Email send error: {exc}")
            return False

    async def close(self) -> None:
        """No persistent resources to release, but keeps interface uniform."""
        pass

    # ─── Plain-Text Builder ───────────────────────────────────

    @staticmethod
    def _build_plain_text(alert: dict) -> str:
        """Build a plain-text email body from the alert dict."""
        severity = alert.get("severity", "medium").upper()
        package_name = alert.get("package_name", "unknown")
        alert_type = alert.get("alert_type", "unknown").replace("_", " ").title()
        alert_id = alert.get("id", "?")
        description = alert.get("description", "No details.")
        created_at = alert.get("created_at", datetime.utcnow().isoformat())

        evidence = alert.get("evidence") or {}
        anomaly_score = evidence.get("anomaly_score", "N/A")
        similar_attacks = evidence.get("similar_attacks") or []
        top_attack = similar_attacks[0] if similar_attacks else None

        attack_line = "No known attack match"
        if top_attack:
            similarity_pct = round(top_attack.get("similarity", 0) * 100)
            attack_line = (
                f"{top_attack.get('attack_name', 'Unknown')} "
                f"({top_attack.get('year', '?')}) — "
                f"{similarity_pct}% match"
            )

        dashboard_link = f"{FRONTEND_BASE_URL}/alerts/{alert_id}"

        return (
            f"PROVENANCE SECURITY ALERT\n"
            f"{'=' * 40}\n\n"
            f"Severity:        {severity}\n"
            f"Package:         {package_name}\n"
            f"Alert Type:      {alert_type}\n"
            f"Anomaly Score:   {anomaly_score}/100\n"
            f"Attack Match:    {attack_line}\n"
            f"Created:         {created_at}\n\n"
            f"Description:\n{description}\n\n"
            f"View in Dashboard: {dashboard_link}\n"
            f"Alert ID: #{alert_id}\n"
        )

    # ─── HTML Builder ─────────────────────────────────────────

    @staticmethod
    def _build_html(alert: dict) -> str:
        """Build a styled HTML email body from the alert dict."""
        severity = alert.get("severity", "medium").lower()
        severity_upper = severity.upper()
        color = _SEVERITY_COLORS.get(severity, "#6b7280")
        package_name = alert.get("package_name", "unknown")
        alert_type = alert.get("alert_type", "unknown").replace("_", " ").title()
        alert_id = alert.get("id", "?")
        title = alert.get("title", "Security Alert")
        description = alert.get("description", "No details.")
        created_at = alert.get("created_at", datetime.utcnow().isoformat())

        evidence = alert.get("evidence") or {}
        anomaly_score = evidence.get("anomaly_score", "N/A")
        similar_attacks = evidence.get("similar_attacks") or []
        top_attack = similar_attacks[0] if similar_attacks else None

        attack_line = "No known attack match"
        if top_attack:
            similarity_pct = round(top_attack.get("similarity", 0) * 100)
            attack_line = (
                f"{top_attack.get('attack_name', 'Unknown')} "
                f"({top_attack.get('year', '?')}) &mdash; "
                f"{similarity_pct}% match"
            )

        dashboard_link = f"{FRONTEND_BASE_URL}/alerts/{alert_id}"

        return f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:
  -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:24px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#fff;border-radius:8px;overflow:hidden;
                    box-shadow:0 1px 3px rgba(0,0,0,0.1);">

        <!-- Severity Banner -->
        <tr>
          <td style="background:{color};padding:16px 24px;">
            <h1 style="margin:0;color:#fff;font-size:18px;font-weight:600;">
              &#x1f6a8; {title}
            </h1>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:24px;">
            <table width="100%" cellpadding="8" cellspacing="0"
                   style="margin-bottom:16px;">
              <tr>
                <td style="border-bottom:1px solid #e5e7eb;color:#6b7280;
                           font-size:13px;width:140px;">Severity</td>
                <td style="border-bottom:1px solid #e5e7eb;">
                  <span style="display:inline-block;padding:2px 10px;
                               border-radius:4px;background:{color};
                               color:#fff;font-size:12px;font-weight:600;">
                    {severity_upper}
                  </span>
                </td>
              </tr>
              <tr>
                <td style="border-bottom:1px solid #e5e7eb;color:#6b7280;
                           font-size:13px;">Package</td>
                <td style="border-bottom:1px solid #e5e7eb;font-family:
                           monospace;font-weight:600;">{package_name}</td>
              </tr>
              <tr>
                <td style="border-bottom:1px solid #e5e7eb;color:#6b7280;
                           font-size:13px;">Alert Type</td>
                <td style="border-bottom:1px solid #e5e7eb;">{alert_type}</td>
              </tr>
              <tr>
                <td style="border-bottom:1px solid #e5e7eb;color:#6b7280;
                           font-size:13px;">Anomaly Score</td>
                <td style="border-bottom:1px solid #e5e7eb;font-weight:600;">
                  {anomaly_score} / 100</td>
              </tr>
              <tr>
                <td style="border-bottom:1px solid #e5e7eb;color:#6b7280;
                           font-size:13px;">Attack Similarity</td>
                <td style="border-bottom:1px solid #e5e7eb;">{attack_line}</td>
              </tr>
              <tr>
                <td style="color:#6b7280;font-size:13px;">Created</td>
                <td>{created_at}</td>
              </tr>
            </table>

            <p style="font-size:14px;color:#374151;line-height:1.6;
                      margin:0 0 20px 0;">
              <strong>Description:</strong><br>{description}
            </p>

            <table cellpadding="0" cellspacing="0" width="100%">
              <tr><td align="center">
                <a href="{dashboard_link}"
                   style="display:inline-block;padding:12px 28px;
                          background:{color};color:#fff;text-decoration:none;
                          border-radius:6px;font-weight:600;font-size:14px;">
                  View Alert in Dashboard &rarr;
                </a>
              </td></tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:12px 24px;background:#f9fafb;
                     border-top:1px solid #e5e7eb;text-align:center;
                     color:#9ca3af;font-size:12px;">
            Software Provenance Tracker &bull; Alert #{alert_id}
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
