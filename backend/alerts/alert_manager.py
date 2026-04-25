"""
Software Provenance Tracker — Alert Manager

Generates, stores, and manages security alerts from
anomaly detection results and contributor analysis.

Alert lifecycle:
  open → investigating → resolved / dismissed

Alert types:
  - typosquatting          (Levenshtein distance match)
  - maintainer_takeover    (new maintainer on established package)
  - account_compromise     (behavioral deviation on trusted account)
  - obfuscated_code        (high obfuscation score)
  - dependency_injection   (suspicious dependency additions)
  - dormant_reactivation   (long-dormant contributor suddenly active)
  - low_trust_publisher    (critically low trust score)
  - binary_injection       (binary files added to package)
"""

import logging
from datetime import datetime

from sqlalchemy import select, func, desc, update

from db.postgres import PostgresManager, Alert

logger = logging.getLogger("provenance.alerts.manager")


class AlertManager:
    """
    Manages the full alert lifecycle:
      1. Generate alerts from anomaly scores and contributor analysis
      2. Store alerts in PostgreSQL
      3. Query and filter alerts
      4. Update alert status (investigate, resolve, dismiss)
      5. Provide alert statistics for the dashboard
    """

    def __init__(self, postgres: PostgresManager):
        self._postgres = postgres

    # ─── Alert Generation ─────────────────────────────────────

    async def generate_from_anomaly(
        self,
        anomaly_result: dict,
        package_name: str,
        package_version: str | None = None,
        contributor_username: str | None = None,
    ) -> list[dict]:
        """
        Generate alerts from an anomaly detection result.

        Reads triggered_rules and risk_level from the anomaly result
        and creates one alert per triggered rule that meets the
        severity threshold.

        Returns list of created alerts.
        """
        triggered = anomaly_result.get("triggered_rules", [])
        if not triggered:
            return []

        risk_level = anomaly_result.get("risk_level", "low")
        if risk_level == "low":
            return []  # No alerts for low risk

        created_alerts = []

        for rule in triggered:
            severity = rule.get("severity", "medium")
            if severity == "low":
                continue  # Skip low severity rules

            # Map rule names to alert types
            alert_type = self._rule_to_alert_type(rule.get("rule", ""))

            title = self._generate_title(alert_type, package_name, severity)
            description = self._generate_description(
                alert_type=alert_type,
                rule=rule,
                anomaly_result=anomaly_result,
                package_name=package_name,
                contributor=contributor_username,
            )

            # Build evidence from the anomaly result
            evidence = {
                "anomaly_score": anomaly_result.get("anomaly_score"),
                "ml_score": anomaly_result.get("ml_score"),
                "rule_score": anomaly_result.get("rule_score"),
                "rule_name": rule.get("rule"),
                "rule_detail": rule.get("detail"),
                "similar_attacks": anomaly_result.get("similar_attacks", []),
            }

            alert = await self.create_alert(
                severity=severity,
                alert_type=alert_type,
                package_name=package_name,
                package_version=package_version,
                contributor_username=contributor_username,
                title=title,
                description=description,
                evidence=evidence,
            )

            created_alerts.append(alert)

        logger.info(
            f"Generated {len(created_alerts)} alert(s) for {package_name} "
            f"(risk: {risk_level})"
        )

        return created_alerts

    async def generate_from_contributor(
        self,
        analysis_result: dict,
        package_name: str | None = None,
    ) -> list[dict]:
        """
        Generate alerts from a contributor analysis result.

        Reads deviations and risk_flags from the contributor analysis
        and creates alerts for significant findings.
        """
        username = analysis_result.get("username", "unknown")
        deviations = analysis_result.get("deviations", [])
        if not deviations:
            return []

        created_alerts = []

        for deviation in deviations:
            severity = deviation.get("severity", "medium")
            dev_type = deviation.get("type", "unknown")

            alert_type = self._deviation_to_alert_type(dev_type)
            pkg = package_name or "N/A"

            title = f"Contributor {dev_type.replace('_', ' ').title()}: {username}"
            description = (
                f"Contributor '{username}' flagged for {dev_type.replace('_', ' ')}. "
                f"{deviation.get('detail', '')}"
            )

            evidence = {
                "deviation_type": dev_type,
                "deviation_detail": deviation.get("detail"),
                "baseline": analysis_result.get("baseline", {}),
            }

            alert = await self.create_alert(
                severity=severity,
                alert_type=alert_type,
                package_name=pkg,
                contributor_username=username,
                title=title,
                description=description,
                evidence=evidence,
            )
            created_alerts.append(alert)

        return created_alerts

    # ─── CRUD Operations ──────────────────────────────────────

    async def create_alert(
        self,
        severity: str,
        alert_type: str,
        package_name: str,
        title: str,
        description: str,
        package_version: str | None = None,
        contributor_username: str | None = None,
        baseline_summary: str | None = None,
        evidence: dict | None = None,
    ) -> dict:
        """Create a new alert in PostgreSQL."""
        async with self._postgres.get_session() as session:
            alert = Alert(
                severity=severity,
                alert_type=alert_type,
                package_name=package_name,
                package_version=package_version,
                contributor_username=contributor_username,
                title=title,
                description=description,
                baseline_summary=baseline_summary,
                evidence=evidence,
                status="open",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            session.add(alert)
            await session.commit()
            await session.refresh(alert)

            logger.info(
                f"Alert #{alert.id} created: [{severity.upper()}] {alert_type} — {package_name}"
            )

            alert_dict = self._alert_to_dict(alert)

            # Fire-and-forget notification for critical/high alerts
            await self._try_notify(alert_dict)

            return alert_dict

    async def get_alert(self, alert_id: int) -> dict | None:
        """Get a single alert by ID."""
        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.id == alert_id)
            )
            alert = result.scalar_one_or_none()
            if alert is None:
                return None
            return self._alert_to_dict(alert)

    async def get_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        package_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """
        Get alerts with optional filtering.
        Returns paginated results with total count.
        """
        async with self._postgres.get_session() as session:
            query = select(Alert)
            count_query = select(func.count(Alert.id))

            if status:
                query = query.where(Alert.status == status)
                count_query = count_query.where(Alert.status == status)
            if severity:
                query = query.where(Alert.severity == severity)
                count_query = count_query.where(Alert.severity == severity)
            if package_name:
                query = query.where(Alert.package_name == package_name)
                count_query = count_query.where(Alert.package_name == package_name)

            # Get total count
            total_result = await session.execute(count_query)
            total = total_result.scalar() or 0

            # Get paginated results
            query = (
                query
                .order_by(desc(Alert.created_at))
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(query)
            alerts = result.scalars().all()

            return {
                "total": total,
                "offset": offset,
                "limit": limit,
                "alerts": [self._alert_to_dict(a) for a in alerts],
            }

    async def update_status(
        self, alert_id: int, new_status: str
    ) -> dict | None:
        """
        Update alert status. Valid transitions:
          open → investigating → resolved / dismissed
        """
        valid_statuses = {"open", "investigating", "resolved", "dismissed"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}. Must be one of {valid_statuses}")

        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.id == alert_id)
            )
            alert = result.scalar_one_or_none()
            if alert is None:
                return None

            alert.status = new_status
            alert.updated_at = datetime.utcnow()
            if new_status in ("resolved", "dismissed"):
                alert.resolved_at = datetime.utcnow()

            await session.commit()
            await session.refresh(alert)

            logger.info(f"Alert #{alert_id} status → {new_status}")
            return self._alert_to_dict(alert)

    async def bulk_update_status(
        self, alert_ids: list[int], new_status: str
    ) -> int:
        """Bulk update status for multiple alerts. Returns count updated."""
        valid_statuses = {"open", "investigating", "resolved", "dismissed"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}")

        async with self._postgres.get_session() as session:
            values = {"status": new_status, "updated_at": datetime.utcnow()}
            if new_status in ("resolved", "dismissed"):
                values["resolved_at"] = datetime.utcnow()

            result = await session.execute(
                update(Alert)
                .where(Alert.id.in_(alert_ids))
                .values(**values)
            )
            await session.commit()

            count = result.rowcount
            logger.info(f"Bulk updated {count} alert(s) → {new_status}")
            return count

    # ─── Statistics ───────────────────────────────────────────

    async def get_stats(self) -> dict:
        """Get alert statistics for the dashboard."""
        async with self._postgres.get_session() as session:
            # Total by status
            status_result = await session.execute(
                select(Alert.status, func.count(Alert.id))
                .group_by(Alert.status)
            )
            by_status = {row[0]: row[1] for row in status_result.all()}

            # Total by severity
            severity_result = await session.execute(
                select(Alert.severity, func.count(Alert.id))
                .group_by(Alert.severity)
            )
            by_severity = {row[0]: row[1] for row in severity_result.all()}

            # Total by type
            type_result = await session.execute(
                select(Alert.alert_type, func.count(Alert.id))
                .group_by(Alert.alert_type)
                .order_by(desc(func.count(Alert.id)))
            )
            by_type = {row[0]: row[1] for row in type_result.all()}

            # Most recent alerts
            recent_result = await session.execute(
                select(Alert)
                .order_by(desc(Alert.created_at))
                .limit(5)
            )
            recent = recent_result.scalars().all()

            total = sum(by_status.values())

            return {
                "total_alerts": total,
                "open_alerts": by_status.get("open", 0),
                "investigating": by_status.get("investigating", 0),
                "resolved": by_status.get("resolved", 0),
                "dismissed": by_status.get("dismissed", 0),
                "by_severity": by_severity,
                "by_type": by_type,
                "recent_alerts": [self._alert_to_dict(a) for a in recent],
            }

    # ─── Notification Hook ────────────────────────────────────

    @staticmethod
    async def _try_notify(alert_dict: dict) -> None:
        """
        Attempt to send a notification for a newly created alert.
        Uses a lazy import to avoid circular dependencies with
        routers.notifications.
        Failures are logged but never propagate — alert creation
        must never fail because of a notification error.
        """
        try:
            from routers.notifications import get_notification_manager

            manager = get_notification_manager()
            if manager is None:
                return  # Not yet initialised (e.g. during tests)

            result = await manager.notify(alert_dict)
            if result.get("notified"):
                logger.info(
                    f"Notification dispatched for alert #{alert_dict.get('id')} "
                    f"(channels: {result.get('channels')})"
                )
        except Exception as exc:
            logger.warning(
                f"Notification attempt failed for alert #{alert_dict.get('id')}: {exc}"
            )

    # ─── Private Helpers ──────────────────────────────────────

    @staticmethod
    def _rule_to_alert_type(rule_name: str) -> str:
        """Map anomaly detection rule names to alert types."""
        mapping = {
            "BRAND_NEW_ACCOUNT": "low_trust_publisher",
            "YOUNG_ACCOUNT": "low_trust_publisher",
            "NEW_MAINTAINER": "maintainer_takeover",
            "INSTALL_SCRIPTS": "dependency_injection",
            "OBFUSCATED_CODE": "obfuscated_code",
            "TYPOSQUAT": "typosquatting",
            "BINARY_ADDED": "binary_injection",
            "DEPENDENCY_EXPLOSION": "dependency_injection",
            "EXTREMELY_LOW_TRUST": "low_trust_publisher",
            "TIMEZONE_SHIFT": "account_compromise",
            "DORMANT_REACTIVATION": "dormant_reactivation",
        }
        return mapping.get(rule_name, "unknown")

    @staticmethod
    def _deviation_to_alert_type(deviation_type: str) -> str:
        """Map contributor deviation types to alert types."""
        mapping = {
            "young_account": "low_trust_publisher",
            "commit_hour_shift": "account_compromise",
            "activity_burst": "dormant_reactivation",
            "no_repos": "low_trust_publisher",
            "low_trust": "low_trust_publisher",
        }
        return mapping.get(deviation_type, "unknown")

    @staticmethod
    def _generate_title(alert_type: str, package_name: str, severity: str) -> str:
        """Generate a human-readable alert title."""
        type_labels = {
            "typosquatting": "Typosquatting Detected",
            "maintainer_takeover": "New Maintainer on Package",
            "account_compromise": "Possible Account Compromise",
            "obfuscated_code": "Obfuscated Code Detected",
            "dependency_injection": "Suspicious Dependency Change",
            "dormant_reactivation": "Dormant Account Reactivated",
            "low_trust_publisher": "Low Trust Publisher",
            "binary_injection": "Binary Files Added",
        }
        label = type_labels.get(alert_type, alert_type.replace("_", " ").title())
        return f"[{severity.upper()}] {label}: {package_name}"

    @staticmethod
    def _generate_description(
        alert_type: str,
        rule: dict,
        anomaly_result: dict,
        package_name: str,
        contributor: str | None,
    ) -> str:
        """Generate a detailed alert description."""
        parts = [rule.get("detail", "")]

        score = anomaly_result.get("anomaly_score", 0)
        parts.append(f"Combined anomaly score: {score}/100.")

        similar = anomaly_result.get("similar_attacks", [])
        if similar:
            top = similar[0]
            parts.append(
                f"Pattern matches '{top['attack_name']}' ({top['year']}) "
                f"with {top['similarity']*100:.0f}% similarity."
            )

        explanation = anomaly_result.get("explanation", "")
        if explanation:
            parts.append(explanation)

        return " ".join(parts)

    @staticmethod
    def _alert_to_dict(alert: Alert) -> dict:
        """Convert an Alert ORM instance to a dict."""
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
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
        }
