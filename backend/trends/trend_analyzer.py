"""
Software Provenance Tracker — Trend Analyser

Records anomaly/trust score snapshots and provides historical
trending queries for packages and contributors.

Capabilities:
  1. Record — persist a score snapshot to the anomaly_trends table.
  2. Timeline — fetch score history for one entity over time.
  3. Top movers — entities whose scores changed the most recently.
  4. Aggregate stats — overall risk distribution over time.
  5. Risk breakdown — count of entities per risk level for a window.

All reads are sorted by recorded_at descending unless stated otherwise.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import select, func, desc, and_, case, cast, Float as SAFloat

from db.postgres import PostgresManager, AnomalyTrend

logger = logging.getLogger("provenance.trends.analyzer")


class TrendAnalyzer:
    """
    Records and queries historical anomaly/trust score snapshots.

    Usage:
        analyzer = TrendAnalyzer(postgres)
        await analyzer.record("package", "requests", "pypi", score_dict)
        timeline = await analyzer.timeline("package", "requests", days=90)
    """

    def __init__(self, postgres: PostgresManager):
        self._postgres = postgres

    # ─── Record ───────────────────────────────────────────────

    async def record(
        self,
        entity_type: str,
        entity_name: str,
        ecosystem: str | None,
        anomaly_score: float | None,
        trust_score: float | None,
        risk_level: str,
        triggered_rules: list[str] | None = None,
    ) -> dict:
        """
        Persist a single score snapshot.

        Called automatically after each anomaly scoring pass
        or contributor analysis.

        Returns the persisted record as a dict.
        """
        async with self._postgres.get_session() as session:
            record = AnomalyTrend(
                entity_type=entity_type,
                entity_name=entity_name,
                ecosystem=ecosystem,
                anomaly_score=anomaly_score,
                trust_score=trust_score,
                risk_level=risk_level,
                triggered_rules=triggered_rules,
                recorded_at=datetime.utcnow(),
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

            logger.info(
                f"Trend recorded: {entity_type}/{entity_name} "
                f"score={anomaly_score} risk={risk_level}"
            )
            return self._to_dict(record)

    # ─── Timeline ─────────────────────────────────────────────

    async def timeline(
        self,
        entity_type: str,
        entity_name: str,
        days: int = 90,
        limit: int = 500,
    ) -> dict:
        """
        Fetch score history for a single entity over the last N days.

        Returns a list of data points sorted oldest → newest
        (suitable for charting).
        """
        cutoff = datetime.utcnow() - timedelta(days=days)

        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(AnomalyTrend)
                .where(
                    AnomalyTrend.entity_type == entity_type,
                    AnomalyTrend.entity_name == entity_name,
                    AnomalyTrend.recorded_at >= cutoff,
                )
                .order_by(AnomalyTrend.recorded_at)  # chronological
                .limit(limit)
            )
            rows = result.scalars().all()

        return {
            "entity_type": entity_type,
            "entity_name": entity_name,
            "days": days,
            "data_points": len(rows),
            "timeline": [self._to_dict(r) for r in rows],
        }

    # ─── Top Movers ───────────────────────────────────────────

    async def top_movers(
        self,
        entity_type: str = "package",
        days: int = 30,
        limit: int = 20,
    ) -> list[dict]:
        """
        Find entities whose anomaly score changed the most over
        the last N days.

        Computes: latest score − earliest score within the window.
        Returns the top movers sorted by absolute change descending.
        """
        cutoff = datetime.utcnow() - timedelta(days=days)

        async with self._postgres.get_session() as session:
            # Subquery: first recorded score in the window per entity
            first_sub = (
                select(
                    AnomalyTrend.entity_name,
                    func.min(AnomalyTrend.recorded_at).label("first_at"),
                )
                .where(
                    AnomalyTrend.entity_type == entity_type,
                    AnomalyTrend.recorded_at >= cutoff,
                    AnomalyTrend.anomaly_score.isnot(None),
                )
                .group_by(AnomalyTrend.entity_name)
                .subquery("first_sub")
            )

            # Subquery: last recorded score in the window per entity
            last_sub = (
                select(
                    AnomalyTrend.entity_name,
                    func.max(AnomalyTrend.recorded_at).label("last_at"),
                )
                .where(
                    AnomalyTrend.entity_type == entity_type,
                    AnomalyTrend.recorded_at >= cutoff,
                    AnomalyTrend.anomaly_score.isnot(None),
                )
                .group_by(AnomalyTrend.entity_name)
                .subquery("last_sub")
            )

            # Join to get actual scores at first and last timestamps
            first_score = (
                select(
                    AnomalyTrend.entity_name,
                    AnomalyTrend.anomaly_score.label("first_score"),
                )
                .join(
                    first_sub,
                    and_(
                        AnomalyTrend.entity_name == first_sub.c.entity_name,
                        AnomalyTrend.recorded_at == first_sub.c.first_at,
                    ),
                )
                .where(AnomalyTrend.entity_type == entity_type)
                .subquery("first_score")
            )

            last_score = (
                select(
                    AnomalyTrend.entity_name,
                    AnomalyTrend.anomaly_score.label("last_score"),
                    AnomalyTrend.risk_level.label("current_risk"),
                )
                .join(
                    last_sub,
                    and_(
                        AnomalyTrend.entity_name == last_sub.c.entity_name,
                        AnomalyTrend.recorded_at == last_sub.c.last_at,
                    ),
                )
                .where(AnomalyTrend.entity_type == entity_type)
                .subquery("last_score")
            )

            # Final query: compute delta, sort by abs(delta)
            query = (
                select(
                    first_score.c.entity_name,
                    first_score.c.first_score,
                    last_score.c.last_score,
                    last_score.c.current_risk,
                    (last_score.c.last_score - first_score.c.first_score).label("delta"),
                )
                .join(
                    last_score,
                    first_score.c.entity_name == last_score.c.entity_name,
                )
                .order_by(
                    desc(func.abs(last_score.c.last_score - first_score.c.first_score))
                )
                .limit(limit)
            )

            result = await session.execute(query)
            rows = result.all()

            # Deduplicate: subquery joins may produce multiple rows per
            # entity when several snapshots share the same min/max timestamp.
            seen = set()
            deduped = []
            for row in rows:
                if row.entity_name not in seen:
                    seen.add(row.entity_name)
                    deduped.append(row)
            rows = deduped[:limit]

        return [
            {
                "entity_name": row.entity_name,
                "first_score": round(row.first_score, 1) if row.first_score else None,
                "latest_score": round(row.last_score, 1) if row.last_score else None,
                "delta": round(row.delta, 1) if row.delta else 0,
                "current_risk": row.current_risk,
                "direction": "up" if (row.delta or 0) > 0 else ("down" if (row.delta or 0) < 0 else "stable"),
            }
            for row in rows
        ]

    # ─── Risk Breakdown ───────────────────────────────────────

    async def risk_breakdown(
        self,
        entity_type: str = "package",
        days: int = 7,
    ) -> dict:
        """
        Count distinct entities per risk level based on their
        most recent score within the window.

        Returns: { "critical": N, "high": N, "medium": N, "low": N }
        """
        cutoff = datetime.utcnow() - timedelta(days=days)

        async with self._postgres.get_session() as session:
            # Latest recorded_at per entity
            latest_sub = (
                select(
                    AnomalyTrend.entity_name,
                    func.max(AnomalyTrend.recorded_at).label("latest_at"),
                )
                .where(
                    AnomalyTrend.entity_type == entity_type,
                    AnomalyTrend.recorded_at >= cutoff,
                )
                .group_by(AnomalyTrend.entity_name)
                .subquery("latest_sub")
            )

            # Join back to get risk_level at that timestamp
            result = await session.execute(
                select(
                    AnomalyTrend.risk_level,
                    func.count(func.distinct(AnomalyTrend.entity_name)),
                )
                .join(
                    latest_sub,
                    and_(
                        AnomalyTrend.entity_name == latest_sub.c.entity_name,
                        AnomalyTrend.recorded_at == latest_sub.c.latest_at,
                    ),
                )
                .where(AnomalyTrend.entity_type == entity_type)
                .group_by(AnomalyTrend.risk_level)
            )
            rows = result.all()

        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for risk_level, count in rows:
            breakdown[risk_level] = count

        return {
            "entity_type": entity_type,
            "window_days": days,
            "breakdown": breakdown,
            "total_entities": sum(breakdown.values()),
        }

    # ─── Aggregate Stats ──────────────────────────────────────

    async def stats(self, cutoff: datetime | None = None) -> dict:
        """
        High-level trending statistics for the dashboard.
        """
        async with self._postgres.get_session() as session:
            # Query for total_snapshots
            query_total = select(func.count(AnomalyTrend.id))
            if cutoff:
                query_total = query_total.where(AnomalyTrend.recorded_at >= cutoff)
            total_result = await session.execute(query_total)
            total_snapshots = total_result.scalar() or 0

            # Query for distinct packages
            query_pkg = select(func.count(func.distinct(AnomalyTrend.entity_name))).where(AnomalyTrend.entity_type == "package")
            if cutoff:
                query_pkg = query_pkg.where(AnomalyTrend.recorded_at >= cutoff)
            distinct_packages = await session.execute(query_pkg)
            pkg_count = distinct_packages.scalar() or 0

            # Query for distinct contributors
            query_contrib = select(func.count(func.distinct(AnomalyTrend.entity_name))).where(AnomalyTrend.entity_type == "contributor")
            if cutoff:
                query_contrib = query_contrib.where(AnomalyTrend.recorded_at >= cutoff)
            distinct_contributors = await session.execute(query_contrib)
            contrib_count = distinct_contributors.scalar() or 0

            # Average anomaly score over last 7 days
            week_ago = datetime.utcnow() - timedelta(days=7)
            avg_result = await session.execute(
                select(func.avg(AnomalyTrend.anomaly_score))
                .where(
                    AnomalyTrend.anomaly_score.isnot(None),
                    AnomalyTrend.recorded_at >= week_ago,
                )
            )
            avg_score_7d = avg_result.scalar()

            # Count of high/critical in last 7 days
            high_risk_result = await session.execute(
                select(func.count(AnomalyTrend.id))
                .where(
                    AnomalyTrend.risk_level.in_(["critical", "high"]),
                    AnomalyTrend.recorded_at >= week_ago,
                )
            )
            high_risk_7d = high_risk_result.scalar() or 0

        return {
            "total_snapshots": total_snapshots,
            "distinct_packages": pkg_count,
            "distinct_contributors": contrib_count,
            "avg_anomaly_score_7d": round(avg_score_7d, 1) if avg_score_7d else None,
            "high_risk_events_7d": high_risk_7d,
        }

    # ─── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _to_dict(record: AnomalyTrend) -> dict:
        return {
            "id": record.id,
            "entity_type": record.entity_type,
            "entity_name": record.entity_name,
            "ecosystem": record.ecosystem,
            "anomaly_score": record.anomaly_score,
            "trust_score": record.trust_score,
            "risk_level": record.risk_level,
            "triggered_rules": record.triggered_rules,
            "recorded_at": record.recorded_at.isoformat() if record.recorded_at else None,
        }
