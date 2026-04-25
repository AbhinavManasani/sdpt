"""
Periodic pruning task for the AnomalyTrend table.
Deletes entries older than 90 days to prevent unbounded growth.
Runs once every 24 hours as a background asyncio task.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from sqlalchemy import delete
from db.postgres import AnomalyTrend, PostgresManager

logger = logging.getLogger("provenance.tasks.pruning")


async def prune_old_trends(postgres: PostgresManager) -> int:
    """
    Delete AnomalyTrend entries older than 90 days.
    Returns the number of rows deleted.
    """
    cutoff = datetime.utcnow() - timedelta(days=90)
    try:
        async with postgres.get_session() as session:
            result = await session.execute(
                delete(AnomalyTrend).where(AnomalyTrend.created_at < cutoff)
            )
            await session.commit()
            deleted = result.rowcount
            logger.info(f"Pruned {deleted} AnomalyTrend entries older than 90 days.")
            return deleted
    except Exception as exc:
        logger.error(f"Trend pruning failed: {exc}")
        return 0


async def run_daily_pruning(postgres: PostgresManager) -> None:
    """
    Loop that runs prune_old_trends once every 24 hours.
    Designed to be launched as an asyncio background task on startup.
    """
    while True:
        await asyncio.sleep(86400)
        await prune_old_trends(postgres)
