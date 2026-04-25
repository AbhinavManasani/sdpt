"""
Software Provenance Tracker — Real-Time Feed Monitor

Continuously polls the PyPI RSS updates feed and processes each
new package publish through the full provenance pipeline:

  1. Parse feed via feedparser
  2. Deduplicate against last-seen guid stored in Redis
  3. Score with ML anomaly detection engine
  4. Record entry in the provenance ledger
  5. Generate alerts for high/critical risk packages
  6. Record trend snapshot for historical analysis

Runs as an asyncio background task started/stopped via the
FastAPI lifespan context.
"""

import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any

import feedparser
import httpx

from db.redis_conn import RedisManager
from db.postgres import PostgresManager
from ml.anomaly_detector import AnomalyDetector
from ledger.ledger_manager import LedgerManager
from alerts.alert_manager import AlertManager
from trends.trend_analyzer import TrendAnalyzer

logger = logging.getLogger("provenance.monitor.feed")

# ─── Constants ────────────────────────────────────────────────
PYPI_RSS_URL = "https://pypi.org/rss/updates.xml"
POLL_INTERVAL_SECONDS = 60
REDIS_PREFIX = "monitor"
REDIS_LAST_SEEN_KEY = "last_seen_guid"
MAX_RECENT_ENTRIES = 200  # In-memory ring buffer for API queries


class FeedEntry:
    """Parsed + scored representation of a single RSS feed item."""

    __slots__ = (
        "guid", "package_name", "package_version", "title",
        "link", "published", "summary", "anomaly_score",
        "risk_level", "triggered_rules", "processed_at",
    )

    def __init__(
        self,
        guid: str,
        package_name: str,
        package_version: str,
        title: str,
        link: str,
        published: str | None,
        summary: str,
        anomaly_score: float = 0.0,
        risk_level: str = "low",
        triggered_rules: list[str] | None = None,
    ):
        self.guid = guid
        self.package_name = package_name
        self.package_version = package_version
        self.title = title
        self.link = link
        self.published = published
        self.summary = summary
        self.anomaly_score = anomaly_score
        self.risk_level = risk_level
        self.triggered_rules = triggered_rules or []
        self.processed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "guid": self.guid,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "title": self.title,
            "link": self.link,
            "published": self.published,
            "summary": self.summary,
            "anomaly_score": self.anomaly_score,
            "risk_level": self.risk_level,
            "triggered_rules": self.triggered_rules,
            "processed_at": self.processed_at,
        }


class FeedMonitor:
    """
    Async background service that polls the PyPI RSS feed,
    scores new publishes, and feeds results into the provenance
    pipeline.

    Usage (in lifespan):
        monitor = FeedMonitor(redis, postgres, detector)
        await monitor.start()
        ...
        await monitor.stop()
    """

    def __init__(
        self,
        redis: RedisManager,
        postgres: PostgresManager,
        detector: AnomalyDetector,
    ):
        self._redis = redis
        self._postgres = postgres
        self._detector = detector

        # Sub-engines (initialised lazily from singletons)
        self._ledger = LedgerManager(postgres)
        self._alerts = AlertManager(postgres)
        self._trends = TrendAnalyzer(postgres)

        # Background task handle
        self._task: asyncio.Task | None = None
        self._running = False

        # In-memory ring buffer of recent processed entries
        self._recent: deque[FeedEntry] = deque(maxlen=MAX_RECENT_ENTRIES)
        self._seen_packages: set[str] = set()

        # HTTP client for fetching the RSS feed
        self._http: httpx.AsyncClient | None = None

    # ─── Lifecycle ────────────────────────────────────────────

    async def start(self) -> None:
        """Start the background polling loop."""
        if self._running:
            logger.warning("Feed monitor is already running")
            return

        self._http = httpx.AsyncClient(timeout=30.0)
        self._running = True
        
        try:
            seen = await self._redis._client.smembers("monitor:seen_packages")
            self._seen_packages = {s.decode('utf-8') if isinstance(s, bytes) else str(s) for s in seen}
            logger.info(f"Loaded {len(self._seen_packages)} seen packages from Redis")
        except Exception as exc:
            logger.warning(f"Failed to load seen packages from Redis: {exc}")

        self._task = asyncio.create_task(self._poll_loop(), name="feed_monitor")
        logger.info(
            f"Feed monitor started — polling {PYPI_RSS_URL} "
            f"every {POLL_INTERVAL_SECONDS}s"
        )

    async def stop(self) -> None:
        """Stop the background polling loop gracefully."""
        self._running = False

        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        if self._http:
            await self._http.aclose()
            self._http = None

        logger.info("Feed monitor stopped")

    # ─── Public Query API ─────────────────────────────────────

    def get_recent(self, limit: int = 50) -> list[dict]:
        """Return the most recently processed feed entries."""
        entries = list(self._recent)
        entries.reverse()  # newest first
        return [e.to_dict() for e in entries[:limit]]

    def get_status(self) -> dict:
        """Return monitor status for the /status endpoint."""
        return {
            "running": self._running,
            "feed_url": PYPI_RSS_URL,
            "poll_interval_seconds": POLL_INTERVAL_SECONDS,
            "entries_in_buffer": len(self._recent),
            "buffer_capacity": MAX_RECENT_ENTRIES,
        }

    # ─── Core Loop ────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Main polling loop — runs until stop() is called."""
        # Small initial delay to let the app finish starting
        await asyncio.sleep(5)

        while self._running:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Feed poll error: {exc}", exc_info=True)

            # Sleep in small increments so cancellation is responsive
            for _ in range(POLL_INTERVAL_SECONDS):
                if not self._running:
                    break
                await asyncio.sleep(1)

    async def _poll_once(self) -> None:
        """Fetch the RSS feed and process any new entries."""
        logger.debug("Polling PyPI RSS feed...")

        # Fetch raw XML
        try:
            response = await self._http.get(PYPI_RSS_URL)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(f"Failed to fetch RSS feed: {exc}")
            return

        # Parse with feedparser
        feed = await asyncio.to_thread(feedparser.parse, response.text)

        if feed.bozo and not feed.entries:
            logger.warning(f"Feed parse error: {feed.bozo_exception}")
            return

        if not feed.entries:
            logger.debug("No entries in feed")
            return

        # Get last-seen guid from Redis
        last_seen = await self._get_last_seen_guid()

        # Collect new entries (feed is newest-first)
        new_entries: list[dict] = []
        for entry in feed.entries:
            guid = entry.get("id") or entry.get("link", "")
            if guid == last_seen:
                break  # Everything from here on has been processed
            new_entries.append(entry)

        if not new_entries:
            logger.debug("No new entries since last poll")
            return

        logger.info(f"Processing {len(new_entries)} new feed entries")

        # Process in chronological order (oldest first)
        new_entries.reverse()

        for raw_entry in new_entries:
            title = raw_entry.get("title", "")
            package_name, package_version = self._parse_title(title)
            pkg_key = f"{package_name}:{package_version}"
            
            if pkg_key in self._seen_packages:
                continue

            try:
                await self._process_entry(raw_entry)
                
                try:
                    await self._redis._client.sadd("monitor:seen_packages", pkg_key)
                    self._seen_packages.add(pkg_key)
                    
                    if len(self._seen_packages) > 10000:
                        for _ in range(1000):
                            old = self._seen_packages.pop()
                            await self._redis._client.srem("monitor:seen_packages", old)
                except Exception as exc:
                    logger.warning(f"Failed to update seen packages in Redis: {exc}")
                    
            except Exception as exc:
                logger.error(
                    f"Error processing entry '{title}': {exc}",
                    exc_info=True,
                )

        # Update last-seen guid to the newest entry
        newest_guid = (
            feed.entries[0].get("id") or feed.entries[0].get("link", "")
        )
        await self._set_last_seen_guid(newest_guid)

    # ─── Entry Processing Pipeline ────────────────────────────

    async def _process_entry(self, raw: dict) -> None:
        """
        Full pipeline for a single RSS entry:
          1. Parse package name + version
          2. Score with ML engine
          3. Record ledger entry
          4. Generate alerts if warranted
          5. Record trend snapshot
          6. Store in ring buffer
        """
        # ── 1. Parse ──────────────────────────────────────────
        title = raw.get("title", "")
        link = raw.get("link", "")
        guid = raw.get("id") or link
        published = raw.get("published", "")
        summary = raw.get("summary", "")

        package_name, package_version = self._parse_title(title)

        # ── 2. Score with ML engine ───────────────────────────
        ecosystem = "pypi"
        cache_key_suffix = f"{ecosystem}:{package_name}:{package_version}"
        cached_data = None
        try:
            cached_data = await self._redis.get_cached("monitor:scored", cache_key_suffix)
        except Exception as exc:
            logger.warning(f"Failed to read Redis cache for {cache_key_suffix}: {exc}")
        if cached_data and isinstance(cached_data, dict):
            logger.debug(f"Using cached score result for {cache_key_suffix}")
            score_result = {**cached_data, "cached": True}
        elif cached_data:
            logger.debug(f"Using legacy cached score for {cache_key_suffix}")
            score_result = {"anomaly_score": 0.0, "risk_level": "low", "triggered_rules": [], "cached": True}
        else:
            features = self._build_feature_dict(package_name, package_version, raw)
            try:
                score_result = self._detector.score(features)
                try:
                    await self._redis.set_cached(
                        "monitor:scored",
                        cache_key_suffix,
                        {
                            "anomaly_score": score_result.get("anomaly_score", 0.0),
                            "risk_level": score_result.get("risk_level", "low"),
                            "triggered_rules": [
                                r.get("rule", "UNKNOWN") if isinstance(r, dict) else str(r)
                                for r in score_result.get("triggered_rules", [])
                            ],
                        },
                        ttl_seconds=86400,
                    )
                except Exception as exc:
                    logger.warning(f"Failed to write Redis cache for {cache_key_suffix}: {exc}")
            except Exception as exc:
                logger.warning(f"ML scoring failed for {package_name}: {exc}")
                score_result = {"anomaly_score": 0.0, "risk_level": "low", "triggered_rules": []}
        anomaly_score = score_result.get("anomaly_score", 0.0)
        risk_level = score_result.get("risk_level", "low")
        triggered_rules = [
            r.get("rule", "UNKNOWN") if isinstance(r, dict) else str(r)
            for r in score_result.get("triggered_rules", [])
        ]

        # ── 3. Record in provenance ledger ────────────────────
        try:
            await self._ledger.record_entry(
                package_name=package_name,
                package_version=package_version,
                ecosystem="pypi",
                anomaly_score=anomaly_score,
                flags_triggered=triggered_rules if triggered_rules else None,
            )
        except Exception as exc:
            logger.error(f"Ledger recording failed for {package_name}: {exc}")

        # ── 4. Generate alerts if high/critical ───────────────
        if risk_level in ("high", "critical"):
            try:
                await self._alerts.generate_from_anomaly(
                    anomaly_result=score_result,
                    package_name=package_name,
                    package_version=package_version,
                )
            except Exception as exc:
                logger.error(f"Alert generation failed for {package_name}: {exc}")

        # ── 5. Record trend snapshot ──────────────────────────
        try:
            await self._trends.record(
                entity_type="package",
                entity_name=package_name,
                ecosystem="pypi",
                anomaly_score=anomaly_score,
                trust_score=None,
                risk_level=risk_level,
                triggered_rules=triggered_rules if triggered_rules else None,
            )
        except Exception as exc:
            logger.error(f"Trend recording failed for {package_name}: {exc}")

        # ── 6. Store in ring buffer ───────────────────────────
        entry = FeedEntry(
            guid=guid,
            package_name=package_name,
            package_version=package_version,
            title=title,
            link=link,
            published=published,
            summary=summary,
            anomaly_score=anomaly_score,
            risk_level=risk_level,
            triggered_rules=triggered_rules,
        )
        self._recent.append(entry)

        log_level = logging.WARNING if risk_level in ("high", "critical") else logging.DEBUG
        logger.log(
            log_level,
            f"{'⚠️ ' if risk_level in ('high', 'critical') else ''}"
            f"{package_name}@{package_version} — "
            f"score={anomaly_score:.1f} risk={risk_level}",
        )

    # ─── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _parse_title(title: str) -> tuple[str, str]:
        """
        Parse package name and version from an RSS entry title.
        PyPI titles are typically: "package-name 1.2.3"
        """
        parts = title.strip().rsplit(" ", 1)
        if len(parts) == 2:
            return parts[0].strip(), parts[1].strip()
        return title.strip(), "unknown"

    @staticmethod
    def _build_feature_dict(
        package_name: str,
        package_version: str,
        raw_entry: dict,
    ) -> dict:
        """
        Build a feature dict suitable for AnomalyDetector.score().

        Since we only have RSS metadata (no deep inspection), we
        use conservative defaults and let the ML model + rules
        assess based on the available signals.
        """
        name_lower = package_name.lower()

        # Heuristic: very short names are more likely typosquats
        typo_distance = max(3, len(name_lower))

        # Heuristic: version "0.0.1" or "0.1.0" → brand new package
        is_initial = package_version in ("0.0.1", "0.1.0", "0.0.0", "1.0.0")

        return {
            "account_age_days": 180 if not is_initial else 30,
            "repo_count": 5,
            "avg_commits_per_week": 3,
            "followers": 5,
            "commit_hour_deviation": 0,
            "is_new_maintainer": 1 if is_initial else 0,
            "days_since_last_commit": 7,
            "version_jump_size": 0,
            "dependency_count_delta": 0,
            "has_install_scripts": 0,
            "binary_files_added": 0,
            "obfuscated_code_score": 0,
            "trust_score": 40 if is_initial else 60,
            "typosquat_distance": typo_distance,
            "contributor_count_change": 0,
        }

    async def _get_last_seen_guid(self) -> str | None:
        """Retrieve the last-seen RSS entry guid from Redis."""
        try:
            result = await self._redis.get_cached(
                REDIS_PREFIX, REDIS_LAST_SEEN_KEY
            )
            if isinstance(result, str):
                return result
            if isinstance(result, dict):
                return result.get("guid")
            return None
        except Exception as exc:
            logger.warning(f"Failed to get last-seen guid from Redis: {exc}")
            return None

    async def _set_last_seen_guid(self, guid: str) -> None:
        """Store the last-seen RSS entry guid in Redis (no expiry)."""
        try:
            await self._redis.set_cached(
                REDIS_PREFIX,
                REDIS_LAST_SEEN_KEY,
                {"guid": guid},
                ttl_seconds=86400 * 30,  # 30-day TTL (effectively permanent)
            )
        except Exception as exc:
            logger.warning(f"Failed to set last-seen guid in Redis: {exc}")
