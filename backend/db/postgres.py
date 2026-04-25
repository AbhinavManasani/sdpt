"""
Software Provenance Tracker — PostgreSQL Connection Manager

Async PostgreSQL connection using SQLAlchemy 2.0 async engine.
Manages connection lifecycle and provides the session factory
used by all database operations throughout the application.

Tables stored in PostgreSQL:
  - contributor_baseline    (behavioral baselines per contributor)
  - contributor_events      (raw commit/access events)
  - anomaly_scores          (ML + rule scores per event)
  - alerts                  (generated alerts with severity)
  - provenance_ledger       (append-only hash-chained records)
  - scan_history            (scan jobs and results)
  - projects                (tracked projects metadata)
  - diff_results            (version diff analysis results)
  - anomaly_trends          (historical anomaly/trust score snapshots)
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    BigInteger,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

logger = logging.getLogger("provenance.db.postgres")


# ─── Base Model ───────────────────────────────────────────────
class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


# ─── ORM Models ──────────────────────────────────────────────

class Project(Base):
    """A software project being tracked."""
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    ecosystem = Column(String(50), nullable=False)  # "pypi" or "npm"
    source_url = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    last_scanned = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_projects_name_ecosystem", "name", "ecosystem", unique=True),
    )


class ContributorBaseline(Base):
    """Behavioral baseline for a GitHub contributor."""
    __tablename__ = "contributor_baseline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    github_username = Column(String(255), nullable=False, unique=True, index=True)
    account_age_days = Column(Integer, nullable=False)
    avg_commits_per_week = Column(Float, nullable=False)
    typical_commit_hour = Column(Integer, nullable=True)  # 0-23 UTC
    avg_lines_changed = Column(Float, nullable=False)
    repo_count = Column(Integer, nullable=False)
    primary_languages = Column(ARRAY(String), nullable=True)
    first_seen = Column(DateTime, nullable=False)
    last_updated = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc), nullable=False)


class ContributorEvent(Base):
    """Raw contributor activity event."""
    __tablename__ = "contributor_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    github_username = Column(String(255), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # "commit", "access_granted", "release_published"
    repo_name = Column(String(255), nullable=False)
    event_timestamp = Column(DateTime, nullable=False)
    details = Column(JSONB, nullable=True)  # Flexible JSON for event-specific data
    created_at = Column(DateTime, default=datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_events_user_timestamp", "github_username", "event_timestamp"),
    )


class AnomalyScore(Base):
    """Combined ML + rule-based anomaly score for an event."""
    __tablename__ = "anomaly_scores"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    event_id = Column(BigInteger, ForeignKey("contributor_events.id"), nullable=False, index=True)
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=True)
    ml_score = Column(Float, nullable=False)  # Isolation Forest score (more negative = more anomalous)
    rule_flags = Column(ARRAY(String), nullable=True)  # Which hard rules triggered
    combined_score = Column(Float, nullable=False)  # Final composite score
    feature_vector = Column(JSONB, nullable=True)  # The features that produced this score
    created_at = Column(DateTime, default=datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_anomaly_package", "package_name", "created_at"),
    )


class Alert(Base):
    """Generated security alert."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    anomaly_score_id = Column(BigInteger, ForeignKey("anomaly_scores.id"), nullable=True)
    severity = Column(String(20), nullable=False)  # "critical", "high", "medium", "low"
    alert_type = Column(String(100), nullable=False)  # "typosquatting", "maintainer_elevation", etc.
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=True)
    contributor_username = Column(String(255), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)  # Human-readable explanation
    baseline_summary = Column(Text, nullable=True)  # What "normal" looked like
    evidence = Column(JSONB, nullable=True)  # Supporting data
    status = Column(String(20), default="open", nullable=False)  # "open", "investigating", "resolved", "dismissed"
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_package", "package_name"),
    )


class ProvenanceLedger(Base):
    """Append-only, hash-chained provenance record for package versions."""
    __tablename__ = "provenance_ledger"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), nullable=False)
    scan_id = Column(BigInteger, ForeignKey("scan_history.id"), nullable=True, index=True)
    publisher_github_id = Column(String(255), nullable=True)
    publish_timestamp = Column(DateTime, nullable=False)
    dependency_graph_hash = Column(String(64), nullable=False)  # SHA-256
    source_commit_hash = Column(String(64), nullable=True)
    build_artifact_hash = Column(String(64), nullable=True)
    anomaly_score = Column(Float, nullable=True)
    flags_triggered = Column(ARRAY(String), nullable=True)
    previous_entry_hash = Column(String(64), nullable=True)  # Chains to previous record
    entry_hash = Column(String(64), nullable=False, unique=True)  # This record's hash
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_ledger_package_version", "package_name", "package_version"),
        Index("ix_ledger_entry_hash", "entry_hash"),
    )


class ScanHistory(Base):
    """Record of dependency scan jobs and their results."""
    __tablename__ = "scan_history"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    project_name = Column(String(255), nullable=False)
    ecosystem = Column(String(50), nullable=False)
    file_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, default="completed")
    total_packages = Column(Integer, nullable=False, default=0)
    direct_dependencies = Column(Integer, nullable=False, default=0)
    transitive_dependencies = Column(Integer, nullable=False, default=0)
    scan_duration_seconds = Column(Float, nullable=True)
    packages_scored = Column(Integer, default=0)
    high_risk = Column(Integer, default=0)
    critical_risk = Column(Integer, default=0)
    alerts_generated = Column(Integer, default=0)
    packages = Column(JSONB, nullable=True)
    sbom_path = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_scan_history_project", "project_name"),
        Index("ix_scan_history_created", "created_at"),
    )


class CveFinding(Base):
    """CVE vulnerability finding linked to a dependency scan."""
    __tablename__ = "cve_findings"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey("scan_history.id"), nullable=True, index=True)
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=True)
    ecosystem = Column(String(50), nullable=False)
    cve_id = Column(String(20), nullable=False)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    published_date = Column(String(50), nullable=True)
    last_modified = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_cve_findings_package", "package_name"),
        Index("ix_cve_findings_cve_id", "cve_id"),
        Index("ix_cve_findings_scan", "scan_id"),
    )


class DiffResult(Base):
    """Stores version diff analysis results."""
    __tablename__ = "diff_results"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    package_name = Column(String(255), nullable=False)
    ecosystem = Column(String(50), nullable=False)
    version_from = Column(String(100), nullable=False)
    version_to = Column(String(100), nullable=False)
    new_dependencies = Column(ARRAY(String), nullable=True)
    removed_dependencies = Column(ARRAY(String), nullable=True)
    changed_dependencies = Column(JSONB, nullable=True)
    install_scripts_added = Column(Boolean, nullable=False, default=False)
    binary_files_added = Column(Boolean, nullable=False, default=False)
    maintainer_changed = Column(Boolean, nullable=False, default=False)
    dependency_count_delta = Column(Integer, nullable=False, default=0)
    version_jump = Column(String(20), nullable=True)
    risk_score = Column(Float, nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_diff_results_package", "package_name", "ecosystem"),
        Index("ix_diff_results_created", "created_at"),
    )


class AnomalyTrend(Base):
    """Historical snapshot of anomaly/trust scores for trending analysis."""
    __tablename__ = "anomaly_trends"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    entity_type = Column(String(20), nullable=False)        # "package" or "contributor"
    entity_name = Column(String(255), nullable=False)       # package name or github username
    ecosystem = Column(String(50), nullable=True)           # "pypi", "npm", or null for contributors
    anomaly_score = Column(Float, nullable=True)
    trust_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=False)         # "critical", "high", "medium", "low"
    triggered_rules = Column(ARRAY(String), nullable=True)
    recorded_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_anomaly_trends_entity", "entity_type", "entity_name", "recorded_at"),
    )


# ─── Connection Manager ──────────────────────────────────────


class PostgresManager:
    """
    Manages async SQLAlchemy engine and session factory.
    Used by main.py lifespan for startup/shutdown.
    """

    def __init__(self):
        self.engine = None
        self.session_factory = None

    async def connect(self, dsn: str) -> None:
        """Create async engine and session factory. Creates all tables."""
        self.engine = create_async_engine(
            dsn,
            echo=False,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("PostgreSQL tables created/verified")

    async def disconnect(self) -> None:
        """Close the engine and all connections."""
        if self.engine:
            await self.engine.dispose()
            logger.info("PostgreSQL engine disposed")

    def get_session(self) -> AsyncSession:
        """Returns a new async session. Use with 'async with'."""
        if not self.session_factory:
            raise RuntimeError("PostgreSQL not connected. Call connect() first.")
        return self.session_factory()

    async def health_check(self) -> None:
        """Verify PostgreSQL is reachable by executing a simple query."""
        if not self.engine:
            raise RuntimeError("PostgreSQL engine not initialized")
        async with self.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
