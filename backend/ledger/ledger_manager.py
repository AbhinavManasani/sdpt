"""
Software Provenance Tracker — Provenance Ledger Manager

Append-only, hash-chained provenance ledger for tracking
every package version event with tamper-evident integrity.

Each entry contains:
  - Package identity (name, version, ecosystem)
  - Publisher identity (GitHub username)
  - Dependency graph hash
  - Source commit and build artifact hashes
  - Anomaly score at time of recording
  - SHA-256 hash chaining to previous entry

The chain creates a tamper-evident audit trail.
If any past entry is modified, the hash chain breaks
and verify_chain() detects the tampering.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select, func, desc

from db.postgres import PostgresManager, ProvenanceLedger

logger = logging.getLogger("provenance.ledger.manager")


class LedgerManager:
    """
    Manages the append-only, hash-chained provenance ledger.

    Every operation that changes the state of a tracked package
    gets recorded as a ledger entry. Entries are chained via
    SHA-256 hashes — each entry includes the hash of the
    previous entry, forming an immutable audit trail.
    """

    def __init__(self, postgres: PostgresManager):
        self._postgres = postgres

    # ─── Write Operations ─────────────────────────────────────

    async def record_entry(
        self,
        package_name: str,
        package_version: str,
        ecosystem: str,
        publisher_github_id: str | None = None,
        publish_timestamp: datetime | None = None,
        dependency_graph_hash: str | None = None,
        source_commit_hash: str | None = None,
        build_artifact_hash: str | None = None,
        anomaly_score: float | None = None,
        flags_triggered: list[str] | None = None,
        scan_id: int | None = None,
    ) -> dict:
        """
        Record a new provenance entry in the ledger.

        Automatically:
          1. Fetches the most recent entry's hash for chaining
          2. Computes SHA-256 hash of all entry data
          3. Links to previous entry via previous_entry_hash
          4. Stores the entry in PostgreSQL

        Returns the created ledger entry as a dict.
        """
        if publish_timestamp is None:
            publish_timestamp = datetime.utcnow()

        # Compute dependency graph hash if not provided
        if dependency_graph_hash is None:
            dependency_graph_hash = self._compute_placeholder_hash(
                package_name, package_version, ecosystem
            )

        async with self._postgres.get_session() as session:
            # Get the hash of the most recent entry for chaining
            previous_hash = await self._get_latest_hash(session)

            # Compute this entry's hash
            entry_data = {
                "package_name": package_name,
                "package_version": package_version,
                "ecosystem": ecosystem,
                "publisher_github_id": publisher_github_id,
                "publish_timestamp": publish_timestamp.isoformat(),
                "dependency_graph_hash": dependency_graph_hash,
                "source_commit_hash": source_commit_hash,
                "build_artifact_hash": build_artifact_hash,
                "anomaly_score": anomaly_score,
                "flags_triggered": flags_triggered,
                "previous_entry_hash": previous_hash,
            }
            entry_hash = self._compute_hash(entry_data)

            # Create the ledger entry
            entry = ProvenanceLedger(
                package_name=package_name,
                package_version=package_version,
                ecosystem=ecosystem,
                scan_id=scan_id,
                publisher_github_id=publisher_github_id,
                publish_timestamp=publish_timestamp,
                dependency_graph_hash=dependency_graph_hash,
                source_commit_hash=source_commit_hash,
                build_artifact_hash=build_artifact_hash,
                anomaly_score=anomaly_score,
                flags_triggered=flags_triggered,
                previous_entry_hash=previous_hash,
                entry_hash=entry_hash,
            )

            session.add(entry)
            await session.commit()
            await session.refresh(entry)

            logger.info(
                f"Ledger entry #{entry.id}: {package_name}@{package_version} "
                f"({ecosystem}) — hash: {entry_hash[:12]}..."
            )

            return self._entry_to_dict(entry)

    # ─── Read Operations ──────────────────────────────────────

    async def get_entry(self, entry_id: int) -> dict | None:
        """Get a single ledger entry by ID."""
        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(ProvenanceLedger).where(ProvenanceLedger.id == entry_id)
            )
            entry = result.scalar_one_or_none()
            if entry is None:
                return None
            return self._entry_to_dict(entry)

    async def get_entry_by_hash(self, entry_hash: str) -> dict | None:
        """Get a single ledger entry by its SHA-256 hash."""
        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(ProvenanceLedger).where(
                    ProvenanceLedger.entry_hash == entry_hash
                )
            )
            entry = result.scalar_one_or_none()
            if entry is None:
                return None
            return self._entry_to_dict(entry)

    async def get_package_history(
        self,
        package_name: str,
        ecosystem: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """
        Get all ledger entries for a package, most recent first.
        Optionally filter by ecosystem.
        """
        async with self._postgres.get_session() as session:
            query = select(ProvenanceLedger).where(
                ProvenanceLedger.package_name == package_name
            )
            if ecosystem:
                query = query.where(ProvenanceLedger.ecosystem == ecosystem)
            query = query.order_by(desc(ProvenanceLedger.id)).limit(limit)

            result = await session.execute(query)
            entries = result.scalars().all()
            return [self._entry_to_dict(e) for e in entries]

    async def get_recent_entries(self, limit: int = 50) -> list[dict]:
        """Get the most recent ledger entries across all packages."""
        async with self._postgres.get_session() as session:
            query = (
                select(ProvenanceLedger)
                .order_by(desc(ProvenanceLedger.id))
                .limit(limit)
            )
            result = await session.execute(query)
            entries = result.scalars().all()
            return [self._entry_to_dict(e) for e in entries]

    async def get_entries_by_scan(self, scan_id: int, limit: int = 200) -> list[dict]:
        """Get all ledger entries recorded during a specific scan, most recent first."""
        async with self._postgres.get_session() as session:
            query = (
                select(ProvenanceLedger)
                .where(ProvenanceLedger.scan_id == scan_id)
                .order_by(desc(ProvenanceLedger.id))
                .limit(limit)
            )
            result = await session.execute(query)
            entries = result.scalars().all()
            return [self._entry_to_dict(e) for e in entries]

    async def get_flagged_entries(self, limit: int = 50) -> list[dict]:
        """Get entries that triggered anomaly flags."""
        async with self._postgres.get_session() as session:
            query = (
                select(ProvenanceLedger)
                .where(ProvenanceLedger.flags_triggered != None)  # noqa: E711
                .where(func.array_length(ProvenanceLedger.flags_triggered, 1) > 0)
                .order_by(desc(ProvenanceLedger.id))
                .limit(limit)
            )
            result = await session.execute(query)
            entries = result.scalars().all()
            return [self._entry_to_dict(e) for e in entries]

    # ─── Chain Verification ───────────────────────────────────

    async def verify_chain(self, limit: int = 0) -> dict:
        """
        Verify the integrity of the hash chain.

        Walks the ledger from oldest to newest and verifies:
          1. Each entry's hash matches its recomputed hash
          2. Each entry's previous_entry_hash matches the prior entry's hash
          3. The genesis entry (first) has previous_entry_hash = None

        Args:
            limit: Number of most recent entries to verify (0 = all)

        Returns:
            Verification result with status, entries checked,
            and details of any tampering detected.
        """
        async with self._postgres.get_session() as session:
            query = select(ProvenanceLedger).order_by(ProvenanceLedger.id)
            if limit > 0:
                # Get the N most recent, but verify in order
                subquery = (
                    select(ProvenanceLedger.id)
                    .order_by(desc(ProvenanceLedger.id))
                    .limit(limit)
                )
                sub_result = await session.execute(subquery)
                ids = [row[0] for row in sub_result.all()]
                if not ids:
                    return {"status": "empty", "message": "No entries in ledger"}
                query = (
                    select(ProvenanceLedger)
                    .where(ProvenanceLedger.id.in_(ids))
                    .order_by(ProvenanceLedger.id)
                )

            result = await session.execute(query)
            entries = result.scalars().all()

        if not entries:
            return {"status": "empty", "message": "No entries in ledger"}

        # Verify each entry
        violations = []
        previous_hash = None

        for i, entry in enumerate(entries):
            # Recompute hash
            entry_data = {
                "package_name": entry.package_name,
                "package_version": entry.package_version,
                "ecosystem": entry.ecosystem,
                "publisher_github_id": entry.publisher_github_id,
                "publish_timestamp": entry.publish_timestamp.isoformat() if entry.publish_timestamp else None,
                "dependency_graph_hash": entry.dependency_graph_hash,
                "source_commit_hash": entry.source_commit_hash,
                "build_artifact_hash": entry.build_artifact_hash,
                "anomaly_score": entry.anomaly_score,
                "flags_triggered": entry.flags_triggered,
                "previous_entry_hash": entry.previous_entry_hash,
            }
            recomputed = self._compute_hash(entry_data)

            # Check 1: Hash integrity
            if recomputed != entry.entry_hash:
                violations.append({
                    "entry_id": entry.id,
                    "type": "hash_mismatch",
                    "expected": entry.entry_hash,
                    "computed": recomputed,
                    "detail": f"Entry #{entry.id} has been tampered with. "
                              f"Stored hash does not match recomputed hash.",
                })

            # Check 2: Chain continuity (skip for entries outside our limit window)
            if i == 0 and limit == 0:
                # Genesis entry should have no previous hash
                if entry.previous_entry_hash is not None:
                    violations.append({
                        "entry_id": entry.id,
                        "type": "genesis_violation",
                        "detail": "First entry has a previous_entry_hash but shouldn't.",
                    })
            elif i > 0:
                # Non-genesis: previous hash should match prior entry's hash
                if entry.previous_entry_hash != previous_hash:
                    violations.append({
                        "entry_id": entry.id,
                        "type": "chain_break",
                        "expected_previous": previous_hash,
                        "actual_previous": entry.previous_entry_hash,
                        "detail": f"Chain broken at entry #{entry.id}. "
                                  f"Previous hash does not match prior entry.",
                    })

            previous_hash = entry.entry_hash

        if violations:
            return {
                "status": "tampered",
                "entries_checked": len(entries),
                "violations_found": len(violations),
                "violations": violations,
                "message": f"⚠️ INTEGRITY VIOLATION: {len(violations)} "
                           f"issue(s) detected in the provenance chain.",
            }

        return {
            "status": "verified",
            "entries_checked": len(entries),
            "violations_found": 0,
            "first_entry_id": entries[0].id,
            "last_entry_id": entries[-1].id,
            "message": f"✅ Chain integrity verified across {len(entries)} entries.",
        }

    # ─── Statistics ───────────────────────────────────────────

    async def get_stats(self) -> dict:
        """Get ledger statistics for the dashboard."""
        async with self._postgres.get_session() as session:
            # Total entries
            total_result = await session.execute(
                select(func.count(ProvenanceLedger.id))
            )
            total = total_result.scalar() or 0

            # Unique packages
            packages_result = await session.execute(
                select(func.count(func.distinct(ProvenanceLedger.package_name)))
            )
            unique_packages = packages_result.scalar() or 0

            # Flagged entries
            flagged_result = await session.execute(
                select(func.count(ProvenanceLedger.id)).where(
                    ProvenanceLedger.flags_triggered != None,  # noqa: E711
                    func.array_length(ProvenanceLedger.flags_triggered, 1) > 0,
                )
            )
            flagged = flagged_result.scalar() or 0

            # Latest entry
            latest_result = await session.execute(
                select(ProvenanceLedger)
                .order_by(desc(ProvenanceLedger.id))
                .limit(1)
            )
            latest = latest_result.scalar_one_or_none()

            return {
                "total_entries": total,
                "unique_packages": unique_packages,
                "flagged_entries": flagged,
                "latest_entry": self._entry_to_dict(latest) if latest else None,
            }

    # ─── Private Helpers ──────────────────────────────────────

    @staticmethod
    def _compute_hash(data: dict) -> str:
        """
        Compute SHA-256 hash of a dict.
        Uses sorted JSON serialization for deterministic ordering.
        """
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _compute_placeholder_hash(
        package_name: str, version: str, ecosystem: str
    ) -> str:
        """Compute a placeholder dependency graph hash from package identity."""
        data = f"{ecosystem}:{package_name}@{version}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    async def _get_latest_hash(session) -> str | None:
        """Get the hash of the most recent ledger entry for chaining."""
        result = await session.execute(
            select(ProvenanceLedger.entry_hash)
            .order_by(desc(ProvenanceLedger.id))
            .limit(1)
        )
        row = result.scalar_one_or_none()
        return row

    @staticmethod
    def _entry_to_dict(entry: ProvenanceLedger) -> dict:
        """Convert a ledger ORM entry to a dict."""
        return {
            "id": entry.id,
            "package_name": entry.package_name,
            "package_version": entry.package_version,
            "ecosystem": entry.ecosystem,
            "publisher_github_id": entry.publisher_github_id,
            "publish_timestamp": entry.publish_timestamp.isoformat() if entry.publish_timestamp else None,
            "dependency_graph_hash": entry.dependency_graph_hash,
            "source_commit_hash": entry.source_commit_hash,
            "build_artifact_hash": entry.build_artifact_hash,
            "anomaly_score": entry.anomaly_score,
            "flags_triggered": entry.flags_triggered,
            "previous_entry_hash": entry.previous_entry_hash,
            "entry_hash": entry.entry_hash,
            "scan_id": entry.scan_id,
            "created_at": entry.created_at.isoformat() if entry.created_at else None,
        }
