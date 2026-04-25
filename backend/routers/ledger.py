"""
Software Provenance Tracker — Ledger API Router

Exposes REST endpoints for the provenance ledger:
  - Record new entries
  - Get entries by ID / hash
  - Get package history
  - Verify chain integrity
  - Get ledger stats
"""

import logging

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from db.postgres import PostgresManager
from ledger.ledger_manager import LedgerManager

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.ledger")

router = APIRouter(prefix="/api/ledger", tags=["ledger"], dependencies=[Depends(verify_api_key)])


# ─── Request Models ───────────────────────────────────────────

class RecordEntryRequest(BaseModel):
    """Request body for recording a new ledger entry."""
    package_name: str = Field(..., min_length=1, max_length=255)
    package_version: str = Field(..., min_length=1, max_length=100)
    ecosystem: str = Field(..., description="pypi or npm")
    publisher_github_id: str | None = Field(default=None, max_length=255)
    dependency_graph_hash: str | None = Field(default=None, max_length=64)
    source_commit_hash: str | None = Field(default=None, max_length=64)
    build_artifact_hash: str | None = Field(default=None, max_length=64)
    anomaly_score: float | None = Field(default=None, ge=0, le=100)
    flags_triggered: list[str] | None = Field(default=None)


# ─── Ledger Instance ─────────────────────────────────────────

_ledger: LedgerManager | None = None


def setup_ledger_engine(postgres: PostgresManager) -> None:
    """Initialize the LedgerManager. Called during app startup."""
    global _ledger
    _ledger = LedgerManager(postgres=postgres)
    logger.info("Ledger router engine initialized")


def cleanup_ledger_engine() -> None:
    """Clean up the LedgerManager. Called during app shutdown."""
    global _ledger
    _ledger = None


def _get_ledger() -> LedgerManager:
    """Get the ledger instance, raising if not initialized."""
    if _ledger is None:
        raise HTTPException(
            status_code=503,
            detail="Ledger not initialized. Server may still be starting up.",
        )
    return _ledger


# ─── Endpoints ────────────────────────────────────────────────


@router.post("/record")
async def record_entry(request: RecordEntryRequest):
    """
    Record a new provenance entry in the ledger.

    Automatically chains to the previous entry via SHA-256 hash.
    Returns the created entry with its hash.
    """
    ledger = _get_ledger()

    if request.ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="Ecosystem must be 'pypi' or 'npm'")

    try:
        entry = await ledger.record_entry(
            package_name=request.package_name,
            package_version=request.package_version,
            ecosystem=request.ecosystem,
            publisher_github_id=request.publisher_github_id,
            dependency_graph_hash=request.dependency_graph_hash,
            source_commit_hash=request.source_commit_hash,
            build_artifact_hash=request.build_artifact_hash,
            anomaly_score=request.anomaly_score,
            flags_triggered=request.flags_triggered,
        )
    except Exception as e:
        logger.error(f"Ledger record failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to record entry: {str(e)}")

    return entry


@router.get("/entry/{entry_id}")
async def get_entry(entry_id: int):
    """Get a single ledger entry by its ID."""
    ledger = _get_ledger()

    entry = await ledger.get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Ledger entry #{entry_id} not found")

    return entry


@router.get("/hash/{entry_hash}")
async def get_entry_by_hash(entry_hash: str):
    """Get a single ledger entry by its SHA-256 hash."""
    ledger = _get_ledger()

    entry = await ledger.get_entry_by_hash(entry_hash)
    if entry is None:
        raise HTTPException(status_code=404, detail="No entry found with that hash")

    return entry


@router.get("/package/{package_name}")
async def get_package_history(
    package_name: str,
    ecosystem: str | None = Query(default=None, description="Filter by ecosystem"),
    limit: int = Query(default=50, ge=1, le=200),
):
    """
    Get the provenance history for a package.
    Returns all ledger entries, most recent first.
    """
    ledger = _get_ledger()

    entries = await ledger.get_package_history(
        package_name=package_name,
        ecosystem=ecosystem,
        limit=limit,
    )

    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "total_entries": len(entries),
        "entries": entries,
    }


@router.get("/recent")
async def get_recent_entries(
    limit: int = Query(default=50, ge=1, le=200),
    scan_id: int | None = Query(default=None, description="Filter entries by scan ID"),
):
    """Get the most recent ledger entries across all packages.

    If scan_id is provided, returns only entries recorded during that scan.
    """
    ledger = _get_ledger()

    if scan_id is not None:
        entries = await ledger.get_entries_by_scan(scan_id=scan_id, limit=limit)
    else:
        entries = await ledger.get_recent_entries(limit=limit)

    return {
        "total_entries": len(entries),
        "entries": entries,
        **({"scan_id": scan_id} if scan_id is not None else {}),
    }


@router.get("/flagged")
async def get_flagged_entries(
    limit: int = Query(default=50, ge=1, le=200),
):
    """Get entries that triggered anomaly flags."""
    ledger = _get_ledger()

    entries = await ledger.get_flagged_entries(limit=limit)

    return {
        "total_flagged": len(entries),
        "entries": entries,
    }


@router.get("/verify")
async def verify_chain(
    limit: int = Query(default=0, ge=0, description="0 = verify all entries"),
):
    """
    Verify the integrity of the hash chain.

    Walks the ledger and checks:
      1. Each entry's hash matches its recomputed hash
      2. Each entry's previous_entry_hash matches the prior entry
      3. The genesis entry has no previous hash

    Returns 'verified' or 'tampered' with violation details.
    """
    ledger = _get_ledger()

    try:
        result = await ledger.verify_chain(limit=limit)
    except Exception as e:
        logger.error(f"Chain verification failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

    return result


@router.get("/stats")
async def get_ledger_stats():
    """
    Get ledger statistics for the dashboard.
    Total entries, unique packages, flagged count, latest entry.
    """
    ledger = _get_ledger()

    try:
        stats = await ledger.get_stats()
    except Exception as e:
        logger.error(f"Ledger stats failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return stats
