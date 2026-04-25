"""
Software Provenance Tracker — CVE API Router

Exposes REST endpoints for CVE vulnerability data:
  - POST /check — check a single package for CVEs
  - GET /scan/{scan_id} — get all CVE findings for a scan
  - GET /package/{ecosystem}/{name} — CVE history for a package
  - POST /scan/{scan_id}/refresh — force re-check (bypass cache)
  - GET /stats — overall CVE statistics
"""

import logging

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from cve.cve_analyzer import CveAnalyzer
from db.redis_conn import RedisManager
from db.postgres import PostgresManager, ScanHistory
from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.cve")

router = APIRouter(
    prefix="/api/cve",
    tags=["cve"],
    dependencies=[Depends(verify_api_key)],
)

# ─── Engine Instance ──────────────────────────────────────────

_analyzer: CveAnalyzer | None = None
_postgres: PostgresManager | None = None


def setup_cve_engine(postgres: PostgresManager, redis: RedisManager) -> None:
    """Initialize the CVE analyzer. Called during app startup."""
    global _analyzer, _postgres
    _analyzer = CveAnalyzer(redis=redis, postgres=postgres)
    _postgres = postgres
    logger.info("CVE engine initialized")


async def cleanup_cve_engine() -> None:
    """Close the CVE analyzer. Called during app shutdown."""
    global _analyzer
    if _analyzer:
        await _analyzer.close()
        _analyzer = None
    logger.info("CVE engine closed")


def get_cve_analyzer() -> CveAnalyzer | None:
    """Return the shared CveAnalyzer instance."""
    return _analyzer


def _get_analyzer() -> CveAnalyzer:
    """Get the analyzer instance, raising if not initialized."""
    if _analyzer is None:
        raise HTTPException(
            status_code=503,
            detail="CVE engine not initialized",
        )
    return _analyzer


# ─── Request / Response Models ────────────────────────────────

class PackageCveRequest(BaseModel):
    """Request body for checking a single package."""
    package_name: str = Field(..., description="Package name to check")
    package_version: str = Field(default="", description="Package version")
    ecosystem: str = Field(default="pypi", description="Ecosystem: pypi or npm")


# ─── Endpoints ────────────────────────────────────────────────

@router.post("/check")
async def check_package_cves(request: PackageCveRequest):
    """
    Check a single package for known CVEs.
    Queries the NVD API and returns matching vulnerabilities.
    Results are cached in Redis for 24 hours.
    """
    analyzer = _get_analyzer()

    if request.ecosystem not in ("pypi", "npm"):
        raise HTTPException(
            status_code=400,
            detail="Ecosystem must be 'pypi' or 'npm'",
        )

    try:
        findings = await analyzer.check_package(
            package_name=request.package_name,
            package_version=request.package_version,
            ecosystem=request.ecosystem,
        )

        return {
            "package_name": request.package_name,
            "package_version": request.package_version,
            "ecosystem": request.ecosystem,
            "total_cves": len(findings),
            "findings": findings,
        }

    except Exception as e:
        logger.error(f"CVE check failed for {request.package_name}: {e}")
        raise HTTPException(status_code=500, detail=f"CVE check failed: {str(e)}")


@router.get("/scan/{scan_id}")
async def get_scan_cves(scan_id: int):
    """
    Get all CVE findings for a specific scan.
    Returns findings sorted by CVSS score (highest first).
    """
    analyzer = _get_analyzer()

    findings = await analyzer.get_findings_by_scan(scan_id)

    # Build severity summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "unknown")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "scan_id": scan_id,
        "total_cves": len(findings),
        "by_severity": severity_counts,
        "findings": findings,
    }


@router.get("/package/{ecosystem}/{package_name}")
async def get_package_cves(
    package_name: str,
    ecosystem: str,
    limit: int = Query(default=50, ge=1, le=200),
):
    """
    Get all stored CVE findings for a specific package.
    Returns findings sorted by CVSS score (highest first).
    """
    analyzer = _get_analyzer()

    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(
            status_code=400,
            detail="Ecosystem must be 'pypi' or 'npm'",
        )

    findings = await analyzer.get_findings_by_package(
        package_name=package_name,
        ecosystem=ecosystem,
        limit=limit,
    )

    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "total_cves": len(findings),
        "findings": findings,
    }


@router.post("/scan/{scan_id}/refresh")
async def refresh_scan_cves(scan_id: int):
    """
    Force re-check CVEs for all packages in a scan.
    Bypasses Redis cache, deletes old findings, and re-queries NVD.
    Use this to get the latest vulnerability data.
    """
    analyzer = _get_analyzer()

    if _postgres is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    # Fetch the scan record to get packages and ecosystem
    async with _postgres.get_session() as session:
        result = await session.execute(
            select(ScanHistory).where(ScanHistory.id == scan_id)
        )
        scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    packages = scan.packages or []
    ecosystem = scan.ecosystem or "pypi"

    if not packages:
        return {
            "scan_id": scan_id,
            "message": "No packages to check",
            "total_cves": 0,
            "findings": [],
        }

    try:
        summary = await analyzer.refresh_scan_packages(
            packages=packages,
            ecosystem=ecosystem,
            scan_id=scan_id,
        )

        return {
            "scan_id": scan_id,
            "message": "CVE data refreshed from NVD",
            **summary,
        }

    except Exception as e:
        logger.error(f"CVE refresh failed for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"CVE refresh failed: {str(e)}",
        )


@router.get("/stats")
async def get_cve_stats():
    """
    Get CVE finding statistics for the dashboard.
    Returns total findings, unique CVEs, affected packages,
    and breakdown by severity.
    """
    analyzer = _get_analyzer()
    return await analyzer.get_stats()
