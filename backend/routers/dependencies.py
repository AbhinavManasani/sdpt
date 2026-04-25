"""
Software Provenance Tracker — Dependencies API Router

Exposes REST endpoints for dependency graph operations:
  - Scan a project (upload dependency file content)
  - Query the dependency tree
  - Get graph visualization data
  - Get dependents (impact analysis)
  - Get graph statistics
"""

import asyncio
import logging
import json
import os

from sqlalchemy import update

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from db.neo4j_conn import Neo4jManager
from db.redis_conn import RedisManager
from db.postgres import PostgresManager, ScanHistory
from graph.graph_engine import GraphEngine

from ml.anomaly_detector import AnomalyDetector
from routers.anomaly import get_anomaly_detector
from ledger.ledger_manager import LedgerManager
from alerts.alert_manager import AlertManager
from github.contributor_analyzer import ContributorAnalyzer
from github.github_client import GitHubClient
from cve.cve_analyzer import CveAnalyzer
from routers.cve import get_cve_analyzer
from routers.typosquat import get_typosquat_detector
from routers.trends import get_trend_analyzer
from routers.sbom import get_sbom_generator
from routers.diff import get_differ

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.dependencies")

router = APIRouter(prefix="/api/dependencies", tags=["dependencies"], dependencies=[Depends(verify_api_key)])

# ─── Request / Response Models ────────────────────────────────


class ScanRequest(BaseModel):
    """Request body for scanning a project's dependencies."""
    content: str = Field(
        ...,
        description="Raw content of the dependency file",
        min_length=1,
    )
    file_type: str = Field(
        ...,
        description="File type: requirements.txt, pyproject.toml, package.json, or package-lock.json",
    )
    project_name: str = Field(
        default="unnamed",
        description="Name for this project in the graph",
        max_length=255,
    )


class PackageQuery(BaseModel):
    """Query parameters for package lookups."""
    package_name: str = Field(..., description="Package name to look up")
    ecosystem: str = Field(..., description="Ecosystem: pypi or npm")
    max_depth: int = Field(default=5, ge=1, le=15, description="Max graph depth")


# ─── Engine Instance ──────────────────────────────────────────
# Initialized by the setup function called from main.py lifespan

_engine: GraphEngine | None = None
_postgres: PostgresManager | None = None
_anomaly = None
_ledger: LedgerManager | None = None
_alerts: AlertManager | None = None
_contributor_analyzer: ContributorAnalyzer | None = None
_cve_analyzer: CveAnalyzer | None = None


def setup_engine(neo4j: Neo4jManager, redis: RedisManager, postgres: PostgresManager) -> None:
    """Initialize the GraphEngine. Called during app startup."""
    global _engine, _postgres, _anomaly, _ledger, _alerts, _contributor_analyzer, _cve_analyzer
    _engine = GraphEngine(neo4j=neo4j, redis=redis)
    _postgres = postgres
    _anomaly = get_anomaly_detector()
    if _anomaly is None:
        logger.warning(
            "AnomalyDetector not yet initialized. "
            "Ensure setup_anomaly_engine() runs before setup_engine()."
        )
    _ledger = LedgerManager(postgres)
    _alerts = AlertManager(postgres)
    github_client = GitHubClient(redis=redis)
    _contributor_analyzer = ContributorAnalyzer(
        github_client=github_client,
        neo4j=neo4j,
        postgres=postgres,
        redis=redis,
    )
    _cve_analyzer = CveAnalyzer(redis=redis, postgres=postgres)
    logger.info("Dependencies router engine initialized")


async def cleanup_engine() -> None:
    """Close the GraphEngine. Called during app shutdown."""
    global _engine
    if _engine:
        await _engine.close()
        _engine = None


def _get_engine() -> GraphEngine:
    """Get the engine instance, raising if not initialized."""
    if _engine is None:
        raise HTTPException(
            status_code=503,
            detail="Graph engine not initialized. Server may still be starting up.",
        )
    return _engine


# ─── Endpoints ────────────────────────────────────────────────

from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

limiter = Limiter(key_func=get_remote_address)

@router.post("/scan")
@limiter.limit("10/minute")
async def scan_project(request: Request, body: ScanRequest):
    """
    Scan a project's dependencies.

    Accepts the raw content of a dependency file, parses it,
    resolves all transitive dependencies via PyPI/npm APIs,
    stores the full graph in Neo4j, and returns results.

    Supported file types:
      - requirements.txt (Python/PyPI)
      - pyproject.toml (Python/PyPI)
      - package.json (JavaScript/npm)
      - package-lock.json (JavaScript/npm)
    """
    engine = _get_engine()

    try:
        result = await engine.scan_project(
            content=body.content,
            file_type=body.file_type,
            project_name=body.project_name,
        )

        if _anomaly is None or _ledger is None or _alerts is None:
            raise HTTPException(status_code=503, detail="Auxiliary engines not configured")

        packages_scored = 0
        high_risk_count = 0
        critical_risk_count = 0
        alerts_generated = 0
        scored_packages = []

        # 1b. Run typosquat detection synchronously for direct deps
        #     so the real Levenshtein distance feeds into the ML features.
        typosquat_scores: dict[str, int] = {}  # {pkg_name: min_distance}
        typosquat_flagged = 0
        _typosquat_detector = get_typosquat_detector()
        if _typosquat_detector:
            direct_pkgs = [
                p for p in result.get("packages", []) if p.get("is_direct")
            ]
            if direct_pkgs:
                try:
                    typo_result = await _typosquat_detector.check_packages(
                        packages=direct_pkgs,
                        ecosystem=result.get("ecosystem", "pypi"),
                    )
                    typosquat_flagged = typo_result.get("total_flagged", 0)
                    for flagged in typo_result.get("flagged", []):
                        pkg_name = flagged["package_name"]
                        min_dist = min(
                            m["distance"] for m in flagged["matches"]
                        )
                        typosquat_scores[pkg_name] = min_dist
                    if typosquat_flagged > 0:
                        logger.warning(
                            f"Typosquat detection: {typosquat_flagged} flagged "
                            f"direct packages in project '{body.project_name}'"
                        )
                except Exception as e:
                    logger.warning(f"Typosquat pre-scoring check failed: {e}")

        # 1c. Run CVE lookup synchronously for direct deps
        #     so has_known_cve feeds into the ML features.
        cve_scores: dict[str, dict] = {}  # {pkg_name: {"has_cve": bool, "max_cvss": float}}
        _cve_pre = get_cve_analyzer()
        if _cve_pre:
            direct_pkgs = [
                p for p in result.get("packages", []) if p.get("is_direct")
            ]
            for pkg in direct_pkgs:
                try:
                    findings = await _cve_pre.check_package(
                        package_name=pkg["name"],
                        package_version=pkg.get("version", ""),
                        ecosystem=result.get("ecosystem", "pypi"),
                    )
                    if findings:
                        max_cvss = max(
                            (f.get("cvss_score") or 0.0) for f in findings
                        )
                        cve_scores[pkg["name"]] = {
                            "has_cve": True,
                            "max_cvss": max_cvss,
                        }
                except Exception as e:
                    logger.warning(f"CVE pre-scoring check failed for {pkg['name']}: {e}")

        # 2. Score each package with the anomaly detector
        for package in result.get("packages", []):
            packages_scored += 1
            
            # a. Build a feature dict for the ML engine
            # Try to get real contributor data from stored baseline
            real_account_age = 365
            real_trust_score = 50
            real_repo_count = 10
            real_followers = 10
            real_commits_per_week = 5

            if package.get("is_direct") and _postgres:
                from sqlalchemy import select
                from db.postgres import ContributorBaseline
                async with _postgres.get_session() as lookup_session:
                    # Find the most recently updated contributor baseline
                    result_bl = await lookup_session.execute(
                        select(ContributorBaseline)
                        .order_by(ContributorBaseline.last_updated.desc())
                        .limit(1)
                    )
                    baseline = result_bl.scalar_one_or_none()
                    if baseline:
                        real_account_age = baseline.account_age_days
                        real_repo_count = baseline.repo_count
                        real_commits_per_week = baseline.avg_commits_per_week

            features = {
                "account_age_days": real_account_age,
                "trust_score": real_trust_score,
                "has_install_scripts": 0,
                "binary_files_added": 0,
                "obfuscated_code_score": 0,
                "has_known_cve": 1 if cve_scores.get(package["name"], {}).get("has_cve") else 0,
                "typosquat_distance": typosquat_scores.get(package["name"], 50),
                "is_new_maintainer": 0,
                "repo_count": real_repo_count,
                "followers": real_followers,
                "avg_commits_per_week": real_commits_per_week,
                "commit_hour_deviation": 0,
                "days_since_last_commit": 7,
                "version_jump_size": 0,
                "dependency_count_delta": 0,
                "contributor_count_change": 0,
            }

            # b. Score it with anomaly_detector
            score = _anomaly.score(features)
            scored_packages.append((package, score))

            # c. If high/critical risk, generate alerts
            risk_level = score.get("risk_level")
            if risk_level in ("high", "critical"):
                if risk_level == "high":
                    high_risk_count += 1
                else: 
                    critical_risk_count += 1
                    
                await _alerts.generate_from_anomaly(
                    anomaly_result=score,
                    package_name=package["name"],
                    package_version=package["version"],
                )
                alerts_generated += 1

        # 3. Add anomaly_summary to the scan response
        result["anomaly_summary"] = {
            "packages_scored": packages_scored,
            "high_risk": high_risk_count,
            "critical_risk": critical_risk_count,
            "alerts_generated": alerts_generated,
            "cve_direct_checked": len(cve_scores),
            "typosquat_flagged": typosquat_flagged,
        }

        # 4. Save scan to history (to get scan_id for ledger entries)
        async with _postgres.get_session() as session:
            scan_record = ScanHistory(
                project_name=body.project_name,
                ecosystem=result.get("ecosystem", "unknown"),
                file_type=body.file_type,
                status=result.get("status", "completed"),
                total_packages=result.get("total_packages", 0),
                direct_dependencies=result.get("direct_dependencies", 0),
                transitive_dependencies=result.get("transitive_dependencies", 0),
                scan_duration_seconds=result.get("scan_duration_seconds"),
                packages_scored=packages_scored,
                high_risk=high_risk_count,
                critical_risk=critical_risk_count,
                alerts_generated=alerts_generated,
                packages=result.get("packages"),
            )
            session.add(scan_record)
            await session.commit()
            await session.refresh(scan_record)
            current_scan_id = scan_record.id

        # 5. Record each scored package in the provenance ledger
        for package, score in scored_packages:
            flags_triggered = [r["rule"] for r in score.get("triggered_rules", [])]
            await _ledger.record_entry(
                package_name=package["name"],
                package_version=package["version"],
                ecosystem=package["ecosystem"],
                anomaly_score=score["anomaly_score"],
                flags_triggered=flags_triggered if flags_triggered else None,
                scan_id=current_scan_id,
            )

        # Record trends for each scored package
        _trend_analyzer = get_trend_analyzer()
        if _trend_analyzer:
            for pkg, score in scored_packages:
                try:
                    await _trend_analyzer.record(
                        entity_type="package",
                        entity_name=pkg["name"],
                        ecosystem=pkg.get("ecosystem", "pypi"),
                        anomaly_score=score.get("anomaly_score"),
                        trust_score=None,
                        risk_level=score.get("risk_level", "low"),
                        triggered_rules=[
                            r["rule"] for r in score.get("triggered_rules", [])
                        ] or None,
                    )
                except Exception as e:
                    logger.warning(f"Trend record failed for {pkg['name']}: {e}")

        # Auto-generate SBOM in background
        async def _generate_sbom_background():
            sbom_gen = get_sbom_generator()
            if not sbom_gen:
                return
            try:
                # SbomGenerator expects just the scan_id to fetch all enrichment data
                bom = await sbom_gen.generate_from_scan(scan_id=current_scan_id)
                
                os.makedirs("data/sboms", exist_ok=True)
                sbom_path = f"data/sboms/sbom-scan-{current_scan_id}.cdx.json"
                with open(sbom_path, "w") as f:
                    json.dump(bom, f, indent=2)

                async with _postgres.get_session() as session:
                    await session.execute(
                        update(ScanHistory)
                        .where(ScanHistory.id == current_scan_id)
                        .values(sbom_path=sbom_path)
                    )
                    await session.commit()
            except Exception as e:
                logger.warning(f"SBOM generation failed for scan {current_scan_id}: {e}")

        asyncio.create_task(_generate_sbom_background())

        # Auto-trigger version diff for packages with prior versions
        async def _run_diffs_background():
            differ = get_differ()
            if not differ:
                return
            for package, score in scored_packages:
                pkg_name = package["name"]
                pkg_version = package.get("version", "")
                ecosystem = package.get("ecosystem", "pypi")
                try:
                    # Check if we have a previous version in ledger
                    async with _postgres.get_session() as session:
                        from sqlalchemy import select
                        from db.postgres import ProvenanceLedger
                        prev = await session.execute(
                            select(ProvenanceLedger.package_version)
                            .where(
                                ProvenanceLedger.package_name == pkg_name,
                                ProvenanceLedger.ecosystem == ecosystem,
                                ProvenanceLedger.id < current_scan_id,
                            )
                            .order_by(ProvenanceLedger.id.desc())
                            .limit(1)
                        )
                        prev_version = prev.scalar_one_or_none()
                    
                    if prev_version and prev_version != pkg_version:
                        await differ.diff(
                            package_name=pkg_name,
                            version_from=prev_version,
                            version_to=pkg_version,
                            ecosystem=ecosystem,
                        )
                except Exception as e:
                    logger.warning(f"Diff failed for {pkg_name}: {e}")
        
        asyncio.create_task(_run_diffs_background())

        # 6. Analyze contributors in background (non-blocking)
        async def _analyze_contributors_background():
            if not _contributor_analyzer:
                return
            direct_packages = [
                p for p in result.get("packages", [])
                if p.get("is_direct") and p.get("repo_url")
            ]
            for pkg in direct_packages[:3]:
                repo_url = pkg.get("repo_url", "")
                parsed = GitHubClient.parse_repo_url(repo_url)
                if parsed:
                    owner, repo = parsed
                    try:
                        await _contributor_analyzer.analyze_package_contributors(
                            owner=owner,
                            repo=repo,
                            ecosystem=pkg.get("ecosystem", "pypi"),
                        )
                    except Exception as e:
                        logger.warning(
                            f"Contributor analysis failed for {owner}/{repo}: {e}"
                        )

        asyncio.create_task(_analyze_contributors_background())

        # 7. Analyze CVEs in background for TRANSITIVE deps only
        #    (direct deps were already checked synchronously in step 1c)
        async def _analyze_cves_background():
            cve_analyzer = get_cve_analyzer()
            if not cve_analyzer:
                return
            try:
                transitive_pkgs = [
                    p for p in result.get("packages", [])
                    if not p.get("is_direct")
                ]
                if transitive_pkgs:
                    await cve_analyzer.analyze_scan_packages(
                        packages=transitive_pkgs,
                        ecosystem=result.get("ecosystem", "pypi"),
                        scan_id=current_scan_id,
                    )
            except Exception as e:
                logger.warning(f"CVE background analysis failed: {e}")

        asyncio.create_task(_analyze_cves_background())

        # 8. Typosquat detection now runs synchronously before scoring
        #    (see step 1b above) — no background task needed.

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    return result


@router.get("/tree/{ecosystem}/{package_name}")
async def get_dependency_tree(
    package_name: str,
    ecosystem: str,
    max_depth: int = 10,
):
    """
    Get the full transitive dependency tree for a package.
    Returns a flat list of all dependencies with their depth.
    """
    engine = _get_engine()

    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="Ecosystem must be 'pypi' or 'npm'")

    if max_depth < 1 or max_depth > 15:
        raise HTTPException(status_code=400, detail="max_depth must be between 1 and 15")

    try:
        tree = await asyncio.to_thread(
            engine.get_dependency_tree, package_name, ecosystem, max_depth
        )
    except Exception as e:
        logger.error(f"Tree query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "max_depth": max_depth,
        "total_dependencies": len(tree),
        "dependencies": tree,
    }


@router.get("/graph/{ecosystem}/{package_name}")
async def get_graph_visualization(
    package_name: str,
    ecosystem: str,
    max_depth: int = 5,
):
    """
    Get graph data formatted for the React force-graph frontend.
    Returns {nodes: [...], links: [...]}.
    """
    engine = _get_engine()

    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="Ecosystem must be 'pypi' or 'npm'")

    try:
        graph = await asyncio.to_thread(
            engine.get_graph_visualization, package_name, ecosystem, max_depth
        )
    except Exception as e:
        logger.error(f"Graph query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return graph


@router.get("/dependents/{ecosystem}/{package_name}")
async def get_dependents(package_name: str, ecosystem: str):
    """
    Get all packages that depend on a specific package.
    Used for impact analysis when a package is flagged.
    """
    engine = _get_engine()

    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="Ecosystem must be 'pypi' or 'npm'")

    try:
        dependents = await asyncio.to_thread(
            engine.get_dependents, package_name, ecosystem
        )
    except Exception as e:
        logger.error(f"Dependents query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "dependent_count": len(dependents),
        "dependents": dependents,
    }


@router.get("/contributors/{ecosystem}/{package_name}")
async def get_package_contributors(package_name: str, ecosystem: str):
    """
    Get all contributors to a specific package.
    Returns contributor profiles from the graph.
    """
    engine = _get_engine()

    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="Ecosystem must be 'pypi' or 'npm'")

    try:
        contributors = await asyncio.to_thread(
            engine.get_package_contributors, package_name, ecosystem
        )
    except Exception as e:
        logger.error(f"Contributors query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "contributor_count": len(contributors),
        "contributors": contributors,
    }


@router.get("/stats")
async def get_graph_stats():
    """
    Get graph-wide statistics for the dashboard.
    Returns total package count, contributor count,
    and dependency edge count.
    """
    engine = _get_engine()

    try:
        stats = await asyncio.to_thread(engine.get_graph_stats)
    except Exception as e:
        logger.error(f"Stats query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return stats


@router.get("/high-risk-paths")
async def get_high_risk_paths(threshold: float = 50.0):
    """
    Query dependency edges where risk_score >= threshold.
    Returns high-risk dependency paths from the graph.
    """
    engine = _get_engine()

    try:
        paths = await asyncio.to_thread(engine.get_high_risk_paths, threshold)
    except Exception as e:
        logger.error(f"High-risk paths query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "threshold": threshold,
        "total_paths": len(paths),
        "paths": paths,
    }


@router.get("/history")
async def get_scan_history():
    """
    Get recent scan history (last 50 scans).
    Returns summary fields for each scan without the full packages list.
    """
    if not _postgres:
        raise HTTPException(status_code=503, detail="Database not configured")

    from sqlalchemy import select

    async with _postgres.get_session() as session:
        query = (
            select(
                ScanHistory.id,
                ScanHistory.project_name,
                ScanHistory.ecosystem,
                ScanHistory.file_type,
                ScanHistory.status,
                ScanHistory.total_packages,
                ScanHistory.direct_dependencies,
                ScanHistory.alerts_generated,
                ScanHistory.created_at,
            )
            .order_by(ScanHistory.created_at.desc())
            .limit(50)
        )
        result = await session.execute(query)
        rows = result.all()

    return {
        "total": len(rows),
        "scans": [
            {
                "id": row.id,
                "project_name": row.project_name,
                "ecosystem": row.ecosystem,
                "file_type": row.file_type,
                "status": row.status,
                "total_packages": row.total_packages,
                "direct_dependencies": row.direct_dependencies,
                "alerts_generated": row.alerts_generated,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ],
    }


@router.get("/history/{scan_id}")
async def get_scan_detail(scan_id: int):
    """
    Get full scan record by ID, including the packages list.
    """
    if not _postgres:
        raise HTTPException(status_code=503, detail="Database not configured")

    from sqlalchemy import select

    async with _postgres.get_session() as session:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await session.execute(query)
        scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    return {
        "id": scan.id,
        "project_name": scan.project_name,
        "ecosystem": scan.ecosystem,
        "file_type": scan.file_type,
        "status": scan.status,
        "total_packages": scan.total_packages,
        "direct_dependencies": scan.direct_dependencies,
        "transitive_dependencies": scan.transitive_dependencies,
        "scan_duration_seconds": scan.scan_duration_seconds,
        "packages_scored": scan.packages_scored,
        "high_risk": scan.high_risk,
        "critical_risk": scan.critical_risk,
        "alerts_generated": scan.alerts_generated,
        "packages": scan.packages,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


@router.get("/history/{scan_id}/sbom")
async def get_history_sbom(scan_id: int):
    """Download the auto-generated SBOM file from a scan."""
    if not _postgres:
        raise HTTPException(status_code=503, detail="Database not configured")

    from sqlalchemy import select
    from fastapi.responses import FileResponse

    async with _postgres.get_session() as session:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await session.execute(query)
        scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if not scan.sbom_path or not os.path.exists(scan.sbom_path):
        raise HTTPException(status_code=404, detail="SBOM file not available or not yet generated.")

    return FileResponse(
        path=scan.sbom_path,
        media_type="application/json",
        filename=os.path.basename(scan.sbom_path)
    )
