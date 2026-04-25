"""
Software Provenance Tracker — CVE Analyzer

Orchestrates CVE vulnerability scanning for packages
discovered during dependency scans.

Workflow:
  1. Receives a list of packages from a completed scan
  2. Queries NVD via NvdClient for each package
  3. Stores findings in PostgreSQL (cve_findings table)
  4. Returns a summary of vulnerabilities found

Designed to run as a background task (non-blocking)
during the scan pipeline.
"""

import logging
from datetime import datetime, timezone

from cve.nvd_client import NvdClient
from db.postgres import PostgresManager, CveFinding
from db.redis_conn import RedisManager

logger = logging.getLogger("provenance.cve.analyzer")


class CveAnalyzer:
    """
    Analyzes packages for known CVE vulnerabilities
    using the NVD API, stores results in PostgreSQL.
    """

    def __init__(self, redis: RedisManager, postgres: PostgresManager):
        self._nvd = NvdClient(redis=redis)
        self._postgres = postgres

    async def close(self) -> None:
        """Close the NVD HTTP client."""
        await self._nvd.close()

    # ─── Scan-Level Analysis ──────────────────────────────────

    async def analyze_scan_packages(
        self,
        packages: list[dict],
        ecosystem: str,
        scan_id: int | None = None,
    ) -> dict:
        """
        Analyze all packages from a scan for known CVEs.

        Args:
            packages: List of package dicts with "name" and "version" keys
            ecosystem: Package ecosystem ("pypi" or "npm")
            scan_id: Optional scan ID to link findings to

        Returns:
            Summary dict with total CVEs found, by severity, and details.
        """
        logger.info(
            f"Starting CVE analysis for {len(packages)} packages "
            f"(ecosystem: {ecosystem}, scan_id: {scan_id})"
        )

        total_cves = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        all_findings: list[dict] = []

        for package in packages:
            pkg_name = package.get("name", "")
            pkg_version = package.get("version", "")

            if not pkg_name:
                continue

            try:
                findings = await self._nvd.search_cves(
                    package_name=pkg_name,
                    ecosystem=ecosystem,
                )

                if not findings:
                    continue

                # Store each finding in PostgreSQL
                for finding in findings:
                    await self._store_finding(
                        scan_id=scan_id,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        ecosystem=ecosystem,
                        finding=finding,
                    )

                    # Count by severity
                    severity = finding.get("severity", "unknown")
                    if severity == "critical":
                        critical_count += 1
                    elif severity == "high":
                        high_count += 1
                    elif severity == "medium":
                        medium_count += 1
                    elif severity == "low":
                        low_count += 1

                total_cves += len(findings)

                all_findings.append({
                    "package_name": pkg_name,
                    "package_version": pkg_version,
                    "cve_count": len(findings),
                    "cves": findings,
                })

            except Exception as e:
                logger.warning(
                    f"CVE lookup failed for {pkg_name}: {e}"
                )
                continue

        summary = {
            "total_cves": total_cves,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "packages_checked": len(packages),
            "packages_with_cves": len(all_findings),
            "findings": all_findings,
        }

        logger.info(
            f"CVE analysis complete: {total_cves} CVE(s) found "
            f"(critical={critical_count}, high={high_count}, "
            f"medium={medium_count}, low={low_count})"
        )

        return summary

    # ─── Single Package Lookup ────────────────────────────────

    async def check_package(
        self,
        package_name: str,
        package_version: str | None = None,
        ecosystem: str = "pypi",
    ) -> list[dict]:
        """
        Check a single package for known CVEs.
        Returns the list of CVE findings without storing them.
        """
        return await self._nvd.search_cves(
            package_name=package_name,
            ecosystem=ecosystem,
        )

    # ─── Refresh (Cache Bypass) ───────────────────────────────

    async def refresh_scan_packages(
        self,
        packages: list[dict],
        ecosystem: str,
        scan_id: int,
    ) -> dict:
        """
        Force re-check CVEs for all packages in a scan.
        Clears Redis cache for each package, deletes old findings
        from PostgreSQL, then re-runs analyze_scan_packages.
        """
        from sqlalchemy import delete

        # 1. Clear Redis cache for each package
        for pkg in packages:
            pkg_name = pkg.get("name", "")
            if pkg_name:
                await self._nvd.clear_package_cache(pkg_name, ecosystem)

        # 2. Delete old findings for this scan from PostgreSQL
        async with self._postgres.get_session() as session:
            await session.execute(
                delete(CveFinding).where(CveFinding.scan_id == scan_id)
            )
            await session.commit()

        logger.info(f"Cleared CVE cache and findings for scan {scan_id}")

        # 3. Re-run analysis (will hit NVD API fresh)
        return await self.analyze_scan_packages(
            packages=packages,
            ecosystem=ecosystem,
            scan_id=scan_id,
        )

    # ─── Query Stored Findings ────────────────────────────────

    async def get_findings_by_scan(self, scan_id: int) -> list[dict]:
        """Get all CVE findings for a specific scan."""
        from sqlalchemy import select, desc

        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(CveFinding)
                .where(CveFinding.scan_id == scan_id)
                .order_by(desc(CveFinding.cvss_score))
            )
            findings = result.scalars().all()
            return [self._finding_to_dict(f) for f in findings]

    async def get_findings_by_package(
        self,
        package_name: str,
        ecosystem: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get all stored CVE findings for a package."""
        from sqlalchemy import select, desc

        async with self._postgres.get_session() as session:
            query = select(CveFinding).where(
                CveFinding.package_name == package_name
            )
            if ecosystem:
                query = query.where(CveFinding.ecosystem == ecosystem)
            query = query.order_by(desc(CveFinding.cvss_score)).limit(limit)

            result = await session.execute(query)
            findings = result.scalars().all()
            return [self._finding_to_dict(f) for f in findings]

    async def get_stats(self) -> dict:
        """Get CVE finding statistics for the dashboard."""
        from sqlalchemy import select, func

        async with self._postgres.get_session() as session:
            # Total findings
            total_result = await session.execute(
                select(func.count(CveFinding.id))
            )
            total = total_result.scalar() or 0

            # By severity
            severity_result = await session.execute(
                select(CveFinding.severity, func.count(CveFinding.id))
                .group_by(CveFinding.severity)
            )
            by_severity = {row[0]: row[1] for row in severity_result.all()}

            # Unique CVEs
            unique_result = await session.execute(
                select(func.count(func.distinct(CveFinding.cve_id)))
            )
            unique_cves = unique_result.scalar() or 0

            # Unique affected packages
            packages_result = await session.execute(
                select(func.count(func.distinct(CveFinding.package_name)))
            )
            affected_packages = packages_result.scalar() or 0

            return {
                "total_findings": total,
                "unique_cves": unique_cves,
                "affected_packages": affected_packages,
                "by_severity": by_severity,
            }

    # ─── Private Helpers ──────────────────────────────────────

    async def _store_finding(
        self,
        scan_id: int | None,
        package_name: str,
        package_version: str,
        ecosystem: str,
        finding: dict,
    ) -> None:
        """Store a single CVE finding in PostgreSQL, skipping duplicates."""
        from sqlalchemy import select

        async with self._postgres.get_session() as session:
            # Check if this CVE finding already exists for this scan
            existing = await session.execute(
                select(CveFinding).where(
                    CveFinding.scan_id == scan_id,
                    CveFinding.package_name == package_name,
                    CveFinding.cve_id == finding["cve_id"],
                )
            )
            if existing.scalar_one_or_none():
                return  # Already stored, skip

            entry = CveFinding(
                scan_id=scan_id,
                package_name=package_name,
                package_version=package_version,
                ecosystem=ecosystem,
                cve_id=finding["cve_id"],
                cvss_score=finding.get("cvss_score"),
                severity=finding.get("severity"),
                description=finding.get("description"),
                published_date=finding.get("published_date"),
                last_modified=finding.get("last_modified"),
            )
            session.add(entry)
            await session.commit()

            logger.debug(
                f"Stored CVE finding: {finding['cve_id']} "
                f"for {package_name}@{package_version}"
            )

    @staticmethod
    def _finding_to_dict(finding: CveFinding) -> dict:
        """Convert a CveFinding ORM instance to a dict."""
        return {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "package_name": finding.package_name,
            "package_version": finding.package_version,
            "ecosystem": finding.ecosystem,
            "cve_id": finding.cve_id,
            "cvss_score": finding.cvss_score,
            "severity": finding.severity,
            "description": finding.description,
            "published_date": finding.published_date,
            "last_modified": finding.last_modified,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }
