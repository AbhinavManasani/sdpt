"""
Software Provenance Tracker — SBOM Generator

Generates Software Bill of Materials (SBOM) in CycloneDX 1.4 JSON
format from completed dependency scans.

Data sources (all from PostgreSQL):
  - scan_history      → scan metadata, package list
  - provenance_ledger → anomaly scores, flags per package
  - cve_findings      → vulnerability data per package
  - typosquat checks  → live detection via TyposquatDetector

Output: CycloneDX 1.4-compliant JSON document, built directly
without any external CycloneDX library.

Spec reference: https://cyclonedx.org/docs/1.4/json/
"""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from db.postgres import (
    PostgresManager,
    ScanHistory,
    ProvenanceLedger,
    CveFinding,
)
from db.redis_conn import RedisManager
from typosquat.typosquat_detector import TyposquatDetector

logger = logging.getLogger("provenance.sbom.generator")

# CycloneDX spec version
CYCLONEDX_SPEC_VERSION = "1.4"
CYCLONEDX_BOM_FORMAT = "CycloneDX"

# Map our ecosystem names to CycloneDX purl type
ECOSYSTEM_TO_PURL_TYPE = {
    "pypi": "pypi",
    "npm": "npm",
}


class SbomGenerator:
    """
    Generates CycloneDX 1.4 JSON SBOMs from scan data stored
    in PostgreSQL, enriched with CVE findings and typosquat flags.
    """

    def __init__(
        self,
        postgres: PostgresManager,
        redis: RedisManager,
        typosquat_detector: TyposquatDetector | None = None,
    ):
        self._postgres = postgres
        self._redis = redis
        self._typosquat = typosquat_detector

    # ─── Public API ───────────────────────────────────────────

    async def generate_from_scan(self, scan_id: int) -> dict:
        """
        Generate a CycloneDX 1.4 JSON SBOM from a completed scan.

        Args:
            scan_id: ID of the scan in scan_history table.

        Returns:
            Complete CycloneDX 1.4 JSON structure as a dict.

        Raises:
            ValueError: If scan_id is not found.
        """
        # 1. Load the scan record
        scan = await self._load_scan(scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")

        packages = scan.packages or []
        ecosystem = scan.ecosystem or "pypi"

        # 2. Load enrichment data in parallel-style
        ledger_map = await self._load_ledger_data(scan_id)
        cve_map = await self._load_cve_data(scan_id)
        typosquat_map = await self._run_typosquat_check(packages, ecosystem)

        # 3. Build CycloneDX components
        components = []
        for pkg in packages:
            component = self._build_component(
                pkg=pkg,
                ecosystem=ecosystem,
                ledger_entry=ledger_map.get(pkg.get("name", "").lower()),
                cve_findings=cve_map.get(pkg.get("name", "").lower(), []),
                typosquat_result=typosquat_map.get(pkg.get("name", "").lower()),
            )
            components.append(component)

        # 4. Build dependency graph
        dependencies = self._build_dependencies(packages)

        # 5. Build vulnerabilities section
        vulnerabilities = self._build_vulnerabilities(cve_map)

        # 6. Assemble the full BOM
        bom = self._assemble_bom(
            scan=scan,
            components=components,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
        )

        logger.info(
            f"SBOM generated for scan {scan_id}: "
            f"{len(components)} components, "
            f"{len(vulnerabilities)} vulnerabilities"
        )

        return bom

    # ─── Data Loaders ─────────────────────────────────────────

    async def _load_scan(self, scan_id: int) -> ScanHistory | None:
        """Load a scan record from PostgreSQL."""
        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(ScanHistory).where(ScanHistory.id == scan_id)
            )
            return result.scalar_one_or_none()

    async def _load_ledger_data(self, scan_id: int) -> dict:
        """
        Load provenance ledger entries for a scan.
        Returns a dict keyed by lowercase package name.
        """
        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(ProvenanceLedger).where(
                    ProvenanceLedger.scan_id == scan_id
                )
            )
            entries = result.scalars().all()

        ledger_map = {}
        for entry in entries:
            key = entry.package_name.lower()
            ledger_map[key] = {
                "anomaly_score": entry.anomaly_score,
                "flags_triggered": entry.flags_triggered or [],
                "entry_hash": entry.entry_hash,
                "dependency_graph_hash": entry.dependency_graph_hash,
                "publisher_github_id": entry.publisher_github_id,
                "source_commit_hash": entry.source_commit_hash,
                "build_artifact_hash": entry.build_artifact_hash,
            }

        return ledger_map

    async def _load_cve_data(self, scan_id: int) -> dict:
        """
        Load CVE findings for a scan.
        Returns a dict keyed by lowercase package name → list of findings.
        """
        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(CveFinding).where(CveFinding.scan_id == scan_id)
            )
            findings = result.scalars().all()

        cve_map: dict[str, list] = {}
        for finding in findings:
            key = finding.package_name.lower()
            if key not in cve_map:
                cve_map[key] = []
            cve_map[key].append({
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "severity": finding.severity,
                "description": finding.description,
                "published_date": finding.published_date,
            })

        return cve_map

    async def _run_typosquat_check(
        self, packages: list[dict], ecosystem: str
    ) -> dict:
        """
        Run typosquat detection on scan packages.
        Returns a dict keyed by lowercase package name → match result.
        """
        if not self._typosquat:
            return {}

        try:
            result = await self._typosquat.check_packages(
                packages=packages, ecosystem=ecosystem
            )
            typo_map = {}
            for flagged in result.get("flagged", []):
                key = flagged["package_name"].lower()
                typo_map[key] = {
                    "is_typosquat": True,
                    "severity": flagged.get("severity"),
                    "matches": flagged.get("matches", []),
                }
            return typo_map

        except Exception as e:
            logger.warning(f"Typosquat check during SBOM generation failed: {e}")
            return {}

    # ─── CycloneDX Builders ───────────────────────────────────

    def _build_component(
        self,
        pkg: dict,
        ecosystem: str,
        ledger_entry: dict | None,
        cve_findings: list[dict],
        typosquat_result: dict | None,
    ) -> dict:
        """Build a CycloneDX component entry for a single package."""
        name = pkg.get("name", "unknown")
        version = pkg.get("version", "unknown")
        purl_type = ECOSYSTEM_TO_PURL_TYPE.get(ecosystem, ecosystem)

        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:{purl_type}/{name}@{version}",
            "bom-ref": f"pkg:{purl_type}/{name}@{version}",
        }

        # Scope: required for direct, optional for transitive
        if pkg.get("is_direct"):
            component["scope"] = "required"
        else:
            component["scope"] = "optional"

        # Description from package metadata
        if pkg.get("description"):
            component["description"] = pkg["description"]

        # Author
        if pkg.get("author"):
            component["author"] = pkg["author"]

        # License (if available in package data)
        license_name = pkg.get("license")
        if license_name:
            component["licenses"] = [
                {"license": {"name": license_name}}
            ]

        # External references
        external_refs = []
        if pkg.get("repo_url"):
            external_refs.append({
                "type": "vcs",
                "url": pkg["repo_url"],
            })
        if pkg.get("homepage"):
            external_refs.append({
                "type": "website",
                "url": pkg["homepage"],
            })
        if external_refs:
            component["externalReferences"] = external_refs

        # Hashes from provenance ledger
        if ledger_entry:
            hashes = []
            if ledger_entry.get("dependency_graph_hash"):
                hashes.append({
                    "alg": "SHA-256",
                    "content": ledger_entry["dependency_graph_hash"],
                })
            if ledger_entry.get("build_artifact_hash"):
                hashes.append({
                    "alg": "SHA-256",
                    "content": ledger_entry["build_artifact_hash"],
                })
            if hashes:
                component["hashes"] = hashes

        # Properties — custom provenance metadata (CycloneDX extension point)
        properties = []

        if ledger_entry:
            if ledger_entry.get("anomaly_score") is not None:
                properties.append({
                    "name": "provenance:anomaly_score",
                    "value": str(ledger_entry["anomaly_score"]),
                })
            if ledger_entry.get("flags_triggered"):
                properties.append({
                    "name": "provenance:flags_triggered",
                    "value": ", ".join(ledger_entry["flags_triggered"]),
                })
            if ledger_entry.get("entry_hash"):
                properties.append({
                    "name": "provenance:ledger_hash",
                    "value": ledger_entry["entry_hash"],
                })
            if ledger_entry.get("publisher_github_id"):
                properties.append({
                    "name": "provenance:publisher_github_id",
                    "value": ledger_entry["publisher_github_id"],
                })
            if ledger_entry.get("source_commit_hash"):
                properties.append({
                    "name": "provenance:source_commit",
                    "value": ledger_entry["source_commit_hash"],
                })

        # CVE count as property
        if cve_findings:
            properties.append({
                "name": "provenance:cve_count",
                "value": str(len(cve_findings)),
            })
            worst_severity = self._worst_cve_severity(cve_findings)
            if worst_severity:
                properties.append({
                    "name": "provenance:cve_worst_severity",
                    "value": worst_severity,
                })

        # Typosquat flag as property
        if typosquat_result and typosquat_result.get("is_typosquat"):
            properties.append({
                "name": "provenance:typosquat_flag",
                "value": "true",
            })
            properties.append({
                "name": "provenance:typosquat_severity",
                "value": typosquat_result.get("severity", "unknown"),
            })
            # Include the top package names it's similar to
            match_names = [
                m["top_package"] for m in typosquat_result.get("matches", [])
            ]
            if match_names:
                properties.append({
                    "name": "provenance:typosquat_similar_to",
                    "value": ", ".join(match_names[:5]),
                })

        if properties:
            component["properties"] = properties

        return component

    def _build_dependencies(self, packages: list[dict]) -> list[dict]:
        """
        Build CycloneDX dependency graph from package data.
        Maps each package to its direct dependencies.
        """
        dependencies = []
        pkg_lookup = {
            p.get("name", "").lower(): p for p in packages
        }

        for pkg in packages:
            name = pkg.get("name", "unknown")
            version = pkg.get("version", "unknown")
            ecosystem = pkg.get("ecosystem", "pypi")
            purl_type = ECOSYSTEM_TO_PURL_TYPE.get(ecosystem, ecosystem)
            ref = f"pkg:{purl_type}/{name}@{version}"

            deps_list = pkg.get("dependencies", [])
            depends_on = []

            for dep in deps_list:
                if isinstance(dep, str):
                    dep_pkg = pkg_lookup.get(dep.lower(), {})
                    dep_version = dep_pkg.get("version", "unknown")
                    dep_eco = dep_pkg.get("ecosystem", ecosystem)
                elif isinstance(dep, dict):
                    dep_name = dep.get("name", "")
                    dep_pkg = pkg_lookup.get(dep_name.lower(), {})
                    dep = dep_name
                    dep_version = dep_pkg.get("version", "unknown")
                    dep_eco = dep_pkg.get("ecosystem", ecosystem)
                else:
                    continue

                dep_purl_type = ECOSYSTEM_TO_PURL_TYPE.get(dep_eco, dep_eco)
                depends_on.append(f"pkg:{dep_purl_type}/{dep}@{dep_version}")

            dependencies.append({
                "ref": ref,
                "dependsOn": depends_on,
            })

        return dependencies

    def _build_vulnerabilities(self, cve_map: dict) -> list[dict]:
        """
        Build CycloneDX vulnerabilities section from CVE findings.
        Each unique CVE becomes one vulnerability entry.
        """
        seen_cves: dict[str, dict] = {}

        for pkg_name, findings in cve_map.items():
            for finding in findings:
                cve_id = finding.get("cve_id", "")
                if not cve_id or cve_id in seen_cves:
                    # Add affected package to existing entry
                    if cve_id in seen_cves:
                        affects = seen_cves[cve_id].get("affects", [])
                        already_listed = any(
                            a.get("ref", "").endswith(f"/{pkg_name}@")
                            or pkg_name in a.get("ref", "")
                            for a in affects
                        )
                        if not already_listed:
                            affects.append({"ref": pkg_name})
                    continue

                vuln = {
                    "id": cve_id,
                    "source": {
                        "name": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    },
                    "description": finding.get("description", ""),
                    "published": finding.get("published_date", ""),
                    "affects": [{"ref": pkg_name}],
                }

                # Ratings
                if finding.get("cvss_score") is not None:
                    severity = finding.get("severity", "unknown")
                    vuln["ratings"] = [{
                        "score": finding["cvss_score"],
                        "severity": severity,
                        "method": "CVSSv3",
                    }]

                seen_cves[cve_id] = vuln

        return list(seen_cves.values())

    def _assemble_bom(
        self,
        scan: ScanHistory,
        components: list[dict],
        dependencies: list[dict],
        vulnerabilities: list[dict],
    ) -> dict:
        """Assemble the complete CycloneDX 1.4 BOM document."""
        serial = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        bom = {
            "bomFormat": CYCLONEDX_BOM_FORMAT,
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "serialNumber": f"urn:uuid:{serial}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [{
                    "vendor": "Software Provenance Tracker",
                    "name": "provenance-sbom-generator",
                    "version": "0.1.0",
                }],
                "component": {
                    "type": "application",
                    "name": scan.project_name,
                    "version": "scan-" + str(scan.id),
                },
                "properties": [
                    {
                        "name": "provenance:scan_id",
                        "value": str(scan.id),
                    },
                    {
                        "name": "provenance:ecosystem",
                        "value": scan.ecosystem,
                    },
                    {
                        "name": "provenance:file_type",
                        "value": scan.file_type,
                    },
                    {
                        "name": "provenance:total_packages",
                        "value": str(scan.total_packages),
                    },
                    {
                        "name": "provenance:direct_dependencies",
                        "value": str(scan.direct_dependencies),
                    },
                    {
                        "name": "provenance:scan_status",
                        "value": scan.status,
                    },
                ],
            },
            "components": components,
            "dependencies": dependencies,
        }

        # Only include vulnerabilities section if there are findings
        if vulnerabilities:
            bom["vulnerabilities"] = vulnerabilities

        return bom

    # ─── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _worst_cve_severity(findings: list[dict]) -> str | None:
        """Return the worst CVE severity from a list of findings."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        worst = None
        worst_rank = 999

        for f in findings:
            sev = (f.get("severity") or "").lower()
            rank = severity_order.get(sev, 999)
            if rank < worst_rank:
                worst_rank = rank
                worst = sev

        return worst
