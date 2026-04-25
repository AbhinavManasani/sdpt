"""
Software Provenance Tracker — Graph Engine

Orchestration layer that ties together:
  - Parsers (PyPI / npm)
  - Dependency Resolver (transitive resolution via registry APIs)
  - Neo4j (graph storage and queries)

This is the main entry point for scanning a project's
dependencies and building the full graph.
"""

import asyncio
import logging
from datetime import datetime, timezone

from parsers.pypi_parser import PyPIParser, ParsedDependency as PyPIParsedDep
from parsers.npm_parser import NpmParser, ParsedDependency as NpmParsedDep
from graph.dependency_resolver import DependencyResolver, ResolvedPackage
from db.neo4j_conn import Neo4jManager
from db.redis_conn import RedisManager
from config import get_settings

logger = logging.getLogger("provenance.graph.engine")


class GraphEngine:
    """
    High-level orchestrator for dependency graph operations.

    Workflow:
      1. Parse dependency files (requirements.txt, package.json, etc.)
      2. Resolve transitive dependencies via registry APIs
      3. Store the full graph in Neo4j
      4. Return results for the API/frontend
    """

    def __init__(self, neo4j: Neo4jManager, redis: RedisManager):
        self._neo4j = neo4j
        self._redis = redis
        self._settings = get_settings()
        self._pypi_parser = PyPIParser()
        self._npm_parser = NpmParser()
        self._resolver = DependencyResolver(redis, self._settings)

    async def close(self) -> None:
        """Clean up resources."""
        await self._resolver.close()

    # ─── Full Scan Workflow ───────────────────────────────────

    async def scan_project(
        self,
        content: str,
        file_type: str,
        project_name: str = "unnamed",
    ) -> dict:
        """
        Full scan pipeline: parse → resolve → store → return results.

        Args:
            content: Raw file content (requirements.txt, package.json, etc.)
            file_type: "requirements.txt", "pyproject.toml", "package.json", "package-lock.json"
            project_name: Name for this project in the graph

        Returns:
            Scan results with stats, resolved packages, and any issues
        """
        scan_start = datetime.now(timezone.utc)
        issues = []

        # Step 1: Determine ecosystem and parse
        ecosystem = self._detect_ecosystem(file_type)
        logger.info(f"Scanning '{project_name}' ({ecosystem}) from {file_type}")

        parsed_deps = self._parse_content(content, file_type, ecosystem)
        if not parsed_deps:
            return {
                "project_name": project_name,
                "ecosystem": ecosystem,
                "status": "no_dependencies",
                "message": "No dependencies found in the provided file.",
                "packages_found": 0,
            }

        logger.info(f"Parsed {len(parsed_deps)} direct dependencies")

        # Step 2: Resolve transitive dependencies
        packages_to_resolve = [
            {"name": dep.name, "version_spec": dep.version_spec}
            for dep in parsed_deps
        ]

        try:
            resolved = await self._resolver.resolve_all(
                packages=packages_to_resolve,
                ecosystem=ecosystem,
            )
        except Exception as e:
            logger.error(f"Resolution failed: {e}")
            return {
                "project_name": project_name,
                "ecosystem": ecosystem,
                "status": "resolution_error",
                "message": f"Dependency resolution failed: {str(e)}",
                "direct_dependencies": len(parsed_deps),
            }

        logger.info(f"Resolved {len(resolved)} total packages (including transitive)")

        # Step 3: Store in Neo4j
        direct_names = {dep.name for dep in parsed_deps}
        store_result = await asyncio.to_thread(
            self._store_in_graph,
            resolved_packages=resolved,
            project_name=project_name,
            ecosystem=ecosystem,
            direct_names=direct_names,
        )

        # Step 4: Build response
        scan_duration = (datetime.now(timezone.utc) - scan_start).total_seconds()

        return {
            "project_name": project_name,
            "ecosystem": ecosystem,
            "status": "completed",
            "scan_duration_seconds": round(scan_duration, 2),
            "direct_dependencies": len(parsed_deps),
            "total_packages": len(resolved),
            "transitive_dependencies": len(resolved) - len(parsed_deps),
            "packages": [
                {
                    "name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "is_direct": pkg.name in direct_names,
                    "summary": pkg.summary,
                    "author": pkg.author,
                    "license": pkg.license,
                    "repo_url": pkg.repo_url,
                    "dependency_count": len(pkg.dependencies),
                }
                for pkg in resolved
            ],
            "stored_in_graph": store_result,
        }

    # ─── Parse from File Path ─────────────────────────────────

    async def scan_file(
        self,
        file_path: str,
        project_name: str = "unnamed",
    ) -> dict:
        """
        Scan a dependency file from the filesystem.
        Auto-detects file type from the filename.
        """
        from pathlib import Path
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Dependency file not found: {file_path}")

        content = path.read_text(encoding="utf-8")
        file_type = path.name

        return await self.scan_project(content, file_type, project_name)

    # ─── Graph Queries (delegated to Neo4jManager) ────────────

    def get_dependency_tree(self, package_name: str, ecosystem: str,
                            max_depth: int = 10) -> list[dict]:
        """Get the full dependency tree for a package."""
        return self._neo4j.get_full_dependency_tree(package_name, ecosystem, max_depth)

    def get_graph_visualization(self, package_name: str, ecosystem: str,
                                max_depth: int = 5) -> dict:
        """Get nodes and links formatted for the frontend force-graph."""
        return self._neo4j.get_graph_for_visualization(package_name, ecosystem, max_depth)

    def get_package_contributors(self, package_name: str,
                                  ecosystem: str) -> list[dict]:
        """Get all contributors to a package."""
        return self._neo4j.get_package_contributors(package_name, ecosystem)

    def get_dependents(self, package_name: str, ecosystem: str) -> list[dict]:
        """Get all packages that depend on a given package (impact analysis)."""
        return self._neo4j.get_dependents(package_name, ecosystem)

    def get_graph_stats(self) -> dict:
        """Get graph statistics for the dashboard."""
        return self._neo4j.get_stats()

    # ─── Private Methods ──────────────────────────────────────

    def _detect_ecosystem(self, file_type: str) -> str:
        """Determine ecosystem from file type."""
        pypi_types = {"requirements.txt", "txt", "pyproject.toml", "toml"}
        npm_types = {"package.json", "package-lock.json"}

        if file_type in pypi_types:
            return "pypi"
        elif file_type in npm_types:
            return "npm"
        else:
            raise ValueError(
                f"Unsupported file type: {file_type}. "
                f"Supported: requirements.txt, pyproject.toml, package.json, package-lock.json"
            )

    def _parse_content(self, content: str, file_type: str,
                       ecosystem: str) -> list:
        """Parse file content using the appropriate parser."""
        if ecosystem == "pypi":
            return self._pypi_parser.parse_content(content, file_type)
        elif ecosystem == "npm":
            return self._npm_parser.parse_content(content, file_type)
        return []

    def _store_in_graph(
        self,
        resolved_packages: list[ResolvedPackage],
        project_name: str,
        ecosystem: str,
        direct_names: set[str],
        risk_scores: dict[str, float] | None = None,
    ) -> dict:
        """
        Store all resolved packages and their relationships in Neo4j.
        risk_scores: optional dict mapping package name -> anomaly score.
        Returns stats about what was stored.
        """
        if risk_scores is None:
            risk_scores = {}

        nodes_created = 0
        edges_created = 0

        # Create the project as a root Package node
        self._neo4j.upsert_package(
            name=project_name,
            ecosystem=ecosystem,
            version="project",
        )

        # Create direct dependency edges from project to direct deps
        for name in direct_names:
            self._neo4j.add_dependency(
                parent_name=project_name,
                parent_ecosystem=ecosystem,
                child_name=name,
                child_ecosystem=ecosystem,
                depth=1,
                risk_score=risk_scores.get(name, 0.0),
            )
            edges_created += 1

        # Create all resolved package nodes and their dependency edges
        for pkg in resolved_packages:
            self._neo4j.upsert_package(
                name=pkg.name,
                ecosystem=pkg.ecosystem,
                version=pkg.version,
            )
            nodes_created += 1

            # Create edges to this package's dependencies
            for dep in pkg.dependencies:
                dep_name = dep["name"]
                self._neo4j.add_dependency(
                    parent_name=pkg.name,
                    parent_ecosystem=pkg.ecosystem,
                    child_name=dep_name,
                    child_ecosystem=pkg.ecosystem,
                    version_constraint=dep.get("version_spec", ""),
                    risk_score=risk_scores.get(dep_name, 0.0),
                )
                edges_created += 1

        logger.info(f"Stored in Neo4j: {nodes_created} nodes, {edges_created} edges")

        return {
            "nodes_created": nodes_created,
            "edges_created": edges_created,
        }

    def get_high_risk_paths(self, threshold: float = 50.0) -> list[dict]:
        """
        Query Neo4j for dependency paths where any edge
        has risk_score >= threshold.
        Returns list of {from_package, to_package, risk_score, ecosystem}
        """
        with self._neo4j.get_session() as session:
            result = session.run(
                """
                MATCH (a:Package)-[r:DEPENDS_ON]->(b:Package)
                WHERE r.risk_score >= $threshold
                RETURN a.name as from_package,
                       b.name as to_package,
                       r.risk_score as risk_score,
                       a.ecosystem as ecosystem
                ORDER BY r.risk_score DESC
                LIMIT 50
                """,
                threshold=threshold,
            )
            return [dict(record) for record in result]

