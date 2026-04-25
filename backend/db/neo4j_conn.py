"""
Software Provenance Tracker — Neo4j Connection Manager

Manages the Neo4j graph database driver for dependency and
contributor relationship mapping.

Graph schema:
  Nodes:
    (:Package {name, version, ecosystem, risk_score, last_checked})
    (:Contributor {username, account_age_days, trust_score, first_seen})

  Edges:
    (:Package)-[:DEPENDS_ON {version_constraint, depth, resolved_at}]->(:Package)
    (:Contributor)-[:CONTRIBUTED_TO {role, first_commit_date, access_level, commit_count}]->(:Package)
"""

import logging
from typing import Any

from neo4j import GraphDatabase, Driver, Session

logger = logging.getLogger("provenance.db.neo4j")


class Neo4jManager:
    """
    Manages the Neo4j driver lifecycle.
    Uses the official neo4j Python driver (synchronous).
    """

    def __init__(self):
        self._driver: Driver | None = None

    def connect(self, uri: str, user: str, password: str) -> None:
        """Create the Neo4j driver and verify connectivity."""
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        # Verify the connection works immediately
        self._driver.verify_connectivity()
        logger.info(f"Neo4j driver connected to {uri}")

        # Create indexes and constraints on first connection
        self._ensure_schema()

    def disconnect(self) -> None:
        """Close the driver and release all connections."""
        if self._driver:
            self._driver.close()
            self._driver = None
            logger.info("Neo4j driver closed")

    def get_session(self) -> Session:
        """Returns a new Neo4j session. Use with 'with' statement."""
        if not self._driver:
            raise RuntimeError("Neo4j not connected. Call connect() first.")
        return self._driver.session()

    def health_check(self) -> None:
        """Verify Neo4j is reachable."""
        if not self._driver:
            raise RuntimeError("Neo4j driver not initialized")
        self._driver.verify_connectivity()

    # ─── Schema Setup ─────────────────────────────────────────

    def _ensure_schema(self) -> None:
        """Create indexes and constraints for optimal query performance."""
        with self.get_session() as session:
            # Uniqueness constraints (also create indexes automatically)
            session.run(
                "CREATE CONSTRAINT package_name_version IF NOT EXISTS "
                "FOR (p:Package) REQUIRE (p.name, p.ecosystem) IS UNIQUE"
            )
            session.run(
                "CREATE CONSTRAINT contributor_username IF NOT EXISTS "
                "FOR (c:Contributor) REQUIRE c.username IS UNIQUE"
            )

            # Additional indexes for frequent lookups
            session.run(
                "CREATE INDEX package_risk IF NOT EXISTS "
                "FOR (p:Package) ON (p.risk_score)"
            )
            session.run(
                "CREATE INDEX package_ecosystem IF NOT EXISTS "
                "FOR (p:Package) ON (p.ecosystem)"
            )
            session.run(
                "CREATE INDEX contributor_trust IF NOT EXISTS "
                "FOR (c:Contributor) ON (c.trust_score)"
            )

        logger.info("Neo4j schema constraints and indexes verified")

    # ─── Package Operations ───────────────────────────────────

    def upsert_package(self, name: str, ecosystem: str, version: str = None,
                       risk_score: float = None) -> None:
        """Create or update a Package node."""
        with self.get_session() as session:
            session.run(
                """
                MERGE (p:Package {name: $name, ecosystem: $ecosystem})
                SET p.version = COALESCE($version, p.version),
                    p.risk_score = COALESCE($risk_score, p.risk_score),
                    p.last_checked = datetime()
                """,
                name=name, ecosystem=ecosystem,
                version=version, risk_score=risk_score,
            )

    def add_dependency(self, parent_name: str, parent_ecosystem: str,
                       child_name: str, child_ecosystem: str,
                       version_constraint: str = None, depth: int = 1,
                       risk_score: float = 0.0) -> None:
        """Create a DEPENDS_ON relationship between two packages."""
        with self.get_session() as session:
            session.run(
                """
                MERGE (parent:Package {name: $parent_name, ecosystem: $parent_ecosystem})
                MERGE (child:Package {name: $child_name, ecosystem: $child_ecosystem})
                MERGE (parent)-[r:DEPENDS_ON]->(child)
                SET r.version_constraint = $version_constraint,
                    r.depth = $depth,
                    r.risk_score = $risk_score,
                    r.resolved_at = datetime()
                """,
                parent_name=parent_name, parent_ecosystem=parent_ecosystem,
                child_name=child_name, child_ecosystem=child_ecosystem,
                version_constraint=version_constraint, depth=depth,
                risk_score=risk_score,
            )

    def get_full_dependency_tree(self, package_name: str, ecosystem: str,
                                 max_depth: int = 10) -> list[dict[str, Any]]:
        """
        Returns the full transitive dependency tree for a package.
        Each result includes the package name, ecosystem, depth, and risk score.
        """
        with self.get_session() as session:
            result = session.run(
                """
                MATCH path = (root:Package {name: $name, ecosystem: $ecosystem})
                              -[:DEPENDS_ON*1..]->(dep:Package)
                WHERE length(path) <= $max_depth
                RETURN dep.name AS name,
                       dep.ecosystem AS ecosystem,
                       dep.version AS version,
                       dep.risk_score AS risk_score,
                       length(path) AS depth
                ORDER BY depth, dep.name
                """,
                name=package_name, ecosystem=ecosystem,
                max_depth=max_depth,
            )
            return [dict(record) for record in result]

    def get_graph_for_visualization(self, package_name: str,
                                    ecosystem: str, max_depth: int = 5) -> dict:
        """
        Returns nodes and edges formatted for the React force-graph frontend.
        """
        with self.get_session() as session:
            # Get all nodes in the subgraph
            nodes_result = session.run(
                """
                MATCH path = (root:Package {name: $name, ecosystem: $ecosystem})
                              -[:DEPENDS_ON*0..]->(dep:Package)
                WHERE length(path) <= $max_depth
                WITH DISTINCT dep
                RETURN dep.name AS name,
                       dep.ecosystem AS ecosystem,
                       dep.version AS version,
                       dep.risk_score AS risk_score
                """,
                name=package_name, ecosystem=ecosystem,
                max_depth=max_depth,
            )
            nodes = [dict(r) for r in nodes_result]

            # Get all edges in the subgraph
            edges_result = session.run(
                """
                MATCH path = (root:Package {name: $name, ecosystem: $ecosystem})
                              -[:DEPENDS_ON*0..]->(parent:Package)
                              -[r:DEPENDS_ON]->(child:Package)
                WHERE length(path) <= $max_depth
                RETURN DISTINCT parent.name AS source,
                       child.name AS target,
                       r.version_constraint AS version_constraint,
                       r.depth AS depth
                """,
                name=package_name, ecosystem=ecosystem,
                max_depth=max_depth,
            )
            edges = [dict(r) for r in edges_result]

        return {"nodes": nodes, "links": edges}

    # ─── Contributor Operations ───────────────────────────────

    def upsert_contributor(self, username: str, account_age_days: int = None,
                           trust_score: float = None) -> None:
        """Create or update a Contributor node."""
        with self.get_session() as session:
            session.run(
                """
                MERGE (c:Contributor {username: $username})
                SET c.account_age_days = COALESCE($account_age_days, c.account_age_days),
                    c.trust_score = COALESCE($trust_score, c.trust_score),
                    c.last_updated = datetime()
                """,
                username=username, account_age_days=account_age_days,
                trust_score=trust_score,
            )

    def add_contribution(self, username: str, package_name: str,
                         package_ecosystem: str, role: str = "contributor",
                         access_level: str = "read", commit_count: int = 0) -> None:
        """Create a CONTRIBUTED_TO relationship between a contributor and a package."""
        with self.get_session() as session:
            session.run(
                """
                MERGE (c:Contributor {username: $username})
                MERGE (p:Package {name: $package_name, ecosystem: $package_ecosystem})
                MERGE (c)-[r:CONTRIBUTED_TO]->(p)
                SET r.role = $role,
                    r.access_level = $access_level,
                    r.commit_count = $commit_count,
                    r.last_updated = datetime()
                """,
                username=username, package_name=package_name,
                package_ecosystem=package_ecosystem,
                role=role, access_level=access_level, commit_count=commit_count,
            )

    # ─── Query Operations ─────────────────────────────────────

    def get_package_contributors(self, package_name: str,
                                  ecosystem: str) -> list[dict[str, Any]]:
        """Get all contributors to a specific package."""
        with self.get_session() as session:
            result = session.run(
                """
                MATCH (c:Contributor)-[r:CONTRIBUTED_TO]->(p:Package {name: $name, ecosystem: $ecosystem})
                RETURN c.username AS username,
                       c.account_age_days AS account_age_days,
                       c.trust_score AS trust_score,
                       r.role AS role,
                       r.access_level AS access_level,
                       r.commit_count AS commit_count
                ORDER BY r.commit_count DESC
                """,
                name=package_name, ecosystem=ecosystem,
            )
            return [dict(record) for record in result]

    def get_contributor_packages(self, username: str) -> list[dict[str, Any]]:
        """Get all packages a contributor has worked on."""
        with self.get_session() as session:
            result = session.run(
                """
                MATCH (c:Contributor {username: $username})-[r:CONTRIBUTED_TO]->(p:Package)
                RETURN p.name AS name,
                       p.ecosystem AS ecosystem,
                       p.risk_score AS risk_score,
                       r.role AS role,
                       r.access_level AS access_level
                ORDER BY p.name
                """,
                username=username,
            )
            return [dict(record) for record in result]

    def get_dependents(self, package_name: str, ecosystem: str) -> list[dict[str, Any]]:
        """Get all packages that depend on a specific package (reverse lookup)."""
        with self.get_session() as session:
            result = session.run(
                """
                MATCH (dependent:Package)-[:DEPENDS_ON*1..5]->(p:Package {name: $name, ecosystem: $ecosystem})
                RETURN DISTINCT dependent.name AS name,
                       dependent.ecosystem AS ecosystem,
                       dependent.risk_score AS risk_score
                ORDER BY dependent.name
                """,
                name=package_name, ecosystem=ecosystem,
            )
            return [dict(record) for record in result]

    def clear_package_graph(self, package_name: str, ecosystem: str) -> None:
        """Remove a package and all its dependency edges (for re-scanning)."""
        with self.get_session() as session:
            session.run(
                """
                MATCH (p:Package {name: $name, ecosystem: $ecosystem})-[r:DEPENDS_ON]->()
                DELETE r
                """,
                name=package_name, ecosystem=ecosystem,
            )

    def get_stats(self) -> dict:
        """Get graph statistics for the dashboard."""
        with self.get_session() as session:
            result = session.run(
                """
                CALL {
                    MATCH (p:Package) RETURN count(p) AS package_count
                }
                CALL {
                    MATCH (c:Contributor) RETURN count(c) AS contributor_count
                }
                CALL {
                    MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS dependency_count
                }
                RETURN package_count, contributor_count, dependency_count
                """
            )
            record = result.single()
            if record:
                return dict(record)
            return {"package_count": 0, "contributor_count": 0, "dependency_count": 0}
