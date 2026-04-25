"""
Software Provenance Tracker — Transitive Dependency Resolver

Resolves the full dependency tree for any package by calling
the PyPI and npm registry APIs directly. No Libraries.io.

APIs used:
  - PyPI:  https://pypi.org/pypi/{package}/json
  - npm:   https://registry.npmjs.org/{package}

Results are cached in Redis to respect rate limits
and avoid redundant API calls.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("provenance.graph.resolver")


@dataclass
class ResolvedPackage:
    """A fully resolved package with its direct dependencies."""
    name: str
    version: str
    ecosystem: str                  # "pypi" or "npm"
    summary: str = ""
    author: str = ""
    homepage: str = ""
    repo_url: str = ""
    license: str = ""
    dependencies: list[dict] = field(default_factory=list)  # [{name, version_spec}]
    download_count: int = 0


class DependencyResolver:
    """
    Resolves transitive dependencies by recursively fetching
    package metadata from PyPI and npm registries.

    Uses Redis caching to avoid hitting API rate limits.
    Tracks visited packages to prevent infinite loops.
    """

    def __init__(self, redis_manager, settings):
        """
        Args:
            redis_manager: RedisManager instance for caching
            settings: Settings instance for API URLs and config
        """
        self._redis = redis_manager
        self._settings = settings
        self._http_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=True,
                headers={"Accept": "application/json"},
            )
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    # ─── Main Resolution Entry Point ─────────────────────────

    async def resolve_all(
        self,
        packages: list[dict],
        ecosystem: str,
        max_depth: int | None = None,
    ) -> list[ResolvedPackage]:
        """
        Resolve the full transitive dependency tree for a list of packages.

        Args:
            packages: List of {"name": str, "version_spec": str}
            ecosystem: "pypi" or "npm"
            max_depth: Max recursion depth (defaults to settings value)

        Returns:
            Flat list of all resolved packages (direct + transitive)
        """
        if max_depth is None:
            max_depth = self._settings.max_dependency_depth

        visited = set()
        all_resolved = []

        for pkg in packages:
            resolved = await self._resolve_recursive(
                name=pkg["name"],
                ecosystem=ecosystem,
                depth=0,
                max_depth=max_depth,
                visited=visited,
            )
            all_resolved.extend(resolved)

        logger.info(
            f"Resolved {len(all_resolved)} total packages "
            f"({len(packages)} direct, {len(all_resolved) - len(packages)} transitive)"
        )
        return all_resolved

    # ─── Recursive Resolution ─────────────────────────────────

    async def _resolve_recursive(
        self,
        name: str,
        ecosystem: str,
        depth: int,
        max_depth: int,
        visited: set[str],
    ) -> list[ResolvedPackage]:
        """Recursively resolve a package and all its dependencies."""
        # Generate a visit key to prevent cycles
        visit_key = f"{ecosystem}:{name.lower()}"
        if visit_key in visited:
            return []
        visited.add(visit_key)

        # Check depth limit
        if depth > max_depth:
            logger.debug(f"Max depth {max_depth} reached at {name}, stopping recursion")
            return []

        # Fetch package metadata (from cache or API)
        try:
            if ecosystem == "pypi":
                resolved = await self._fetch_pypi_package(name)
            elif ecosystem == "npm":
                resolved = await self._fetch_npm_package(name)
            else:
                logger.error(f"Unknown ecosystem: {ecosystem}")
                return []
        except Exception as e:
            logger.warning(f"Failed to resolve {name} ({ecosystem}): {e}")
            return []

        if resolved is None:
            return []

        result = [resolved]

        # Recursively resolve each dependency
        if resolved.dependencies and depth < max_depth:
            tasks = []
            for dep in resolved.dependencies:
                tasks.append(
                    self._resolve_recursive(
                        name=dep["name"],
                        ecosystem=ecosystem,
                        depth=depth + 1,
                        max_depth=max_depth,
                        visited=visited,
                    )
                )
            # Resolve dependencies concurrently (batched to avoid overwhelming APIs)
            batch_size = 10
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for batch_result in batch_results:
                    if isinstance(batch_result, Exception):
                        logger.warning(f"Batch resolution error: {batch_result}")
                    elif isinstance(batch_result, list):
                        result.extend(batch_result)

        return result

    # ─── PyPI API ─────────────────────────────────────────────

    async def _fetch_pypi_package(self, name: str) -> ResolvedPackage | None:
        """
        Fetch package metadata from PyPI JSON API.
        URL: https://pypi.org/pypi/{package}/json

        Caches the response in Redis.
        """
        # Normalize name for PyPI
        normalized = re.sub(r"[-_.]+", "-", name).lower()

        # Check Redis cache first
        cached = await self._redis.get_pypi_package(normalized)
        if cached is not None:
            logger.debug(f"Cache hit: pypi:{normalized}")
            return self._parse_pypi_response(cached, normalized)

        # Fetch from PyPI API
        client = await self._get_client()
        url = f"{self._settings.pypi_api_url}/{normalized}/json"

        try:
            response = await client.get(url)
        except httpx.RequestError as e:
            logger.error(f"PyPI API request failed for {normalized}: {e}")
            raise

        if response.status_code == 404:
            logger.warning(f"Package not found on PyPI: {normalized}")
            return None

        if response.status_code != 200:
            logger.error(f"PyPI API error for {normalized}: HTTP {response.status_code}")
            raise RuntimeError(f"PyPI API returned {response.status_code} for {normalized}")

        data = response.json()

        # Cache the response
        await self._redis.set_pypi_package(
            normalized, data, ttl_seconds=self._settings.registry_cache_ttl
        )

        return self._parse_pypi_response(data, normalized)

    def _parse_pypi_response(self, data: dict, name: str) -> ResolvedPackage:
        """Parse PyPI JSON API response into a ResolvedPackage."""
        info = data.get("info", {})

        # Extract dependencies from requires_dist
        dependencies = []
        requires_dist = info.get("requires_dist") or []
        for req in requires_dist:
            dep = self._parse_pypi_requirement(req)
            if dep:
                dependencies.append(dep)

        # Try to find repository URL
        project_urls = info.get("project_urls") or {}
        repo_url = (
            project_urls.get("Source")
            or project_urls.get("Repository")
            or project_urls.get("Source Code")
            or project_urls.get("GitHub")
            or project_urls.get("Homepage", "")
        )

        return ResolvedPackage(
            name=name,
            version=info.get("version", ""),
            ecosystem="pypi",
            summary=info.get("summary", ""),
            author=info.get("author", "") or info.get("maintainer", ""),
            homepage=info.get("home_page", ""),
            repo_url=repo_url,
            license=info.get("license", ""),
            dependencies=dependencies,
        )

    @staticmethod
    def _parse_pypi_requirement(req_string: str) -> dict | None:
        """
        Parse a single requirement from requires_dist.
        Format: "package_name (>=1.0) ; extra == 'test'"

        Skips dependencies that require extras (conditional deps).
        """
        # Skip extra-only dependencies (e.g. "package ; extra == 'dev'")
        if "extra ==" in req_string or "extra==" in req_string:
            return None

        # Extract name and version spec
        match = re.match(
            r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
            r"(?:\[.*?\])?"              # optional extras
            r"\s*"
            r"(?:\(([^)]*)\))?"          # optional version in parens
            r"([^;]*)?",                 # optional version without parens
            req_string,
        )

        if not match:
            return None

        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()

        # Version might be in parens or directly after name
        version = (match.group(3) or match.group(4) or "").strip()

        return {"name": name, "version_spec": version}

    # ─── npm API ──────────────────────────────────────────────

    async def _fetch_npm_package(self, name: str) -> ResolvedPackage | None:
        """
        Fetch package metadata from npm Registry API.
        URL: https://registry.npmjs.org/{package}

        Uses abbreviated metadata endpoint for efficiency.
        Caches the response in Redis.
        """
        # Check Redis cache first
        cached = await self._redis.get_npm_package(name)
        if cached is not None:
            logger.debug(f"Cache hit: npm:{name}")
            return self._parse_npm_response(cached, name)

        # Fetch from npm registry (abbreviated metadata)
        client = await self._get_client()
        url = f"{self._settings.npm_registry_url}/{name}"

        try:
            response = await client.get(
                url,
                headers={"Accept": "application/vnd.npm.install-v1+json"},
            )
        except httpx.RequestError as e:
            logger.error(f"npm API request failed for {name}: {e}")
            raise

        if response.status_code == 404:
            logger.warning(f"Package not found on npm: {name}")
            return None

        if response.status_code != 200:
            logger.error(f"npm API error for {name}: HTTP {response.status_code}")
            raise RuntimeError(f"npm API returned {response.status_code} for {name}")

        data = response.json()

        # Cache the response
        await self._redis.set_npm_package(
            name, data, ttl_seconds=self._settings.registry_cache_ttl
        )

        return self._parse_npm_response(data, name)

    def _parse_npm_response(self, data: dict, name: str) -> ResolvedPackage:
        """Parse npm registry API response into a ResolvedPackage."""
        # Get the latest version info
        dist_tags = data.get("dist-tags", {})
        latest_version = dist_tags.get("latest", "")

        versions = data.get("versions", {})
        version_info = versions.get(latest_version, {})

        # Extract dependencies from the latest version
        dependencies = []
        deps = version_info.get("dependencies", {})
        for dep_name, version_spec in deps.items():
            dependencies.append({
                "name": dep_name,
                "version_spec": version_spec,
            })

        # Extract metadata
        repo = version_info.get("repository", {})
        repo_url = ""
        if isinstance(repo, dict):
            repo_url = repo.get("url", "")
            # Clean git+https:// and .git suffix
            repo_url = repo_url.replace("git+", "").rstrip(".git")
        elif isinstance(repo, str):
            repo_url = repo

        return ResolvedPackage(
            name=name,
            version=latest_version,
            ecosystem="npm",
            summary=version_info.get("description", "") or data.get("description", ""),
            author=self._extract_npm_author(version_info),
            homepage=version_info.get("homepage", ""),
            repo_url=repo_url,
            license=version_info.get("license", ""),
            dependencies=dependencies,
        )

    @staticmethod
    def _extract_npm_author(version_info: dict) -> str:
        """Extract author name from npm version info."""
        author = version_info.get("author", "")
        if isinstance(author, dict):
            return author.get("name", "")
        elif isinstance(author, str):
            return author
        return ""
