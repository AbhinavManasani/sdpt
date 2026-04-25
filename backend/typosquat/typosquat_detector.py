"""
Software Provenance Tracker — Typosquat Detector

Detects potential typosquatting attacks by comparing scanned package
names against the most popular packages on PyPI and npm.

Data sources (real, never mocked):
  - PyPI top 5000: https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json
  - npm  top 1000: https://registry.npmjs.org/-/v1/search?text=&size=250
    (4 pages: from=0, 250, 500, 750)

Detection method:
  - Levenshtein distance via rapidfuzz
  - Distance 1 → severity: critical
  - Distance 2 → severity: high
  - Distance 0 (exact match) → safe, no flag

Results are NOT stored in a database; they are computed on-the-fly
with the popular-package lists cached in Redis (24-hour TTL).
"""

import asyncio
import logging
from datetime import datetime, timezone

import httpx
from rapidfuzz.distance import Levenshtein

from db.redis_conn import RedisManager

logger = logging.getLogger("provenance.typosquat.detector")

# ─── Constants ────────────────────────────────────────────────

PYPI_TOP_URL = (
    "https://hugovk.github.io/top-pypi-packages/"
    "top-pypi-packages-30-days.min.json"
)
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
NPM_PAGE_SIZE = 250
NPM_PAGES = 4  # 0, 250, 500, 750 → 1000 packages

CACHE_PREFIX = "typosquat"
CACHE_KEY_PYPI = "top_pypi_packages"
CACHE_KEY_NPM = "top_npm_packages"
CACHE_TTL = 86400  # 24 hours

MAX_LEVENSHTEIN_DISTANCE = 2
HTTP_TIMEOUT = 30.0


class TyposquatDetector:
    """
    Compares package names against top PyPI / npm packages
    and flags any that are within Levenshtein distance ≤ 2
    of a popular package.
    """

    def __init__(self, redis: RedisManager):
        self._redis = redis
        self._http: httpx.AsyncClient | None = None

    # ─── Lifecycle ────────────────────────────────────────────

    async def _ensure_http(self) -> httpx.AsyncClient:
        """Lazily create an httpx client."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                timeout=HTTP_TIMEOUT,
                follow_redirects=True,
                headers={"Accept": "application/json"},
            )
        return self._http

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None
        logger.info("TyposquatDetector HTTP client closed")

    # ─── Public API ───────────────────────────────────────────

    async def check_packages(
        self,
        packages: list[dict],
        ecosystem: str,
    ) -> dict:
        """
        Check a list of packages for potential typosquatting.

        Args:
            packages: List of dicts with at least a "name" key.
            ecosystem: "pypi" or "npm"

        Returns:
            Summary dict with flagged packages and statistics.
        """
        top_names = await self._get_top_packages(ecosystem)

        if not top_names:
            logger.warning(
                f"No top package list available for {ecosystem}; "
                "typosquat check skipped"
            )
            return {
                "ecosystem": ecosystem,
                "packages_checked": len(packages),
                "flagged": [],
                "total_flagged": 0,
                "error": f"Could not load top {ecosystem} packages",
            }

        # Build a set for O(1) exact-match lookups
        top_set = set(top_names)
        flagged: list[dict] = []

        for pkg in packages:
            pkg_name = pkg.get("name", "").strip().lower()
            if not pkg_name:
                continue

            # Exact match → legitimate, skip
            if pkg_name in top_set:
                continue

            # Compare against every top package
            matches = self._find_close_matches(pkg_name, top_names)
            if matches:
                flagged.append({
                    "package_name": pkg_name,
                    "package_version": pkg.get("version", ""),
                    "matches": matches,
                    "severity": self._worst_severity(matches),
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                })

        flagged.sort(
            key=lambda f: (
                0 if f["severity"] == "critical" else 1,
                f["package_name"],
            )
        )

        summary = {
            "ecosystem": ecosystem,
            "packages_checked": len(packages),
            "top_packages_loaded": len(top_names),
            "total_flagged": len(flagged),
            "critical_count": sum(
                1 for f in flagged if f["severity"] == "critical"
            ),
            "high_count": sum(
                1 for f in flagged if f["severity"] == "high"
            ),
            "flagged": flagged,
        }

        logger.info(
            f"Typosquat check complete for {ecosystem}: "
            f"{len(flagged)} flagged out of {len(packages)} packages"
        )
        return summary

    async def check_single(
        self,
        package_name: str,
        ecosystem: str,
    ) -> dict:
        """
        Check a single package name for typosquatting.

        Returns:
            Dict with match results and severity.
        """
        top_names = await self._get_top_packages(ecosystem)
        name_lower = package_name.strip().lower()

        if not top_names:
            return {
                "package_name": name_lower,
                "ecosystem": ecosystem,
                "is_typosquat": False,
                "matches": [],
                "severity": None,
                "error": f"Could not load top {ecosystem} packages",
            }

        top_set = set(top_names)

        # Exact match → safe
        if name_lower in top_set:
            return {
                "package_name": name_lower,
                "ecosystem": ecosystem,
                "is_typosquat": False,
                "is_top_package": True,
                "matches": [],
                "severity": None,
            }

        matches = self._find_close_matches(name_lower, top_names)
        severity = self._worst_severity(matches) if matches else None

        return {
            "package_name": name_lower,
            "ecosystem": ecosystem,
            "is_typosquat": len(matches) > 0,
            "is_top_package": False,
            "matches": matches,
            "severity": severity,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    # ─── Top-Package Loaders ──────────────────────────────────

    async def _get_top_packages(self, ecosystem: str) -> list[str]:
        """
        Return cached top packages, fetching fresh if the cache
        is empty or expired (24-hour TTL).
        """
        cache_key = (
            CACHE_KEY_PYPI if ecosystem == "pypi" else CACHE_KEY_NPM
        )

        # Try Redis cache first
        cached = await self._redis.get_cached(CACHE_PREFIX, cache_key)
        if cached and isinstance(cached, list) and len(cached) > 0:
            logger.debug(
                f"Top {ecosystem} packages loaded from cache "
                f"({len(cached)} entries)"
            )
            return cached

        # Cache miss — fetch from upstream
        if ecosystem == "pypi":
            names = await self._fetch_top_pypi()
        elif ecosystem == "npm":
            names = await self._fetch_top_npm()
        else:
            logger.error(f"Unknown ecosystem: {ecosystem}")
            return []

        # Store in Redis with 24hr TTL
        if names:
            await self._redis.set_cached(
                CACHE_PREFIX, cache_key, names, ttl_seconds=CACHE_TTL
            )
            logger.info(
                f"Cached {len(names)} top {ecosystem} packages "
                f"(TTL: {CACHE_TTL}s)"
            )

        return names

    async def _fetch_top_pypi(self) -> list[str]:
        """
        Fetch top 5000 PyPI packages from hugovk's aggregated dataset.
        Returns a list of lowercase package names.
        """
        client = await self._ensure_http()

        try:
            logger.info(f"Fetching top PyPI packages from {PYPI_TOP_URL}")
            resp = await client.get(PYPI_TOP_URL)
            resp.raise_for_status()
            data = resp.json()

            rows = data.get("rows", [])
            names = [
                row["project"].strip().lower()
                for row in rows
                if row.get("project")
            ]

            # Limit to top 5000
            names = names[:5000]
            logger.info(f"Loaded {len(names)} top PyPI packages")
            return names

        except Exception as e:
            logger.error(f"Failed to fetch top PyPI packages: {e}")
            return []

    async def _fetch_top_npm(self) -> list[str]:
        """
        Fetch top ~1000 npm packages from the npm registry search API.
        Uses multiple common query terms to get broad coverage,
        since the API requires a non-empty text parameter.
        Returns a deduplicated list of lowercase package names.
        """
        client = await self._ensure_http()
        all_names: list[str] = []
        seen: set[str] = set()

        # Use common letters to get broad coverage of top packages
        queries = ["is", "the", "a", "js"]

        for query in queries:
            params = {
                "text": query,
                "size": 250,
                "from": 0,
            }
            try:
                logger.info(f"Fetching npm packages query='{query}'")
                resp = await client.get(NPM_SEARCH_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
                objects = data.get("objects", [])
                for obj in objects:
                    pkg = obj.get("package", {})
                    name = pkg.get("name", "").strip().lower()
                    if name and name not in seen:
                        seen.add(name)
                        all_names.append(name)
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Failed npm query '{query}': {e}")
                continue

        logger.info(f"Loaded {len(all_names)} top npm packages")
        return all_names

    # ─── Levenshtein Matching ─────────────────────────────────

    def _find_close_matches(
        self,
        name: str,
        top_names: list[str],
    ) -> list[dict]:
        """
        Find all top packages within Levenshtein distance ≤ 2
        of the given name. Returns a list of match dicts sorted
        by distance (closest first).

        Short-circuits per-candidate: skips candidates whose length
        differs by more than MAX_LEVENSHTEIN_DISTANCE (impossible
        to match within budget).
        """
        matches: list[dict] = []
        name_len = len(name)

        for top_name in top_names:
            # Length-based pruning: if lengths differ by more than
            # the max distance, Levenshtein can't be ≤ threshold
            if abs(len(top_name) - name_len) > MAX_LEVENSHTEIN_DISTANCE:
                continue

            dist = Levenshtein.distance(name, top_name)

            if 1 <= dist <= MAX_LEVENSHTEIN_DISTANCE:
                matches.append({
                    "top_package": top_name,
                    "distance": dist,
                    "severity": "critical" if dist == 1 else "high",
                })

        # Sort by distance ascending, then alphabetically
        matches.sort(key=lambda m: (m["distance"], m["top_package"]))
        return matches

    @staticmethod
    def _worst_severity(matches: list[dict]) -> str:
        """Return the worst (lowest distance) severity from matches."""
        if any(m["severity"] == "critical" for m in matches):
            return "critical"
        return "high"

    # ─── Cache Management ─────────────────────────────────────

    async def refresh_cache(self, ecosystem: str) -> int:
        """
        Force-refresh the top package cache for an ecosystem.
        Deletes the existing cache entry and re-fetches.
        Returns the count of packages loaded.
        """
        cache_key = (
            CACHE_KEY_PYPI if ecosystem == "pypi" else CACHE_KEY_NPM
        )
        await self._redis.delete_cached(CACHE_PREFIX, cache_key)
        names = await self._get_top_packages(ecosystem)
        return len(names)

    async def get_cache_info(self) -> dict:
        """
        Return info about the current cache state for both ecosystems.
        """
        pypi_cached = await self._redis.get_cached(
            CACHE_PREFIX, CACHE_KEY_PYPI
        )
        npm_cached = await self._redis.get_cached(
            CACHE_PREFIX, CACHE_KEY_NPM
        )

        return {
            "pypi": {
                "cached": pypi_cached is not None,
                "count": len(pypi_cached) if pypi_cached else 0,
            },
            "npm": {
                "cached": npm_cached is not None,
                "count": len(npm_cached) if npm_cached else 0,
            },
            "ttl_seconds": CACHE_TTL,
        }
