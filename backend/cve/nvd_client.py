"""
Software Provenance Tracker — NVD Client

Queries the NIST National Vulnerability Database (NVD) API v2.0
to look up known CVEs for software packages.

API: https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limits (no API key):
  - 5 requests per 30-second rolling window
  - We enforce a 6-second sleep between requests to stay safe

Caching:
  - Results cached in Redis with 24-hour TTL
  - Cache key format: nvd:<ecosystem>:<package_name>

CVSS score extraction:
  - Tries cvssMetricV31 first, falls back to cvssMetricV30
  - Maps base score to severity: critical/high/medium/low
"""

import asyncio
import logging
from datetime import datetime, timezone

import httpx

_nvd_semaphore = asyncio.Semaphore(1)

from db.redis_conn import RedisManager

logger = logging.getLogger("provenance.cve.nvd_client")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PREFIX = "nvd"
CACHE_TTL = 86400  # 24 hours
REQUEST_DELAY = 6.0  # seconds between NVD API calls


class NvdClient:
    """
    Async client for the NVD CVE API v2.0.

    Searches for known vulnerabilities by package name and ecosystem,
    caches results in Redis, and respects NVD rate limits.
    """

    # Map ecosystem to NVD keyword search terms
    ECOSYSTEM_KEYWORDS = {
        "pypi": "python",
        "npm": "node.js",
    }

    def __init__(self, redis: RedisManager):
        self._redis = redis
        self._http: httpx.AsyncClient | None = None
        self._last_request_time: float = 0.0

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Lazy-init the HTTP client."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                timeout=30.0,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "SoftwareProvenanceTracker/1.0",
                },
            )
        return self._http

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    async def clear_package_cache(
        self, package_name: str, ecosystem: str
    ) -> None:
        """Remove a package's cached CVE results from Redis."""
        cache_key = f"{ecosystem}:{package_name.lower()}"
        await self._redis.delete_cached(CACHE_PREFIX, cache_key)

    # ─── Public API ───────────────────────────────────────────

    async def search_cves(
        self,
        package_name: str,
        ecosystem: str = "pypi",
    ) -> list[dict]:
        """
        Search the NVD for CVEs matching a package name and ecosystem.

        1. Check Redis cache first
        2. If cache miss, query NVD API
        3. Parse and filter results to relevant ecosystem
        4. Cache the filtered results
        5. Return list of CVE findings

        Returns list of dicts with:
            cve_id, cvss_score, severity, description,
            published_date, last_modified
        """
        cache_key = f"{ecosystem}:{package_name.lower()}"

        # 1. Check cache
        cached = await self._redis.get_cached(CACHE_PREFIX, cache_key)
        if cached is not None:
            logger.debug(f"NVD cache hit: {cache_key} ({len(cached)} CVEs)")
            return cached

        # 2. Query NVD API
        logger.info(f"Querying NVD for '{package_name}' (ecosystem: {ecosystem})")
        raw_cves = await self._query_nvd(package_name, ecosystem)

        # 3. Parse and filter
        findings = self._parse_cve_results(raw_cves, package_name, ecosystem)

        # 4. Cache results (even empty lists to avoid re-querying)
        await self._redis.set_cached(
            CACHE_PREFIX, cache_key, findings, ttl_seconds=CACHE_TTL
        )

        logger.info(
            f"NVD results for '{package_name}': "
            f"{len(findings)} relevant CVE(s) found"
        )

        return findings

    # ─── NVD API Query ────────────────────────────────────────

    async def _query_nvd(
        self, package_name: str, ecosystem: str
    ) -> list[dict]:
        """
        Query the NVD API v2.0 for CVEs matching the package.

        Uses ecosystem-aware keyword search to reduce false positives.
        For pypi, short package names use the "python-{name}" format
        which mirrors how CVE databases reference Python packages.

        Enforces a 6-second delay between requests to respect
        the NVD rate limit (5 req / 30 sec without API key).
        """
        # Rate limit: wait at least 6 seconds since last request
        await self._enforce_rate_limit()

        # Build a more specific search keyword per ecosystem
        if ecosystem == "pypi":
            # Try the package name directly first — NVD indexes by
            # the package's canonical name (e.g. "Pillow", "Django").
            # Append "python" as a secondary keyword to reduce false
            # positives from unrelated projects with the same name.
            search_term = f"{package_name} python"
        elif ecosystem == "npm":
            search_term = f"{package_name} npm"
        else:
            search_term = package_name

        params = {
            "keywordSearch": search_term,
            "resultsPerPage": 50,
        }

        try:
            client = await self._get_http_client()
            async with _nvd_semaphore:
                response = await client.get(NVD_API_BASE, params=params)

                if response.status_code == 403:
                    logger.warning(
                        "NVD rate limit exceeded. Backing off 30 seconds."
                    )
                    await asyncio.sleep(30)
                    response = await client.get(NVD_API_BASE, params=params)

                await asyncio.sleep(6)  # Force 6s delay between requests

            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            logger.debug(
                f"NVD returned {data.get('totalResults', 0)} total results, "
                f"fetched {len(vulnerabilities)}"
            )

            return vulnerabilities

        except httpx.TimeoutException:
            logger.error(f"NVD API timeout for '{package_name}'")
            return []
        except httpx.HTTPStatusError as e:
            logger.error(
                f"NVD API error {e.response.status_code} for '{package_name}': "
                f"{e.response.text[:200]}"
            )
            return []
        except Exception as e:
            logger.error(f"NVD query failed for '{package_name}': {e}")
            return []

    async def _enforce_rate_limit(self) -> None:
        """Ensure at least REQUEST_DELAY seconds between API calls."""
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request_time
        if elapsed < REQUEST_DELAY:
            wait_time = REQUEST_DELAY - elapsed
            logger.debug(f"NVD rate limit: waiting {wait_time:.1f}s")
            await asyncio.sleep(wait_time)
        self._last_request_time = asyncio.get_event_loop().time()

    # ─── Result Parsing ───────────────────────────────────────

    def _parse_cve_results(
        self,
        vulnerabilities: list[dict],
        package_name: str,
        ecosystem: str,
    ) -> list[dict]:
        """
        Parse raw NVD API response into clean CVE finding dicts.

        Filters results to only include CVEs whose description
        mentions the package name (case-insensitive) to reduce
        false positives from keyword search.
        """
        findings = []
        pkg_lower = package_name.lower()

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            # Get English description
            description = self._get_english_description(cve_data)

            # Filter: description must be relevant to this package + ecosystem
            if not self._is_relevant_cve(description, package_name, ecosystem):
                continue

            # Extract CVSS score (try v3.1, then v3.0)
            cvss_score, severity = self._extract_cvss(cve_data)

            # Parse dates
            published = cve_data.get("published", "")
            last_modified = cve_data.get("lastModified", "")

            findings.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description[:500],  # Truncate long descriptions
                "published_date": published,
                "last_modified": last_modified,
            })

        # Sort by CVSS score descending (most critical first)
        findings.sort(key=lambda x: x["cvss_score"], reverse=True)

        return findings

    def _is_relevant_cve(self, description: str, package_name: str,
                         ecosystem: str) -> bool:
        """Check whether a CVE description is genuinely about this package."""
        desc_lower = description.lower()
        pkg_lower = package_name.lower()

        # Must mention the package name
        if pkg_lower not in desc_lower:
            return False

        # Must also mention the ecosystem or package-specific context
        ecosystem_hints = {
            "pypi": ["python", "pypi", "pip", "python-" + pkg_lower,
                     pkg_lower + " python", "py-" + pkg_lower],
            "npm": ["npm", "node", "javascript", "nodejs",
                    pkg_lower + ".js", "node_modules"],
        }
        hints = ecosystem_hints.get(ecosystem, [])

        if not any(hint in desc_lower for hint in hints):
            return False

        # For short generic names, require either the ecosystem hint
        # OR the package name appearing near a version number pattern
        # (e.g. "Pillow before 9.0.1" or "Pillow 9.0.0")
        # This catches CVEs that describe the package by name + version
        # without needing "python-pillow" style phrasing.
        if len(package_name) <= 10 and ecosystem == "pypi":
            import re
            version_pattern = re.compile(
                rf"{re.escape(pkg_lower)}\s+(before|through|prior|<=|<|\d)",
                re.IGNORECASE,
            )
            has_version_context = bool(version_pattern.search(desc_lower))
            has_ecosystem_hint = any(hint in desc_lower for hint in hints)
            if not has_version_context and not has_ecosystem_hint:
                return False

        return True

    @staticmethod
    def _get_english_description(cve_data: dict) -> str:
        """Extract the English description from CVE data."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        # Fallback: return first description if no English one found
        if descriptions:
            return descriptions[0].get("value", "")
        return ""

    @staticmethod
    def _extract_cvss(cve_data: dict) -> tuple[float, str]:
        """
        Extract CVSS base score and severity from CVE metrics.

        Priority:
          1. cvssMetricV31 (CVSS v3.1)
          2. cvssMetricV30 (CVSS v3.0)
          3. Default to 0.0 / "unknown"

        Severity mapping (NVD standard):
          0.0       → none
          0.1 - 3.9 → low
          4.0 - 6.9 → medium
          7.0 - 8.9 → high
          9.0 - 10.0 → critical
        """
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first
        v31 = metrics.get("cvssMetricV31", [])
        if v31:
            cvss_data = v31[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "").lower()
            if severity:
                return float(score), severity

        # Fall back to CVSS v3.0
        v30 = metrics.get("cvssMetricV30", [])
        if v30:
            cvss_data = v30[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "").lower()
            if severity:
                return float(score), severity

        # No CVSS v3 data — derive severity from score if available
        # Check v2 as last resort for the score
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            score = v2[0].get("cvssData", {}).get("baseScore", 0.0)
            return float(score), NvdClient._score_to_severity(score)

        return 0.0, "unknown"

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Map CVSS base score to severity string."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0.0:
            return "low"
        return "none"
