"""
Software Provenance Tracker — Multi-Version Diff Analyser

Compares two versions of the same package (PyPI or npm) by
fetching metadata directly from the registry APIs and computing
a structured diff report.

Detections:
  - New / removed / changed dependencies
  - New install scripts (postinstall, preinstall, etc.)
  - Binary files added (detected from file extensions)
  - Maintainer changed between versions
  - Dependency count delta
  - Version jump size (major / minor / patch)
  - Composite risk score (0–100)

Caching:
  Results are cached in Redis under prefix "diff:" with a 24-hour TTL.

Persistence:
  Each diff result is also stored in the `diff_results` PostgreSQL table.
"""

import logging
import re
from datetime import datetime

import httpx

from db.redis_conn import RedisManager
from db.postgres import PostgresManager, DiffResult

logger = logging.getLogger("provenance.diff.version_differ")

# ─── Constants ────────────────────────────────────────────────

PYPI_API = "https://pypi.org/pypi"
NPM_API = "https://registry.npmjs.org"

REDIS_PREFIX = "diff"
REDIS_TTL = 86_400  # 24 hours

# File extensions that indicate binary content
_BINARY_EXTENSIONS = frozenset({
    ".so", ".dll", ".dylib", ".exe", ".bin", ".pyc", ".pyd",
    ".wasm", ".node", ".o", ".a", ".lib", ".obj",
})

# npm lifecycle scripts that can execute arbitrary code
_INSTALL_SCRIPT_KEYS = frozenset({
    "preinstall", "install", "postinstall",
    "preuninstall", "uninstall", "postuninstall",
    "prepublish", "preprepare", "prepare", "postprepare",
})

# Semver parsing pattern
_SEMVER_RE = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)"
)


class VersionDiffer:
    """
    Fetches two versions of a package from PyPI or npm and
    produces a structured diff report.

    Usage:
        differ = VersionDiffer(redis, postgres)
        result = await differ.diff("requests", "pypi", "2.28.0", "2.31.0")
    """

    def __init__(self, redis: RedisManager, postgres: PostgresManager):
        self._redis = redis
        self._postgres = postgres
        self._client = httpx.AsyncClient(timeout=20.0)

    # ─── Public API ───────────────────────────────────────────

    async def diff(
        self,
        package_name: str,
        ecosystem: str,
        version_from: str,
        version_to: str,
    ) -> dict:
        """
        Compare two versions and return a structured diff report.

        Checks Redis cache first, otherwise fetches from the registry,
        computes the diff, persists to Postgres, and caches in Redis.
        """
        cache_key = f"{package_name}:{ecosystem}:{version_from}:{version_to}"

        # ── Cache hit ─────────────────────────────────────────
        cached = await self._redis.get_cached(REDIS_PREFIX, cache_key)
        if cached is not None:
            logger.info(f"Cache hit for diff {cache_key}")
            return cached

        # ── Fetch metadata ────────────────────────────────────
        logger.info(
            f"Fetching {ecosystem} metadata for {package_name} "
            f"v{version_from} → v{version_to}"
        )

        if ecosystem.lower() == "pypi":
            meta_from = await self._fetch_pypi(package_name, version_from)
            meta_to = await self._fetch_pypi(package_name, version_to)
        elif ecosystem.lower() == "npm":
            meta_from = await self._fetch_npm(package_name, version_from)
            meta_to = await self._fetch_npm(package_name, version_to)
        else:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")

        # ── Compute diff ──────────────────────────────────────
        report = self._compute_diff(
            package_name=package_name,
            ecosystem=ecosystem,
            version_from=version_from,
            version_to=version_to,
            meta_from=meta_from,
            meta_to=meta_to,
        )

        # ── Persist to Postgres ───────────────────────────────
        await self._persist(report)

        # ── Cache result ──────────────────────────────────────
        await self._redis.set_cached(REDIS_PREFIX, cache_key, report, REDIS_TTL)

        return report

    async def close(self) -> None:
        """Shut down the HTTP client."""
        await self._client.aclose()

    # ─── Registry Fetchers ────────────────────────────────────

    async def _fetch_pypi(self, package: str, version: str) -> dict:
        """Fetch a specific PyPI version's metadata."""
        url = f"{PYPI_API}/{package}/{version}/json"
        resp = await self._client.get(url)

        if resp.status_code == 404:
            raise ValueError(
                f"PyPI package '{package}' version '{version}' not found."
            )
        resp.raise_for_status()

        data = resp.json()
        info = data.get("info", {})
        urls = data.get("urls", [])

        # Extract dependencies from requires_dist
        requires = info.get("requires_dist") or []
        deps = {}
        for req in requires:
            # "requests (>=2.20,<3.0) ; extra == 'security'"
            name = req.split(" ")[0].split(";")[0].split("(")[0].strip().lower()
            deps[name] = req

        # Detect binary files from distribution URLs
        filenames = [u.get("filename", "") for u in urls]
        has_binaries = any(
            any(fn.endswith(ext) for ext in _BINARY_EXTENSIONS)
            for fn in filenames
        )

        # Maintainer info
        maintainer = (
            info.get("maintainer")
            or info.get("maintainer_email")
            or info.get("author")
            or info.get("author_email")
            or "unknown"
        )

        return {
            "dependencies": deps,
            "filenames": filenames,
            "has_binaries": has_binaries,
            "maintainer": maintainer,
            "install_scripts": {},  # PyPI doesn't expose these in metadata
        }

    async def _fetch_npm(self, package: str, version: str) -> dict:
        """Fetch a specific npm version's metadata."""
        url = f"{NPM_API}/{package}/{version}"
        resp = await self._client.get(url)

        if resp.status_code == 404:
            raise ValueError(
                f"npm package '{package}' version '{version}' not found."
            )
        resp.raise_for_status()

        data = resp.json()

        # Dependencies (production)
        raw_deps = data.get("dependencies") or {}
        deps = {k.lower(): f"{k} {v}" for k, v in raw_deps.items()}

        # Install / lifecycle scripts
        scripts = data.get("scripts") or {}
        install_scripts = {
            k: v for k, v in scripts.items()
            if k.lower() in _INSTALL_SCRIPT_KEYS
        }

        # Detect binary files from dist/tarball filenames
        dist = data.get("dist") or {}
        tarball = dist.get("tarball", "")
        # npm tarballs are .tgz; check supplementary files list if present
        filenames = []
        if tarball:
            filenames.append(tarball.split("/")[-1])

        # Check for native bindings / binary add-ons
        has_binaries = bool(data.get("binary")) or any(
            any(fn.endswith(ext) for ext in _BINARY_EXTENSIONS)
            for fn in filenames
        )

        # Maintainer info
        maintainers = data.get("maintainers") or []
        if maintainers:
            maintainer = maintainers[0].get("name", "unknown")
        else:
            # Fall back to _npmUser
            npm_user = data.get("_npmUser") or {}
            maintainer = npm_user.get("name", "unknown")

        return {
            "dependencies": deps,
            "filenames": filenames,
            "has_binaries": has_binaries,
            "maintainer": maintainer,
            "install_scripts": install_scripts,
        }

    # ─── Diff Engine ──────────────────────────────────────────

    def _compute_diff(
        self,
        package_name: str,
        ecosystem: str,
        version_from: str,
        version_to: str,
        meta_from: dict,
        meta_to: dict,
    ) -> dict:
        """
        Produce a structured diff report from two metadata dicts.
        """
        deps_from = meta_from["dependencies"]
        deps_to = meta_to["dependencies"]

        keys_from = set(deps_from.keys())
        keys_to = set(deps_to.keys())

        new_deps = sorted(keys_to - keys_from)
        removed_deps = sorted(keys_from - keys_to)

        # Changed = same key but different spec
        changed_deps = {}
        for dep in keys_from & keys_to:
            if deps_from[dep] != deps_to[dep]:
                changed_deps[dep] = {
                    "from": deps_from[dep],
                    "to": deps_to[dep],
                }

        dep_count_delta = len(keys_to) - len(keys_from)

        # Install scripts added
        scripts_from = set(meta_from.get("install_scripts", {}).keys())
        scripts_to = set(meta_to.get("install_scripts", {}).keys())
        install_scripts_added = bool(scripts_to - scripts_from)

        # Binary files
        binary_from = meta_from.get("has_binaries", False)
        binary_to = meta_to.get("has_binaries", False)
        binary_files_added = (not binary_from) and binary_to

        # Maintainer change
        maintainer_from = meta_from.get("maintainer", "").lower().strip()
        maintainer_to = meta_to.get("maintainer", "").lower().strip()
        maintainer_changed = (
            maintainer_from != maintainer_to
            and maintainer_from != ""
            and maintainer_to != ""
        )

        # Version jump
        version_jump = self._classify_version_jump(version_from, version_to)

        # Composite risk score
        risk_score = self._calculate_risk_score(
            new_deps=new_deps,
            removed_deps=removed_deps,
            changed_deps=changed_deps,
            install_scripts_added=install_scripts_added,
            binary_files_added=binary_files_added,
            maintainer_changed=maintainer_changed,
            dep_count_delta=dep_count_delta,
            version_jump=version_jump,
        )

        # Human-readable summary
        summary = self._build_summary(
            package_name=package_name,
            version_from=version_from,
            version_to=version_to,
            new_deps=new_deps,
            removed_deps=removed_deps,
            changed_deps=changed_deps,
            install_scripts_added=install_scripts_added,
            binary_files_added=binary_files_added,
            maintainer_changed=maintainer_changed,
            maintainer_from=meta_from.get("maintainer", "unknown"),
            maintainer_to=meta_to.get("maintainer", "unknown"),
            dep_count_delta=dep_count_delta,
            version_jump=version_jump,
            risk_score=risk_score,
        )

        return {
            "package_name": package_name,
            "ecosystem": ecosystem,
            "version_from": version_from,
            "version_to": version_to,
            "new_dependencies": new_deps,
            "removed_dependencies": removed_deps,
            "changed_dependencies": changed_deps,
            "install_scripts_added": install_scripts_added,
            "binary_files_added": binary_files_added,
            "maintainer_changed": maintainer_changed,
            "dependency_count_delta": dep_count_delta,
            "version_jump": version_jump,
            "risk_score": round(risk_score, 1),
            "summary": summary,
            "created_at": datetime.utcnow().isoformat(),
        }

    # ─── Risk Scoring ─────────────────────────────────────────

    @staticmethod
    def _calculate_risk_score(
        new_deps: list,
        removed_deps: list,
        changed_deps: dict,
        install_scripts_added: bool,
        binary_files_added: bool,
        maintainer_changed: bool,
        dep_count_delta: int,
        version_jump: str,
    ) -> float:
        """
        Compute a 0–100 risk score for the version diff.

        Weights:
          - Install scripts added   → +30
          - Binary files added      → +25
          - Maintainer changed      → +20
          - New dependencies        → +3 each (max +15)
          - Removed dependencies    → +1 each (max +5)
          - Changed dependencies    → +2 each (max +10)
          - Large dep count delta   → +5 if |delta| >= 5
          - Major version jump      → +5
        """
        score = 0.0

        if install_scripts_added:
            score += 30.0
        if binary_files_added:
            score += 25.0
        if maintainer_changed:
            score += 20.0

        score += min(len(new_deps) * 3.0, 15.0)
        score += min(len(removed_deps) * 1.0, 5.0)
        score += min(len(changed_deps) * 2.0, 10.0)

        if abs(dep_count_delta) >= 5:
            score += 5.0

        if version_jump == "major":
            score += 5.0

        return min(score, 100.0)

    # ─── Version Jump Classification ──────────────────────────

    @staticmethod
    def _classify_version_jump(v_from: str, v_to: str) -> str:
        """Classify the version jump as major, minor, or patch."""
        m_from = _SEMVER_RE.match(v_from)
        m_to = _SEMVER_RE.match(v_to)

        if not m_from or not m_to:
            return "unknown"

        major_f, minor_f, patch_f = int(m_from.group(1)), int(m_from.group(2)), int(m_from.group(3))
        major_t, minor_t, patch_t = int(m_to.group(1)), int(m_to.group(2)), int(m_to.group(3))

        if major_t != major_f:
            return "major"
        if minor_t != minor_f:
            return "minor"
        if patch_t != patch_f:
            return "patch"
        return "none"

    # ─── Summary Builder ──────────────────────────────────────

    @staticmethod
    def _build_summary(
        package_name: str,
        version_from: str,
        version_to: str,
        new_deps: list,
        removed_deps: list,
        changed_deps: dict,
        install_scripts_added: bool,
        binary_files_added: bool,
        maintainer_changed: bool,
        maintainer_from: str,
        maintainer_to: str,
        dep_count_delta: int,
        version_jump: str,
        risk_score: float,
    ) -> str:
        """Build a concise human-readable summary of the diff."""
        lines = [
            f"Diff: {package_name} {version_from} → {version_to} "
            f"({version_jump} bump, risk {risk_score:.0f}/100)",
        ]

        if new_deps:
            lines.append(f"  + {len(new_deps)} new dep(s): {', '.join(new_deps[:5])}"
                         + (" …" if len(new_deps) > 5 else ""))
        if removed_deps:
            lines.append(f"  − {len(removed_deps)} removed dep(s): {', '.join(removed_deps[:5])}"
                         + (" …" if len(removed_deps) > 5 else ""))
        if changed_deps:
            lines.append(f"  Δ {len(changed_deps)} changed dep(s)")
        if install_scripts_added:
            lines.append("  ⚠ Install scripts added")
        if binary_files_added:
            lines.append("  ⚠ Binary files added")
        if maintainer_changed:
            lines.append(f"  ⚠ Maintainer changed: {maintainer_from} → {maintainer_to}")

        lines.append(f"  Dependency count delta: {dep_count_delta:+d}")

        return "\n".join(lines)

    # ─── Persistence ──────────────────────────────────────────

    async def _persist(self, report: dict) -> None:
        """Store the diff result in PostgreSQL."""
        try:
            async with self._postgres.get_session() as session:
                record = DiffResult(
                    package_name=report["package_name"],
                    ecosystem=report["ecosystem"],
                    version_from=report["version_from"],
                    version_to=report["version_to"],
                    new_dependencies=report["new_dependencies"],
                    removed_dependencies=report["removed_dependencies"],
                    changed_dependencies=report["changed_dependencies"],
                    install_scripts_added=report["install_scripts_added"],
                    binary_files_added=report["binary_files_added"],
                    maintainer_changed=report["maintainer_changed"],
                    dependency_count_delta=report["dependency_count_delta"],
                    version_jump=report["version_jump"],
                    risk_score=report["risk_score"],
                    summary=report["summary"],
                    created_at=datetime.utcnow(),
                )
                session.add(record)
                await session.commit()
                logger.info(
                    f"Diff result persisted: {report['package_name']} "
                    f"{report['version_from']} → {report['version_to']}"
                )
        except Exception as exc:
            logger.error(f"Failed to persist diff result: {exc}", exc_info=True)
