"""
Software Provenance Tracker — npm Dependency Parser

Parses JavaScript/Node.js dependency files to extract
package names and version specifiers. Supports:
  - package.json (dependencies, devDependencies, etc.)
  - package-lock.json (resolved dependency tree)

All parsing uses real data only — no mock fallbacks.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("provenance.parsers.npm")


@dataclass
class ParsedDependency:
    """A single parsed dependency with name and version constraint."""
    name: str
    version_spec: str = ""          # e.g. "^1.0.0" or "~2.3.4" or ">=1.0.0 <2.0.0"
    resolved_version: str = ""      # Exact resolved version from lock file
    ecosystem: str = "npm"
    is_dev: bool = False
    is_peer: bool = False
    is_optional: bool = False


class NpmParser:
    """
    Parses npm dependency files and returns structured
    dependency lists. Handles all dependency categories
    and lock file resolution.
    """

    def parse_package_json(self, content: str) -> list[ParsedDependency]:
        """
        Parse a package.json file content.

        Extracts from all dependency sections:
          - dependencies (production)
          - devDependencies (development only)
          - peerDependencies (required by consumers)
          - optionalDependencies (install if possible)
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse package.json: {e}")
            raise ValueError(f"Invalid package.json format: {e}") from e

        dependencies = []

        # Parse each dependency section
        dep_sections = [
            ("dependencies", False, False, False),
            ("devDependencies", True, False, False),
            ("peerDependencies", False, True, False),
            ("optionalDependencies", False, False, True),
        ]

        for section_name, is_dev, is_peer, is_optional in dep_sections:
            section = data.get(section_name, {})
            for name, version_spec in section.items():
                # Skip URL-based dependencies
                if self._is_url_dependency(version_spec):
                    logger.warning(
                        f"URL dependency '{name}': '{version_spec}' skipped "
                        f"— not supported for provenance tracking"
                    )
                    continue

                # Skip file: protocol dependencies
                if version_spec.startswith("file:"):
                    logger.warning(
                        f"Local file dependency '{name}': '{version_spec}' skipped"
                    )
                    continue

                dependencies.append(ParsedDependency(
                    name=name,
                    version_spec=version_spec,
                    ecosystem="npm",
                    is_dev=is_dev,
                    is_peer=is_peer,
                    is_optional=is_optional,
                ))

        logger.info(
            f"Parsed {len(dependencies)} dependencies from package.json "
            f"({sum(1 for d in dependencies if not d.is_dev)} production, "
            f"{sum(1 for d in dependencies if d.is_dev)} dev)"
        )
        return dependencies

    def parse_package_lock_json(self, content: str) -> list[ParsedDependency]:
        """
        Parse a package-lock.json file content.

        Supports both lockfile formats:
          - v2/v3 (npm 7+): uses "packages" field
          - v1 (npm 6): uses "dependencies" field

        Returns resolved exact versions for every package
        in the full dependency tree (transitive included).
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse package-lock.json: {e}")
            raise ValueError(f"Invalid package-lock.json format: {e}") from e

        lockfile_version = data.get("lockfileVersion", 1)
        dependencies = []

        if lockfile_version >= 2 and "packages" in data:
            # v2/v3 format — "packages" field (preferred)
            dependencies = self._parse_lockfile_v2(data)
        elif "dependencies" in data:
            # v1 format — "dependencies" field
            dependencies = self._parse_lockfile_v1(data["dependencies"])
        else:
            logger.warning("package-lock.json has no 'packages' or 'dependencies' field")

        logger.info(
            f"Parsed {len(dependencies)} resolved packages from "
            f"package-lock.json (lockfileVersion: {lockfile_version})"
        )
        return dependencies

    def parse_file(self, file_path: str) -> list[ParsedDependency]:
        """
        Auto-detect file type and parse accordingly.
        Raises FileNotFoundError if the file doesn't exist.
        Raises ValueError if the file type is not supported.
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Dependency file not found: {file_path}")

        content = path.read_text(encoding="utf-8")

        if path.name == "package-lock.json":
            return self.parse_package_lock_json(content)
        elif path.name == "package.json":
            return self.parse_package_json(content)
        else:
            raise ValueError(
                f"Unsupported npm dependency file: {path.name}. "
                f"Expected package.json or package-lock.json"
            )

    def parse_content(self, content: str, file_type: str) -> list[ParsedDependency]:
        """
        Parse raw content string with explicit file type.
        file_type: "package.json" or "package-lock.json"
        """
        if file_type == "package.json":
            return self.parse_package_json(content)
        elif file_type == "package-lock.json":
            return self.parse_package_lock_json(content)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")

    # ─── Private Helpers ──────────────────────────────────────

    def _parse_lockfile_v2(self, data: dict) -> list[ParsedDependency]:
        """Parse lockfile v2/v3 format using the 'packages' field."""
        dependencies = []
        packages = data.get("packages", {})

        for key, pkg_info in packages.items():
            # Skip the root package (empty key "")
            if not key:
                continue

            # Extract package name from the key path
            # Key format: "node_modules/package-name" or
            #             "node_modules/scope/package-name"
            name = self._extract_name_from_path(key)
            if not name:
                continue

            version = pkg_info.get("version", "")
            is_dev = pkg_info.get("dev", False)
            is_optional = pkg_info.get("optional", False)
            is_peer = pkg_info.get("peer", False)

            dependencies.append(ParsedDependency(
                name=name,
                version_spec=version,
                resolved_version=version,
                ecosystem="npm",
                is_dev=is_dev,
                is_peer=is_peer,
                is_optional=is_optional,
            ))

        return dependencies

    def _parse_lockfile_v1(self, deps: dict, prefix: str = "") -> list[ParsedDependency]:
        """Parse lockfile v1 format recursively through nested 'dependencies'."""
        dependencies = []

        for name, info in deps.items():
            version = info.get("version", "")
            is_dev = info.get("dev", False)
            is_optional = info.get("optional", False)

            dependencies.append(ParsedDependency(
                name=name,
                version_spec=version,
                resolved_version=version,
                ecosystem="npm",
                is_dev=is_dev,
                is_optional=is_optional,
            ))

            # Recurse into nested dependencies
            nested = info.get("dependencies", {})
            if nested:
                dependencies.extend(self._parse_lockfile_v1(nested, f"{prefix}{name}/"))

        return dependencies

    @staticmethod
    def _extract_name_from_path(key: str) -> str:
        """
        Extract the npm package name from a node_modules path.
        Examples:
          "node_modules/lodash" -> "lodash"
          "node_modules/@types/node" -> "@types/node"
          "node_modules/a/node_modules/b" -> "b"
        """
        parts = key.split("node_modules/")
        if not parts:
            return ""
        # Take the last segment (handles nested node_modules)
        last_part = parts[-1]
        if not last_part:
            return ""

        # Handle scoped packages (@scope/name)
        if last_part.startswith("@"):
            return last_part  # e.g. "@types/node"
        else:
            # Take only the first path segment
            return last_part.split("/")[0]

    @staticmethod
    def _is_url_dependency(version_spec: str) -> bool:
        """Check if a version specifier is actually a URL."""
        url_prefixes = (
            "git+", "git://", "http://", "https://",
            "ssh://", "github:", "gitlab:", "bitbucket:",
        )
        return version_spec.startswith(url_prefixes)
