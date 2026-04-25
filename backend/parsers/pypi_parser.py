"""
Software Provenance Tracker — PyPI Dependency Parser

Parses Python dependency files to extract package names
and version specifiers. Supports:
  - requirements.txt (PEP 508)
  - pyproject.toml (PEP 621)

All parsing uses real data only — no mock fallbacks.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("provenance.parsers.pypi")


@dataclass
class ParsedDependency:
    """A single parsed dependency with name and version constraint."""
    name: str
    version_spec: str = ""        # e.g. ">=1.0,<2.0" or "==3.2.1"
    extras: list[str] = field(default_factory=list)  # e.g. ["security", "socks"]
    ecosystem: str = "pypi"
    is_dev: bool = False


class PyPIParser:
    """
    Parses Python dependency files and returns structured
    dependency lists. Handles edge cases: comments, blank lines,
    inline comments, environment markers, extras, URLs, and
    recursive -r includes.
    """

    # Regex for a valid package line in requirements.txt
    # Matches: package_name[extras]>=version,<version ; markers
    _REQ_PATTERN = re.compile(
        r"^"
        r"(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
        r"(?:\[(?P<extras>[^\]]+)\])?"                            # optional extras
        r"(?P<version>[^;#\s]*)"                                  # version spec
        r"(?:\s*;[^#]*)?"                                         # optional env markers
        r"(?:\s*#.*)?"                                             # optional inline comment
        r"$"
    )

    def parse_requirements_txt(self, content: str) -> list[ParsedDependency]:
        """
        Parse a requirements.txt file content.

        Handles:
          - Comments (# lines)
          - Blank lines
          - Inline comments (package==1.0 # comment)
          - Version specifiers (==, >=, <=, ~=, !=, <, >)
          - Extras (package[extra1,extra2])
          - Environment markers (package; python_version >= "3.8")
          - -r/-c recursive includes (flagged but not followed)
          - --index-url and other pip flags (skipped)
          - URL-based dependencies (skipped with warning)
        """
        dependencies = []

        for line_num, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Skip pip flags (--index-url, --extra-index-url, --trusted-host, etc.)
            if line.startswith("-") and not line.startswith("-e"):
                if line.startswith(("-r ", "-c ")):
                    logger.info(
                        f"Line {line_num}: recursive include '{line}' detected "
                        f"— referenced file must be parsed separately"
                    )
                continue

            # Skip editable installs and URL-based deps
            if line.startswith(("-e ", "git+", "http://", "https://")):
                logger.warning(
                    f"Line {line_num}: URL/editable dependency '{line}' skipped "
                    f"— not supported for provenance tracking"
                )
                continue

            # Parse the dependency line
            dep = self._parse_requirement_line(line, line_num)
            if dep:
                dependencies.append(dep)

        logger.info(f"Parsed {len(dependencies)} dependencies from requirements.txt")
        return dependencies

    def parse_pyproject_toml(self, content: str) -> list[ParsedDependency]:
        """
        Parse a pyproject.toml file content (PEP 621 format).

        Extracts from:
          - [project] dependencies = [...]
          - [project.optional-dependencies] dev = [...], test = [...]
        """
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        try:
            data = tomllib.loads(content)
        except Exception as e:
            logger.error(f"Failed to parse pyproject.toml: {e}")
            raise ValueError(f"Invalid pyproject.toml format: {e}") from e

        dependencies = []

        # Parse [project] dependencies
        project = data.get("project", {})
        for dep_str in project.get("dependencies", []):
            dep = self._parse_requirement_line(dep_str.strip(), 0)
            if dep:
                dependencies.append(dep)

        # Parse [project.optional-dependencies]
        optional = project.get("optional-dependencies", {})
        for group_name, dep_list in optional.items():
            for dep_str in dep_list:
                dep = self._parse_requirement_line(dep_str.strip(), 0)
                if dep:
                    dep.is_dev = group_name in ("dev", "test", "testing", "development")
                    dep.extras = []  # Reset extras — they come from the dep_str itself
                    dependencies.append(dep)

        logger.info(
            f"Parsed {len(dependencies)} dependencies from pyproject.toml"
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

        if path.name == "requirements.txt" or path.suffix == ".txt":
            return self.parse_requirements_txt(content)
        elif path.name == "pyproject.toml":
            return self.parse_pyproject_toml(content)
        else:
            raise ValueError(
                f"Unsupported Python dependency file: {path.name}. "
                f"Expected requirements.txt or pyproject.toml"
            )

    def parse_content(self, content: str, file_type: str) -> list[ParsedDependency]:
        """
        Parse raw content string with explicit file type.
        file_type: "requirements.txt" or "pyproject.toml"
        """
        if file_type in ("requirements.txt", "txt"):
            return self.parse_requirements_txt(content)
        elif file_type in ("pyproject.toml", "toml"):
            return self.parse_pyproject_toml(content)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")

    # ─── Private Helpers ──────────────────────────────────────

    def _parse_requirement_line(self, line: str, line_num: int) -> ParsedDependency | None:
        """Parse a single requirement line into a ParsedDependency."""
        # Strip inline comments
        comment_idx = line.find(" #")
        if comment_idx != -1:
            line = line[:comment_idx].strip()

        # Strip environment markers (everything after ;)
        marker_idx = line.find(";")
        if marker_idx != -1:
            line = line[:marker_idx].strip()

        match = self._REQ_PATTERN.match(line)
        if not match:
            logger.warning(
                f"Line {line_num}: Could not parse dependency line: '{line}'"
            )
            return None

        name = self._normalize_name(match.group("name"))
        version_spec = match.group("version").strip() if match.group("version") else ""
        extras_str = match.group("extras")
        extras = [e.strip() for e in extras_str.split(",")] if extras_str else []

        return ParsedDependency(
            name=name,
            version_spec=version_spec,
            extras=extras,
            ecosystem="pypi",
        )

    @staticmethod
    def _normalize_name(name: str) -> str:
        """
        Normalize a Python package name per PEP 503.
        Converts to lowercase and replaces [-_.] with hyphens.
        e.g. "Flask_RESTful" -> "flask-restful"
        """
        return re.sub(r"[-_.]+", "-", name).lower()
