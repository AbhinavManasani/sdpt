"""
Software Provenance Tracker — Contributor Analyzer

Builds behavioral baselines for GitHub contributors and
detects deviations that may indicate account compromise
or supply chain attacks.

Baseline metrics per contributor:
  - Account age (days since creation)
  - Average commits per week
  - Typical commit hour (UTC)
  - Average lines changed per commit
  - Repository count
  - Primary programming languages
  - Access patterns across packages

Deviation signals:
  - New maintainer with young account
  - Sudden commit hour shift
  - Unusual language in commit
  - Burst of activity from dormant account
  - Access elevation on critical package
"""

import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any
from collections import Counter

from github.github_client import GitHubClient
from db.neo4j_conn import Neo4jManager
from db.postgres import PostgresManager, ContributorBaseline, ContributorEvent
from db.redis_conn import RedisManager
from sqlalchemy import select

logger = logging.getLogger("provenance.github.analyzer")


class ContributorAnalyzer:
    """
    Analyzes GitHub contributors to build behavioral baselines
    and detect anomalous activity patterns.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        neo4j: Neo4jManager,
        postgres: PostgresManager,
        redis: RedisManager,
    ):
        self._github = github_client
        self._neo4j = neo4j
        self._postgres = postgres
        self._redis = redis

    async def close(self) -> None:
        """Clean up resources."""
        await self._github.close()

    # ─── Full Profile Analysis ────────────────────────────────

    async def analyze_contributor(self, username: str) -> dict:
        """
        Full contributor analysis pipeline:
          1. Fetch GitHub profile + repos + events
          2. Build behavioral baseline
          3. Store baseline in PostgreSQL
          4. Store contributor node in Neo4j
          5. Detect deviations from baseline
          6. Return complete analysis

        Returns a dict with profile, baseline, deviations, and risk flags.
        """
        logger.info(f"Analyzing contributor: {username}")

        # Step 1: Fetch all data from GitHub concurrently
        profile, repos, events = await asyncio.gather(
            self._github.get_user_profile(username),
            self._github.get_user_repos(username),
            self._github.get_user_events(username),
        )

        if profile is None:
            return {
                "username": username,
                "status": "not_found",
                "message": f"GitHub user '{username}' not found",
            }

        # Step 2: Build baseline from fetched data
        baseline = self._build_baseline(profile, repos, events)

        # Step 3: Store baseline in PostgreSQL
        await self._store_baseline(baseline)

        # Step 4: Store contributor node in Neo4j
        await asyncio.to_thread(
            self._neo4j.upsert_contributor,
            username=username,
            account_age_days=baseline["account_age_days"],
            trust_score=baseline["trust_score"],
        )

        # Step 5: Detect deviations
        deviations = self._detect_deviations(baseline, events)

        # Step 6: Build response
        return {
            "username": username,
            "status": "analyzed",
            "profile": {
                "name": profile.get("name", ""),
                "bio": profile.get("bio", ""),
                "company": profile.get("company", ""),
                "location": profile.get("location", ""),
                "public_repos": profile.get("public_repos", 0),
                "followers": profile.get("followers", 0),
                "following": profile.get("following", 0),
                "created_at": profile.get("created_at", ""),
                "avatar_url": profile.get("avatar_url", ""),
            },
            "baseline": baseline,
            "deviations": deviations,
            "risk_flags": self._generate_risk_flags(baseline, deviations),
        }

    # ─── Analyze Contributors for a Package ───────────────────

    async def analyze_package_contributors(
        self,
        owner: str,
        repo: str,
        ecosystem: str = "pypi",
    ) -> dict:
        """
        Analyze all contributors to a specific repository.
        Links contributors to the package in Neo4j.

        Returns:
          - List of analyzed contributors
          - Package-level risk summary
        """
        logger.info(f"Analyzing contributors for {owner}/{repo}")

        # Fetch contributors list
        contributors = await self._github.get_repo_contributors(owner, repo)
        if not contributors:
            return {
                "package": f"{owner}/{repo}",
                "status": "no_contributors",
                "message": "No contributors found for this repository",
            }

        results = []
        for contributor in contributors[:20]:  # Limit to top 20 contributors
            username = contributor.get("login", "")
            if not username:
                continue

            try:
                analysis = await self.analyze_contributor(username)
                analysis["contributions"] = contributor.get("contributions", 0)

                # Link contributor to package in Neo4j
                await asyncio.to_thread(
                    self._neo4j.add_contribution,
                    username=username,
                    package_name=repo,
                    package_ecosystem=ecosystem,
                    role="contributor",
                    commit_count=contributor.get("contributions", 0),
                )

                results.append(analysis)
            except Exception as e:
                logger.warning(f"Failed to analyze {username}: {e}")
                results.append({
                    "username": username,
                    "status": "error",
                    "message": str(e),
                })

        # Calculate package-level risk
        analyzed = [r for r in results if r.get("status") == "analyzed"]
        flagged = [r for r in analyzed if r.get("risk_flags")]

        return {
            "package": f"{owner}/{repo}",
            "ecosystem": ecosystem,
            "status": "completed",
            "total_contributors": len(contributors),
            "analyzed_count": len(analyzed),
            "flagged_count": len(flagged),
            "contributors": results,
            "package_risk_summary": self._package_risk_summary(analyzed),
        }

    # ─── Baseline Builder ─────────────────────────────────────

    def _build_baseline(
        self, profile: dict, repos: list, events: list
    ) -> dict:
        """
        Build a behavioral baseline from GitHub data.
        """
        created_at = profile.get("created_at", "")
        account_age_days = 0
        if created_at:
            try:
                created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                account_age_days = (datetime.now(timezone.utc) - created).days
            except (ValueError, TypeError):
                pass

        # Analyze commit patterns from events
        commit_hours = []
        commit_dates = []
        push_events = [e for e in events if e.get("type") == "PushEvent"]
        total_commits = 0

        for event in push_events:
            event_time = event.get("created_at", "")
            if event_time:
                try:
                    dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                    commit_hours.append(dt.hour)
                    commit_dates.append(dt.date())
                except (ValueError, TypeError):
                    pass
            commits = event.get("payload", {}).get("commits", [])
            total_commits += len(commits)

        # Calculate commits per week
        if commit_dates:
            date_range = (max(commit_dates) - min(commit_dates)).days or 1
            weeks = max(date_range / 7, 1)
            avg_commits_per_week = round(total_commits / weeks, 2)
        else:
            avg_commits_per_week = 0.0

        # Typical commit hour
        typical_hour = None
        if commit_hours:
            hour_counter = Counter(commit_hours)
            typical_hour = hour_counter.most_common(1)[0][0]

        # Languages from repos
        languages = []
        for repo in repos:
            lang = repo.get("language")
            if lang:
                languages.append(lang)
        lang_counter = Counter(languages)
        primary_languages = [lang for lang, _ in lang_counter.most_common(5)]

        # Trust score (0-100)
        trust_score = self._calculate_trust_score(
            account_age_days=account_age_days,
            repo_count=len(repos),
            followers=profile.get("followers", 0),
            total_commits=total_commits,
        )

        return {
            "github_username": profile.get("login", ""),
            "account_age_days": account_age_days,
            "avg_commits_per_week": avg_commits_per_week,
            "typical_commit_hour": typical_hour,
            "avg_lines_changed": 0.0,  # Requires per-commit API calls — populated on deep scan
            "repo_count": len(repos),
            "primary_languages": primary_languages,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "trust_score": trust_score,
            "total_recent_commits": total_commits,
            "total_recent_events": len(events),
        }

    # ─── Trust Score ──────────────────────────────────────────

    @staticmethod
    def _calculate_trust_score(
        account_age_days: int,
        repo_count: int,
        followers: int,
        total_commits: int,
    ) -> float:
        """
        Calculate a trust score (0-100) based on account maturity.

        Factors (weighted):
          - Account age: 30% (max at 365+ days)
          - Repo count: 25% (max at 20+ repos)
          - Followers: 20% (max at 50+ followers)
          - Recent commits: 25% (max at 50+ commits)
        """
        age_score = min(account_age_days / 365, 1.0) * 30
        repo_score = min(repo_count / 20, 1.0) * 25
        follower_score = min(followers / 50, 1.0) * 20
        commit_score = min(total_commits / 50, 1.0) * 25

        return round(age_score + repo_score + follower_score + commit_score, 1)

    # ─── Deviation Detection ─────────────────────────────────

    def _detect_deviations(self, baseline: dict, events: list) -> list[dict]:
        """
        Detect behavioral deviations from the established baseline.
        Returns a list of deviation signals with type, severity, and details.
        """
        deviations = []

        # 1. Young account with maintainer activity
        if baseline["account_age_days"] < 90:
            deviations.append({
                "type": "young_account",
                "severity": "high" if baseline["account_age_days"] < 30 else "medium",
                "detail": (
                    f"Account is only {baseline['account_age_days']} days old. "
                    f"New accounts publishing packages are a common attack vector."
                ),
            })

        # 2. Unusual commit hours (if baseline exists)
        if baseline["typical_commit_hour"] is not None:
            off_hour_commits = self._count_off_hour_commits(
                events, baseline["typical_commit_hour"]
            )
            if off_hour_commits > 5:
                deviations.append({
                    "type": "commit_hour_shift",
                    "severity": "medium",
                    "detail": (
                        f"{off_hour_commits} commits outside typical hour "
                        f"({baseline['typical_commit_hour']}:00 UTC). "
                        f"Could indicate timezone change or account compromise."
                    ),
                })

        # 3. Burst activity from low-activity account
        if baseline["avg_commits_per_week"] < 2 and baseline["total_recent_events"] > 30:
            deviations.append({
                "type": "activity_burst",
                "severity": "medium",
                "detail": (
                    f"Low-activity account ({baseline['avg_commits_per_week']} "
                    f"commits/week) suddenly had {baseline['total_recent_events']} "
                    f"events. Sudden bursts can indicate automated attacks."
                ),
            })

        # 4. No repositories but publishing packages
        if baseline["repo_count"] == 0:
            deviations.append({
                "type": "no_repos",
                "severity": "high",
                "detail": (
                    "Account has zero public repositories but is associated "
                    "with package activity. Legitimate developers typically "
                    "have visible repositories."
                ),
            })

        # 5. Very low trust score
        if baseline["trust_score"] < 20:
            deviations.append({
                "type": "low_trust",
                "severity": "high",
                "detail": (
                    f"Trust score {baseline['trust_score']}/100 is critically low. "
                    f"This account lacks established history."
                ),
            })

        return deviations

    def _count_off_hour_commits(
        self, events: list, typical_hour: int, window: int = 4
    ) -> int:
        """Count commits that fall outside the typical working window."""
        count = 0
        for event in events:
            if event.get("type") != "PushEvent":
                continue
            event_time = event.get("created_at", "")
            if event_time:
                try:
                    dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                    hour_diff = abs(dt.hour - typical_hour)
                    if hour_diff > 12:
                        hour_diff = 24 - hour_diff
                    if hour_diff > window:
                        count += 1
                except (ValueError, TypeError):
                    pass
        return count

    # ─── Risk Flags ───────────────────────────────────────────

    @staticmethod
    def _generate_risk_flags(baseline: dict, deviations: list) -> list[str]:
        """Generate human-readable risk flags from baseline and deviations."""
        flags = []
        for dev in deviations:
            if dev["severity"] in ("high", "critical"):
                flags.append(f"[{dev['severity'].upper()}] {dev['type']}: {dev['detail']}")
        return flags

    # ─── Package Risk Summary ─────────────────────────────────

    @staticmethod
    def _package_risk_summary(analyzed_contributors: list) -> dict:
        """Generate a risk summary across all analyzed contributors."""
        total = len(analyzed_contributors)
        if total == 0:
            return {"risk_level": "unknown", "reason": "No contributors analyzed"}

        high_risk = 0
        medium_risk = 0
        all_deviations = []

        for contrib in analyzed_contributors:
            deviations = contrib.get("deviations", [])
            all_deviations.extend(deviations)
            severities = [d["severity"] for d in deviations]
            if "high" in severities or "critical" in severities:
                high_risk += 1
            elif "medium" in severities:
                medium_risk += 1

        if high_risk > 0:
            risk_level = "high"
            reason = f"{high_risk} contributor(s) with high-severity signals"
        elif medium_risk > total * 0.5:
            risk_level = "medium"
            reason = f"{medium_risk} contributor(s) with medium-severity signals"
        else:
            risk_level = "low"
            reason = "No significant contributor anomalies detected"

        return {
            "risk_level": risk_level,
            "reason": reason,
            "total_deviations": len(all_deviations),
            "high_risk_contributors": high_risk,
            "medium_risk_contributors": medium_risk,
        }

    # ─── PostgreSQL Storage ───────────────────────────────────

    async def _store_baseline(self, baseline: dict) -> None:
        """Store or update contributor baseline in PostgreSQL."""
        async with self._postgres.get_session() as session:
            # Check if baseline exists
            result = await session.execute(
                select(ContributorBaseline).where(
                    ContributorBaseline.github_username == baseline["github_username"]
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing baseline
                existing.account_age_days = baseline["account_age_days"]
                existing.avg_commits_per_week = baseline["avg_commits_per_week"]
                existing.typical_commit_hour = baseline["typical_commit_hour"]
                existing.avg_lines_changed = baseline["avg_lines_changed"]
                existing.repo_count = baseline["repo_count"]
                existing.primary_languages = baseline["primary_languages"]
                existing.last_updated = datetime.utcnow()
            else:
                # Create new baseline
                new_baseline = ContributorBaseline(
                    github_username=baseline["github_username"],
                    account_age_days=baseline["account_age_days"],
                    avg_commits_per_week=baseline["avg_commits_per_week"],
                    typical_commit_hour=baseline["typical_commit_hour"],
                    avg_lines_changed=baseline["avg_lines_changed"],
                    repo_count=baseline["repo_count"],
                    primary_languages=baseline["primary_languages"],
                    first_seen=datetime.utcnow(),
                    last_updated=datetime.utcnow(),
                )
                session.add(new_baseline)

            await session.commit()
            logger.info(f"Baseline stored for {baseline['github_username']}")

    # ─── Lookup Existing Baseline ─────────────────────────────

    async def get_stored_baseline(self, username: str) -> dict | None:
        """Retrieve a previously stored baseline from PostgreSQL."""
        async with self._postgres.get_session() as session:
            result = await session.execute(
                select(ContributorBaseline).where(
                    ContributorBaseline.github_username == username
                )
            )
            baseline = result.scalar_one_or_none()

            if baseline is None:
                return None

            return {
                "github_username": baseline.github_username,
                "account_age_days": baseline.account_age_days,
                "avg_commits_per_week": baseline.avg_commits_per_week,
                "typical_commit_hour": baseline.typical_commit_hour,
                "avg_lines_changed": baseline.avg_lines_changed,
                "repo_count": baseline.repo_count,
                "primary_languages": baseline.primary_languages,
                "first_seen": baseline.first_seen.isoformat() if baseline.first_seen else None,
                "last_updated": baseline.last_updated.isoformat() if baseline.last_updated else None,
            }
