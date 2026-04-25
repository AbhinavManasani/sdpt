"""
Software Provenance Tracker — Contributors API Router

Exposes REST endpoints for contributor analysis:
  - Analyze a single contributor
  - Analyze all contributors for a repository
  - Get stored baselines
  - Get GitHub rate limit status
"""

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from db.neo4j_conn import Neo4jManager
from db.postgres import PostgresManager
from db.redis_conn import RedisManager
from github.github_client import GitHubClient
from github.contributor_analyzer import ContributorAnalyzer

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.contributors")

router = APIRouter(prefix="/api/contributors", tags=["contributors"], dependencies=[Depends(verify_api_key)])


# ─── Request Models ───────────────────────────────────────────

class AnalyzeContributorRequest(BaseModel):
    """Request body for analyzing a single contributor."""
    username: str = Field(
        ...,
        description="GitHub username to analyze",
        min_length=1,
        max_length=255,
    )


class AnalyzeRepoContributorsRequest(BaseModel):
    """Request body for analyzing all contributors to a repository."""
    owner: str = Field(..., description="Repository owner", min_length=1)
    repo: str = Field(..., description="Repository name", min_length=1)
    ecosystem: str = Field(
        default="pypi",
        description="Package ecosystem: pypi or npm",
    )


# ─── Analyzer Instance ───────────────────────────────────────

_analyzer: ContributorAnalyzer | None = None
_github_client: GitHubClient | None = None


def setup_contributors_engine(
    neo4j: Neo4jManager,
    postgres: PostgresManager,
    redis: RedisManager,
) -> None:
    """Initialize the ContributorAnalyzer. Called during app startup."""
    global _analyzer, _github_client
    _github_client = GitHubClient(redis=redis)
    _analyzer = ContributorAnalyzer(
        github_client=_github_client,
        neo4j=neo4j,
        postgres=postgres,
        redis=redis,
    )
    logger.info("Contributors router engine initialized")


async def cleanup_contributors_engine() -> None:
    """Close the ContributorAnalyzer. Called during app shutdown."""
    global _analyzer, _github_client
    if _analyzer:
        await _analyzer.close()
        _analyzer = None
    _github_client = None


def _get_analyzer() -> ContributorAnalyzer:
    """Get the analyzer instance, raising if not initialized."""
    if _analyzer is None:
        raise HTTPException(
            status_code=503,
            detail="Contributor analyzer not initialized. Server may still be starting up.",
        )
    return _analyzer


def _get_github_client() -> GitHubClient:
    """Get the GitHub client instance."""
    if _github_client is None:
        raise HTTPException(
            status_code=503,
            detail="GitHub client not initialized.",
        )
    return _github_client


# ─── Endpoints ────────────────────────────────────────────────


@router.post("/analyze")
async def analyze_contributor(request: AnalyzeContributorRequest):
    """
    Analyze a single GitHub contributor.

    Fetches their profile, repositories, and events from GitHub,
    builds a behavioral baseline, detects deviations, and stores
    the results in PostgreSQL and Neo4j.

    Returns the full analysis including profile, baseline,
    deviations, and risk flags.
    """
    analyzer = _get_analyzer()

    try:
        result = await analyzer.analyze_contributor(request.username)
    except RuntimeError as e:
        if "rate limit" in str(e).lower():
            raise HTTPException(status_code=429, detail=str(e))
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis failed for {request.username}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    return result


@router.post("/analyze-repo")
async def analyze_repo_contributors(request: AnalyzeRepoContributorsRequest):
    """
    Analyze all contributors to a GitHub repository.

    Fetches the contributor list, analyzes each one (up to top 20),
    links them to the package in Neo4j, and returns a package-level
    risk summary.
    """
    analyzer = _get_analyzer()

    if request.ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="Ecosystem must be 'pypi' or 'npm'")

    try:
        result = await analyzer.analyze_package_contributors(
            owner=request.owner,
            repo=request.repo,
            ecosystem=request.ecosystem,
        )
    except RuntimeError as e:
        if "rate limit" in str(e).lower():
            raise HTTPException(status_code=429, detail=str(e))
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(
            f"Repo analysis failed for {request.owner}/{request.repo}: {e}",
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    return result


@router.get("/baseline/{username}")
async def get_contributor_baseline(username: str):
    """
    Get the stored behavioral baseline for a contributor.
    Returns 404 if the contributor hasn't been analyzed yet.
    """
    analyzer = _get_analyzer()

    baseline = await analyzer.get_stored_baseline(username)
    if baseline is None:
        raise HTTPException(
            status_code=404,
            detail=f"No baseline found for '{username}'. Run POST /analyze first.",
        )

    return {
        "username": username,
        "baseline": baseline,
    }


@router.get("/package/{ecosystem}/{package_name}")
async def get_package_contributors(package_name: str, ecosystem: str):
    """
    Get all contributors linked to a package in the graph.
    Returns contributor profiles from Neo4j.
    """
    analyzer = _get_analyzer()

    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="Ecosystem must be 'pypi' or 'npm'")

    try:
        contributors = await asyncio.to_thread(
            analyzer._neo4j.get_package_contributors, package_name, ecosystem
        )
    except Exception as e:
        logger.error(f"Package contributors query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "contributor_count": len(contributors),
        "contributors": contributors,
    }


@router.get("/rate-limit")
async def get_github_rate_limit():
    """
    Get current GitHub API rate limit status.
    Useful for monitoring API usage from the dashboard.
    """
    client = _get_github_client()

    try:
        status = await client.get_rate_limit_status()
    except Exception as e:
        logger.error(f"Rate limit check failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return status
