"""
Software Provenance Tracker — GitHub API Client

Async client for the GitHub REST API. Fetches contributor
profiles, commit histories, repository metadata, and
collaborator information.

Uses the user's GitHub PAT for authenticated requests
(5000 req/hr). Tracks rate limits in Redis to avoid
hitting GitHub's ceiling.

All data is real — no mock fallbacks.
"""

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from config import get_settings
from db.redis_conn import RedisManager

logger = logging.getLogger("provenance.github.client")


class GitHubClient:
    """
    Async GitHub REST API client with Redis caching
    and automatic rate limit tracking.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self, redis: RedisManager):
        self._redis = redis
        self._settings = get_settings()
        self._client: httpx.AsyncClient | None = None

        token = self._settings.github_token
        if token:
            self._headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        else:
            logger.warning("No GitHub token configured. Rate limit: 60/hour")
            self._headers = {"Accept": "application/vnd.github+json"}

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=True,
                headers=self._headers,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ─── Rate Limit Tracking ─────────────────────────────────

    async def _check_rate_limit(self) -> None:
        """Check if we have API calls remaining before making a request."""
        remaining = await self._redis.get_rate_limit_remaining("github")
        if remaining == 0:
            raise RuntimeError(
                "GitHub API rate limit exhausted. "
                "Wait for the rate limit to reset before retrying."
            )
        if remaining != -1 and remaining < 100:
            logger.warning(f"GitHub API rate limit low: {remaining} calls remaining")

    async def _update_rate_limit(self, response: httpx.Response) -> None:
        """Extract and store rate limit info from response headers."""
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_ts = response.headers.get("X-RateLimit-Reset")

        if remaining is not None and reset_ts is not None:
            await self._redis.set_rate_limit_remaining(
                remaining=int(remaining),
                reset_timestamp=int(reset_ts),
                api="github",
            )

    # ─── Core Request Method ─────────────────────────────────

    async def _request(
        self,
        endpoint: str,
        params: dict | None = None,
        cache_key: str | None = None,
        cache_ttl: int | None = None,
    ) -> dict | list | None:
        """
        Make an authenticated GitHub API request with caching.

        Args:
            endpoint: API path (e.g. "/users/torvalds")
            params: Query parameters
            cache_key: Redis cache key (skips cache if None)
            cache_ttl: Cache TTL in seconds (defaults to settings value)

        Returns:
            Parsed JSON response or None if 404
        """
        # Check cache first
        if cache_key:
            cached = await self._redis.get_github_data(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit: github:{cache_key}")
                return cached

        # Check rate limit
        await self._check_rate_limit()

        # Make the request
        client = await self._get_client()
        try:
            response = await client.get(endpoint, params=params)
        except httpx.RequestError as e:
            logger.error(f"GitHub API request failed for {endpoint}: {e}")
            raise

        # Update rate limit tracking
        await self._update_rate_limit(response)

        if response.status_code == 404:
            logger.warning(f"GitHub resource not found: {endpoint}")
            return None

        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining", "unknown")
            if remaining == "0":
                raise RuntimeError("GitHub API rate limit exceeded")
            raise RuntimeError(f"GitHub API forbidden: {response.text}")

        if response.status_code != 200:
            raise RuntimeError(
                f"GitHub API error: {response.status_code} for {endpoint}"
            )

        data = response.json()

        # Cache the response
        if cache_key:
            ttl = cache_ttl or self._settings.github_cache_ttl
            await self._redis.set_github_data(cache_key, data, ttl_seconds=ttl)

        return data

    async def _request_paginated(
        self,
        endpoint: str,
        params: dict | None = None,
        cache_key: str | None = None,
        cache_ttl: int | None = None,
        max_pages: int = 5,
    ) -> list:
        """
        Fetch all pages of a paginated GitHub API response.
        Returns the combined list of all items across pages.
        """
        # Check cache for the full result
        if cache_key:
            cached = await self._redis.get_github_data(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit (paginated): github:{cache_key}")
                return cached

        all_items = []
        params = dict(params) if params else {}
        params.setdefault("per_page", 100)

        for page in range(1, max_pages + 1):
            params["page"] = page

            await self._check_rate_limit()
            client = await self._get_client()

            try:
                response = await client.get(endpoint, params=params)
            except httpx.RequestError as e:
                logger.error(f"GitHub paginated request failed: {e}")
                raise

            await self._update_rate_limit(response)

            if response.status_code != 200:
                logger.warning(
                    f"GitHub API returned {response.status_code} on page {page}"
                )
                break

            page_data = response.json()
            if not page_data:
                break

            all_items.extend(page_data)

            # Check if there are more pages
            link_header = response.headers.get("Link", "")
            if 'rel="next"' not in link_header:
                break

        # Cache the full result
        if cache_key and all_items:
            ttl = cache_ttl or self._settings.github_cache_ttl
            await self._redis.set_github_data(cache_key, all_items, ttl_seconds=ttl)

        return all_items

    # ─── User Profile ────────────────────────────────────────

    async def get_user_profile(self, username: str) -> dict | None:
        """
        Fetch a GitHub user's public profile.
        Returns: login, name, bio, company, created_at,
                 public_repos, followers, etc.
        """
        return await self._request(
            f"/users/{username}",
            cache_key=f"user:{username}",
        )

    # ─── User Repositories ───────────────────────────────────

    async def get_user_repos(self, username: str) -> list:
        """
        Fetch all public repositories for a user.
        Returns: list of repo objects with name, language,
                 stargazers_count, created_at, pushed_at, etc.
        """
        return await self._request_paginated(
            f"/users/{username}/repos",
            params={"type": "all", "sort": "pushed"},
            cache_key=f"repos:{username}",
        )

    # ─── User Events (Recent Activity) ───────────────────────

    async def get_user_events(self, username: str) -> list:
        """
        Fetch a user's recent public events.
        Limited to the last 90 days / 300 events by GitHub.
        """
        return await self._request_paginated(
            f"/users/{username}/events/public",
            cache_key=f"events:{username}",
            max_pages=3,  # Events are limited anyway
        )

    # ─── Repository Contributors ─────────────────────────────

    async def get_repo_contributors(
        self, owner: str, repo: str
    ) -> list:
        """
        Fetch all contributors to a repository.
        Returns: list of {login, contributions, avatar_url, ...}
        """
        return await self._request_paginated(
            f"/repos/{owner}/{repo}/contributors",
            cache_key=f"contributors:{owner}/{repo}",
        )

    # ─── Repository Commits ──────────────────────────────────

    async def get_repo_commits(
        self,
        owner: str,
        repo: str,
        author: str | None = None,
        since: str | None = None,
        max_pages: int = 3,
    ) -> list:
        """
        Fetch commits for a repository, optionally filtered by author.
        Returns: list of commit objects with sha, message, author, date, etc.
        """
        params = {}
        if author:
            params["author"] = author
        if since:
            params["since"] = since

        cache_key = f"commits:{owner}/{repo}"
        if author:
            cache_key += f":{author}"

        return await self._request_paginated(
            f"/repos/{owner}/{repo}/commits",
            params=params,
            cache_key=cache_key,
            max_pages=max_pages,
        )

    # ─── Repository Details ──────────────────────────────────

    async def get_repo_details(self, owner: str, repo: str) -> dict | None:
        """
        Fetch full repository metadata.
        Returns: name, description, language, stargazers_count,
                 forks_count, created_at, updated_at, etc.
        """
        return await self._request(
            f"/repos/{owner}/{repo}",
            cache_key=f"repo:{owner}/{repo}",
        )

    # ─── Repository Collaborators ─────────────────────────────

    async def get_repo_collaborators(
        self, owner: str, repo: str
    ) -> list:
        """
        Fetch collaborators with direct access to a repository.
        Requires push access to the repo for this endpoint.
        Falls back to contributors if forbidden.
        """
        try:
            return await self._request_paginated(
                f"/repos/{owner}/{repo}/collaborators",
                cache_key=f"collaborators:{owner}/{repo}",
            )
        except RuntimeError as e:
            if "forbidden" in str(e).lower():
                logger.info(
                    f"Collaborators endpoint forbidden for {owner}/{repo}, "
                    f"falling back to contributors"
                )
                return await self.get_repo_contributors(owner, repo)
            raise

    # ─── Rate Limit Status ────────────────────────────────────

    async def get_rate_limit_status(self) -> dict:
        """
        Fetch current rate limit status from GitHub API.
        Does not count against the rate limit.
        """
        client = await self._get_client()
        response = await client.get("/rate_limit")
        if response.status_code == 200:
            data = response.json()
            core = data.get("resources", {}).get("core", {})
            return {
                "limit": core.get("limit", 0),
                "remaining": core.get("remaining", 0),
                "reset_at": datetime.fromtimestamp(
                    core.get("reset", 0), tz=timezone.utc
                ).isoformat(),
                "used": core.get("used", 0),
            }
        return {"error": f"Failed to fetch rate limit: {response.status_code}"}

    # ─── Convenience: Extract Repo from URL ──────────────────

    @staticmethod
    def parse_repo_url(url: str) -> tuple[str, str] | None:
        """
        Extract (owner, repo) from a GitHub URL.
        Supports:
          - https://github.com/owner/repo
          - https://github.com/owner/repo.git
          - git@github.com:owner/repo.git
        Returns None if not a valid GitHub URL.
        """
        import re

        patterns = [
            r"github\.com[/:](?P<owner>[^/]+)/(?P<repo>[^/.]+?)(?:\.git)?$",
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group("owner"), match.group("repo")
        return None
