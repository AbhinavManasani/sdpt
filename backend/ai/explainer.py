"""
Software Provenance Tracker — AI Alert Explainer

Uses Groq API to generate plain-English explanations
of security alerts for developers who don't understand security jargon.

Each explanation covers:
  - What the threat is
  - Why it matters
  - What to do about it

Explanations are cached in Redis with a 1-hour TTL to avoid
redundant API calls for the same alert.

API: https://api.groq.com/openai/v1/chat/completions
Model: llama-3.3-70b-versatile
Key: loaded from .env as GROQ_API_KEY
"""

import json
import logging
import os

import httpx

from db.redis_conn import RedisManager

logger = logging.getLogger("provenance.ai.explainer")

# ─── Constants ────────────────────────────────────────────────

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

CACHE_PREFIX = "explanation"
CACHE_TTL = 3600  # 1 hour

HTTP_TIMEOUT = 30.0
MAX_TOKENS = 300  # ~200 words output

SYSTEM_PROMPT = """You are a security alert explainer for a software supply chain monitoring tool.
Your audience is software developers who may not be familiar with security terminology.

When given a security alert, explain it in plain English using this structure:

**What happened:** One sentence explaining the threat in simple terms.
**Why it matters:** One to two sentences on the real-world impact.
**What to do:** Two to three concrete action items the developer should take.

Rules:
- Keep the total explanation under 200 words.
- Avoid jargon — if you must use a technical term, define it briefly.
- Be specific to the package and alert details provided.
- Use a calm, helpful tone — not alarmist.
- Do NOT use markdown headers or bullet points — use the bold labels above, then plain text."""


class AlertExplainer:
    """
    Generates plain-English explanations of security alerts
    using Groq, with Redis caching.
    """

    def __init__(self, redis: RedisManager):
        self._redis = redis
        self._http: httpx.AsyncClient | None = None
        self._api_key: str | None = os.getenv("GROQ_API_KEY")

        if not self._api_key:
            logger.warning(
                "GROQ_API_KEY not set — AI explanations will be unavailable"
            )

    # ─── Lifecycle ────────────────────────────────────────────

    async def _ensure_http(self) -> httpx.AsyncClient:
        """Lazily create an httpx client."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                timeout=HTTP_TIMEOUT,
                headers={
                    "Authorization": f"Bearer {self._api_key or ''}",
                    "Content-Type": "application/json",
                },
            )
        return self._http

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None
        logger.info("AlertExplainer HTTP client closed")

    # ─── Public API ───────────────────────────────────────────

    async def explain_alert(
        self,
        alert: dict,
        package_context: dict | None = None,
    ) -> dict:
        """
        Generate a plain-English explanation of a security alert.

        Args:
            alert: Alert dict from the alerts table (id, severity,
                   alert_type, package_name, title, description, evidence).
            package_context: Optional extra context about the package
                   (version, ecosystem, dependencies, repo_url, etc.).

        Returns:
            Dict with explanation text, model used, and cache status.
        """
        alert_id = alert.get("id")

        # 1. Check Redis cache
        if alert_id:
            cached = await self._get_cached_explanation(alert_id)
            if cached:
                logger.debug(f"Explanation cache hit for alert {alert_id}")
                return {
                    "alert_id": alert_id,
                    "explanation": cached,
                    "model": GROQ_MODEL,
                    "cached": True,
                }

        # 2. Check API key availability
        if not self._api_key:
            return {
                "alert_id": alert_id,
                "explanation": None,
                "error": "GROQ_API_KEY not configured",
                "cached": False,
            }

        # 3. Build the prompt
        user_prompt = self._build_prompt(alert, package_context)

        # 4. Call Groq API
        try:
            explanation = await self._call_groq(user_prompt)
        except Exception as e:
            logger.error(f"Groq API call failed for alert {alert_id}: {e}")
            return {
                "alert_id": alert_id,
                "explanation": None,
                "error": f"AI explanation failed: {str(e)}",
                "cached": False,
            }

        # 5. Cache the result
        if alert_id and explanation:
            await self._cache_explanation(alert_id, explanation)

        return {
            "alert_id": alert_id,
            "explanation": explanation,
            "model": GROQ_MODEL,
            "cached": False,
        }

    async def explain_batch(
        self,
        alerts: list[dict],
    ) -> list[dict]:
        """
        Generate explanations for multiple alerts.
        Processes sequentially to respect rate limits.
        """
        results = []
        for alert in alerts:
            result = await self.explain_alert(alert)
            results.append(result)
        return results

    # ─── Prompt Builder ───────────────────────────────────────

    @staticmethod
    def _build_prompt(
        alert: dict,
        package_context: dict | None = None,
    ) -> str:
        """Build the user prompt from alert data and optional context."""
        parts = [
            "Explain this security alert to a developer:\n",
            f"Alert Type: {alert.get('alert_type', 'unknown')}",
            f"Severity: {alert.get('severity', 'unknown')}",
            f"Package: {alert.get('package_name', 'unknown')}",
        ]

        if alert.get("package_version"):
            parts.append(f"Version: {alert['package_version']}")

        if alert.get("title"):
            parts.append(f"Title: {alert['title']}")

        if alert.get("description"):
            parts.append(f"Details: {alert['description']}")

        if alert.get("contributor_username"):
            parts.append(f"Contributor: {alert['contributor_username']}")

        # Evidence
        evidence = alert.get("evidence", {})
        if evidence:
            if evidence.get("anomaly_score") is not None:
                parts.append(f"Anomaly Score: {evidence['anomaly_score']}/100")
            if evidence.get("rule_name"):
                parts.append(f"Triggered Rule: {evidence['rule_name']}")
            if evidence.get("rule_detail"):
                parts.append(f"Rule Detail: {evidence['rule_detail']}")

        # Package context
        if package_context:
            parts.append("\nAdditional Package Context:")
            if package_context.get("ecosystem"):
                parts.append(f"Ecosystem: {package_context['ecosystem']}")
            if package_context.get("repo_url"):
                parts.append(f"Repository: {package_context['repo_url']}")
            if package_context.get("author"):
                parts.append(f"Author: {package_context['author']}")
            if package_context.get("license"):
                parts.append(f"License: {package_context['license']}")
            if package_context.get("dependency_count") is not None:
                parts.append(
                    f"Dependencies: {package_context['dependency_count']}"
                )

        return "\n".join(parts)

    # ─── Groq API ─────────────────────────────────────────────

    async def _call_groq(self, user_prompt: str) -> str:
        """
        Make a real call to the Groq API using OpenAI-compatible format.
        Returns the text content of Groq's response.
        """
        client = await self._ensure_http()

        payload = {
            "model": GROQ_MODEL,
            "max_tokens": MAX_TOKENS,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        }

        resp = await client.post(GROQ_API_URL, json=payload)

        if resp.status_code != 200:
            raise RuntimeError(
                f"Groq API returned {resp.status_code}: {resp.text}"
            )

        data = resp.json()
        explanation = data["choices"][0]["message"]["content"].strip()

        if not explanation:
            raise RuntimeError("Groq returned an empty response")

        logger.info(
            f"Groq response received "
            f"({data.get('usage', {}).get('completion_tokens', '?')} tokens)"
        )

        return explanation

    # ─── Redis Cache ──────────────────────────────────────────

    async def _get_cached_explanation(self, alert_id: int) -> str | None:
        """Get a cached explanation by alert ID."""
        cached = await self._redis.get_cached(
            CACHE_PREFIX, str(alert_id)
        )
        if cached and isinstance(cached, dict):
            return cached.get("explanation")
        return None

    async def _cache_explanation(
        self, alert_id: int, explanation: str
    ) -> None:
        """Cache an explanation with 1-hour TTL."""
        await self._redis.set_cached(
            CACHE_PREFIX,
            str(alert_id),
            {"explanation": explanation},
            ttl_seconds=CACHE_TTL,
        )
        logger.debug(f"Cached explanation for alert {alert_id} (TTL: {CACHE_TTL}s)")

    async def clear_cache(self, alert_id: int | None = None) -> int:
        """
        Clear cached explanations.
        If alert_id is provided, clear just that one.
        Otherwise, clear all cached explanations.
        """
        if alert_id is not None:
            await self._redis.delete_cached(CACHE_PREFIX, str(alert_id))
            return 1
        else:
            return await self._redis.clear_prefix(CACHE_PREFIX)
