"""
Software Provenance Tracker — FastAPI Application Entry Point

Initializes the FastAPI app, registers all routers, manages database
connections via lifespan events, and exposes the /health endpoint
for infrastructure monitoring.
"""

import asyncio
import logging
import sys
import os
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.dirname(__file__))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

import logging.handlers

def setup_logging():
    log_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'sdpt.log')
    
    formatter = logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    )
    
    # Rotating file handler — 10MB per file, keep 5 backups
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding='utf-8',
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

setup_logging()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import get_settings
from db.postgres import PostgresManager
from db.neo4j_conn import Neo4jManager
from db.redis_conn import RedisManager
from routers.dependencies import router as dependencies_router, setup_engine, cleanup_engine
from routers.contributors import router as contributors_router, setup_contributors_engine, cleanup_contributors_engine
from routers.anomaly import router as anomaly_router, setup_anomaly_engine, cleanup_anomaly_engine
from routers.ledger import router as ledger_router, setup_ledger_engine, cleanup_ledger_engine
from routers.alerts import router as alerts_router, setup_alerts_engine, cleanup_alerts_engine
from routers.cve import router as cve_router, setup_cve_engine, cleanup_cve_engine
from routers.typosquat import (
    router as typosquat_router,
    setup_typosquat_engine,
    cleanup_typosquat_engine,
)
from routers.sbom import (
    router as sbom_router,
    setup_sbom_engine,
    cleanup_sbom_engine,
)
from routers.typosquat import get_typosquat_detector
from routers.ai import (
    router as ai_router,
    setup_ai_engine,
    cleanup_ai_engine,
)
from routers.notifications import (
    router as notifications_router,
    setup_notifications_engine,
    cleanup_notifications_engine,
)
from routers.diff import (
    router as diff_router,
    setup_diff_engine,
    cleanup_diff_engine,
)
from routers.trends import (
    router as trends_router,
    setup_trends_engine,
    cleanup_trends_engine,
)
from routers.monitor import (
    router as monitor_router,
    setup_monitor_engine,
    start_monitor,
    cleanup_monitor_engine,
)
from routers.anomaly import get_anomaly_detector
from routers.auth import router as auth_router, setup_auth_router
from auth.api_key import setup_auth

logger = logging.getLogger("provenance")

# ─── Database Managers (module-level singletons) ──────────────
postgres = PostgresManager()
neo4j = Neo4jManager()
redis = RedisManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: validate settings, connect to all databases.
    Shutdown: close all connections cleanly.
    """
    settings = get_settings()

    logger.info("Starting Software Provenance Tracker...")
    logger.info(f"Environment: {settings.app_env}")

    # Connect to all databases
    try:
        await postgres.connect(settings.postgres_dsn)
        logger.info("PostgreSQL connected")
    except Exception as e:
        logger.error(f"PostgreSQL connection failed: {e}")
        raise

    try:
        neo4j.connect(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
        logger.info("Neo4j connected")
    except Exception as e:
        logger.error(f"Neo4j connection failed: {e}")
        raise

    try:
        await redis.connect(settings.redis_url)
        logger.info("Redis connected")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        raise

    import httpx as _httpx
    try:
        async with _httpx.AsyncClient(timeout=5.0) as _gh_client:
            _gh_resp = await _gh_client.get(
                "https://api.github.com/rate_limit",
                headers={"Authorization": f"Bearer {settings.github_token}"},
            )
        _gh_valid = _gh_resp.status_code == 200
    except Exception:
        _gh_valid = False
    await redis.set_raw("github:token:valid", "true" if _gh_valid else "false", ttl_seconds=3600)
    logger.info(f"GitHub token status: {'valid' if _gh_valid else 'invalid/expired'}")

    # Initialize auth
    await setup_auth(redis)
    setup_auth_router(redis)

    # Initialize router engines
    setup_anomaly_engine()
    setup_engine(neo4j, redis, postgres)
    setup_contributors_engine(neo4j, postgres, redis)
    setup_ledger_engine(postgres)
    setup_alerts_engine(postgres)
    setup_diff_engine(redis=redis, postgres=postgres)
    setup_cve_engine(postgres, redis)
    setup_typosquat_engine(redis)
    setup_sbom_engine(postgres, redis, get_typosquat_detector())
    setup_ai_engine(redis, postgres)
    setup_notifications_engine(redis)
    setup_trends_engine(postgres)
    setup_monitor_engine(
        redis=redis,
        postgres=postgres,
        detector=get_anomaly_detector(),
    )
    await start_monitor()

    logger.info("All services connected. Application ready.")

    from tasks.pruning import run_daily_pruning
    asyncio.create_task(run_daily_pruning(postgres))
    logger.info("Daily trend pruning task scheduled.")

    yield

    # Shutdown — close all connections
    logger.info("Shutting down...")
    await cleanup_engine()
    await cleanup_contributors_engine()
    cleanup_anomaly_engine()
    cleanup_ledger_engine()
    cleanup_alerts_engine()
    await cleanup_cve_engine()
    await cleanup_typosquat_engine()
    cleanup_sbom_engine()
    await cleanup_ai_engine()
    await cleanup_notifications_engine()
    await cleanup_diff_engine()
    cleanup_trends_engine()
    await cleanup_monitor_engine()
    await postgres.disconnect()
    neo4j.disconnect()
    await redis.disconnect()
    logger.info("All connections closed. Goodbye.")


# ─── FastAPI App ──────────────────────────────────────────────
app = FastAPI(
    title="Software Provenance Tracker",
    description=(
        "Production-grade system monitoring software dependencies "
        "and contributor behavior to detect supply chain attacks."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class LimitRequestSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.headers.get("content-length"):
            content_length = int(request.headers["content-length"])
            if content_length > 1_048_576:  # 1MB
                return Response("Request too large. Maximum size is 1MB.", status_code=413)
        return await call_next(request)

app.add_middleware(LimitRequestSizeMiddleware)

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── CORS Middleware ──────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Health Check Endpoint ────────────────────────────────────
@app.get("/health", tags=["infrastructure"])
async def health_check():
    """
    Checks connectivity to Neo4j, PostgreSQL, and Redis.
    Returns 200 if all services are reachable.
    Returns 503 with details of which service is down.
    """
    status = {
        "postgres": "down",
        "neo4j": "down",
        "redis": "down",
    }
    all_healthy = True

    # Check PostgreSQL
    try:
        await postgres.health_check()
        status["postgres"] = "up"
    except Exception as e:
        all_healthy = False
        status["postgres"] = f"down — {str(e)}"

    # Check Neo4j
    try:
        neo4j.health_check()
        status["neo4j"] = "up"
    except Exception as e:
        all_healthy = False
        status["neo4j"] = f"down — {str(e)}"

    # Check Redis
    try:
        await redis.health_check()
        status["redis"] = "up"
    except Exception as e:
        all_healthy = False
        status["redis"] = f"down — {str(e)}"

    gh_raw = await redis.get_raw("github:token:valid")  
    github_status = gh_raw if gh_raw else "unknown"

    response = {
        "status": "healthy" if all_healthy else "degraded",
        "services": status,
        "github_token": github_status
    }

    if all_healthy:
        return JSONResponse(content=response, status_code=200)
    else:
        return JSONResponse(content=response, status_code=503)


# ─── Router Registration ─────────────────────────────────────
app.include_router(dependencies_router)
from fastapi import Request as FastAPIRequest
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: FastAPIRequest, exc: Exception):
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Check server logs for details."},
    )

app.include_router(contributors_router)
app.include_router(anomaly_router)
app.include_router(ledger_router)
app.include_router(alerts_router)
app.include_router(auth_router)
app.include_router(cve_router)
app.include_router(typosquat_router)
app.include_router(sbom_router)
app.include_router(ai_router)
app.include_router(notifications_router)
app.include_router(diff_router)
app.include_router(trends_router)
app.include_router(monitor_router)


# ─── Development Server ──────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.app_env == "development",
        log_level=settings.app_log_level.lower(),
    )
